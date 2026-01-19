# accounts/middleware.py
import logging
from django.shortcuts import redirect
from django.contrib import messages
from django.http import JsonResponse
from django.urls import resolve
from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token

logger = logging.getLogger(__name__)
User = get_user_model()

class EmailVerificationMiddleware:
    """
    Middleware to handle email verification requirements.
    API endpoints are excluded to prevent JSON/HTML conflicts.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not request.user.is_authenticated:
            return self.get_response(request)
        
        profile = getattr(request.user, 'userprofile', None)
        
        if not profile or profile.email_verified:
            return self.get_response(request)
        
        user_email = getattr(request.user, 'email', '').strip()
        if not user_email:
            return self.get_response(request)
        
        current_path = request.path
        
        skip_paths = [
            '/api/',
            '/files/',
            '/s/',
            '/admin/',
            '/static/',
            '/media/',
            '/accounts/verify-email/',
            '/accounts/verify-prompt/',
            '/accounts/logout/',
            '/accounts/login/',
            '/accounts/signup/',
            '/health/',
        ]
        
        for skip_path in skip_paths:
            if current_path.startswith(skip_path):
                return self.get_response(request)
        
        if current_path == '/':
            return self.get_response(request)
        
        if current_path.startswith('/dashboard'):
            if not request.session.get('verification_warning_shown'):
                messages.warning(request, "📧 Please verify your email to unlock all features.")
                request.session['verification_warning_shown'] = True
            return self.get_response(request)
        
        messages.warning(request, "Please verify your email to access this page.")
        return redirect('verify_email_prompt')


class SessionCleanupMiddleware:
    """Clean up corrupted sessions"""
    
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        try:
            if hasattr(request, 'session'):
                _ = request.session.session_key
        except Exception:
            request.session.flush()
        
        return self.get_response(request)



class TokenAuthenticationMiddleware:
    """
    Middleware to authenticate users via Token in Authorization header.
    This allows API requests to work with token-based auth.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Skip if user is already authenticated via session
        if request.user.is_authenticated:
            return self.get_response(request)
        
        # Check for Authorization header with Token
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        
        if auth_header.startswith('Token '):
            token_key = auth_header.split(' ')[1]
            
            try:
                token = Token.objects.select_related('user').get(key=token_key)
                
                # Set the user on the request
                request.user = token.user
                
                logger.debug(f"Token auth successful for: {token.user.email}")
                
            except Token.DoesNotExist:
                logger.warning(f"Invalid token attempted: {token_key[:10]}...")
        
        return self.get_response(request)


class PasswordResetRequiredMiddleware:
    """
    Redirect users with unusable passwords to password reset flow.
    This catches users affected by corrupted password bug.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        
        # URLs that don't require password reset check
        self.exempt_urls = [
            'api_forgot_password',
            'api_reset_password',
            'api_verify_reset_token',
            'api_logout',
            'api_google_login',
            'api_signup',
            'api_login',
            'health_check',
            'shared_file',
            'shared_file_download',
        ]
        
        # Path prefixes that are always exempt
        self.exempt_paths = [
            '/admin/',
            '/static/',
            '/media/',
            '/s/',  # Shared file links
        ]
    
    def __call__(self, request):
        # Skip for non-authenticated requests
        if not request.user.is_authenticated:
            return self.get_response(request)
        
        # Skip for exempt paths
        for path in self.exempt_paths:
            if request.path.startswith(path):
                return self.get_response(request)
        
        # Skip for exempt URLs
        try:
            url_name = resolve(request.path_info).url_name
            if url_name in self.exempt_urls:
                return self.get_response(request)
        except:
            pass
        
        # Check if user has unusable password (corrupted or OAuth-only)
        if not request.user.has_usable_password():
            # Allow password reset endpoints
            if '/api/set-password/' in request.path or '/api/forgot-password/' in request.path:
                return self.get_response(request)
            
            # For API endpoints, return JSON response
            if request.path.startswith('/api/'):
                logger.warning(f"User {request.user.email} needs password reset")
                
                return JsonResponse({
                    'error': 'password_reset_required',
                    'message': 'Your password needs to be reset. Please use "Forgot Password" to set a new password.',
                    'action_required': 'PASSWORD_RESET',
                    'user_email': request.user.email
                }, status=403)
        
        return self.get_response(request)


class APILoggingMiddleware:
    """
    Log all API requests for debugging and monitoring
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Only log API requests
        if request.path.startswith('/api/'):
            user_info = f"User: {request.user.email}" if request.user.is_authenticated else "Anonymous"
            logger.info(f"API Request: {request.method} {request.path} - {user_info}")
        
        response = self.get_response(request)
        
        # Log response status for errors
        if request.path.startswith('/api/') and response.status_code >= 400:
            logger.warning(f"API Error: {request.method} {request.path} - Status: {response.status_code}")
        
        return response


class RateLimitMiddleware:
    """
    Simple rate limiting middleware using cache.
    More sophisticated than Django's built-in throttling.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        
        # Rate limits per endpoint type (requests per minute)
        self.rate_limits = {
            'upload': 10,
            'download': 30,
            'api': 100,
            'login': 5,
        }
    
    def __call__(self, request):
        # Skip for non-API requests
        if not request.path.startswith('/api/'):
            return self.get_response(request)
        
        # Determine rate limit category
        category = self._get_category(request.path)
        
        if category:
            # Get client identifier
            client_id = self._get_client_id(request)
            
            # Check rate limit
            from django.core.cache import cache
            
            cache_key = f"ratelimit:{category}:{client_id}"
            current = cache.get(cache_key, 0)
            
            limit = self.rate_limits.get(category, 100)
            
            if current >= limit:
                logger.warning(f"Rate limit exceeded: {client_id} on {category}")
                
                return JsonResponse({
                    'error': 'rate_limit_exceeded',
                    'message': f'Too many requests. Please try again in a minute.',
                    'retry_after': 60
                }, status=429)
            
            # Increment counter (60 second window)
            cache.set(cache_key, current + 1, timeout=60)
        
        response = self.get_response(request)
        
        # Add rate limit headers
        if category:
            limit = self.rate_limits.get(category, 100)
            response['X-RateLimit-Limit'] = limit
            response['X-RateLimit-Remaining'] = max(0, limit - current - 1)
        
        return response
    
    def _get_category(self, path):
        """Determine rate limit category from path"""
        if '/upload' in path:
            return 'upload'
        elif '/download' in path:
            return 'download'
        elif '/login' in path or '/signup' in path:
            return 'login'
        elif path.startswith('/api/'):
            return 'api'
        return None
    
    def _get_client_id(self, request):
        """Get unique client identifier"""
        # Prefer authenticated user
        if request.user.is_authenticated:
            return f"user:{request.user.id}"
        
        # Fall back to IP address
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', 'unknown')
        
        return f"ip:{ip}"
