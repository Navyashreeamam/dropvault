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


class TokenAuthenticationMiddleware:
    """
    Middleware to authenticate users via Token in Authorization header.
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
                request.user = token.user
                logger.debug(f"Token auth successful for: {token.user.email}")
            except Token.DoesNotExist:
                logger.warning(f"Invalid token attempted")
        
        return self.get_response(request)


class PasswordResetRequiredMiddleware:
    """
    Redirect users with unusable passwords to password reset flow.
    CRITICAL: Excludes Google OAuth users - they don't have passwords by design.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        
        # URLs that don't require password check
        self.exempt_urls = [
            'api_forgot_password',
            'api_reset_password',
            'api_verify_reset_token',
            'api_logout',
            'api_google_login',
            'api_signup',
            'api_login',
            'api_check_auth',
            'api_set_password',
            'api_verify_email',
            'api_verify_email_token',
            'api_resend_verification',
            'api_dashboard',
            'api_user_profile',
            'api_user_storage',
            'api_notifications',
            'api_list',
            'api_upload',
            'api_delete',
            'api_trash',
            'api_restore',
            'api_share',
            'api_shared_files',
            'api_download',
            'api_test_email',
            'health_check',
            'shared_file',
            'shared_file_download',
        ]
        
        # Path prefixes that are always exempt
        self.exempt_paths = [
            '/admin/',
            '/static/',
            '/media/',
            '/s/',
            '/health/',
            '/api/auth/',
            '/api/login/',
            '/api/logout/',
            '/api/signup/',
            '/api/verify',
            '/api/resend',
            '/api/forgot',
            '/api/reset',
            '/api/set-password/',
            '/api/test',
            '/api/debug',
            '/api/dashboard/',
            '/api/user/',
            '/api/list/',
            '/api/upload/',
            '/api/files/',
            '/api/notifications/',
            '/api/trash/',
            '/api/share/',
            '/api/shared/',
            '/api/download/',
            '/api/delete/',
            '/api/restore/',
        ]
    
    def __call__(self, request):
        # Skip for non-authenticated requests
        if not request.user.is_authenticated:
            return self.get_response(request)
        
        # Skip for exempt paths
        for path in self.exempt_paths:
            if request.path.startswith(path):
                return self.get_response(request)
        
        # Skip for exempt URL names
        try:
            url_name = resolve(request.path_info).url_name
            if url_name and url_name in self.exempt_urls:
                return self.get_response(request)
        except:
            pass
        
        # ✅ CRITICAL FIX: Check if user is a Google OAuth user
        # Google users don't have passwords - this is EXPECTED behavior
        try:
            profile = request.user.profile
            if profile.signup_method == 'google':
                # Google users don't need passwords - allow through
                logger.debug(f"Google user {request.user.email} - skipping password check")
                return self.get_response(request)
        except Exception as e:
            logger.debug(f"Could not check profile for {request.user.email}: {e}")
            pass
        
        # Check if user has unusable password
        # But ONLY block non-Google users with corrupted passwords
        if not request.user.has_usable_password():
            # Double-check signup method
            try:
                profile = request.user.profile
                if profile.signup_method == 'google':
                    return self.get_response(request)
            except:
                pass
            
            # For API endpoints, return JSON response
            if request.path.startswith('/api/'):
                logger.warning(f"User {request.user.email} needs password reset (non-Google user with no password)")
                
                return JsonResponse({
                    'error': 'password_reset_required',
                    'message': 'Your password needs to be reset. Please use "Forgot Password" to set a new password.',
                    'action_required': 'PASSWORD_RESET',
                    'user_email': request.user.email
                }, status=403)
        
        return self.get_response(request)


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


class EmailVerificationMiddleware:
    """
    Middleware to handle email verification requirements.
    API endpoints are excluded to prevent JSON/HTML conflicts.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Always allow through - let the views handle verification
        return self.get_response(request)