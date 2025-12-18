# accounts/middleware.py
import logging
from django.urls import reverse
from django.shortcuts import redirect
from django.contrib import messages

logger = logging.getLogger(__name__)


class EmailVerificationMiddleware:
    """
    Middleware to handle email verification requirements.
    IMPORTANT: API endpoints must be excluded to prevent JSON/HTML conflicts.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip if user not authenticated
        if not request.user.is_authenticated:
            return self.get_response(request)
        
        # Get user profile
        profile = getattr(request.user, 'userprofile', None)
        
        # ✅ If no profile or email already verified, allow access
        if not profile or profile.email_verified:
            return self.get_response(request)
        
        # ✅ If user has no email, allow access
        user_email = getattr(request.user, 'email', '').strip()
        if not user_email:
            return self.get_response(request)
        
        current_path = request.path
        
        # ═══════════════════════════════════════════════════════════
        # ✅ API PATHS - NEVER redirect, let API views handle auth
        # ═══════════════════════════════════════════════════════════
        api_paths = [
            '/api/',
            '/files/',
        ]
        
        for api_path in api_paths:
            if current_path.startswith(api_path):
                # Let API views handle authentication - don't redirect
                return self.get_response(request)
        
        # ═══════════════════════════════════════════════════════════
        # ✅ EXEMPT PATHS - Don't require email verification
        # ═══════════════════════════════════════════════════════════
        exempt_paths = [
            '/accounts/verify-email/',
            '/accounts/verify-prompt/',
            '/accounts/logout/',
            '/accounts/login/',
            '/accounts/signup/',
            '/admin/',
            '/static/',
            '/media/',
            '/',
        ]
        
        for exempt_path in exempt_paths:
            if current_path.startswith(exempt_path) or current_path == exempt_path:
                return self.get_response(request)
        
        # ═══════════════════════════════════════════════════════════
        # ✅ DASHBOARD - Allow access but show warning
        # ═══════════════════════════════════════════════════════════
        if current_path.startswith('/dashboard'):
            # Don't block, just warn once per session
            if not request.session.get('verification_warning_shown'):
                messages.warning(request, "📧 Please verify your email to unlock all features.")
                request.session['verification_warning_shown'] = True
            return self.get_response(request)
        
        # ═══════════════════════════════════════════════════════════
        # ❌ ALL OTHER PATHS - Redirect to verification prompt
        # ═══════════════════════════════════════════════════════════
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
        except Exception as e:
            if 'Session data corrupted' not in str(e):
                logger.warning(f"Session error: {e}")
            request.session.flush()
            request.session.cycle_key()
        
        response = self.get_response(request)
        return response