# accounts/middleware.py
import logging
from django.shortcuts import redirect
from django.contrib import messages

logger = logging.getLogger(__name__)


class EmailVerificationMiddleware:
    """
    Middleware to handle email verification requirements.
    API endpoints are excluded to prevent JSON/HTML conflicts.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip if user not authenticated
        if not request.user.is_authenticated:
            return self.get_response(request)
        
        # Get user profile
        profile = getattr(request.user, 'userprofile', None)
        
        # If no profile or email already verified, allow access
        if not profile or profile.email_verified:
            return self.get_response(request)
        
        # If user has no email, allow access
        user_email = getattr(request.user, 'email', '').strip()
        if not user_email:
            return self.get_response(request)
        
        current_path = request.path
        
        # ═══════════════════════════════════════════════════════════
        # ✅ SKIP THESE PATHS - They handle their own auth/return JSON
        # ═══════════════════════════════════════════════════════════
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
        
        # Home page
        if current_path == '/':
            return self.get_response(request)
        
        # Dashboard - allow but show warning
        if current_path.startswith('/dashboard'):
            if not request.session.get('verification_warning_shown'):
                messages.warning(request, "📧 Please verify your email to unlock all features.")
                request.session['verification_warning_shown'] = True
            return self.get_response(request)
        
        # All other paths - redirect to verification
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