# accounts/middleware.py
import logging
from django.urls import reverse
from django.shortcuts import redirect
from django.contrib import messages

logger = logging.getLogger(__name__)

class EmailVerificationMiddleware:
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
        
        # ✅ If user has no email, allow access (but log warning)
        user_email = getattr(request.user, 'email', '').strip()
        if not user_email:
            return self.get_response(request)
        
        # ✅ List of paths that DON'T require email verification
        exempt_paths = [
            '/accounts/verify-email/',
            '/accounts/verify-prompt/',
            '/accounts/logout/',
            '/admin/',
            '/accounts/api/',
            '/files/upload/',
            '/files/list/',
            '/files/delete/',
            '/files/share/',
            '/files/trash/',
            '/static/',
            '/media/',
        ]
        
        # Check if current path is exempt
        current_path = request.path
        
        # ✅ IMPORTANT: Allow dashboard access even without verification
        # Just show a message instead of blocking
        if current_path.startswith('/dashboard/'):
            # Don't block, just warn once per session
            if not request.session.get('verification_warning_shown'):
                messages.warning(request, "📧 Please verify your email to unlock all features.")
                request.session['verification_warning_shown'] = True
            return self.get_response(request)
        
        # For other paths, check if exempt
        for exempt_path in exempt_paths:
            if current_path.startswith(exempt_path):
                return self.get_response(request)
        
        # If not exempt and not verified, redirect to verification prompt
        messages.warning(request, "Please verify your email to access this page.")
        return redirect('verify_email_prompt')

class SessionCleanupMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        # Check for corrupted session
        try:
            if hasattr(request, 'session'):
                # Try to access session
                _ = request.session.session_key
        except Exception as e:
            if 'Session data corrupted' not in str(e):
                logger.warning(f"Session error: {e}")
            # Clear the bad session
            request.session.flush()
            request.session.cycle_key()
        
        response = self.get_response(request)
        return response
