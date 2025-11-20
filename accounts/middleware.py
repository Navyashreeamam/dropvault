from django.urls import reverse
from django.shortcuts import redirect
from django.contrib import messages


class EmailVerificationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            profile = getattr(request.user, 'userprofile', None)
            if profile and not profile.email_verified:
                # ✅ Safety: If user has no email, skip enforcement (but log/alert if needed)
                user_email = getattr(request.user, 'email', '').strip()
                if not user_email:
                    # Optional: Log or warn — but allow access so user can set email
                    # print(f"⚠️ Middleware bypass: user {request.user.username} has no email")
                    return self.get_response(request)

                # List of exempt paths (safe to access without email verification)
                exempt_paths = [
                    '/accounts/verify-email/',   # covers /accounts/verify-email/?token=...
                    reverse('verify_email_prompt'),
                    reverse('logout'),
                    '/admin/',
                    '/accounts/api/',
                ]

                # Check if current path is exempt
                if not any(request.path.startswith(path) for path in exempt_paths):
                    messages.warning(request, "Please verify your email to access the dashboard.")
                    return redirect('verify_email_prompt')

        return self.get_response(request)