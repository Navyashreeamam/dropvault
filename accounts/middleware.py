from django.shortcuts import redirect
from django.urls import reverse
from django.contrib import messages

class EmailVerificationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            # ✅ Safe check: only proceed if user has profile
            if hasattr(request.user, 'userprofile'):
                profile = request.user.userprofile
                exempt_urls = [
                    reverse('verify_email'),
                    reverse('verify_email_prompt'),
                    reverse('logout'),
                    '/admin/',          # ← add admin
                    '/accounts/',       # allauth URLs
                ]
                if not profile.email_verified and not any(request.path.startswith(url) for url in exempt_urls):
                    messages.warning(request, "Please verify your email to access the dashboard.")
                    return redirect('verify_email_prompt')
        return self.get_response(request)

##clicking your verification link → email_verified = True → access granted

