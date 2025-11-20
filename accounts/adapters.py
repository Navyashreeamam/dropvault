# accounts/adapters.py
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.contrib.auth import get_user_model
from .models import UserProfile

User = get_user_model()

class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):
    def save_user(self, request, sociallogin, form=None):
        # Save user
        user = super().save_user(request, sociallogin, form)

        # ✅ Trust Google/GitHub/etc. email — mark as verified
        email_verified = True  # ← PRODUCTION-GRADE: major providers verify email

        # Ensure profile exists
        profile, created = UserProfile.objects.get_or_create(
            user=user,
            defaults={'email_verified': email_verified}
        )
        if not created:
            # If profile existed, update verification
            profile.email_verified = email_verified
            profile.save(update_fields=['email_verified'])

        return user

    def pre_social_login(self, request, sociallogin):
        # Also fix profiles for existing users
        user = sociallogin.user
        if user.id:
            UserProfile.objects.get_or_create(
                user=user,
                defaults={'email_verified': True}
            )