# accounts/adapters.py
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.contrib.auth import get_user_model
from .models import UserProfile

User = get_user_model()

class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):
    def save_user(self, request, sociallogin, form=None):
        # Save user
        user = super().save_user(request, sociallogin, form)

        email_verified = True

        # Ensure profile exists
        profile, created = UserProfile.objects.get_or_create(
            user=user,
            defaults={'email_verified': email_verified}
        )
        if not created:
            profile.email_verified = email_verified
            profile.save(update_fields=['email_verified'])

        return user

    def pre_social_login(self, request, sociallogin):
        user = sociallogin.user
        if user.id:
            UserProfile.objects.get_or_create(
                user=user,
                defaults={'email_verified': True}
            )