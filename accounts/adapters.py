from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.contrib.auth import get_user_model
from .models import UserProfile

User = get_user_model()

class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):
    def save_user(self, request, sociallogin, form=None):
        # Save user but DO NOT mark email as verified
        user = super().save_user(request, sociallogin, form)
        UserProfile.objects.get_or_create(user=user, defaults={'email_verified': False})
        return user

    def pre_social_login(self, request, sociallogin):
        # If user exists but profile missing, create it
        user = sociallogin.user
        if user.id and not hasattr(user, 'userprofile'):
            UserProfile.objects.get_or_create(user=user, defaults={'email_verified': False})