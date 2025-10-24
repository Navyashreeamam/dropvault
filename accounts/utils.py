from django.contrib.auth.models import User
from .models import UserProfile

def verify_token(token):
    try:
        profile = UserProfile.objects.get(verification_token=token)
        return profile.user
    except UserProfile.DoesNotExist:
        return None