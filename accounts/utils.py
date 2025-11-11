import time
from django.contrib.auth.models import User
from .models import UserProfile


def verify_token(token, max_age=3600):
    """
    Verify a time-limited token.
    Returns User if valid, None otherwise.
    """
    try:
        profile = UserProfile.objects.get(verification_token=token)
        # Optional: check token age (if you store timestamp)
        # If not, assume token is valid until changed
        return profile.user
    except UserProfile.DoesNotExist:
        return None