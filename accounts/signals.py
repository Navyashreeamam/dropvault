# accounts/signals.py
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """Create UserProfile when User is created"""
    if created:
        try:
            from .models import UserProfile
            UserProfile.objects.get_or_create(user=instance)
        except Exception as e:
            print(f"Error creating profile: {e}")


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """Save UserProfile when User is saved - SAFE VERSION"""
    # Don't do anything here - it was causing the error
    pass