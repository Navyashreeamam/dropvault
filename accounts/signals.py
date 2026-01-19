# accounts/signals.py
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from .models import UserProfile

@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.get_or_create(user=instance)
        
    # Ensure email is set from username if missing
    if not instance.email and '@' in instance.username:
        instance.email = instance.username
        instance.save(update_fields=['email'])