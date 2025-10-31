from django.db import models
from django.contrib.auth.models import User

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    email_verified = models.BooleanField(default=False)
    verification_token = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return f"{self.user.email} Profile"

class LoginAttempt(models.Model):
    email = models.CharField(max_length=254)
    ip_address = models.GenericIPAddressField()
    success = models.BooleanField()
    timestamp = models.DateTimeField(auto_now_add=True)