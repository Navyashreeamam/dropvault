from django.db import models
from django.contrib.auth.models import User
import uuid
import os
import secrets
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta


def user_upload_path(instance, filename):
    """Store as: media/user_<id>/<uuid>.<ext>"""
    ext = filename.split('.')[-1].lower()
    safe_name = f"{uuid.uuid4().hex}.{ext}"
    return os.path.join(f"user_{instance.user.id}", safe_name)

class File(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, db_index=True)
    file = models.FileField(upload_to=user_upload_path)
    original_name = models.CharField(max_length=255)
    size = models.PositiveBigIntegerField()
    uploaded_at = models.DateTimeField(auto_now_add=True)
    deleted = models.BooleanField(default=False, db_index=True)
    sha256 = models.CharField(max_length=64, db_index=True)

    class Meta:
        indexes = [
            models.Index(fields=['user', 'deleted']),
        ]

class Trash(models.Model):
    file = models.OneToOneField(File, on_delete=models.CASCADE)
    deleted_at = models.DateTimeField(auto_now_add=True)

class FileLog(models.Model):
    ACTIONS = [('UPLOAD', 'Upload'), ('DELETE', 'Delete'), ('RESTORE', 'Restore')]
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file = models.ForeignKey(File, on_delete=models.CASCADE)
    action = models.CharField(max_length=10, choices=ACTIONS)
    timestamp = models.DateTimeField(auto_now_add=True)

class SharedLink(models.Model):
    file = models.ForeignKey(File, on_delete=models.CASCADE)
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    slug = models.CharField(max_length=12, unique=True, db_index=True)  # public short ID
    token = models.CharField(max_length=128, unique=True)               # internal secure token
    max_downloads = models.PositiveIntegerField(default=5)
    view_count = models.PositiveIntegerField(default=0)
    download_count = models.PositiveIntegerField(default=0)
    first_accessed_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    def is_expired(self):
        if not self.is_active:
            return True
        if self.expires_at:
            return timezone.now() > self.expires_at
        return False

    def activate_expiry(self):
        """Start 24h timer on first access"""
        if self.first_accessed_at is None:
            now = timezone.now()
            self.first_accessed_at = now
            self.expires_at = now + timedelta(hours=24)
            self.save(update_fields=['first_accessed_at', 'expires_at'])