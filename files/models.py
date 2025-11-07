# C:\Users\Navy\dropvault\files\models.py
import os
import uuid
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta


def user_upload_path(instance, filename):
    ext = filename.split('.')[-1].lower()
    safe_name = f"{uuid.uuid4().hex}.{ext}"
    return os.path.join(f"user_{instance.user.id}", safe_name)


class File(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file = models.FileField(upload_to=user_upload_path)
    original_name = models.CharField(max_length=255)
    size = models.PositiveBigIntegerField()
    sha256 = models.CharField(max_length=64)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    deleted = models.BooleanField(default=False, db_index=True)
    encryption_meta = models.TextField(default='[]')

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
    slug = models.CharField(max_length=12, unique=True, db_index=True)
    token = models.CharField(max_length=64, unique=True, null=True, blank=True)
    max_downloads = models.PositiveIntegerField(default=5)
    view_count = models.PositiveIntegerField(default=0)
    download_count = models.PositiveIntegerField(default=0)
    first_accessed_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    def save(self, *args, **kwargs):
        if not self.slug:
            import secrets
            self.slug = secrets.token_urlsafe(8)[:12]
        if not self.token:
            import secrets
            self.token = secrets.token_urlsafe(48)
        super().save(*args, **kwargs)

    def is_expired(self):
        if not self.is_active:
            return True
        if self.expires_at and timezone.now() > self.expires_at:
            return True
        return False

    def activate_expiry(self):
        if self.first_accessed_at is None:
            now = timezone.now()
            SharedLink.objects.filter(id=self.id).update(
                first_accessed_at=now,
                expires_at=now + timedelta(hours=24)
            )