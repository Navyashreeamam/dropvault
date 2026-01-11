# files/models.py
import os
import uuid
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth import get_user_model

User = get_user_model()


def user_upload_path(instance, filename):
    """Generate unique file path for each user"""
    ext = filename.split('.')[-1].lower()
    safe_name = f"{uuid.uuid4().hex}.{ext}"
    return os.path.join(f"user_{instance.user.id}", safe_name)


class ActiveFileManager(models.Manager):
    """Manager to get only active (non-deleted) files"""
    def get_queryset(self):
        return super().get_queryset().filter(deleted_at__isnull=True)


class TrashFileManager(models.Manager):
    """Manager to get only trashed files"""
    def get_queryset(self):
        return super().get_queryset().filter(deleted_at__isnull=False)


class File(models.Model):
    """File model with soft delete functionality"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='files')
    file = models.FileField(upload_to=user_upload_path, blank=True, null=True)
    original_name = models.CharField(max_length=255)
    size = models.PositiveBigIntegerField()
    sha256 = models.CharField(max_length=64, db_index=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    deleted = models.BooleanField(default=False, db_index=True)
    deleted_at = models.DateTimeField(null=True, blank=True, db_index=True)
    encryption_meta = models.TextField(default='[]', blank=True)
    
    cloudinary_url = models.URLField(max_length=500, blank=True, null=True)
    cloudinary_public_id = models.CharField(max_length=255, blank=True, null=True)
    cloudinary_resource_type = models.CharField(max_length=20, blank=True, null=True)

    objects = models.Manager()
    
    class Meta:
        ordering = ['-uploaded_at']
        indexes = [
            models.Index(fields=['user', 'deleted']),
            models.Index(fields=['user', 'deleted_at']),
            models.Index(fields=['sha256']),
        ]

    def get_download_url(self):
        """Get the correct download URL"""
        # Prefer Cloudinary URL if available
        if self.cloudinary_url:
            return self.cloudinary_url
        # Fallback to file field URL
        if self.file:
            try:
                return self.file.url
            except:
                pass
        return None

    def soft_delete(self):
        self.deleted = True
        self.deleted_at = timezone.now()
        self.save(update_fields=['deleted', 'deleted_at'])

    def restore(self):
        self.deleted = False
        self.deleted_at = None
        self.save(update_fields=['deleted', 'deleted_at'])

    def is_in_trash(self):
        return self.deleted or self.deleted_at is not None

    def __str__(self):
        status = '🗑️' if self.is_in_trash() else '✅'
        return f"{self.original_name} ({status})"
    

class Trash(models.Model):
    """Legacy trash model - kept for backward compatibility"""
    file = models.OneToOneField(File, on_delete=models.CASCADE)
    deleted_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Trash: {self.file.original_name}"


class FileLog(models.Model):
    """Log file actions for audit trail"""
    ACTIONS = [
        ('UPLOAD', 'Upload'),
        ('DELETE', 'Delete'),
        ('RESTORE', 'Restore'),
        ('DOWNLOAD', 'Download'),
        ('SHARE', 'Share'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file = models.ForeignKey(File, on_delete=models.CASCADE, related_name='logs')
    action = models.CharField(max_length=10, choices=ACTIONS)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.user.email} - {self.action} - {self.file.original_name}"


class SharedLink(models.Model):
    """Shareable links for files"""
    file = models.ForeignKey(File, on_delete=models.CASCADE, related_name='shared_links')
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='shared_links')
    slug = models.CharField(max_length=12, unique=True, db_index=True)
    token = models.CharField(max_length=64, unique=True, null=True, blank=True)
    max_downloads = models.PositiveIntegerField(default=5)
    view_count = models.PositiveIntegerField(default=0)
    download_count = models.PositiveIntegerField(default=0)
    first_accessed_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    is_email_only = models.BooleanField(default=False)

    class Meta:
        ordering = ['-created_at']

    def save(self, *args, **kwargs):
        """Auto-generate slug and token if not set"""
        if not self.slug:
            import secrets
            self.slug = secrets.token_urlsafe(8)[:12]
        if not self.token:
            import secrets
            self.token = secrets.token_urlsafe(48)
        super().save(*args, **kwargs)

    def is_expired(self):
        """Check if link has expired"""
        if not self.is_active:
            return True
        if self.expires_at and timezone.now() > self.expires_at:
            return True
        if self.download_count >= self.max_downloads:
            return True
        return False

    def activate_expiry(self):
        """Activate 24-hour expiry on first access"""
        if self.first_accessed_at is None:
            now = timezone.now()
            SharedLink.objects.filter(id=self.id).update(
                first_accessed_at=now,
                expires_at=now + timedelta(hours=24)
            )

    def __str__(self):
        status = "Expired" if self.is_expired() else "🟢 Active"
        return f"{self.file.original_name} - {self.slug} ({status})"