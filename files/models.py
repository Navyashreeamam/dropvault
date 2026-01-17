# files/models.py
import os
import uuid
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.conf import settings
from datetime import timedelta


def user_upload_path(instance, filename):
    """Generate unique file path for each user"""
    ext = filename.split('.')[-1].lower()
    safe_name = f"{uuid.uuid4().hex}.{ext}"
    return os.path.join(f"user_{instance.user.id}", safe_name)


class File(models.Model):
    """File model with Cloudinary support"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='files')
    file = models.FileField(upload_to=user_upload_path, blank=True, null=True)
    original_name = models.CharField(max_length=255)
    size = models.PositiveBigIntegerField()
    sha256 = models.CharField(max_length=64, db_index=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    deleted = models.BooleanField(default=False, db_index=True)
    deleted_at = models.DateTimeField(null=True, blank=True, db_index=True)
    encryption_meta = models.TextField(default='[]', blank=True)
    
    # Cloudinary fields
    cloudinary_url = models.URLField(max_length=500, blank=True, null=True)
    cloudinary_public_id = models.CharField(max_length=255, blank=True, null=True)
    cloudinary_resource_type = models.CharField(max_length=20, default='auto', blank=True, null=True)

    objects = models.Manager()
    
    class Meta:
        ordering = ['-uploaded_at']
        indexes = [
            models.Index(fields=['user', 'deleted']),
            models.Index(fields=['user', 'deleted_at']),
            models.Index(fields=['sha256']),
        ]

    def __str__(self):
        status = '🗑️' if self.is_in_trash() else '✅'
        return f"{self.original_name} ({status})"

    def save(self, *args, **kwargs):
        """Override save to upload to Cloudinary if configured"""
        if self.file and hasattr(settings, 'CLOUDINARY_CLOUD_NAME') and settings.CLOUDINARY_CLOUD_NAME:
            try:
                import cloudinary.uploader
                
                # Upload to Cloudinary
                result = cloudinary.uploader.upload(
                    self.file,
                    folder=f'dropvault/user_{self.user.id}',
                    use_filename=True,
                    unique_filename=True,
                    resource_type='auto'
                )
                
                # Store Cloudinary info
                self.cloudinary_url = result.get('secure_url')
                self.cloudinary_public_id = result.get('public_id')
                self.cloudinary_resource_type = result.get('resource_type', 'auto')
                
                print(f"✅ Uploaded to Cloudinary: {self.cloudinary_url}")
            except Exception as e:
                print(f"⚠️ Cloudinary upload failed: {e}")
                # Continue saving to local storage as fallback
        
        super().save(*args, **kwargs)

    def get_download_url(self):
        """Get the correct download URL"""
        # Prefer Cloudinary URL if available
        if self.cloudinary_url:
            return self.cloudinary_url
        # Fallback to local file
        if self.file:
            try:
                return self.file.url
            except:
                pass
        return None

    def soft_delete(self):
        """Move file to trash"""
        self.deleted = True
        self.deleted_at = timezone.now()
        self.save(update_fields=['deleted', 'deleted_at'])

    def restore(self):
        """Restore file from trash"""
        self.deleted = False
        self.deleted_at = None
        self.save(update_fields=['deleted', 'deleted_at'])

    def is_in_trash(self):
        """Check if file is in trash"""
        return self.deleted or self.deleted_at is not None

    def delete(self, *args, **kwargs):
        """Override delete to remove from Cloudinary"""
        if self.cloudinary_public_id:
            try:
                import cloudinary.uploader
                cloudinary.uploader.destroy(self.cloudinary_public_id)
                print(f"✅ Deleted from Cloudinary: {self.cloudinary_public_id}")
            except Exception as e:
                print(f"⚠️ Cloudinary delete failed: {e}")
        
        # Delete local file if exists
        if self.file:
            try:
                self.file.delete()
            except:
                pass
        
        super().delete(*args, **kwargs)


class Trash(models.Model):
    """Legacy trash model"""
    file = models.OneToOneField(File, on_delete=models.CASCADE)
    deleted_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Trash: {self.file.original_name}"


class FileLog(models.Model):
    """Log file actions"""
    ACTIONS = [
        ('UPLOAD', 'Upload'),
        ('DELETE', 'Delete'),
        ('RESTORE', 'Restore'),
        ('DOWNLOAD', 'Download'),
        ('SHARE', 'Share'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='file_logs')
    file = models.ForeignKey(File, on_delete=models.CASCADE, related_name='logs')
    action = models.CharField(max_length=10, choices=ACTIONS)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.user.username} - {self.action} - {self.file.original_name}"


class SharedLink(models.Model):
    """Shareable links for files"""
    file = models.ForeignKey(File, on_delete=models.CASCADE, related_name='shared_links')
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='owned_shared_links')
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

    def __str__(self):
        status = "Expired" if self.is_expired() else "🟢 Active"
        return f"{self.file.original_name} - {self.slug} ({status})"

    def save(self, *args, **kwargs):
        """Auto-generate slug and token"""
        if not self.slug:
            import secrets
            self.slug = secrets.token_urlsafe(8)[:12]
        if not self.token:
            import secrets
            self.token = secrets.token_urlsafe(48)
        super().save(*args, **kwargs)

    def is_expired(self):
        """Check if link expired"""
        if not self.is_active:
            return True
        if self.expires_at and timezone.now() > self.expires_at:
            return True
        if self.download_count >= self.max_downloads:
            return True
        return False

    def activate_expiry(self):
        """Activate 24-hour expiry"""
        if self.first_accessed_at is None:
            now = timezone.now()
            SharedLink.objects.filter(id=self.id).update(
                first_accessed_at=now,
                expires_at=now + timedelta(hours=24)
            )