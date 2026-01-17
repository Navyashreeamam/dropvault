# files/models.py
from django.db import models
from django.conf import settings
from django.utils import timezone
from django.utils.crypto import get_random_string
import os

# ✅ FIXED: Use settings.AUTH_USER_MODEL instead of get_user_model()
# This allows string reference instead of importing the actual model


def upload_to_path(instance, filename):
    """Generate upload path for files"""
    # Get file extension
    ext = filename.split('.')[-1] if '.' in filename else ''
    
    # Generate random filename
    random_name = get_random_string(32)
    new_filename = f"{random_name}.{ext}" if ext else random_name
    
    # Return path: uploads/user_<id>/filename
    return os.path.join('uploads', f'user_{instance.owner.id}', new_filename)


class File(models.Model):
    """File model for storing uploaded files"""
    
    # ✅ FIXED: Use settings.AUTH_USER_MODEL string reference
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='files'
    )
    
    # File fields
    file = models.FileField(upload_to=upload_to_path)
    original_filename = models.CharField(max_length=255)
    file_size = models.BigIntegerField(help_text="File size in bytes")
    content_type = models.CharField(max_length=100, blank=True)
    
    # Metadata
    uploaded_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Soft delete
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)
    
    # File organization
    folder = models.CharField(max_length=255, blank=True, default='')
    tags = models.CharField(max_length=500, blank=True, help_text="Comma-separated tags")
    
    class Meta:
        ordering = ['-uploaded_at']
        indexes = [
            models.Index(fields=['owner', 'is_deleted']),
            models.Index(fields=['uploaded_at']),
        ]
    
    def __str__(self):
        return f"{self.original_filename} - {self.owner.username}"
    
    def soft_delete(self):
        """Soft delete the file"""
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.save()
    
    def restore(self):
        """Restore a soft-deleted file"""
        self.is_deleted = False
        self.deleted_at = None
        self.save()
    
    def get_file_extension(self):
        """Get file extension"""
        return self.original_filename.split('.')[-1].lower() if '.' in self.original_filename else ''
    
    def get_readable_size(self):
        """Return human-readable file size"""
        size = self.file_size
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"


class SharedLink(models.Model):
    """Model for sharing files via links"""
    
    file = models.ForeignKey(
        File,
        on_delete=models.CASCADE,
        related_name='shared_links'
    )
    
    # ✅ FIXED: Use settings.AUTH_USER_MODEL string reference
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='created_shares'
    )
    
    # Share link details
    slug = models.SlugField(max_length=50, unique=True, db_index=True)
    password = models.CharField(max_length=255, blank=True, null=True)
    
    # Expiration
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    
    # Access control
    is_active = models.BooleanField(default=True)
    max_downloads = models.IntegerField(null=True, blank=True, help_text="Max number of downloads allowed")
    download_count = models.IntegerField(default=0)
    
    # Tracking
    last_accessed = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['slug']),
            models.Index(fields=['file', 'is_active']),
        ]
    
    def __str__(self):
        return f"Share: {self.file.original_filename} - {self.slug}"
    
    def is_expired(self):
        """Check if link is expired"""
        if self.expires_at and timezone.now() > self.expires_at:
            return True
        if self.max_downloads and self.download_count >= self.max_downloads:
            return True
        return False
    
    def increment_download(self):
        """Increment download count"""
        self.download_count += 1
        self.last_accessed = timezone.now()
        self.save()
    
    def get_share_url(self):
        """Get the full share URL"""
        from django.conf import settings
        return f"{settings.SITE_URL}/s/{self.slug}/"


class FileVersion(models.Model):
    """Model for storing file versions"""
    
    file = models.ForeignKey(
        File,
        on_delete=models.CASCADE,
        related_name='versions'
    )
    
    # Version details
    version_number = models.IntegerField()
    file_data = models.FileField(upload_to='versions/')
    file_size = models.BigIntegerField()
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='file_versions'
    )
    
    change_description = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-version_number']
        unique_together = ['file', 'version_number']
        indexes = [
            models.Index(fields=['file', 'version_number']),
        ]
    
    def __str__(self):
        return f"{self.file.original_filename} - v{self.version_number}"


class FileAccessLog(models.Model):
    """Log file access for security/auditing"""
    
    file = models.ForeignKey(
        File,
        on_delete=models.CASCADE,
        related_name='access_logs'
    )
    
    # ✅ FIXED: Use settings.AUTH_USER_MODEL string reference
    accessed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='file_accesses'
    )
    
    # Access details
    action = models.CharField(
        max_length=50,
        choices=[
            ('view', 'Viewed'),
            ('download', 'Downloaded'),
            ('share', 'Shared'),
            ('delete', 'Deleted'),
            ('restore', 'Restored'),
        ]
    )
    
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=500, blank=True)
    
    accessed_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-accessed_at']
        indexes = [
            models.Index(fields=['file', 'accessed_at']),
            models.Index(fields=['accessed_by', 'accessed_at']),
        ]
    
    def __str__(self):
        user = self.accessed_by.username if self.accessed_by else 'Anonymous'
        return f"{user} - {self.action} - {self.file.original_filename}"