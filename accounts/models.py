# accounts/models.py
from django.db import models
from django.contrib.auth.models import User  # Using Django's default User
from django.utils import timezone
from datetime import timedelta

# =============================================================================
# USER PROFILE - Extends Django's default User model
# =============================================================================

class UserProfile(models.Model):
    """Extended user profile with additional fields"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    
    # Email verification
    email_verified = models.BooleanField(default=False)
    verification_token = models.CharField(max_length=255, blank=True, null=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Storage tracking (calculated from files, not stored here)
    @property
    def storage_used(self):
        """Calculate total storage used from files"""
        from files.models import File
        from django.db.models import Sum
        total = File.objects.filter(
            user=self.user, 
            deleted=False
        ).aggregate(total=Sum('size'))['total']
        return total or 0
    
    @property
    def storage_limit(self):
        """Storage limit in bytes (10GB default)"""
        return 10 * 1024 * 1024 * 1024  # 10GB
    
    @property
    def storage_used_mb(self):
        return round(self.storage_used / (1024 * 1024), 2)
    
    @property
    def storage_limit_mb(self):
        return round(self.storage_limit / (1024 * 1024), 2)
    
    @property
    def storage_percentage(self):
        if self.storage_limit == 0:
            return 0
        return round((self.storage_used / self.storage_limit) * 100, 2)
    
    @property
    def storage_remaining(self):
        return self.storage_limit - self.storage_used
    
    def __str__(self):
        return f"{self.user.email} Profile"
    
    class Meta:
        verbose_name = "User Profile"
        verbose_name_plural = "User Profiles"


# =============================================================================
# LOGIN ATTEMPTS - Security tracking
# =============================================================================

class LoginAttempt(models.Model):
    """Track login attempts for security"""
    email = models.CharField(max_length=254, db_index=True)
    ip_address = models.GenericIPAddressField()
    success = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)
    user_agent = models.TextField(blank=True, default='')
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['email', 'timestamp']),
            models.Index(fields=['ip_address', 'timestamp']),
        ]
    
    def __str__(self):
        status = 'Success' if self.success else 'Failed'
        return f"{self.email} - {status} - {self.timestamp}"


# =============================================================================
# NOTIFICATIONS - User activity notifications
# =============================================================================

class Notification(models.Model):
    """
    Notification system for user activities
    
    Logic:
    - Unread notifications persist until read
    - After reading, they stay visible for 24 hours then auto-delete
    - Frontend shows only: unread OR (read within last 24 hours)
    """
    
    NOTIFICATION_TYPES = [
        ('FILE_UPLOAD', 'File Uploaded'),
        ('FILE_SHARE', 'File Shared'),
        ('FILE_DOWNLOAD', 'File Downloaded'),
        ('SHARE_ACCESSED', 'Shared Link Accessed'),
        ('FILE_DELETED', 'File Deleted'),
        ('FILE_RESTORED', 'File Restored'),
        ('STORAGE_WARNING', 'Storage Warning'),
        ('SYSTEM', 'System Notification'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    notification_type = models.CharField(max_length=20, choices=NOTIFICATION_TYPES)
    title = models.CharField(max_length=200)
    message = models.TextField()
    
    # Related file info (optional)
    file_name = models.CharField(max_length=255, blank=True, null=True)
    file_id = models.IntegerField(blank=True, null=True)
    
    # Status tracking
    is_read = models.BooleanField(default=False, db_index=True)
    read_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'is_read']),
            models.Index(fields=['user', 'created_at']),
        ]
        verbose_name = "Notification"
        verbose_name_plural = "Notifications"
    
    def __str__(self):
        return f"{self.notification_type}: {self.title} ({self.user.email})"
    
    def mark_as_read(self):
        """Mark notification as read and set read timestamp"""
        if not self.is_read:
            self.is_read = True
            self.read_at = timezone.now()
            self.save(update_fields=['is_read', 'read_at'])
    
    def should_be_visible(self):
        """
        Check if notification should be visible:
        - Unread: Always visible
        - Read: Visible only if read within last 24 hours
        """
        if not self.is_read:
            return True
        
        if self.read_at:
            hours_since_read = (timezone.now() - self.read_at).total_seconds() / 3600
            return hours_since_read <= 24
        
        return False
    
    @classmethod
    def get_visible_notifications(cls, user):
        """Get all visible notifications for a user"""
        # Get unread notifications
        unread = cls.objects.filter(user=user, is_read=False)
        
        # Get recently read notifications (within 24 hours)
        cutoff_time = timezone.now() - timedelta(hours=24)
        recent_read = cls.objects.filter(
            user=user, 
            is_read=True, 
            read_at__gte=cutoff_time
        )
        
        # Combine and return
        return list(unread) | list(recent_read)
    
    @classmethod
    def cleanup_old_notifications(cls, user):
        """Delete notifications that are read and older than 24 hours"""
        cutoff_time = timezone.now() - timedelta(hours=24)
        deleted_count = cls.objects.filter(
            user=user,
            is_read=True,
            read_at__lt=cutoff_time
        ).delete()[0]
        return deleted_count
    
    @classmethod
    def create_notification(cls, user, notification_type, title, message, file_name=None, file_id=None):
        """Helper to create a notification"""
        return cls.objects.create(
            user=user,
            notification_type=notification_type,
            title=title,
            message=message,
            file_name=file_name,
            file_id=file_id
        )