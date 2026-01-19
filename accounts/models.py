# accounts/models.py
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta


class UserProfile(models.Model):
    """Extended user profile"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    email_verified = models.BooleanField(default=False)
    verification_token = models.CharField(max_length=255, blank=True, null=True)
    storage_used = models.BigIntegerField(default=0)
    storage_limit = models.BigIntegerField(default=10737418240)  # 10GB
    

    password_set_by_user = models.BooleanField(default=False)

    signed_up_with_google = models.BooleanField(default=False)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Profile: {self.user.email}"
    
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


class LoginAttempt(models.Model):
    """Track login attempts for security"""
    email = models.CharField(max_length=254)
    ip_address = models.GenericIPAddressField()
    success = models.BooleanField()
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.email} - {'Success' if self.success else 'Failed'} - {self.timestamp}"


class Notification(models.Model):
    """Notification system for user activities"""
    
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
    is_read = models.BooleanField(default=False)
    read_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'is_read']),
            models.Index(fields=['user', 'created_at']),
        ]
    
    def __str__(self):
        return f"{self.notification_type}: {self.title} ({self.user.username})"
    
    def mark_as_read(self):
        """Mark notification as read"""
        if not self.is_read:
            self.is_read = True
            self.read_at = timezone.now()
            self.save(update_fields=['is_read', 'read_at'])
    
    def should_be_visible(self):
        """Check if notification should be visible"""
        if not self.is_read:
            return True
        
        if self.read_at:
            hours_since_read = (timezone.now() - self.read_at).total_seconds() / 3600
            return hours_since_read <= 24
        
        return False
    
    # ✅ ADD THIS METHOD (it was missing!)
    @classmethod
    def get_visible_notifications(cls, user):
        """Get all visible notifications for a user"""
        from django.utils import timezone
        from datetime import timedelta
        
        # Get unread notifications
        unread = cls.objects.filter(user=user, is_read=False)
        
        # Get read notifications from last 24 hours
        cutoff_time = timezone.now() - timedelta(hours=24)
        recent_read = cls.objects.filter(
            user=user,
            is_read=True,
            read_at__gte=cutoff_time
        )
        
        # Combine and return as list
        return list(unread) + list(recent_read)
    
    @classmethod
    def cleanup_old_notifications(cls, user):
        """Delete old read notifications"""
        from django.utils import timezone
        from datetime import timedelta
        
        cutoff_time = timezone.now() - timedelta(hours=24)
        cls.objects.filter(
            user=user,
            is_read=True,
            read_at__lt=cutoff_time
        ).delete()
    
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