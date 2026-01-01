# accounts/models.py
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta

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
        # Get all notifications for user
        all_notifications = cls.objects.filter(user=user)
        
        # Filter to only visible ones
        visible = []
        for notif in all_notifications:
            if notif.should_be_visible():
                visible.append(notif)
        
        return visible
    
    @classmethod
    def cleanup_old_notifications(cls, user):
        """Delete notifications that are read and older than 24 hours"""
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