# accounts/models.py

from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta
import secrets


class UserProfile(models.Model):
    """Extended user profile"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    
    # Email verification
    email_verified = models.BooleanField(default=False)
    verification_token = models.CharField(max_length=255, blank=True, null=True)
    verification_sent_at = models.DateTimeField(blank=True, null=True)
    
    # Signup method
    signup_method = models.CharField(max_length=20, default='email')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def generate_verification_token(self):
        """Generate a new verification token"""
        self.verification_token = secrets.token_urlsafe(32)
        self.verification_sent_at = timezone.now()
        self.save()
        return self.verification_token
    
    def is_verification_token_valid(self, token):
        """Check if token is valid (not expired - 24 hours)"""
        if not self.verification_token or self.verification_token != token:
            return False
        
        if not self.verification_sent_at:
            return False
        
        # Token expires after 24 hours
        expiry = self.verification_sent_at + timedelta(hours=24)
        return timezone.now() < expiry
    
    @property
    def storage_used(self):
        from files.models import File
        from django.db.models import Sum
        total = File.objects.filter(user=self.user, deleted=False).aggregate(total=Sum('size'))['total']
        return total or 0
    
    @property
    def storage_limit(self):
        return 10 * 1024 * 1024 * 1024  # 10GB
    
    def __str__(self):
        return f"{self.user.email} Profile"


class Notification(models.Model):
    """User notifications"""
    
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
    file_name = models.CharField(max_length=255, blank=True, null=True)
    file_id = models.IntegerField(blank=True, null=True)
    is_read = models.BooleanField(default=False, db_index=True)
    read_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def mark_as_read(self):
        if not self.is_read:
            self.is_read = True
            self.read_at = timezone.now()
            self.save(update_fields=['is_read', 'read_at'])
    
    @classmethod
    def get_visible_notifications(cls, user):
        """Get visible notifications - FIXED"""
        unread = list(cls.objects.filter(user=user, is_read=False).order_by('-created_at'))
        cutoff = timezone.now() - timedelta(hours=24)
        recent_read = list(cls.objects.filter(user=user, is_read=True, read_at__gte=cutoff).order_by('-created_at'))
        return unread + recent_read  # Use + not |
    
    @classmethod
    def cleanup_old_notifications(cls, user):
        cutoff = timezone.now() - timedelta(hours=24)
        return cls.objects.filter(user=user, is_read=True, read_at__lt=cutoff).delete()[0]
    
    @classmethod
    def create_notification(cls, user, notification_type, title, message, file_name=None, file_id=None):
        return cls.objects.create(
            user=user,
            notification_type=notification_type,
            title=title,
            message=message,
            file_name=file_name,
            file_id=file_id
        )