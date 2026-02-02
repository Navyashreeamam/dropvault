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
    verification_token_expiry = models.DateTimeField(blank=True, null=True)
    
    # Signup tracking
    signup_method = models.CharField(max_length=20, default='email')  # 'email' or 'google'
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # ✅ ADD THIS PROPERTY
    @property
    def is_google_user(self):
        """Check if user signed up with Google"""
        return self.signup_method == 'google'
    
    def generate_verification_token(self):
        """Generate a new verification token with 24-hour expiry"""
        self.verification_token = secrets.token_urlsafe(32)
        self.verification_sent_at = timezone.now()
        self.save()
        return self.verification_token
    
    def is_verification_token_valid(self, token):
        """Check if the provided token is valid and not expired"""
        if not self.verification_token or self.verification_token != token:
            return False
        if not self.verification_sent_at:
            return False
        
        # Token expires after 24 hours
        expiry = self.verification_sent_at + timedelta(hours=24)
        return timezone.now() < expiry
    
    def clear_verification_token(self):
        """Clear the verification token after successful verification"""
        self.verification_token = None
        self.verification_sent_at = None
        self.save()
    
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
        verified = "✓" if self.email_verified else "✗"
        method = f"[{self.signup_method}]" if self.signup_method else ""
        return f"{self.user.email} {method} ({verified})"
    
    class Meta:
        verbose_name = "User Profile"
        verbose_name_plural = "User Profiles"

class LoginAttempt(models.Model):
    """Track login attempts for security"""
    email = models.CharField(max_length=254, db_index=True)
    ip_address = models.GenericIPAddressField()
    success = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)
    user_agent = models.TextField(blank=True, default='')
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        status = 'Success' if self.success else 'Failed'
        return f"{self.email} - {status} - {self.timestamp}"


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
        ('EMAIL_VERIFIED', 'Email Verified'),
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
    
    def __str__(self):
        return f"{self.notification_type}: {self.title}"
    
    def mark_as_read(self):
        if not self.is_read:
            self.is_read = True
            self.read_at = timezone.now()
            self.save(update_fields=['is_read', 'read_at'])
    
    @classmethod
    def get_visible_notifications(cls, user):
        unread = list(cls.objects.filter(user=user, is_read=False).order_by('-created_at'))
        cutoff = timezone.now() - timedelta(hours=24)
        recent_read = list(cls.objects.filter(user=user, is_read=True, read_at__gte=cutoff).order_by('-created_at'))
        return unread + recent_read
    
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