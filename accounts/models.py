# accounts/models.py
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
import pyotp
import qrcode
from io import BytesIO
import base64


class User(AbstractUser):
    """Custom User model extending Django's AbstractUser"""
    
    # Additional fields
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    
    # Email verification
    is_email_verified = models.BooleanField(default=False)
    email_verification_token = models.CharField(max_length=100, blank=True, null=True)
    email_verified_at = models.DateTimeField(null=True, blank=True)
    
    # MFA/2FA settings
    mfa_enabled = models.BooleanField(default=False)
    mfa_secret = models.CharField(max_length=32, blank=True, null=True)
    
    # Profile
    profile_picture = models.ImageField(upload_to='profiles/', blank=True, null=True)
    bio = models.TextField(max_length=500, blank=True)
    
    # Storage quota (in bytes)
    storage_quota = models.BigIntegerField(default=5368709120)  # 5GB default
    storage_used = models.BigIntegerField(default=0)
    
    # Account status
    is_premium = models.BooleanField(default=False)
    premium_until = models.DateTimeField(null=True, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    
    class Meta:
        db_table = 'accounts_user'
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        ordering = ['-created_at']
    
    def __str__(self):
        return self.username
    
    def get_full_name(self):
        """Return full name or username"""
        return super().get_full_name() or self.username
    
    def verify_email(self):
        """Mark email as verified"""
        self.is_email_verified = True
        self.email_verified_at = timezone.now()
        self.email_verification_token = None
        self.save()
    
    def get_storage_used_readable(self):
        """Return human-readable storage used"""
        size = self.storage_used
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"
    
    def get_storage_quota_readable(self):
        """Return human-readable storage quota"""
        size = self.storage_quota
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"
    
    def get_storage_percentage(self):
        """Return storage used as percentage"""
        if self.storage_quota == 0:
            return 0
        return (self.storage_used / self.storage_quota) * 100
    
    def has_storage_space(self, file_size):
        """Check if user has enough storage space"""
        return (self.storage_used + file_size) <= self.storage_quota
    
    def update_storage_used(self):
        """Recalculate storage used from user's files"""
        from files.models import File
        total = File.objects.filter(
            owner=self,
            is_deleted=False
        ).aggregate(
            total=models.Sum('file_size')
        )['total'] or 0
        
        self.storage_used = total
        self.save()
    
    # MFA Methods
    def generate_mfa_secret(self):
        """Generate new MFA secret"""
        self.mfa_secret = pyotp.random_base32()
        self.save()
        return self.mfa_secret
    
    def get_totp_uri(self):
        """Get TOTP URI for QR code"""
        if not self.mfa_secret:
            self.generate_mfa_secret()
        return pyotp.totp.TOTP(self.mfa_secret).provisioning_uri(
            name=self.email,
            issuer_name='DropVault'
        )
    
    def verify_totp(self, token):
        """Verify TOTP token"""
        if not self.mfa_secret:
            return False
        totp = pyotp.TOTP(self.mfa_secret)
        return totp.verify(token, valid_window=1)
    
    def get_qr_code(self):
        """Generate QR code for MFA setup"""
        uri = self.get_totp_uri()
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        
        # Return base64 encoded image
        img_str = base64.b64encode(buffer.getvalue()).decode()
        return f"data:image/png;base64,{img_str}"
    
    def enable_mfa(self):
        """Enable MFA for user"""
        if not self.mfa_secret:
            self.generate_mfa_secret()
        self.mfa_enabled = True
        self.save()
    
    def disable_mfa(self):
        """Disable MFA for user"""
        self.mfa_enabled = False
        self.mfa_secret = None
        self.save()


class LoginAttempt(models.Model):
    """Track login attempts for security"""
    
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='login_attempts',
        null=True,
        blank=True
    )
    
    username = models.CharField(max_length=150)
    ip_address = models.GenericIPAddressField()
    user_agent = models.CharField(max_length=500, blank=True)
    
    success = models.BooleanField(default=False)
    failure_reason = models.CharField(max_length=255, blank=True)
    
    attempted_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-attempted_at']
        indexes = [
            models.Index(fields=['ip_address', 'attempted_at']),
            models.Index(fields=['user', 'attempted_at']),
        ]
    
    def __str__(self):
        status = 'Success' if self.success else 'Failed'
        return f"{self.username} - {status} - {self.attempted_at}"


class UserSession(models.Model):
    """Track user sessions"""
    
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='sessions'
    )
    
    session_key = models.CharField(max_length=40, unique=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.CharField(max_length=500, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField()
    
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['-last_activity']
        indexes = [
            models.Index(fields=['user', 'is_active']),
            models.Index(fields=['session_key']),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.ip_address}"