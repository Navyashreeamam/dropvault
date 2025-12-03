# accounts/utils.py
import secrets
from django.core.mail import send_mail, EmailMultiAlternatives
from django.template.loader import render_to_string
from django.urls import reverse
from django.conf import settings
from .models import UserProfile


def send_verification_email(user):
    """
    Send email verification link to user
    """
    print("=" * 60)
    print("📩 SEND_VERIFICATION_EMAIL CALLED")
    print(f"   User ID: {user.id}")
    print(f"   Username: {user.username}")
    print(f"   Email: '{user.email}'")
    print("=" * 60)
    
    # Validate user has email
    if not user.email:
        print("❌ User has no email address")
        return False
    
    try:
        # Get or create profile
        profile, created = UserProfile.objects.get_or_create(user=user)
        
        # Generate verification token
        if not profile.verification_token:
            profile.verification_token = secrets.token_urlsafe(32)
            profile.save(update_fields=['verification_token'])
        
        token = profile.verification_token
        print(f"✅ Verification token: {token[:20]}...")
        
        # Build verification URL
        verification_path = reverse('verify_email', kwargs={'token': token})
        verification_url = f"{settings.SITE_URL}{verification_path}"
        
        print(f"✅ Verification URL: {verification_url}")
        
        # Email subject and content
        subject = 'Verify Your Email - DropVault'
        
        # Plain text version
        text_content = f"""
Hi {user.first_name or user.email},

Welcome to DropVault! Please verify your email address by clicking the link below:

{verification_url}

This link will expire in 24 hours.

If you didn't create this account, you can safely ignore this email.

Thanks,
The DropVault Team
        """
        
        # HTML version
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
            border-radius: 10px 10px 0 0;
        }}
        .content {{
            background: #f9f9f9;
            padding: 30px;
            border-radius: 0 0 10px 10px;
        }}
        .button {{
            display: inline-block;
            padding: 15px 30px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            margin: 20px 0;
            font-weight: bold;
        }}
        .footer {{
            text-align: center;
            margin-top: 20px;
            color: #666;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 DropVault</h1>
            <p>Secure File Storage</p>
        </div>
        <div class="content">
            <h2>Welcome to DropVault!</h2>
            <p>Hi {user.first_name or user.email},</p>
            <p>Thanks for signing up! Please verify your email address to unlock all features:</p>
            
            <div style="text-align: center;">
                <a href="{verification_url}" class="button">Verify Email Address</a>
            </div>
            
            <p>Or copy and paste this link into your browser:</p>
            <p style="background: white; padding: 10px; word-break: break-all; font-size: 12px;">
                {verification_url}
            </p>
            
            <p style="margin-top: 30px; color: #666; font-size: 14px;">
                This link will expire in 24 hours.<br>
                If you didn't create this account, you can safely ignore this email.
            </p>
        </div>
        <div class="footer">
            <p>© 2025 DropVault. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
        """
        
        # Send email
        print(f"📤 Sending email to: {user.email}")
        print(f"   From: {settings.DEFAULT_FROM_EMAIL}")
        print(f"   Backend: {settings.EMAIL_BACKEND}")
        
        msg = EmailMultiAlternatives(
            subject=subject,
            body=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user.email]
        )
        msg.attach_alternative(html_content, "text/html")
        msg.send(fail_silently=False)
        
        print("✅ Email sent successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Email sending failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def verify_token(token):
    """
    Verify a token and return the associated user
    """
    try:
        profile = UserProfile.objects.get(verification_token=token)
        return profile.user
    except UserProfile.DoesNotExist:
        return None