# accounts/utils.py
import secrets
import threading
import requests
from django.core.mail import EmailMultiAlternatives
from django.urls import reverse
from django.conf import settings
from .models import UserProfile


def send_email_async(func, *args, **kwargs):
    """Run email sending in background thread"""
    thread = threading.Thread(target=func, args=args, kwargs=kwargs)
    thread.daemon = True
    thread.start()


def _send_with_resend(to_email, subject, html_content, text_content):
    """Send email using Resend API (works on Render free tier)"""
    api_key = getattr(settings, 'RESEND_API_KEY', '')
    
    if not api_key:
        print("❌ RESEND_API_KEY not configured")
        return False
    
    try:
        response = requests.post(
            'https://api.resend.com/emails',
            headers={
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json'
            },
            json={
                'from': settings.DEFAULT_FROM_EMAIL,
                'to': [to_email],
                'subject': subject,
                'html': html_content,
                'text': text_content
            },
            timeout=30
        )
        
        if response.status_code == 200:
            print(f"✅ Email sent via Resend to {to_email}")
            return True
        else:
            print(f"❌ Resend API error: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Resend API exception: {e}")
        return False


def _send_with_smtp(to_email, subject, html_content, text_content):
    """Send email using SMTP (fallback for local development)"""
    try:
        msg = EmailMultiAlternatives(
            subject=subject,
            body=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[to_email]
        )
        msg.attach_alternative(html_content, "text/html")
        msg.send(fail_silently=False)
        print(f"✅ Email sent via SMTP to {to_email}")
        return True
    except Exception as e:
        print(f"❌ SMTP error: {e}")
        return False


def _do_send_verification_email(user_id, email, first_name, token, verification_url):
    """
    Actually send the email (runs in background thread)
    """
    print(f"📤 Background: Sending verification email to {email}")
    
    subject = 'Verify Your Email - DropVault'
    
    # Plain text version
    text_content = f"""
Hi {first_name or email},

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
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
        .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }}
        .button {{ display: inline-block; padding: 15px 30px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; font-weight: bold; }}
        .footer {{ text-align: center; margin-top: 20px; color: #666; font-size: 12px; }}
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
            <p>Hi {first_name or email},</p>
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
    
    # Try Resend API first (works on Render), fallback to SMTP
    resend_key = getattr(settings, 'RESEND_API_KEY', '')
    
    if resend_key:
        success = _send_with_resend(email, subject, html_content, text_content)
    else:
        success = _send_with_smtp(email, subject, html_content, text_content)
    
    return success


def send_verification_email(user):
    """
    Send email verification link to user (NON-BLOCKING)
    Returns immediately, email sends in background
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
        
        # Build verification URL using correct SITE_URL
        verification_path = reverse('verify_email', kwargs={'token': token})
        site_url = getattr(settings, 'SITE_URL', 'http://localhost:8000')
        verification_url = f"{site_url.rstrip('/')}{verification_path}"
        
        print(f"✅ Verification URL: {verification_url}")
        print(f"✅ SITE_URL: {site_url}")
        
        # Send email in background thread (NON-BLOCKING!)
        send_email_async(
            _do_send_verification_email,
            user.id,
            user.email,
            user.first_name,
            token,
            verification_url
        )
        
        print("✅ Email queued for background sending!")
        return True
        
    except Exception as e:
        print(f"❌ Email setup failed: {e}")
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