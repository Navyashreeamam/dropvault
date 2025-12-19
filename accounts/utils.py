# accounts/utils.py
import secrets
import threading
from django.urls import reverse
from django.conf import settings
from .models import UserProfile


def _send_with_resend(to_email, subject, html_content, text_content):
    """Send email using Resend API (works on Render free tier)"""
    import requests
    
    api_key = getattr(settings, 'RESEND_API_KEY', '').strip()
    
    if not api_key:
        print("❌ RESEND_API_KEY not configured!")
        print("   👉 Add RESEND_API_KEY to Render environment variables")
        print("   👉 Get free API key from https://resend.com")
        return False
    
    from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'DropVault <onboarding@resend.dev>')
    
    try:
        print(f"📤 Sending via Resend API to: {to_email}")
        print(f"   From: {from_email}")
        print(f"   API Key: {api_key[:10]}...")
        
        response = requests.post(
            'https://api.resend.com/emails',
            headers={
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json'
            },
            json={
                'from': from_email,
                'to': [to_email],
                'subject': subject,
                'html': html_content,
                'text': text_content
            },
            timeout=30
        )
        
        print(f"   Response status: {response.status_code}")
        print(f"   Response body: {response.text}")
        
        if response.status_code == 200:
            print(f"✅ Email sent successfully to {to_email}")
            return True
        else:
            print(f"❌ Resend API error: {response.status_code}")
            print(f"   Error: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Resend API exception: {e}")
        import traceback
        traceback.print_exc()
        return False


def _build_email_content(user, verification_url):
    """Build email HTML and text content"""
    name = user.first_name or user.email
    
    text_content = f"""
Hi {name},

Welcome to DropVault! Please verify your email address by clicking the link below:

{verification_url}

This link will expire in 24 hours.

If you didn't create this account, you can safely ignore this email.

Thanks,
The DropVault Team
    """
    
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
            <h1 style="margin: 0;">🔐 DropVault</h1>
            <p style="margin: 10px 0 0 0;">Secure File Storage</p>
        </div>
        <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px;">
            <h2 style="color: #333; margin-top: 0;">Welcome to DropVault!</h2>
            <p>Hi {name},</p>
            <p>Thanks for signing up! Please verify your email address to unlock all features:</p>
            
            <div style="text-align: center; margin: 30px 0;">
                <a href="{verification_url}" style="display: inline-block; padding: 15px 30px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; font-weight: bold;">
                    Verify Email Address
                </a>
            </div>
            
            <p style="font-size: 14px; color: #666;">Or copy and paste this link into your browser:</p>
            <p style="background: white; padding: 10px; word-break: break-all; font-size: 12px; border-radius: 5px;">
                {verification_url}
            </p>
            
            <hr style="border: none; border-top: 1px solid #ddd; margin: 30px 0;">
            
            <p style="color: #666; font-size: 14px; margin-bottom: 0;">
                This link will expire in 24 hours.<br>
                If you didn't create this account, you can safely ignore this email.
            </p>
        </div>
        <div style="text-align: center; margin-top: 20px; color: #666; font-size: 12px;">
            <p>© 2025 DropVault. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
    """
    
    return text_content, html_content


def _do_send_email_background(to_email, subject, html_content, text_content):
    """Background thread function to send email"""
    try:
        success = _send_with_resend(to_email, subject, html_content, text_content)
        if success:
            print(f"✅ Background email sent to {to_email}")
        else:
            print(f"❌ Background email failed for {to_email}")
    except Exception as e:
        print(f"❌ Background email exception: {e}")


def send_verification_email(user, async_send=True):
    """
    Send email verification link to user.
    
    Args:
        user: User object
        async_send: If True, send in background thread (non-blocking)
                   If False, send synchronously and return success status
    
    Returns:
        bool: True if email was queued/sent, False if failed
    """
    print("=" * 60)
    print("📩 SEND_VERIFICATION_EMAIL CALLED")
    print(f"   User ID: {user.id}")
    print(f"   Username: {user.username}")
    print(f"   Email: '{user.email}'")
    print(f"   Async: {async_send}")
    print("=" * 60)
    
    # Validate user has email
    if not user.email:
        print("❌ User has no email address")
        return False
    
    # Check if Resend is configured
    resend_key = getattr(settings, 'RESEND_API_KEY', '').strip()
    if not resend_key:
        print("=" * 60)
        print("⚠️  EMAIL SERVICE NOT CONFIGURED!")
        print("   To enable email sending:")
        print("   1. Sign up at https://resend.com (free)")
        print("   2. Create an API key")
        print("   3. Add RESEND_API_KEY to Render environment variables")
        print("=" * 60)
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
        
        # Get correct site URL
        site_url = getattr(settings, 'SITE_URL', '').strip()
        
        # Auto-detect from Render if not set
        if not site_url or 'localhost' in site_url:
            import os
            render_host = os.environ.get('RENDER_EXTERNAL_HOSTNAME', '')
            if render_host:
                site_url = f'https://{render_host}'
                print(f"   Auto-detected Render URL: {site_url}")
        
        # Fallback
        if not site_url:
            site_url = 'http://localhost:8000'
        
        verification_url = f"{site_url.rstrip('/')}{verification_path}"
        print(f"✅ Verification URL: {verification_url}")
        
        # Build email content
        text_content, html_content = _build_email_content(user, verification_url)
        subject = 'Verify Your Email - DropVault'
        
        if async_send:
            # Send in background thread (non-blocking)
            thread = threading.Thread(
                target=_do_send_email_background,
                args=(user.email, subject, html_content, text_content)
            )
            thread.daemon = True
            thread.start()
            print("✅ Email queued for background sending")
            return True
        else:
            # Send synchronously (blocking)
            return _send_with_resend(user.email, subject, html_content, text_content)
        
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