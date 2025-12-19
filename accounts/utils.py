# accounts/utils.py
import secrets
import threading
import os
import re as regex
from django.urls import reverse
from django.conf import settings
from .models import UserProfile


# ═══════════════════════════════════════════════════════════
# 📧 CORE EMAIL FUNCTION - Used by ALL features
# ═══════════════════════════════════════════════════════════

def get_resend_api_key():
    """Get Resend API key from settings or environment"""
    # Try settings first
    api_key = getattr(settings, 'RESEND_API_KEY', '').strip()
    
    # Fallback to environment
    if not api_key:
        api_key = os.environ.get('RESEND_API_KEY', '').strip()
    
    return api_key


def send_email_via_resend(to_email, subject, html_content, text_content=None):
    """
    Send email using Resend HTTP API.
    This works on Render free tier (SMTP is blocked).
    
    Args:
        to_email: Recipient email (string or list)
        subject: Email subject
        html_content: HTML body
        text_content: Plain text body (optional)
    
    Returns:
        tuple: (success: bool, error_message: str or None)
    """
    import requests
    
    print("=" * 60)
    print("📧 SEND_EMAIL_VIA_RESEND CALLED")
    print(f"   To: {to_email}")
    print(f"   Subject: {subject}")
    print("=" * 60)
    
    # Get API key
    api_key = get_resend_api_key()
    
    print(f"   RESEND_API_KEY exists: {bool(api_key)}")
    if api_key:
        print(f"   API Key preview: {api_key[:15]}...")
    
    if not api_key:
        error_msg = "RESEND_API_KEY not configured in environment variables"
        print(f"❌ {error_msg}")
        print("   👉 Go to Render Dashboard → Environment → Add RESEND_API_KEY")
        print("   👉 Get free API key from https://resend.com")
        return False, error_msg
    
    # Validate API key format
    if not api_key.startswith('re_'):
        error_msg = f"Invalid API key format. Should start with 're_', got: {api_key[:10]}..."
        print(f"❌ {error_msg}")
        return False, error_msg
    
    # Get from email
    from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', '').strip()
    if not from_email:
        from_email = os.environ.get('DEFAULT_FROM_EMAIL', 'DropVault <onboarding@resend.dev>').strip()
    
    print(f"   From: {from_email}")
    
    # Handle single email or list
    if isinstance(to_email, str):
        to_list = [to_email.strip()]
    else:
        to_list = [e.strip() for e in to_email]
    
    # Create plain text from HTML if not provided
    if not text_content:
        text_content = regex.sub(r'<[^>]+>', '', html_content)
        text_content = regex.sub(r'\s+', ' ', text_content).strip()
    
    # Prepare request
    url = 'https://api.resend.com/emails'
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json'
    }
    payload = {
        'from': from_email,
        'to': to_list,
        'subject': subject,
        'html': html_content,
        'text': text_content
    }
    
    try:
        print(f"📤 Making request to Resend API...")
        print(f"   URL: {url}")
        print(f"   To: {to_list}")
        
        response = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=30
        )
        
        print(f"   Response Status: {response.status_code}")
        print(f"   Response Body: {response.text}")
        
        if response.status_code == 200:
            print(f"✅ Email sent successfully to {to_list}")
            return True, None
        else:
            # Parse error from response
            try:
                error_data = response.json()
                error_msg = error_data.get('message', response.text)
            except:
                error_msg = response.text
            
            print(f"❌ Resend API error: {response.status_code}")
            print(f"   Error: {error_msg}")
            return False, f"Resend API error ({response.status_code}): {error_msg}"
            
    except requests.exceptions.Timeout:
        error_msg = "Request timed out after 30 seconds"
        print(f"❌ {error_msg}")
        return False, error_msg
    except requests.exceptions.ConnectionError as e:
        error_msg = f"Connection error: {str(e)}"
        print(f"❌ {error_msg}")
        return False, error_msg
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        print(f"❌ {error_msg}")
        import traceback
        traceback.print_exc()
        return False, error_msg


def send_email_async(to_email, subject, html_content, text_content=None):
    """Send email in background thread (non-blocking)"""
    def _send():
        try:
            send_email_via_resend(to_email, subject, html_content, text_content)
        except Exception as e:
            print(f"❌ Async email error: {e}")
    
    thread = threading.Thread(target=_send)
    thread.daemon = True
    thread.start()
    print(f"📧 Email queued for background sending to {to_email}")
    return True


# ═══════════════════════════════════════════════════════════
# 📁 FILE SHARING EMAIL
# ═══════════════════════════════════════════════════════════

def send_file_share_email(to_email, from_user, file_name, share_url, message=None):
    """
    Send file sharing notification email.
    
    Returns:
        tuple: (success: bool, error_message: str or None)
    """
    print("=" * 60)
    print("📁 SEND_FILE_SHARE_EMAIL CALLED")
    print(f"   To: {to_email}")
    print(f"   From User: {from_user.email}")
    print(f"   File: {file_name}")
    print(f"   URL: {share_url}")
    print(f"   Message: {message}")
    print("=" * 60)
    
    sender_name = from_user.first_name or from_user.email.split('@')[0]
    sender_email = from_user.email
    
    subject = f"📎 {sender_name} shared a file with you - DropVault"
    
    # Build message section
    message_html = ""
    message_text = ""
    if message:
        message_html = f"""
            <div style="background: #f0f4ff; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #667eea;">
                <p style="margin: 0; color: #444; font-style: italic;">💬 "{message}"</p>
                <p style="margin: 10px 0 0 0; color: #666; font-size: 12px;">- {sender_name}</p>
            </div>
        """
        message_text = f'\nMessage from {sender_name}: "{message}"\n'
    
    text_content = f"""
Hi there,

{sender_name} ({sender_email}) has shared a file with you on DropVault.

📄 File: {file_name}
{message_text}
🔗 Click here to download:
{share_url}

This link may expire, so download soon!

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
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; background: #f5f5f5;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 12px 12px 0 0;">
            <h1 style="margin: 0; font-size: 28px;">🔐 DropVault</h1>
            <p style="margin: 8px 0 0 0; opacity: 0.9;">Secure File Sharing</p>
        </div>
        
        <div style="background: white; padding: 30px; border-radius: 0 0 12px 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1);">
            <h2 style="color: #333; margin-top: 0; font-size: 22px;">📁 Someone shared a file with you!</h2>
            
            <p style="color: #555; font-size: 16px;">
                <strong>{sender_name}</strong> ({sender_email}) has shared a file:
            </p>
            
            <div style="background: linear-gradient(135deg, #f8f9ff 0%, #f0f4ff 100%); padding: 20px; border-radius: 10px; margin: 20px 0; border: 1px solid #e0e7ff;">
                <p style="margin: 0; font-size: 18px; color: #333;">
                    📄 <strong>{file_name}</strong>
                </p>
            </div>
            
            {message_html}
            
            <div style="text-align: center; margin: 30px 0;">
                <a href="{share_url}" style="display: inline-block; padding: 16px 40px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 16px; box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);">
                    📥 Download File
                </a>
            </div>
            
            <p style="font-size: 13px; color: #888; margin-top: 25px;">Can't click the button? Copy this link:</p>
            <div style="background: #f8f9fa; padding: 12px; word-break: break-all; font-size: 12px; border-radius: 6px; border: 1px solid #e9ecef; color: #555;">
                {share_url}
            </div>
            
            <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
            
            <p style="color: #999; font-size: 12px; margin-bottom: 0; text-align: center;">
                ⏰ This link may expire. Download your file soon!<br>
                Shared securely via DropVault
            </p>
        </div>
        
        <div style="text-align: center; margin-top: 20px; color: #888; font-size: 12px;">
            <p>© 2025 DropVault. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
    """
    
    return send_email_via_resend(to_email, subject, html_content, text_content)


# ═══════════════════════════════════════════════════════════
# ✅ EMAIL VERIFICATION
# ═══════════════════════════════════════════════════════════

def send_verification_email(user, async_send=True):
    """Send email verification link to user."""
    print("=" * 60)
    print("📩 SEND_VERIFICATION_EMAIL CALLED")
    print(f"   User ID: {user.id}")
    print(f"   Username: {user.username}")
    print(f"   Email: '{user.email}'")
    print(f"   Async: {async_send}")
    print("=" * 60)
    
    if not user.email:
        print("❌ User has no email address")
        return False
    
    # Check if Resend is configured
    api_key = get_resend_api_key()
    
    if not api_key:
        print("⚠️  EMAIL SERVICE NOT CONFIGURED!")
        print("   Add RESEND_API_KEY to Render environment variables")
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
        
        # Auto-detect from Render
        if not site_url or 'localhost' in site_url:
            render_host = os.environ.get('RENDER_EXTERNAL_HOSTNAME', '')
            if render_host:
                site_url = f'https://{render_host}'
        
        if not site_url:
            site_url = 'http://localhost:8000'
        
        verification_url = f"{site_url.rstrip('/')}{verification_path}"
        print(f"✅ Verification URL: {verification_url}")
        
        # Build email
        name = user.first_name or user.email.split('@')[0]
        subject = 'Verify Your Email - DropVault'
        
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
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; background: #f5f5f5;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 12px 12px 0 0;">
            <h1 style="margin: 0; font-size: 28px;">🔐 DropVault</h1>
            <p style="margin: 8px 0 0 0; opacity: 0.9;">Secure File Storage</p>
        </div>
        <div style="background: white; padding: 30px; border-radius: 0 0 12px 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1);">
            <h2 style="color: #333; margin-top: 0;">Verify Your Email</h2>
            <p>Hi {name},</p>
            <p>Thanks for signing up! Please verify your email address to unlock all features:</p>
            
            <div style="text-align: center; margin: 30px 0;">
                <a href="{verification_url}" style="display: inline-block; padding: 16px 40px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 16px;">
                    ✅ Verify Email Address
                </a>
            </div>
            
            <p style="font-size: 13px; color: #888;">Or copy this link:</p>
            <div style="background: #f8f9fa; padding: 12px; word-break: break-all; font-size: 12px; border-radius: 6px; border: 1px solid #e9ecef;">
                {verification_url}
            </div>
            
            <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
            
            <p style="color: #888; font-size: 13px; margin-bottom: 0; text-align: center;">
                This link expires in 24 hours.<br>
                If you didn't create this account, ignore this email.
            </p>
        </div>
        <div style="text-align: center; margin-top: 20px; color: #888; font-size: 12px;">
            <p>© 2025 DropVault. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
        """
        
        if async_send:
            send_email_async(user.email, subject, html_content, text_content)
            return True
        else:
            success, error = send_email_via_resend(user.email, subject, html_content, text_content)
            return success
        
    except Exception as e:
        print(f"❌ Email setup failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def verify_token(token):
    """Verify a token and return the associated user"""
    try:
        profile = UserProfile.objects.get(verification_token=token)
        return profile.user
    except UserProfile.DoesNotExist:
        return None