# accounts/utils.py

import os
import secrets
import logging
import threading
import requests
from django.conf import settings

logger = logging.getLogger(__name__)



def get_resend_api_key():
    """Get Resend API key from environment"""
    return os.environ.get('RESEND_API_KEY', '').strip()


def _send_email_via_resend(to_email, subject, html_content, text_content=None):
    """Send email using Resend API"""
    resend_api_key = get_resend_api_key()
    
    if not resend_api_key:
        logger.warning("No RESEND_API_KEY found")
        print("❌ No RESEND_API_KEY found")
        return False
    
    print("=" * 60)
    print("📧 SEND_EMAIL_VIA_RESEND CALLED")
    print(f"   To: {to_email}")
    print(f"   Subject: {subject}")
    print("=" * 60)
    print(f"   RESEND_API_KEY exists: True")
    print(f"   API Key preview: {resend_api_key[:10]}...")
    
    # Get from email
    from_email = os.environ.get('RESEND_FROM_EMAIL', 'DropVault <onboarding@resend.dev>')
    print(f"   From: {from_email}")
    
    try:
        print("📤 Making request to Resend API...")
        print(f"   URL: https://api.resend.com/emails")
        print(f"   To: {[to_email]}")
        
        response = requests.post(
            'https://api.resend.com/emails',
            headers={
                'Authorization': f'Bearer {resend_api_key}',
                'Content-Type': 'application/json'
            },
            json={
                'from': from_email,
                'to': [to_email],
                'subject': subject,
                'html': html_content,
                'text': text_content or subject
            },
            timeout=10
        )
        
        print(f"   Response Status: {response.status_code}")
        
        if response.status_code in [200, 201]:
            print(f" Email sent successfully to {to_email}")
            return True
        else:
            try:
                error_data = response.json()
                error_message = error_data.get('message', 'Unknown error')
            except:
                error_message = response.text
            print(f"❌ Resend API error: {response.status_code}")
            print(f"   Error: {error_message}")
            return False
            
    except Exception as e:
        print(f"❌ Exception sending email: {e}")
        logger.error(f"Email send error: {e}")
        return False

def send_verification_email(user, async_send=True):
    """
    Send verification email to user
    Returns True if sent successfully, False otherwise
    """
    try:
        from .models import UserProfile
        
        # Generate token
        token = secrets.token_urlsafe(32)
        
        profile, created = UserProfile.objects.get_or_create(user=user)
        profile.verification_token = token
        profile.save(update_fields=['verification_token'])
        
        site_url = getattr(settings, 'SITE_URL', 'http://localhost:8000')
        verify_url = f"{site_url}/accounts/verify-email/{token}/"
        
        # Check if Resend is configured
        resend_api_key = get_resend_api_key()
        
        if not resend_api_key:
            logger.warning("No RESEND_API_KEY configured - skipping email")
            print(f"⚠️ Email verification link (no email service): {verify_url}")
            return False
        
        subject = "Verify Your Email - DropVault"
        html_content = f"""
        <html>
        <body style="font-family: Arial, sans-serif; padding: 20px; background-color: #f4f4f4;">
            <div style="max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px;">
                <h2 style="color: #4F46E5;">Welcome to DropVault!</h2>
                <p>Please verify your email address by clicking the button below:</p>
                <p style="margin: 30px 0; text-align: center;">
                    <a href="{verify_url}" 
                       style="background-color: #4F46E5; color: white; padding: 14px 30px; 
                              text-decoration: none; border-radius: 5px; display: inline-block;
                              font-weight: bold;">
                        Verify Email
                    </a>
                </p>
                <p>Or copy and paste this link:</p>
                <p style="color: #666; word-break: break-all; background: #f0f0f0; padding: 10px; border-radius: 5px;">
                    {verify_url}
                </p>
                <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
                <p style="color: #999; font-size: 12px;">
                    If you didn't create an account, you can ignore this email.
                </p>
            </div>
        </body>
        </html>
        """
        
        text_content = f"""
Welcome to DropVault!

Please verify your email by visiting:
{verify_url}

If you didn't create an account, you can ignore this email.
        """
        
        if async_send:
            thread = threading.Thread(
                target=_send_email_via_resend,
                args=(user.email, subject, html_content, text_content)
            )
            thread.start()
            print(f"📧 Email queued for background sending to {user.email}")
            return True
        else:
            return _send_email_via_resend(user.email, subject, html_content, text_content)
            
    except Exception as e:
        logger.error(f"Error in send_verification_email: {e}")
        print(f"❌ Error sending verification email: {e}")
        return False


def send_file_share_email(to_email, from_user, file_name, share_url, message=None):
    """
    Send file sharing notification email
    Returns: (success: bool, error_message: str or None)
    """
    resend_api_key = get_resend_api_key()
    
    if not resend_api_key:
        logger.warning("No RESEND_API_KEY - cannot send share email")
        print(f"⚠️ Share email skipped (no API key): {to_email}")
        return False, "Email service not configured"
    
    from_name = from_user.first_name or from_user.username or from_user.email
    
    subject = f"{from_name} shared a file with you - DropVault"
    
    message_html = ""
    if message:
        message_html = f"""
        <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <p style="margin: 0; color: #666;"><strong>Message:</strong></p>
            <p style="margin: 10px 0 0 0; color: #333;">{message}</p>
        </div>
        """
    
    html_content = f"""
    <html>
    <body style="font-family: Arial, sans-serif; padding: 20px; background-color: #f4f4f4;">
        <div style="max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px;">
            <h2 style="color: #4F46E5;">📁 File Shared With You</h2>
            <p><strong>{from_name}</strong> has shared a file with you on DropVault:</p>
            
            <div style="background: #f0f4ff; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <p style="margin: 0; font-size: 18px;">📄 <strong>{file_name}</strong></p>
            </div>
            
            {message_html}
            
            <p style="margin: 30px 0; text-align: center;">
                <a href="{share_url}" 
                   style="background-color: #4F46E5; color: white; padding: 14px 30px; 
                          text-decoration: none; border-radius: 5px; display: inline-block;
                          font-weight: bold;">
                    View & Download File
                </a>
            </p>
            
            <p>Or copy this link:</p>
            <p style="color: #666; word-break: break-all; background: #f0f0f0; padding: 10px; border-radius: 5px;">
                {share_url}
            </p>
            
            <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
            <p style="color: #999; font-size: 12px;">
                This is an automated message from DropVault. 
                If you don't recognize the sender, please ignore this email.
            </p>
        </div>
    </body>
    </html>
    """
    
    text_content = f"""
{from_name} shared a file with you on DropVault!

File: {file_name}
{f"Message: {message}" if message else ""}

View the file here: {share_url}

---
This is an automated message from DropVault.
    """
    
    try:
        success = _send_email_via_resend(to_email, subject, html_content, text_content)
        if success:
            return True, None
        else:
            return False, "Failed to send email via Resend"
    except Exception as e:
        logger.error(f"Error sending share email: {e}")
        print(f"❌ Error sending share email: {e}")
        return False, str(e)

def verify_token(token):
    """Verify email token and return user if valid"""
    try:
        from .models import UserProfile
        profile = UserProfile.objects.get(verification_token=token)
        return profile.user
    except:
        return None


def generate_token(length=32):
    """Generate a random URL-safe token"""
    return secrets.token_urlsafe(length)


def send_email(to_email, subject, html_content, text_content=None, async_send=True):
    """
    Generic email sending function
    """
    if async_send:
        thread = threading.Thread(
            target=_send_email_via_resend,
            args=(to_email, subject, html_content, text_content)
        )
        thread.start()
        return True
    else:
        return _send_email_via_resend(to_email, subject, html_content, text_content)