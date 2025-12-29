# accounts/utils.py

import os
import secrets
import logging
import threading
from django.conf import settings

logger = logging.getLogger(__name__)

def send_verification_email(user, async_send=True):
    """
    Send verification email to user
    Returns True if sent successfully, False otherwise
    """
    try:
        from .models import UserProfile
        
        # Generate token
        token = secrets.token_urlsafe(32)
        
        # Save token to profile
        profile, created = UserProfile.objects.get_or_create(user=user)
        profile.verification_token = token
        profile.save(update_fields=['verification_token'])
        
        # Build verification URL
        site_url = getattr(settings, 'SITE_URL', 'http://localhost:8000')
        verify_url = f"{site_url}/accounts/verify-email/{token}/"
        
        # Check if Resend is configured
        resend_api_key = os.environ.get('RESEND_API_KEY', '').strip()
        
        if not resend_api_key:
            logger.warning("No RESEND_API_KEY configured - skipping email")
            print(f"⚠️ Email verification link (no email service): {verify_url}")
            return False
        
        # Prepare email content
        subject = "Verify Your Email - DropVault"
        html_content = f"""
        <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <h2>Welcome to DropVault!</h2>
            <p>Please verify your email address by clicking the button below:</p>
            <p style="margin: 30px 0;">
                <a href="{verify_url}" 
                   style="background-color: #4F46E5; color: white; padding: 12px 30px; 
                          text-decoration: none; border-radius: 5px; display: inline-block;">
                    Verify Email
                </a>
            </p>
            <p>Or copy and paste this link:</p>
            <p style="color: #666; word-break: break-all;">{verify_url}</p>
            <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
            <p style="color: #999; font-size: 12px;">
                If you didn't create an account, you can ignore this email.
            </p>
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
            # Send in background thread
            thread = threading.Thread(
                target=_send_email_via_resend,
                args=(user.email, subject, html_content, text_content)
            )
            thread.start()
            print(f"📧 Email queued for background sending to {user.email}")
            return True
        else:
            # Send synchronously
            return _send_email_via_resend(user.email, subject, html_content, text_content)
            
    except Exception as e:
        logger.error(f"Error in send_verification_email: {e}")
        print(f"❌ Error sending verification email: {e}")
        return False


def _send_email_via_resend(to_email, subject, html_content, text_content):
    """Send email using Resend API"""
    import requests
    import os
    
    resend_api_key = os.environ.get('RESEND_API_KEY', '').strip()
    
    if not resend_api_key:
        print("❌ No RESEND_API_KEY found")
        return False
    
    print("=" * 60)
    print("📧 SEND_EMAIL_VIA_RESEND CALLED")
    print(f"   To: {to_email}")
    print(f"   Subject: {subject}")
    print("=" * 60)
    
    # Get from email - use environment variable or default
    from_email = os.environ.get('RESEND_FROM_EMAIL', 'DropVault <onboarding@resend.dev>')
    
    try:
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
                'text': text_content
            },
            timeout=10
        )
        
        print(f"   Response Status: {response.status_code}")
        
        if response.status_code in [200, 201]:
            print(f"✅ Email sent successfully to {to_email}")
            return True
        else:
            error_data = response.json()
            error_message = error_data.get('message', 'Unknown error')
            print(f"❌ Resend API error: {response.status_code}")
            print(f"   Error: {error_message}")
            
            # Log the verification URL so user can still verify manually
            print(f"   ⚠️ User can still verify via direct link")
            return False
            
    except Exception as e:
        print(f"❌ Exception sending email: {e}")
        return False


def verify_token(token):
    """Verify email token and return user if valid"""
    try:
        from .models import UserProfile
        profile = UserProfile.objects.get(verification_token=token)
        return profile.user
    except:
        return None