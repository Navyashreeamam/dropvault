# accounts/email_utils.py
import os
import logging
from django.conf import settings

logger = logging.getLogger(__name__)

def send_email(to_email, subject, text_content, html_content=None):
    """
    Send email using Resend API or fallback to Django's send_mail
    Returns True if successful, False otherwise
    """
    resend_api_key = getattr(settings, 'RESEND_API_KEY', '') or os.environ.get('RESEND_API_KEY', '')
    
    if resend_api_key:
        return send_email_resend(to_email, subject, text_content, html_content, resend_api_key)
    else:
        return send_email_django(to_email, subject, text_content, html_content)


def send_email_resend(to_email, subject, text_content, html_content, api_key):
    """Send email using Resend API"""
    try:
        import resend
        resend.api_key = api_key
        
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'DropVault <onboarding@resend.dev>')
        
        params = {
            "from": from_email,
            "to": [to_email] if isinstance(to_email, str) else to_email,
            "subject": subject,
            "text": text_content,
        }
        
        if html_content:
            params["html"] = html_content
        
        response = resend.Emails.send(params)
        logger.info(f"✅ Email sent via Resend to {to_email}")
        print(f"✅ Email sent via Resend to {to_email}", flush=True)
        return True
        
    except Exception as e:
        logger.error(f"❌ Resend email failed: {str(e)}")
        print(f"❌ Resend email failed: {str(e)}", flush=True)
        return False


def send_email_django(to_email, subject, text_content, html_content=None):
    """Send email using Django's built-in send_mail"""
    try:
        from django.core.mail import send_mail, EmailMultiAlternatives
        
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@dropvault.app')
        
        if html_content:
            msg = EmailMultiAlternatives(subject, text_content, from_email, [to_email])
            msg.attach_alternative(html_content, "text/html")
            msg.send(fail_silently=False)
        else:
            send_mail(subject, text_content, from_email, [to_email], fail_silently=False)
        
        logger.info(f"✅ Email sent via Django to {to_email}")
        print(f"✅ Email sent via Django to {to_email}", flush=True)
        return True
        
    except Exception as e:
        logger.error(f"❌ Django email failed: {str(e)}")
        print(f"❌ Django email failed: {str(e)}", flush=True)
        return False