import secrets
from urllib.parse import urlencode
from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse
from .models import UserProfile


def send_verification_email(user):
    # 🔍 Debug header — helps trace calls in console
    print("\n" + "=" * 60)
    print("📩 SEND_VERIFICATION_EMAIL CALLED")
    print(f"   User ID: {user.id}")
    print(f"   Username: {user.username}")
    print(f"   Email: '{user.email}'")
    print("=" * 60 + "\n")

    # ✅ Safely check for missing/empty email
    if not user.email or not user.email.strip():
        print("❌ ABORT: User has no email address.")
        return False

    try:
        # Generate secure token
        token = secrets.token_urlsafe(48)

        # Get or create profile (idempotent)
        profile, created = UserProfile.objects.get_or_create(user=user)
        profile.verification_token = token
        profile.save(update_fields=['verification_token'])

        # ✅ Build URL with query parameter (matches your current URL pattern)
        base_url = settings.SITE_URL.rstrip('/') + reverse('verify_email')
        verify_url = base_url + '?' + urlencode({'token': token})

        print(f"🔗 Generated verify URL: {verify_url}")

        # Send email
        send_mail(
            subject="Verify your Dropvault account",
            message=f"Hello {user.username},\n\nPlease click the link below to verify your email:\n\n{verify_url}\n\nThis link expires in 24 hours.",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )

        print("✅ Verification email sent successfully.")
        return True

    except Exception as e:
        print(f"❌ Email sending failed: {e}")
        return False


def verify_token(token):
    """Utility to fetch user from token — used if needed elsewhere."""
    try:
        profile = UserProfile.objects.get(verification_token=token)
        return profile.user
    except UserProfile.DoesNotExist:
        return None