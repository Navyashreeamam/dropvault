import secrets
from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse
from .models import UserProfile


def send_verification_email(user):
    # 🔍 Debug prints (safe to keep during development)
    print("\n" + "=" * 50)
    print("🚨 SEND_VERIFICATION_EMAIL WAS CALLED!")
    print(f"   User: {user.username} | Email: {user.email}")
    print("=" * 50 + "\n")

    try:
        print(f"📧 Sending to: {user.email}")
        if not user.email:
            print("❌ User has no email!")
            return False

        # Get or create user profile and generate token
        profile, _ = UserProfile.objects.get_or_create(user=user)
        token = secrets.token_urlsafe(48)
        profile.verification_token = token
        profile.save(update_fields=['verification_token'])

        # Build verification URL
        verify_url = settings.SITE_URL.rstrip('/') + reverse('verify_email', args=[token])
        print(f"🔗 Verify URL: {verify_url}")

        # ✉️ Send professional, deliverability-optimized email
        subject = "Verify your Dropvault account"
        message = (
            f"Hello {user.username},\n\n"
            "Please confirm your email address by clicking the link below:\n\n"
            f"{verify_url}\n\n"
            "This link will expire in 24 hours.\n\n"
            "If you didn’t request this, please ignore this email.\n\n"
            "Best regards,\n"
            "The Dropvault Team"
        )

        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )
        print("✅ Verification email sent successfully!")
        return True

    except Exception as e:
        print("📧 Email failed:", e)
        return False


def verify_token(token):
    try:
        profile = UserProfile.objects.get(verification_token=token)
        return profile.user
    except UserProfile.DoesNotExist:
        return None