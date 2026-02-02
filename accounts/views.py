# accounts/views.py

import os
import json
import logging
import requests
import secrets
import re

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import check_password
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Sum
from django.contrib.auth import update_session_auth_hash
from django.db import transaction
from django.utils import timezone
from django.core.cache import cache
from django.core.mail import send_mail
from django.conf import settings

from rest_framework.authtoken.models import Token

from .models import UserProfile, Notification, LoginAttempt

logger = logging.getLogger(__name__)
User = get_user_model()


# =============================================================================
# ✅ HELPER: GET FRONTEND URL - UPDATED FOR MULTIPLE FRONTENDS
# =============================================================================

# List of allowed frontend URLs
ALLOWED_FRONTEND_URLS = [
    'https://dropvaultnew-frontend.onrender.com',
    'https://dropvault-frontend.onrender.com',
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'http://localhost:5173',
]

# Default frontend URL
DEFAULT_FRONTEND_URL = 'https://dropvaultnew-frontend.onrender.com'


def get_frontend_url(request=None):
    """
    Get the frontend URL based on the request origin.
    If request is provided, tries to match the Origin/Referer header.
    Falls back to environment variable or default.
    """
    # Try to get from request headers
    if request:
        # Check Origin header first
        origin = request.META.get('HTTP_ORIGIN', '')
        if origin:
            # Check if origin is in allowed list
            for allowed_url in ALLOWED_FRONTEND_URLS:
                if origin.rstrip('/') == allowed_url.rstrip('/'):
                    logger.info(f"🌐 Frontend URL from Origin: {origin}")
                    return origin.rstrip('/')
            
            # Check if it's an onrender.com URL (allow any subdomain)
            if '.onrender.com' in origin:
                logger.info(f"🌐 Frontend URL from Origin (onrender): {origin}")
                return origin.rstrip('/')
        
        # Check Referer header as fallback
        referer = request.META.get('HTTP_REFERER', '')
        if referer:
            # Extract base URL from referer
            from urllib.parse import urlparse
            parsed = urlparse(referer)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            for allowed_url in ALLOWED_FRONTEND_URLS:
                if base_url.rstrip('/') == allowed_url.rstrip('/'):
                    logger.info(f"🌐 Frontend URL from Referer: {base_url}")
                    return base_url.rstrip('/')
            
            if '.onrender.com' in base_url:
                logger.info(f"🌐 Frontend URL from Referer (onrender): {base_url}")
                return base_url.rstrip('/')
    
    # Fallback to environment variable or default
    env_url = os.environ.get('FRONTEND_URL', DEFAULT_FRONTEND_URL)
    logger.info(f"🌐 Frontend URL from env/default: {env_url}")
    return env_url.rstrip('/')


def is_valid_frontend_origin(request):
    """Check if request comes from a valid frontend"""
    origin = request.META.get('HTTP_ORIGIN', '')
    referer = request.META.get('HTTP_REFERER', '')
    
    # Check origin
    if origin:
        if any(origin.rstrip('/') == url.rstrip('/') for url in ALLOWED_FRONTEND_URLS):
            return True
        if '.onrender.com' in origin:
            return True
    
    # Check referer
    if referer:
        if any(url in referer for url in ALLOWED_FRONTEND_URLS):
            return True
        if '.onrender.com' in referer:
            return True
    
    # Allow if no origin (could be direct API call)
    return True


# =============================================================================
# EMAIL VALIDATION HELPERS
# =============================================================================

def is_valid_email_format(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def is_disposable_email(email):
    disposable_domains = [
        'tempmail.com', 'throwaway.email', 'guerrillamail.com', 
        'mailinator.com', '10minutemail.com', 'temp-mail.org',
        'fakeinbox.com', 'trashmail.com', 'yopmail.com',
    ]
    domain = email.split('@')[1].lower() if '@' in email else ''
    return domain in disposable_domains


def validate_email_complete(email):
    if not email:
        return False, "Email is required"
    
    email = email.strip().lower()
    
    if not is_valid_email_format(email):
        return False, "Please enter a valid email address"
    
    if is_disposable_email(email):
        return False, "Disposable email addresses are not allowed"
    
    return True, None


# =============================================================================
# EMAIL SENDING FUNCTIONS - BREVO API
# =============================================================================

def send_verification_email(user, verification_link):
    """Send verification email using Brevo API"""
    try:
        import requests as http_requests
        
        logger.info("=" * 60)
        logger.info("📧 SEND_VERIFICATION_EMAIL")
        logger.info(f"   To: {user.email}")
        logger.info(f"   Link: {verification_link}")
        print(f"📧 Sending verification email to {user.email}...", flush=True)
        
        brevo_api_key = os.environ.get('BREVO_API_KEY', '')
        resend_api_key = os.environ.get('RESEND_API_KEY', '')
        
        subject = "Verify your DropVault account"
        
        html_message = f"""
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f4f4f4; padding: 20px;">
        <tr>
            <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background: white; border-radius: 10px; overflow: hidden;">
                    <tr>
                        <td style="background: linear-gradient(135deg, #4f46e5, #7c3aed); padding: 30px; text-align: center;">
                            <h1 style="color: white; margin: 0;">🔐 DropVault</h1>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 40px 30px;">
                            <h2 style="color: #333;">Hi {user.first_name or user.username}! 👋</h2>
                            <p style="color: #666; font-size: 16px;">
                                Welcome to DropVault! Please verify your email:
                            </p>
                            <table width="100%" style="margin: 30px 0;">
                                <tr>
                                    <td align="center">
                                        <a href="{verification_link}" 
                                           style="display: inline-block; background: #4f46e5; 
                                                  color: white; padding: 15px 40px; text-decoration: none; 
                                                  border-radius: 8px; font-weight: bold;">
                                            ✓ Verify My Email
                                        </a>
                                    </td>
                                </tr>
                            </table>
                            <p style="color: #999; font-size: 14px;">Or copy this link:</p>
                            <p style="background: #f5f5f5; padding: 15px; border-radius: 5px; 
                                      word-break: break-all; color: #4f46e5; font-size: 14px;">
                                {verification_link}
                            </p>
                            <p style="color: #e74c3c; font-size: 14px;">⏰ Expires in 24 hours.</p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
"""
        
        plain_message = f"Verify your email: {verification_link}"
        
        # Try Brevo API first
        if brevo_api_key:
            print("📧 Using Brevo API...", flush=True)
            try:
                response = http_requests.post(
                    'https://api.brevo.com/v3/smtp/email',
                    headers={
                        'api-key': brevo_api_key,
                        'Content-Type': 'application/json'
                    },
                    json={
                        'sender': {'name': 'DropVault', 'email': 'dropvault.dev@gmail.com'},
                        'to': [{'email': user.email, 'name': user.first_name or user.username}],
                        'subject': subject,
                        'htmlContent': html_message,
                        'textContent': plain_message,
                    },
                    timeout=30
                )
                
                print(f"📨 Brevo Response: {response.status_code}", flush=True)
                
                if response.status_code in [200, 201, 202]:
                    logger.info(f"✅ Email sent via Brevo to {user.email}")
                    print(f"✅ Email sent via Brevo!", flush=True)
                    return True
                else:
                    print(f"❌ Brevo error: {response.text}", flush=True)
            except Exception as e:
                print(f"❌ Brevo failed: {e}", flush=True)
        
        # Fallback to Resend
        if resend_api_key:
            print("📧 Trying Resend API...", flush=True)
            try:
                response = http_requests.post(
                    'https://api.resend.com/emails',
                    headers={
                        'Authorization': f'Bearer {resend_api_key}',
                        'Content-Type': 'application/json'
                    },
                    json={
                        'from': 'DropVault <onboarding@resend.dev>',
                        'to': [user.email],
                        'subject': subject,
                        'html': html_message,
                        'text': plain_message,
                    },
                    timeout=30
                )
                
                if response.status_code in [200, 201]:
                    logger.info(f"✅ Email sent via Resend to {user.email}")
                    return True
                else:
                    print(f"❌ Resend error: {response.text}", flush=True)
            except Exception as e:
                print(f"❌ Resend failed: {e}", flush=True)
        
        logger.error("❌ All email methods failed!")
        return False
            
    except Exception as e:
        logger.error(f"❌ Email sending failed: {e}")
        print(f"❌ Email error: {e}", flush=True)
        import traceback
        traceback.print_exc()
        return False


def send_password_reset_email(user, reset_link):
    """Send password reset email using Brevo API"""
    try:
        import requests as http_requests
        
        brevo_api_key = os.environ.get('BREVO_API_KEY', '')
        
        if not brevo_api_key:
            logger.error("❌ BREVO_API_KEY not configured!")
            return False
        
        subject = "Reset your DropVault password"
        
        html_message = f"""
<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; padding: 20px; background-color: #f4f4f4;">
    <div style="max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px;">
        <h1 style="color: #4f46e5;">🔐 DropVault</h1>
        <h2>Password Reset Request</h2>
        <p>Hi {user.first_name or user.username},</p>
        <p>Click the button below to reset your password:</p>
        <div style="text-align: center; margin: 30px 0;">
            <a href="{reset_link}" 
               style="background-color: #4f46e5; color: white; padding: 15px 30px; 
                      text-decoration: none; border-radius: 5px; font-weight: bold;">
                Reset Password
            </a>
        </div>
        <p style="color: #999; font-size: 14px;">This link expires in 1 hour.</p>
        <p style="color: #999; font-size: 14px;">If you didn't request this, ignore this email.</p>
    </div>
</body>
</html>
"""
        
        plain_message = f"Reset your password: {reset_link}"
        
        response = http_requests.post(
            'https://api.brevo.com/v3/smtp/email',
            headers={
                'api-key': brevo_api_key,
                'Content-Type': 'application/json'
            },
            json={
                'sender': {'name': 'DropVault', 'email': 'dropvault.dev@gmail.com'},
                'to': [{'email': user.email, 'name': user.first_name or user.username}],
                'subject': subject,
                'htmlContent': html_message,
                'textContent': plain_message,
            },
            timeout=30
        )
        
        if response.status_code in [200, 201, 202]:
            logger.info(f"✅ Password reset email sent to {user.email}")
            return True
        else:
            logger.error(f"❌ Brevo error: {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"❌ Password reset email failed: {e}")
        return False


# =============================================================================
# API: TEST EMAIL
# =============================================================================

@csrf_exempt
def api_test_email(request):
    """Test email sending with Brevo API"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    import requests as http_requests
    
    test_email = request.GET.get('email', '')
    
    if not test_email:
        return JsonResponse({
            'success': False,
            'error': 'Please provide email: /api/test-email/?email=your@email.com'
        })
    
    brevo_api_key = os.environ.get('BREVO_API_KEY', '')
    resend_api_key = os.environ.get('RESEND_API_KEY', '')
    
    config_status = {
        'BREVO_API_KEY': 'SET' if brevo_api_key else 'NOT SET',
        'RESEND_API_KEY': 'SET' if resend_api_key else 'NOT SET',
        'EMAIL_HOST_USER': os.environ.get('EMAIL_HOST_USER', '')[:10] + '***' if os.environ.get('EMAIL_HOST_USER') else 'NOT SET',
    }
    
    if brevo_api_key:
        try:
            print(f"📧 Testing email to {test_email} via Brevo API...", flush=True)
            
            response = http_requests.post(
                'https://api.brevo.com/v3/smtp/email',
                headers={
                    'api-key': brevo_api_key,
                    'Content-Type': 'application/json'
                },
                json={
                    'sender': {'name': 'DropVault', 'email': 'dropvault.dev@gmail.com'},
                    'to': [{'email': test_email, 'name': 'Test User'}],
                    'subject': 'DropVault Email Test ✅',
                    'htmlContent': f'''
                        <h1>🎉 Email is Working!</h1>
                        <p>Congratulations! Your DropVault email system is properly configured with Brevo.</p>
                        <p>Sent to: {test_email}</p>
                        <p>Time: {timezone.now().isoformat()}</p>
                    ''',
                    'textContent': f'Email is working! Sent to: {test_email}',
                },
                timeout=30
            )
            
            print(f"📨 Brevo Response: {response.status_code}", flush=True)
            
            if response.status_code in [200, 201, 202]:
                return JsonResponse({
                    'success': True,
                    'message': f'Email sent to {test_email} via Brevo!',
                    'provider': 'brevo',
                    'config': config_status,
                    'note': 'Check inbox AND spam folder'
                })
            else:
                print(f"❌ Brevo error: {response.text}", flush=True)
                return JsonResponse({
                    'success': False,
                    'error': f'Brevo API error: {response.text}',
                    'status_code': response.status_code,
                    'config': config_status
                })
                
        except Exception as e:
            print(f"❌ Brevo Error: {e}", flush=True)
            return JsonResponse({
                'success': False,
                'error': str(e),
                'provider': 'brevo',
                'config': config_status
            })
    
    return JsonResponse({
        'success': False,
        'error': 'No email API configured',
        'config': config_status,
        'fix': 'Add BREVO_API_KEY to Render environment variables'
    })


@csrf_exempt
def api_debug_email_config(request):
    """Debug endpoint to check email configuration"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    brevo_key = os.environ.get('BREVO_API_KEY', '')
    resend_key = os.environ.get('RESEND_API_KEY', '')
    email_user = os.environ.get('EMAIL_HOST_USER', '')
    email_pass = os.environ.get('EMAIL_HOST_PASSWORD', '')
    
    return JsonResponse({
        'brevo_api': {
            'BREVO_API_KEY': 'SET' if brevo_key else 'NOT SET',
            'key_preview': brevo_key[:15] + '...' if brevo_key else None,
        },
        'resend_api': {
            'RESEND_API_KEY': 'SET' if resend_key else 'NOT SET',
            'key_preview': resend_key[:15] + '...' if resend_key else None,
        },
        'smtp_config': {
            'EMAIL_HOST': os.environ.get('EMAIL_HOST', 'NOT SET'),
            'EMAIL_PORT': os.environ.get('EMAIL_PORT', 'NOT SET'),
            'EMAIL_HOST_USER': email_user[:10] + '***' if email_user else 'NOT SET',
            'EMAIL_HOST_PASSWORD': 'SET' if email_pass else 'NOT SET',
        },
        'frontend_config': {
            'allowed_frontends': ALLOWED_FRONTEND_URLS,
            'default_frontend': DEFAULT_FRONTEND_URL,
            'env_frontend': os.environ.get('FRONTEND_URL', 'NOT SET'),
        },
        'recommendation': 'Use Brevo API (free 300 emails/day, works on Render)',
    })


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def authenticate_request(request):
    if request.user.is_authenticated:
        return request.user
    
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if auth_header.startswith('Token '):
        token_key = auth_header.split(' ')[1]
        try:
            token = Token.objects.get(key=token_key)
            return token.user
        except Token.DoesNotExist:
            pass
    
    return None


def format_file_size(size_bytes):
    if size_bytes == 0:
        return "0 B"
    
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    unit_index = 0
    size = float(size_bytes)
    
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1
    
    return f"{size:.2f} {units[unit_index]}"


# =============================================================================
# WEB VIEWS
# =============================================================================

def home(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'home.html')


def signup_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'signup.html')


def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'login.html')


@login_required
def logout_view(request):
    if request.method == 'POST':
        logout(request)
        return redirect('home')
    return render(request, 'logout_confirm.html')


@login_required
def dashboard(request):
    return render(request, 'dashboard.html')


def verify_email(request, token):
    """Verify email from link (web view)"""
    try:
        profile = UserProfile.objects.get(verification_token=token)
        
        if profile.is_verification_token_valid(token):
            profile.email_verified = True
            profile.clear_verification_token()
            
            messages.success(request, "Email verified successfully!")
            login(request, profile.user, backend='django.contrib.auth.backends.ModelBackend')
            return redirect('dashboard')
        else:
            messages.error(request, "Verification link has expired.")
            return redirect('home')
            
    except UserProfile.DoesNotExist:
        messages.error(request, "Invalid verification link.")
        return redirect('home')


@login_required
def verify_email_prompt(request):
    return render(request, 'verify_prompt.html')


@login_required
def upload_test(request):
    return render(request, 'upload_test.html')


# =============================================================================
# ✅ API: SIGNUP - UPDATED TO USE REQUEST FOR FRONTEND URL
# =============================================================================

@csrf_exempt
def api_signup(request):
    """User signup with email verification"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')

        name = data.get('name', '').strip()
        if not name:
            name = data.get('username', '').strip()
        
        logger.info("=" * 60)
        logger.info(f"📝 SIGNUP REQUEST: {email}")
        
        frontend_url = get_frontend_url(request)
        logger.info(f"   Frontend URL: {frontend_url}")
        
        # Validate email
        is_valid, error = validate_email_complete(email)
        if not is_valid:
            logger.warning(f"   ❌ Invalid email: {error}")
            return JsonResponse({'success': False, 'error': error}, status=400)
        
        # Validate password
        if not password or len(password) < 8:
            return JsonResponse({
                'success': False, 
                'error': 'Password must be at least 8 characters'
            }, status=400)
        
        # Check if email exists
        if User.objects.filter(email=email).exists():
            existing = User.objects.get(email=email)
            
            try:
                profile = existing.profile
                if not profile.email_verified:
                    # Resend verification email
                    verification_token = profile.generate_verification_token()
                    verification_link = f"{frontend_url}/verify-email?token={verification_token}"
                    email_sent = send_verification_email(existing, verification_link)

                    logger.info(f"   📧 Resent verification: {email}")
                    return JsonResponse({
                        'success': True,
                        'requires_verification': True,
                        'message': 'Verification email sent. Please check your inbox.',
                        'email': email,
                        'email_sent': email_sent
                    })
            except UserProfile.DoesNotExist:
                pass
            
            if not existing.has_usable_password():
                existing.set_password(password)
                existing.save()
                
                login(request, existing, backend='django.contrib.auth.backends.ModelBackend')
                token, _ = Token.objects.get_or_create(user=existing)
                
                return JsonResponse({
                    'success': True,
                    'token': token.key,
                    'sessionid': request.session.session_key,
                    'user': {
                        'id': existing.id,
                        'email': existing.email,
                        'username': existing.username,
                        'name': f"{existing.first_name} {existing.last_name}".strip() or existing.username,
                        'email_verified': True,
                    }
                })
            
            return JsonResponse({
                'success': False, 
                'error': 'An account with this email already exists. Please login.'
            }, status=400)
        
        # Create username
        username = email.split('@')[0]
        counter = 1
        base = username
        while User.objects.filter(username=username).exists():
            username = f"{base}{counter}"
            counter += 1
        
        if name:
            parts = name.split()
            first_name = parts[0] if parts else ''
            last_name = ' '.join(parts[1:]) if len(parts) > 1 else ''
        else:
            first_name = username
            last_name = ''
        
        logger.info(f"   Creating user: username={username}, first_name={first_name}, last_name={last_name}")
        
        # Create user
        with transaction.atomic():
            user = User(
                username=username,
                email=email,
                first_name=first_name,
                last_name=last_name,
                is_active=True
            )
            user.set_password(password)
            user.save()
            
            if not check_password(password, user.password):
                user.delete()
                return JsonResponse({'success': False, 'error': 'Signup failed'}, status=500)
            
            profile, _ = UserProfile.objects.get_or_create(user=user)
            profile.signup_method = 'email'
            profile.email_verified = False
            profile.save()
        
        verification_token = profile.generate_verification_token()
        verification_link = f"{frontend_url}/verify-email?token={verification_token}"
        
        logger.info(f"   🔗 Verification link: {verification_link}")
        
        email_sent = send_verification_email(user, verification_link)
        
        logger.info(f"✅ SIGNUP SUCCESS: {email}, email_sent={email_sent}")
        logger.info("=" * 60)
        
        return JsonResponse({
            'success': True,
            'requires_verification': True,
            'message': 'Account created! Please check your email to verify.',
            'email': email,
            'email_sent': email_sent
        })
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid request'}, status=400)
    except Exception as e:
        logger.error(f"❌ Signup error: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({'success': False, 'error': 'Signup failed'}, status=500)


# =============================================================================
# API: VERIFY EMAIL TOKEN
# =============================================================================

@csrf_exempt
def api_verify_email_token(request):
    """Verify email using token from link"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    token = request.GET.get('token', '')
    if not token:
        try:
            data = json.loads(request.body)
            token = data.get('token', '')
        except:
            pass
    
    if not token:
        return JsonResponse({'success': False, 'error': 'Token required'}, status=400)
    
    logger.info(f"🔑 Verifying token: {token[:20]}...")
    
    try:
        profile = UserProfile.objects.get(verification_token=token)
        user = profile.user
        
        if profile.email_verified:
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            auth_token, _ = Token.objects.get_or_create(user=user)
            
            return JsonResponse({
                'success': True,
                'message': 'Email already verified!',
                'token': auth_token.key,
                'sessionid': request.session.session_key,
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'username': user.username,
                    'name': f"{user.first_name} {user.last_name}".strip() or user.username,
                    'email_verified': True,
                }
            })
        
        if profile.is_verification_token_valid(token):
            profile.email_verified = True
            profile.clear_verification_token()
            
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            auth_token, _ = Token.objects.get_or_create(user=user)
            
            Notification.create_notification(
                user=user,
                notification_type='EMAIL_VERIFIED',
                title='Welcome to DropVault!',
                message='Your email has been verified successfully.'
            )
            
            logger.info(f"✅ Email verified: {user.email}")
            
            return JsonResponse({
                'success': True,
                'message': 'Email verified successfully!',
                'token': auth_token.key,
                'sessionid': request.session.session_key,
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'username': user.username,
                    'name': f"{user.first_name} {user.last_name}".strip() or user.username,
                    'email_verified': True,
                }
            })
        else:
            return JsonResponse({
                'success': False,
                'error': 'Verification link has expired.',
                'expired': True,
                'email': user.email
            }, status=400)
            
    except UserProfile.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Invalid verification link'}, status=400)


# =============================================================================
# ✅ API: RESEND VERIFICATION EMAIL - UPDATED
# =============================================================================

@csrf_exempt
def api_resend_verification(request):
    """Resend verification email"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()
        
        if not email:
            return JsonResponse({'success': False, 'error': 'Email required'}, status=400)
        
        logger.info(f"📧 Resend verification: {email}")
        
        # ✅ Get frontend URL from request
        frontend_url = get_frontend_url(request)
        
        try:
            user = User.objects.get(email=email)
            profile = user.profile
            
            if profile.email_verified:
                return JsonResponse({
                    'success': False, 
                    'error': 'Email already verified. Please login.'
                }, status=400)
            
            # Rate limit: 1 minute
            if profile.verification_sent_at:
                time_since = timezone.now() - profile.verification_sent_at
                if time_since.total_seconds() < 60:
                    wait = int(60 - time_since.total_seconds())
                    return JsonResponse({
                        'success': False,
                        'error': f'Please wait {wait} seconds'
                    }, status=429)
            
            verification_token = profile.generate_verification_token()
            # ✅ Use frontend URL from request
            verification_link = f"{frontend_url}/verify-email?token={verification_token}"
            
            if send_verification_email(user, verification_link):
                return JsonResponse({'success': True, 'message': 'Email sent!'})
            else:
                return JsonResponse({'success': False, 'error': 'Failed to send email'}, status=500)
                
        except User.DoesNotExist:
            return JsonResponse({'success': True, 'message': 'If account exists, email will be sent.'})
        except UserProfile.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Account error'}, status=500)
            
    except Exception as e:
        logger.error(f"Resend error: {e}")
        return JsonResponse({'success': False, 'error': 'Failed'}, status=500)


# =============================================================================
# ✅ API: LOGIN - UPDATED
# =============================================================================

@csrf_exempt
def api_login(request):
    """User login with email verification check"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        logger.info(f"🔐 LOGIN ATTEMPT: {email}")
        print(f"🔐 LOGIN ATTEMPT: {email}", flush=True)
        
        # ✅ Get frontend URL from request
        frontend_url = get_frontend_url(request)
        
        if not email or not is_valid_email_format(email):
            return JsonResponse({'success': False, 'error': 'Valid email required'}, status=400)
        
        if not password:
            return JsonResponse({'success': False, 'error': 'Password required'}, status=400)
        
        # Find user
        try:
            user = User.objects.get(email=email)
            print(f"   Found user: {user.username}", flush=True)
        except User.DoesNotExist:
            print(f"   ❌ User not found: {email}", flush=True)
            return JsonResponse({'success': False, 'error': 'Invalid email or password'}, status=401)
        
        if not user.is_active:
            return JsonResponse({'success': False, 'error': 'Account disabled'}, status=403)
        
        # Check if user has password
        if not user.has_usable_password():
            print(f"   ❌ No usable password", flush=True)
            try:
                profile = user.profile
                if profile.signup_method == 'google':
                    return JsonResponse({
                        'success': False,
                        'error': 'This account uses Google login. Please use "Continue with Google".',
                        'is_google_account': True,
                    }, status=400)
            except:
                pass
            return JsonResponse({'success': False, 'error': 'Please use Google login'}, status=400)
        
        # Check password
        if not check_password(password, user.password):
            print(f"   ❌ Wrong password", flush=True)
            return JsonResponse({'success': False, 'error': 'Invalid email or password'}, status=401)
        
        print(f"   ✅ Password correct", flush=True)
        
        # Check email verification
        try:
            profile = user.profile
            email_verified = profile.email_verified
            print(f"   Email verified: {email_verified}", flush=True)
        except UserProfile.DoesNotExist:
            profile = UserProfile.objects.create(user=user, email_verified=False)
            email_verified = False
        
        if not email_verified:
            print(f"   ⚠️ Email not verified, sending verification...", flush=True)
            
            # Check if we should resend
            should_resend = True
            if profile.verification_sent_at:
                time_since = timezone.now() - profile.verification_sent_at
                if time_since.total_seconds() < 300:
                    should_resend = False
            
            email_sent = False
            if should_resend:
                try:
                    verification_token = profile.generate_verification_token()
                    # ✅ Use frontend URL from request
                    verification_link = f"{frontend_url}/verify-email?token={verification_token}"
                    email_sent = send_verification_email(user, verification_link)
                    print(f"   📧 Verification email sent: {email_sent}", flush=True)
                except Exception as e:
                    print(f"   ❌ Failed to send verification: {e}", flush=True)
            
            return JsonResponse({
                'success': False,
                'error': 'Please verify your email first. Check your inbox.',
                'requires_verification': True,
                'email': email,
                'email_sent': email_sent
            }, status=403)
        
        # Login success!
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        token, _ = Token.objects.get_or_create(user=user)
        
        print(f"✅ LOGIN SUCCESS: {email}", flush=True)
        
        return JsonResponse({
            'success': True,
            'message': 'Login successful',
            'token': token.key,
            'sessionid': request.session.session_key,
            'user': {
                'id': user.id,
                'email': user.email,
                'username': user.username,
                'name': f"{user.first_name} {user.last_name}".strip() or user.username,
                'email_verified': True,
            }
        })
        
    except json.JSONDecodeError as e:
        print(f"❌ JSON Error: {e}", flush=True)
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        print(f"❌ Login Error: {e}", flush=True)
        import traceback
        traceback.print_exc()
        return JsonResponse({
            'success': False, 
            'error': f'Login failed: {str(e)}',
            'error_type': type(e).__name__
        }, status=500)


# =============================================================================
# ✅ API: GOOGLE OAUTH - UPDATED
# =============================================================================

@csrf_exempt
def api_google_login(request):
    """Google OAuth login - Google verifies the email"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        code = data.get('code')
        
        if not code:
            return JsonResponse({'success': False, 'error': 'Authorization code required'}, status=400)
        
        client_id = os.environ.get('GOOGLE_CLIENT_ID', '')
        client_secret = os.environ.get('GOOGLE_CLIENT_SECRET', '')
        
        if not client_id or not client_secret:
            logger.error("❌ Google OAuth not configured")
            return JsonResponse({'success': False, 'error': 'Google OAuth not configured on server'}, status=501)
        
        # ✅ Determine redirect URI based on origin
        origin = request.META.get('HTTP_ORIGIN', '')
        
        if 'localhost' in origin or '127.0.0.1' in origin:
            redirect_uri = 'http://localhost:3000/google-callback'
        elif 'dropvaultnew-frontend' in origin:
            redirect_uri = 'https://dropvaultnew-frontend.onrender.com/google-callback'
        else:
            # Default to the primary frontend
            redirect_uri = f"{get_frontend_url(request)}/google-callback"
        
        logger.info(f"🔐 Google OAuth - Origin: {origin}")
        logger.info(f"🔐 Google OAuth - Redirect URI: {redirect_uri}")
        
        # Exchange code for token
        token_response = requests.post('https://oauth2.googleapis.com/token', data={
            'code': code,
            'client_id': client_id,
            'client_secret': client_secret,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code'
        }, timeout=15)
        
        if token_response.status_code != 200:
            logger.error(f"❌ Google token exchange failed: {token_response.text}")
            return JsonResponse({
                'success': False, 
                'error': 'Failed to exchange authorization code',
                'details': token_response.text
            }, status=401)
        
        token_data = token_response.json()
        access_token = token_data.get('access_token')
        
        if not access_token:
            logger.error("❌ No access token in Google response")
            return JsonResponse({'success': False, 'error': 'No access token received'}, status=401)
        
        # Get user info from Google
        user_info_response = requests.get(
            'https://www.googleapis.com/oauth2/v2/userinfo',
            headers={'Authorization': f'Bearer {access_token}'},
            timeout=10
        )
        
        if user_info_response.status_code != 200:
            logger.error(f"❌ Failed to get user info from Google: {user_info_response.text}")
            return JsonResponse({'success': False, 'error': 'Failed to get user info from Google'}, status=401)
        
        google_data = user_info_response.json()
        email = google_data.get('email', '').lower().strip()
        name = google_data.get('name', '')
        first_name = google_data.get('given_name', '')
        last_name = google_data.get('family_name', '')
        
        if not email:
            return JsonResponse({'success': False, 'error': 'No email received from Google'}, status=400)
        
        logger.info(f"🔐 Google user info: {email}")
        
        # Find or create user
        created = False
        try:
            user = User.objects.get(email=email)
            logger.info(f"   Found existing user: {email}")
        except User.DoesNotExist:
            username = email.split('@')[0]
            counter = 1
            base_username = username
            while User.objects.filter(username=username).exists():
                username = f"{base_username}{counter}"
                counter += 1
            
            user = User.objects.create(
                username=username,
                email=email,
                first_name=first_name or (name.split()[0] if name else ''),
                last_name=last_name or (' '.join(name.split()[1:]) if name and len(name.split()) > 1 else ''),
                is_active=True
            )
            user.set_unusable_password()
            user.save()
            created = True
            logger.info(f"   Created new user: {email}")
        
        # Update/Create profile
        profile, _ = UserProfile.objects.get_or_create(user=user)
        profile.email_verified = True
        profile.signup_method = 'google'
        profile.save()
        
        # Login the user
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        token, _ = Token.objects.get_or_create(user=user)
        
        logger.info(f"✅ Google login SUCCESS: {email} (new_user={created})")
        
        return JsonResponse({
            'success': True,
            'message': 'Google login successful',
            'token': token.key,
            'sessionid': request.session.session_key,
            'user': {
                'id': user.id,
                'email': user.email,
                'username': user.username,
                'name': f"{user.first_name} {user.last_name}".strip() or user.username,
                'has_password': False,
                'email_verified': True,
                'is_google_user': True,
                'signup_method': 'google',
            },
            'is_new_user': created
        })
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid request data'}, status=400)
    except Exception as e:
        logger.error(f"❌ Google OAuth error: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({'success': False, 'error': 'Google authentication failed'}, status=500)


# =============================================================================
# API: LOGOUT
# =============================================================================

@csrf_exempt
def api_logout(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if user:
        Token.objects.filter(user=user).delete()
    logout(request)
    return JsonResponse({'success': True, 'message': 'Logged out successfully'})


# =============================================================================
# API: CHECK AUTH
# =============================================================================

@csrf_exempt
def api_check_auth(request):
    """Check if user is authenticated"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if user:
        try:
            profile = user.profile
            email_verified = profile.email_verified
            signup_method = profile.signup_method
        except:
            email_verified = False
            signup_method = 'email'
        
        is_google_user = signup_method == 'google'
        
        return JsonResponse({
            'authenticated': True,
            'user': {
                'id': user.id,
                'email': user.email,
                'username': user.username,
                'name': f"{user.first_name} {user.last_name}".strip() or user.username,
                'email_verified': email_verified,
                'has_password': user.has_usable_password(),
                'is_google_user': is_google_user,
                'signup_method': signup_method,
            }
        })
    
    return JsonResponse({'authenticated': False})


# =============================================================================
# API: DASHBOARD
# =============================================================================

@csrf_exempt
def api_dashboard(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        from files.models import File, SharedLink
        
        total_files = File.objects.filter(user=user, deleted=False).count()
        total_trash = File.objects.filter(user=user, deleted=True).count()
        shared_links = SharedLink.objects.filter(owner=user, is_active=True)
        shared_count = sum(1 for link in shared_links if not link.is_expired())
        total_storage = File.objects.filter(user=user, deleted=False).aggregate(total=Sum('size'))['total'] or 0
        recent_files = File.objects.filter(user=user, deleted=False).order_by('-uploaded_at')[:5]
        recent_data = [{'id': f.id, 'name': f.original_name, 'size': f.size} for f in recent_files]
        
        return JsonResponse({
            'success': True,
            'data': {
                'storageUsed': total_storage,
                'storageTotal': 10737418240,
                'totalFiles': total_files,
                'trashFiles': total_trash,
                'sharedFiles': shared_count,
                'recentFiles': recent_data,
            },
            'user': {
                'id': user.id,
                'email': user.email,
                'name': f"{user.first_name} {user.last_name}".strip() or user.username,
            }
        })
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


# =============================================================================
# API: NOTIFICATIONS
# =============================================================================

@csrf_exempt
def api_notifications(request):
    """Get all visible notifications for the user"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        Notification.cleanup_old_notifications(user)
        notifications = Notification.get_visible_notifications(user)
        
        notification_list = []
        unread_count = 0
        
        for notif in notifications:
            notification_list.append({
                'id': notif.id,
                'type': notif.notification_type,
                'title': notif.title,
                'message': notif.message,
                'file_name': notif.file_name,
                'file_id': notif.file_id,
                'is_read': notif.is_read,
                'created_at': notif.created_at.isoformat(),
                'read_at': notif.read_at.isoformat() if notif.read_at else None,
            })
            
            if not notif.is_read:
                unread_count += 1
        
        return JsonResponse({
            'success': True,
            'notifications': notification_list,
            'unread_count': unread_count,
            'total_count': len(notification_list)
        })
        
    except Exception as e:
        logger.error(f"Notification error: {e}")
        return JsonResponse({
            'success': True,
            'notifications': [],
            'unread_count': 0,
            'total_count': 0
        })


@csrf_exempt
def api_notification_read(request, notification_id):
    """Mark a single notification as read"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        notification = Notification.objects.get(id=notification_id, user=user)
        notification.mark_as_read()
        return JsonResponse({'success': True})
    except Notification.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
def api_notifications_read_all(request):
    """Mark all notifications as read"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        updated = Notification.objects.filter(
            user=user,
            is_read=False
        ).update(
            is_read=True,
            read_at=timezone.now()
        )
        return JsonResponse({'success': True, 'count': updated})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
def api_notification_delete(request, notification_id):
    """Delete a notification"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        Notification.objects.filter(id=notification_id, user=user).delete()
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


# =============================================================================
# API: USER PROFILE & STORAGE
# =============================================================================

@csrf_exempt
def api_user_profile(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    full_name = f"{user.first_name} {user.last_name}".strip()
    
    if not full_name:
        full_name = user.username
    
    if not full_name:
        full_name = user.email.split('@')[0] if user.email else 'User'
    
    return JsonResponse({
        'success': True,
        'data': {
            'id': user.id,
            'email': user.email,
            'username': user.username,
            'name': full_name,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'has_password': user.has_usable_password(),
        }
    })

@csrf_exempt
def api_update_user_name(request):
    """Update user's name"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        data = json.loads(request.body)
        name = data.get('name', '').strip()
        
        if not name:
            return JsonResponse({'success': False, 'error': 'Name is required'}, status=400)
        
        # Parse name
        parts = name.split()
        user.first_name = parts[0] if parts else ''
        user.last_name = ' '.join(parts[1:]) if len(parts) > 1 else ''
        user.save()
        
        return JsonResponse({
            'success': True,
            'message': 'Name updated successfully',
            'user': {
                'id': user.id,
                'email': user.email,
                'name': f"{user.first_name} {user.last_name}".strip(),
                'first_name': user.first_name,
                'last_name': user.last_name,
            }
        })
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@csrf_exempt
def api_user_storage(request):
    """Get user's storage usage details"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        from files.models import File
        from django.db.models import Sum
        
        total = File.objects.filter(user=user, deleted=False).aggregate(total=Sum('size'))['total'] or 0
        count = File.objects.filter(user=user, deleted=False).count()
        limit = 10 * 1024 * 1024 * 1024
        
        files = File.objects.filter(user=user, deleted=False)
        
        documents_size = 0
        images_size = 0
        videos_size = 0
        audio_size = 0
        other_size = 0
        
        doc_exts = ['.pdf', '.doc', '.docx', '.txt', '.xls', '.xlsx', '.ppt', '.pptx']
        image_exts = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.ico', '.bmp']
        video_exts = ['.mp4', '.mov', '.avi', '.webm', '.mkv', '.flv', '.wmv']
        audio_exts = ['.mp3', '.wav', '.flac', '.aac', '.ogg', '.m4a']
        
        for f in files:
            ext = f.original_name.lower().split('.')[-1] if '.' in f.original_name else ''
            ext_with_dot = f'.{ext}'
            
            if ext_with_dot in doc_exts:
                documents_size += f.size
            elif ext_with_dot in image_exts:
                images_size += f.size
            elif ext_with_dot in video_exts:
                videos_size += f.size
            elif ext_with_dot in audio_exts:
                audio_size += f.size
            else:
                other_size += f.size
        
        return JsonResponse({
            'success': True,
            'storage': {
                'used': total,
                'used_formatted': format_file_size(total),
                'limit': limit,
                'limit_formatted': format_file_size(limit),
                'percentage': round((total / limit) * 100, 2) if limit > 0 else 0,
                'file_count': count,
                'remaining': limit - total,
                'remaining_formatted': format_file_size(limit - total),
                'breakdown': {
                    'documents': documents_size,
                    'documents_formatted': format_file_size(documents_size),
                    'images': images_size,
                    'images_formatted': format_file_size(images_size),
                    'videos': videos_size,
                    'videos_formatted': format_file_size(videos_size),
                    'audio': audio_size,
                    'audio_formatted': format_file_size(audio_size),
                    'other': other_size,
                    'other_formatted': format_file_size(other_size),
                }
            }
        })
    except Exception as e:
        logger.error(f"Storage API error: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


# =============================================================================
# API: PASSWORD MANAGEMENT
# =============================================================================

@csrf_exempt
def api_set_password(request):
    """Allow OAuth users to set a password"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        data = json.loads(request.body)
        new_password = data.get('password', '')
        confirm_password = data.get('confirm_password', new_password)
        
        if not new_password or len(new_password) < 8:
            return JsonResponse({
                'success': False,
                'error': 'Password must be at least 8 characters'
            }, status=400)
        
        if new_password != confirm_password:
            return JsonResponse({
                'success': False,
                'error': 'Passwords do not match'
            }, status=400)
        
        user.set_password(new_password)
        user.save()
        update_session_auth_hash(request, user)
        
        return JsonResponse({
            'success': True,
            'message': 'Password set successfully!'
        })
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
def api_forgot_password(request):
    """Request password reset"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()
        
        if not email:
            return JsonResponse({'success': False, 'error': 'Email is required'}, status=400)
        
        # ✅ Get frontend URL from request
        frontend_url = get_frontend_url(request)
        
        try:
            user = User.objects.get(email=email)
            
            reset_token = secrets.token_urlsafe(32)
            cache_key = f'password_reset:{reset_token}'
            cache.set(cache_key, {'user_id': user.id, 'email': email}, timeout=3600)
            
            # ✅ Use frontend URL from request
            reset_link = f"{frontend_url}/reset-password?token={reset_token}"
            
            # Send password reset email
            if send_password_reset_email(user, reset_link):
                logger.info(f"Password reset email sent to {email}")
            else:
                logger.warning(f"Failed to send password reset email to {email}")
            
        except User.DoesNotExist:
            pass
        
        return JsonResponse({
            'success': True,
            'message': 'If an account exists, a reset link has been sent.'
        })
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': 'Request failed'}, status=500)


@csrf_exempt
def api_reset_password(request):
    """Reset password with token"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        token = data.get('token', '').strip()
        new_password = data.get('password', '')
        
        if not token:
            return JsonResponse({'success': False, 'error': 'Token required'}, status=400)
        
        if not new_password or len(new_password) < 8:
            return JsonResponse({
                'success': False,
                'error': 'Password must be at least 8 characters'
            }, status=400)
        
        cache_key = f'password_reset:{token}'
        reset_data = cache.get(cache_key)
        
        if not reset_data:
            return JsonResponse({
                'success': False,
                'error': 'Invalid or expired reset link'
            }, status=400)
        
        try:
            user = User.objects.get(id=reset_data['user_id'])
            user.set_password(new_password)
            user.save()
            
            cache.delete(cache_key)
            Token.objects.filter(user=user).delete()
            
            return JsonResponse({
                'success': True,
                'message': 'Password reset successfully! Please login.'
            })
            
        except User.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'User not found'}, status=404)
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
def api_request_password_reset(request):
    return api_forgot_password(request)


@csrf_exempt
def api_verify_reset_token(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    token = request.GET.get('token', '')
    if not token:
        return JsonResponse({'valid': False}, status=400)
    
    cache_key = f'password_reset:{token}'
    reset_data = cache.get(cache_key)
    
    return JsonResponse({'valid': bool(reset_data)})


@csrf_exempt
def api_check_user_password_status(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    return JsonResponse({
        'success': True,
        'has_password': user.has_usable_password(),
        'email': user.email
    })


# =============================================================================
# API: ADMIN/DEBUG ENDPOINTS
# =============================================================================

@csrf_exempt
def api_debug_user(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    email = request.GET.get('email', '').strip().lower()
    if not email:
        return JsonResponse({'error': 'Email required'}, status=400)
    
    try:
        user = User.objects.get(email=email)
        try:
            profile = user.profile
            email_verified = profile.email_verified
        except:
            email_verified = False
        
        return JsonResponse({
            'success': True,
            'user': {
                'id': user.id,
                'email': user.email,
                'username': user.username,
                'has_password': user.has_usable_password(),
                'is_active': user.is_active,
                'email_verified': email_verified,
            }
        })
    except User.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Not found'}, status=404)


@csrf_exempt
def api_debug_list_users(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    users = User.objects.all().order_by('id')
    user_list = []
    
    for u in users:
        try:
            email_verified = u.profile.email_verified
        except:
            email_verified = False
        
        user_list.append({
            'id': u.id,
            'email': u.email,
            'username': u.username,
            'has_password': u.has_usable_password(),
            'is_active': u.is_active,
            'email_verified': email_verified,
        })
    
    return JsonResponse({
        'success': True,
        'count': len(user_list),
        'users': user_list
    })


@csrf_exempt
def api_debug_fix_password(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()
        new_password = data.get('new_password', '')
        
        if not email or not new_password:
            return JsonResponse({'success': False, 'error': 'Email and new_password required'}, status=400)
        
        user = User.objects.get(email=email)
        user.set_password(new_password)
        user.save()
        
        verified = check_password(new_password, user.password)
        Token.objects.filter(user=user).delete()
        
        return JsonResponse({
            'success': True,
            'email': email,
            'password_verified': verified
        })
        
    except User.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'User not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
def api_admin_delete_all_users(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        admin_key = data.get('admin_key', '')
        confirm = data.get('confirm', False)
        
        expected_key = os.environ.get('ADMIN_FIX_KEY', 'dropvault-admin-fix-2024')
        if admin_key != expected_key:
            return JsonResponse({'success': False, 'error': 'Invalid admin key'}, status=403)
        
        users = User.objects.filter(is_superuser=False)
        
        if not confirm:
            return JsonResponse({
                'success': False,
                'message': 'Add "confirm": true to delete',
                'would_delete': users.count()
            })
        
        count = users.count()
        
        from files.models import File, SharedLink
        user_ids = list(users.values_list('id', flat=True))
        
        Token.objects.filter(user_id__in=user_ids).delete()
        File.objects.filter(user_id__in=user_ids).delete()
        SharedLink.objects.filter(owner_id__in=user_ids).delete()
        UserProfile.objects.filter(user_id__in=user_ids).delete()
        Notification.objects.filter(user_id__in=user_ids).delete()
        
        users.delete()
        
        return JsonResponse({'success': True, 'deleted_count': count})
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


# =============================================================================
# STUB ENDPOINTS
# =============================================================================

# ✅ REPLACE WITH THIS:
@csrf_exempt
def api_verify_email(request):
    """Verify email using token - handles both GET and POST"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    # Get token from multiple sources
    token = None
    
    # Try GET parameter first
    token = request.GET.get('token', '')
    
    # Try POST body if not in GET
    if not token and request.method == "POST":
        try:
            data = json.loads(request.body)
            token = data.get('token', '')
        except:
            pass
    
    if not token:
        return JsonResponse({
            'success': False, 
            'error': 'Verification token is required',
            'message': 'Verification token is required'
        }, status=400)
    
    logger.info(f"🔑 Verifying email token: {token[:20]}...")
    print(f"🔑 Verifying email token: {token[:20]}...", flush=True)
    
    try:
        profile = UserProfile.objects.get(verification_token=token)
        user = profile.user
        
        print(f"   Found user: {user.email}", flush=True)
        
        # Already verified
        if profile.email_verified:
            print(f"   Already verified, logging in...", flush=True)
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            auth_token, _ = Token.objects.get_or_create(user=user)
            
            return JsonResponse({
                'success': True,
                'message': 'Email already verified!',
                'token': auth_token.key,
                'sessionid': request.session.session_key,
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'username': user.username,
                    'name': f"{user.first_name} {user.last_name}".strip() or user.username,
                    'email_verified': True,
                }
            })
        
        # Check if token is valid (not expired)
        if profile.is_verification_token_valid(token):
            profile.email_verified = True
            profile.clear_verification_token()
            
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            auth_token, _ = Token.objects.get_or_create(user=user)
            
            # Create welcome notification
            try:
                Notification.create_notification(
                    user=user,
                    notification_type='EMAIL_VERIFIED',
                    title='Welcome to DropVault!',
                    message='Your email has been verified successfully.'
                )
            except Exception as e:
                print(f"   ⚠️ Notification error (non-critical): {e}", flush=True)
            
            logger.info(f"✅ Email verified successfully: {user.email}")
            print(f"✅ Email verified successfully: {user.email}", flush=True)
            
            return JsonResponse({
                'success': True,
                'message': 'Email verified successfully!',
                'token': auth_token.key,
                'sessionid': request.session.session_key,
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'username': user.username,
                    'name': f"{user.first_name} {user.last_name}".strip() or user.username,
                    'email_verified': True,
                }
            })
        else:
            print(f"   ❌ Token expired for: {user.email}", flush=True)
            return JsonResponse({
                'success': False,
                'error': 'Verification link has expired. Please request a new one.',
                'message': 'Verification link has expired. Please request a new one.',
                'expired': True,
                'email': user.email
            }, status=400)
            
    except UserProfile.DoesNotExist:
        print(f"   ❌ No profile found for token: {token[:20]}...", flush=True)
        return JsonResponse({
            'success': False, 
            'error': 'Invalid verification link',
            'message': 'Invalid verification link'
        }, status=400)
    except Exception as e:
        print(f"   ❌ Verification error: {e}", flush=True)
        import traceback
        traceback.print_exc()
        return JsonResponse({
            'success': False,
            'error': 'Verification failed',
            'message': 'Verification failed'
        }, status=500)

@csrf_exempt
def api_update_profile(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    return JsonResponse({'success': True})


@csrf_exempt
def api_change_password(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    return JsonResponse({'success': True})


@csrf_exempt
def api_preferences(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    return JsonResponse({'success': True, 'data': {}})


def test_email(request):
    return HttpResponse("OK")


# MFA endpoints
@login_required
def setup_mfa(request):
    from django_otp.plugins.otp_totp.models import TOTPDevice
    device, _ = TOTPDevice.objects.get_or_create(user=request.user, confirmed=False, defaults={'name': 'Auth'})
    if request.method == 'POST' and device.verify_token(request.POST.get('token', '')):
        device.confirmed = True
        device.save()
        return redirect('dashboard')
    return render(request, 'setup_mfa.html', {'device': device})


@login_required
def otp_verify(request):
    from django_otp import match_token
    if request.method == 'POST' and match_token(request.user, request.POST.get('otp', '')):
        return redirect('dashboard')
    return render(request, 'otp_verify.html')


@login_required
def disable_mfa(request):
    from django_otp.plugins.otp_totp.models import TOTPDevice
    if request.method == 'POST':
        TOTPDevice.objects.filter(user=request.user).delete()
        return redirect('dashboard')
    return render(request, 'disable_mfa.html')