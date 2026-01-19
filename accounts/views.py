# accounts/views.py - COMPLETE FILE WITH EMAIL VERIFICATION

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
# EMAIL VALIDATION HELPERS
# =============================================================================

def is_valid_email_format(email):
    """Check if email format is valid"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def is_disposable_email(email):
    """Check if email is from a disposable email provider"""
    disposable_domains = [
        'tempmail.com', 'throwaway.email', 'guerrillamail.com', 
        'mailinator.com', '10minutemail.com', 'temp-mail.org',
        'fakeinbox.com', 'trashmail.com', 'yopmail.com',
        'tempail.com', 'tmpmail.org', 'getnada.com',
        'sharklasers.com', 'guerrillamail.info', 'grr.la',
        'maildrop.cc', 'discard.email', 'tempr.email',
    ]
    domain = email.split('@')[1].lower() if '@' in email else ''
    return domain in disposable_domains


def validate_email_complete(email):
    """
    Complete email validation
    Returns (is_valid, error_message)
    """
    if not email:
        return False, "Email is required"
    
    email = email.strip().lower()
    
    if not is_valid_email_format(email):
        return False, "Please enter a valid email address"
    
    if is_disposable_email(email):
        return False, "Disposable email addresses are not allowed"
    
    return True, None


# =============================================================================
# EMAIL SENDING FUNCTIONS
# =============================================================================

def send_verification_email(user, verification_link):
    """Send verification email to user using Resend or Django's email backend"""
    try:
        subject = "Verify your DropVault account"
        
        html_message = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
        .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }}
        .button {{ display: inline-block; background: #667eea; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
        .button:hover {{ background: #5a6fd6; }}
        .footer {{ text-align: center; margin-top: 20px; color: #666; font-size: 12px; }}
        .link {{ word-break: break-all; color: #667eea; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 DropVault</h1>
            <p>Secure File Storage</p>
        </div>
        <div class="content">
            <h2>Hi {user.first_name or user.username}!</h2>
            <p>Welcome to DropVault! Please verify your email address to complete your registration and access your dashboard.</p>
            
            <p style="text-align: center;">
                <a href="{verification_link}" class="button">✓ Verify My Email</a>
            </p>
            
            <p>Or copy and paste this link into your browser:</p>
            <p class="link">{verification_link}</p>
            
            <p><strong>This link will expire in 24 hours.</strong></p>
            
            <p>If you didn't create an account with DropVault, please ignore this email.</p>
        </div>
        <div class="footer">
            <p>© 2024 DropVault. All rights reserved.</p>
            <p>This is an automated message, please do not reply.</p>
        </div>
    </div>
</body>
</html>
        """
        
        plain_message = f"""
Hi {user.first_name or user.username},

Welcome to DropVault! Please verify your email address by clicking the link below:

{verification_link}

This link will expire in 24 hours.

If you didn't create an account, please ignore this email.

Best regards,
The DropVault Team
        """
        
        # Try Resend API first if configured
        resend_api_key = os.environ.get('RESEND_API_KEY', '')
        
        if resend_api_key:
            response = requests.post(
                'https://api.resend.com/emails',
                headers={
                    'Authorization': f'Bearer {resend_api_key}',
                    'Content-Type': 'application/json'
                },
                json={
                    'from': settings.DEFAULT_FROM_EMAIL,
                    'to': [user.email],
                    'subject': subject,
                    'html': html_message,
                    'text': plain_message,
                },
                timeout=30
            )
            
            if response.status_code in [200, 201]:
                logger.info(f"✅ Verification email sent via Resend to: {user.email}")
                return True
            else:
                logger.error(f"❌ Resend API error: {response.status_code} - {response.text}")
        
        # Fallback to Django's email backend
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )
        logger.info(f"✅ Verification email sent via Django to: {user.email}")
        return True
        
    except Exception as e:
        logger.error(f"❌ Failed to send verification email to {user.email}: {e}")
        import traceback
        traceback.print_exc()
        return False


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def authenticate_request(request):
    """Authenticate request using Token or Session"""
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
    """Convert bytes to human readable format"""
    if size_bytes == 0:
        return "0 B"
    
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    unit_index = 0
    size = float(size_bytes)
    
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1
    
    return f"{size:.2f} {units[unit_index]}"


def check_email_verified(user):
    """Check if user's email is verified"""
    try:
        profile = user.profile
        return profile.email_verified
    except UserProfile.DoesNotExist:
        return False


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
    if request.method == 'GET':
        return render(request, 'signup.html')
    
    email = request.POST.get('email', '').strip().lower()
    password = request.POST.get('password', '')
    name = request.POST.get('name', '').strip()
    
    # Validate email
    is_valid, error = validate_email_complete(email)
    if not is_valid:
        messages.error(request, error)
        return render(request, 'signup.html')
    
    if User.objects.filter(email=email).exists():
        messages.error(request, "Email already exists.")
        return render(request, 'signup.html')
    
    username = email.split('@')[0]
    counter = 1
    while User.objects.filter(username=username).exists():
        username = f"{email.split('@')[0]}{counter}"
        counter += 1
    
    user = User(username=username, email=email, first_name=name, is_active=True)
    user.set_password(password)
    user.save()
    
    profile, _ = UserProfile.objects.get_or_create(user=user)
    
    login(request, user, backend='django.contrib.auth.backends.ModelBackend')
    return redirect('dashboard')


def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    if request.method == 'GET':
        return render(request, 'login.html')
    
    email = request.POST.get('email', '').strip().lower()
    password = request.POST.get('password', '')
    
    try:
        user = User.objects.get(email=email)
        if check_password(password, user.password):
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            return redirect('dashboard')
    except User.DoesNotExist:
        pass
    
    messages.error(request, "Invalid credentials.")
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
            
            messages.success(request, "Email verified successfully! You can now access your dashboard.")
            login(request, profile.user, backend='django.contrib.auth.backends.ModelBackend')
            return redirect('dashboard')
        else:
            messages.error(request, "Verification link has expired. Please request a new one.")
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
# API: SIGNUP - WITH EMAIL VERIFICATION REQUIRED
# =============================================================================

@csrf_exempt
def api_signup(request):
    """
    User signup with EMAIL VERIFICATION REQUIRED
    User cannot access dashboard until email is verified
    """
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        name = data.get('name', '').strip()
        
        logger.info("=" * 60)
        logger.info(f"📝 SIGNUP REQUEST: {email}")
        
        # ========================================
        # STEP 1: VALIDATE EMAIL FORMAT
        # ========================================
        is_valid, error = validate_email_complete(email)
        if not is_valid:
            logger.warning(f"   ❌ Invalid email format: {error}")
            return JsonResponse({'success': False, 'error': error}, status=400)
        
        # ========================================
        # STEP 2: VALIDATE PASSWORD
        # ========================================
        if not password or len(password) < 8:
            return JsonResponse({
                'success': False, 
                'error': 'Password must be at least 8 characters'
            }, status=400)
        
        # ========================================
        # STEP 3: CHECK IF EMAIL EXISTS
        # ========================================
        if User.objects.filter(email=email).exists():
            existing = User.objects.get(email=email)
            
            # Check if this is an unverified account
            try:
                profile = existing.profile
                if not profile.email_verified:
                    # Resend verification email
                    verification_token = profile.generate_verification_token()
                    frontend_url = os.environ.get('FRONTEND_URL', 'https://dropvault-frontend-1.onrender.com')
                    verification_link = f"{frontend_url}/verify-email?token={verification_token}"
                    
                    send_verification_email(existing, verification_link)
                    
                    logger.info(f"   📧 Resent verification to unverified account: {email}")
                    return JsonResponse({
                        'success': True,
                        'requires_verification': True,
                        'message': 'A verification email has been sent. Please check your inbox.',
                        'email': email
                    })
            except UserProfile.DoesNotExist:
                pass
            
            # If OAuth user without password, let them set one
            if not existing.has_usable_password():
                existing.set_password(password)
                existing.save()
                
                login(request, existing, backend='django.contrib.auth.backends.ModelBackend')
                token, _ = Token.objects.get_or_create(user=existing)
                
                logger.info(f"✅ Password set for OAuth user: {email}")
                return JsonResponse({
                    'success': True,
                    'message': 'Password set successfully!',
                    'token': token.key,
                    'sessionid': request.session.session_key,
                    'email_verified': True,  # OAuth users are verified by provider
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
                'error': 'An account with this email already exists. Please login instead.'
            }, status=400)
        
        # ========================================
        # STEP 4: CREATE USER (NOT ACTIVE YET)
        # ========================================
        username = email.split('@')[0]
        counter = 1
        base = username
        while User.objects.filter(username=username).exists():
            username = f"{base}{counter}"
            counter += 1
        
        parts = name.split() if name else [username]
        first = parts[0] if parts else ''
        last = ' '.join(parts[1:]) if len(parts) > 1 else ''
        
        with transaction.atomic():
            user = User(
                username=username,
                email=email,
                first_name=first,
                last_name=last,
                is_active=True  # User is active but email not verified
            )
            user.set_password(password)
            user.save()
            
            # Verify password was set correctly
            if not check_password(password, user.password):
                user.delete()
                logger.error(f"❌ Password verification failed: {email}")
                return JsonResponse({'success': False, 'error': 'Signup failed. Please try again.'}, status=500)
            
            # Create profile with email_verified = False
            profile, _ = UserProfile.objects.get_or_create(user=user)
            profile.signup_method = 'email'
            profile.email_verified = False
            profile.save()
        
        # ========================================
        # STEP 5: SEND VERIFICATION EMAIL
        # ========================================
        verification_token = profile.generate_verification_token()
        frontend_url = os.environ.get('FRONTEND_URL', 'https://dropvault-frontend-1.onrender.com')
        verification_link = f"{frontend_url}/verify-email?token={verification_token}"
        
        email_sent = send_verification_email(user, verification_link)
        
        if not email_sent:
            logger.warning(f"   ⚠️ Could not send verification email to: {email}")
        
        logger.info(f"✅ SIGNUP SUCCESS (pending verification): {email}")
        logger.info(f"   📧 Verification link: {verification_link}")
        logger.info("=" * 60)
        
        # ========================================
        # STEP 6: RETURN - DO NOT LOGIN
        # ========================================
        # User must verify email before accessing dashboard
        return JsonResponse({
            'success': True,
            'requires_verification': True,
            'message': 'Account created! Please check your email to verify your account before logging in.',
            'email': email,
            'email_sent': email_sent
        })
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid request data'}, status=400)
    except Exception as e:
        logger.error(f"❌ Signup error: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({'success': False, 'error': 'Signup failed. Please try again.'}, status=500)


# =============================================================================
# API: RESEND VERIFICATION EMAIL
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
            return JsonResponse({'success': False, 'error': 'Email is required'}, status=400)
        
        logger.info(f"📧 Resend verification requested for: {email}")
        
        try:
            user = User.objects.get(email=email)
            profile = user.profile
            
            if profile.email_verified:
                return JsonResponse({
                    'success': False, 
                    'error': 'Email is already verified. Please login.'
                }, status=400)
            
            # Check rate limit (1 minute cooldown)
            if profile.verification_sent_at:
                time_since = timezone.now() - profile.verification_sent_at
                if time_since.total_seconds() < 60:
                    wait_time = int(60 - time_since.total_seconds())
                    return JsonResponse({
                        'success': False,
                        'error': f'Please wait {wait_time} seconds before requesting another email'
                    }, status=429)
            
            # Generate new token and send email
            verification_token = profile.generate_verification_token()
            frontend_url = os.environ.get('FRONTEND_URL', 'https://dropvault-frontend-1.onrender.com')
            verification_link = f"{frontend_url}/verify-email?token={verification_token}"
            
            if send_verification_email(user, verification_link):
                return JsonResponse({
                    'success': True,
                    'message': 'Verification email sent! Please check your inbox.'
                })
            else:
                return JsonResponse({
                    'success': False,
                    'error': 'Failed to send email. Please try again later.'
                }, status=500)
                
        except User.DoesNotExist:
            # Don't reveal if email exists
            return JsonResponse({
                'success': True,
                'message': 'If an account exists with this email, a verification link will be sent.'
            })
        except UserProfile.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Account configuration error. Please contact support.'
            }, status=500)
            
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid request'}, status=400)
    except Exception as e:
        logger.error(f"Resend verification error: {e}")
        return JsonResponse({'success': False, 'error': 'Request failed'}, status=500)


# =============================================================================
# API: VERIFY EMAIL TOKEN
# =============================================================================

@csrf_exempt
def api_verify_email_token(request):
    """Verify email using token from link"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    # Accept token from query params (GET) or body (POST)
    if request.method == "GET":
        token = request.GET.get('token', '')
    else:
        try:
            data = json.loads(request.body)
            token = data.get('token', '')
        except:
            token = request.GET.get('token', '')
    
    if not token:
        return JsonResponse({
            'success': False, 
            'error': 'Verification token is required'
        }, status=400)
    
    logger.info(f"🔑 Verifying token: {token[:20]}...")
    
    try:
        profile = UserProfile.objects.get(verification_token=token)
        user = profile.user
        
        if profile.email_verified:
            # Already verified
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
            # Verify the email
            profile.email_verified = True
            profile.clear_verification_token()
            
            # Login the user
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            auth_token, _ = Token.objects.get_or_create(user=user)
            
            # Create welcome notification
            Notification.create_notification(
                user=user,
                notification_type='EMAIL_VERIFIED',
                title='Email Verified!',
                message='Welcome to DropVault! Your email has been verified successfully.'
            )
            
            logger.info(f"✅ Email verified successfully: {user.email}")
            
            return JsonResponse({
                'success': True,
                'message': 'Email verified successfully! Welcome to DropVault!',
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
            logger.warning(f"   ❌ Token expired for: {user.email}")
            return JsonResponse({
                'success': False,
                'error': 'Verification link has expired. Please request a new one.',
                'expired': True,
                'email': user.email
            }, status=400)
            
    except UserProfile.DoesNotExist:
        logger.warning(f"   ❌ Invalid token: {token[:20]}...")
        return JsonResponse({
            'success': False,
            'error': 'Invalid verification link. Please request a new one.'
        }, status=400)
    except Exception as e:
        logger.error(f"Verify token error: {e}")
        return JsonResponse({'success': False, 'error': 'Verification failed'}, status=500)


# =============================================================================
# API: LOGIN - WITH EMAIL VERIFICATION CHECK
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
        
        logger.info("=" * 60)
        logger.info(f"🔐 LOGIN ATTEMPT: {email}")
        
        # Validate inputs
        if not email or not is_valid_email_format(email):
            return JsonResponse({
                'success': False, 
                'error': 'Please enter a valid email address'
            }, status=400)
        
        if not password:
            return JsonResponse({'success': False, 'error': 'Password is required'}, status=400)
        
        # Find user
        try:
            user = User.objects.get(email=email)
            logger.info(f"   User found: {user.username}")
        except User.DoesNotExist:
            logger.warning(f"   ❌ User not found: {email}")
            return JsonResponse({
                'success': False, 
                'error': 'Invalid email or password'
            }, status=401)
        
        if not user.is_active:
            return JsonResponse({'success': False, 'error': 'Account is disabled'}, status=403)
        
        # Check password
        has_password = user.has_usable_password()
        
        if not has_password:
            return JsonResponse({
                'success': False, 
                'error': 'This account uses Google login. Please sign in with Google.'
            }, status=400)
        
        if not check_password(password, user.password):
            logger.warning(f"   ❌ Wrong password for: {email}")
            return JsonResponse({
                'success': False, 
                'error': 'Invalid email or password'
            }, status=401)
        
        # ========================================
        # CHECK EMAIL VERIFICATION
        # ========================================
        try:
            profile = user.profile
            email_verified = profile.email_verified
        except UserProfile.DoesNotExist:
            # Create profile if missing
            profile = UserProfile.objects.create(user=user, email_verified=False)
            email_verified = False
        
        if not email_verified:
            logger.warning(f"   ⚠️ Email not verified: {email}")
            
            # Optionally resend verification email
            # Check if we recently sent one
            should_resend = True
            if profile.verification_sent_at:
                time_since = timezone.now() - profile.verification_sent_at
                if time_since.total_seconds() < 300:  # 5 minute cooldown
                    should_resend = False
            
            if should_resend:
                verification_token = profile.generate_verification_token()
                frontend_url = os.environ.get('FRONTEND_URL', 'https://dropvault-frontend-1.onrender.com')
                verification_link = f"{frontend_url}/verify-email?token={verification_token}"
                send_verification_email(user, verification_link)
            
            return JsonResponse({
                'success': False,
                'error': 'Please verify your email before logging in. Check your inbox for the verification link.',
                'requires_verification': True,
                'email': email,
                'email_sent': should_resend
            }, status=403)
        
        # ========================================
        # LOGIN SUCCESS
        # ========================================
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        token, _ = Token.objects.get_or_create(user=user)
        
        logger.info(f"✅ LOGIN SUCCESS: {email}")
        logger.info("=" * 60)
        
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
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid request data'}, status=400)
    except Exception as e:
        logger.error(f"❌ Login error: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({'success': False, 'error': 'Login failed'}, status=500)


# =============================================================================
# API: GOOGLE OAUTH - EMAIL IS VERIFIED BY GOOGLE
# =============================================================================

@csrf_exempt
def api_google_login(request):
    """Google OAuth login - email is verified by Google"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        code = data.get('code')
        
        if not code:
            return JsonResponse({'success': False, 'error': 'Authorization code required'}, status=400)
        
        client_id = os.environ.get('GOOGLE_CLIENT_ID', '').strip()
        client_secret = os.environ.get('GOOGLE_CLIENT_SECRET', '').strip()
        
        if not client_id or not client_secret:
            return JsonResponse({'success': False, 'error': 'Google OAuth not configured'}, status=501)
        
        origin = request.META.get('HTTP_ORIGIN', '')
        if 'localhost' in origin or '127.0.0.1' in origin:
            redirect_uri = 'http://localhost:3000/google-callback'
        else:
            redirect_uri = 'https://dropvault-frontend-1.onrender.com/google-callback'
        
        resp = requests.post('https://oauth2.googleapis.com/token', data={
            'code': code,
            'client_id': client_id,
            'client_secret': client_secret,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code'
        }, timeout=15)
        
        if resp.status_code != 200:
            logger.error(f"Google token error: {resp.text}")
            return JsonResponse({'success': False, 'error': 'Google authentication failed'}, status=401)
        
        access_token = resp.json().get('access_token')
        if not access_token:
            return JsonResponse({'success': False, 'error': 'No access token received'}, status=401)
        
        user_resp = requests.get(
            'https://www.googleapis.com/oauth2/v2/userinfo',
            headers={'Authorization': f'Bearer {access_token}'},
            timeout=10
        )
        
        if user_resp.status_code != 200:
            return JsonResponse({'success': False, 'error': 'Failed to get user info'}, status=401)
        
        google_data = user_resp.json()
        email = google_data.get('email')
        name = google_data.get('name', '')
        google_verified = google_data.get('verified_email', True)
        
        if not email:
            return JsonResponse({'success': False, 'error': 'No email from Google'}, status=400)
        
        logger.info(f"🔐 Google login: {email}")
        
        # Find or create user
        try:
            user = User.objects.get(email=email)
            created = False
        except User.DoesNotExist:
            username = email.split('@')[0]
            counter = 1
            while User.objects.filter(username=username).exists():
                username = f"{email.split('@')[0]}{counter}"
                counter += 1
            
            parts = name.split() if name else [username]
            user = User.objects.create(
                username=username,
                email=email,
                first_name=parts[0] if parts else '',
                last_name=' '.join(parts[1:]) if len(parts) > 1 else '',
                is_active=True
            )
            user.set_unusable_password()
            user.save()
            created = True
        
        # Create/update profile - Google emails are verified by Google!
        profile, _ = UserProfile.objects.get_or_create(user=user)
        profile.email_verified = True  # Google verifies the email
        profile.signup_method = 'google'
        profile.clear_verification_token()  # Clear any pending tokens
        profile.save()
        
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        token, _ = Token.objects.get_or_create(user=user)
        
        logger.info(f"✅ Google login success: {email} (new_user={created})")
        
        return JsonResponse({
            'success': True,
            'token': token.key,
            'sessionid': request.session.session_key,
            'user': {
                'id': user.id,
                'email': user.email,
                'username': user.username,
                'name': f"{user.first_name} {user.last_name}".strip() or user.username,
                'has_password': user.has_usable_password(),
                'email_verified': True,
            }
        })
        
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
# API: DASHBOARD - WITH EMAIL VERIFICATION CHECK
# =============================================================================

@csrf_exempt
def api_dashboard(request):
    """Dashboard API with email verification check"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    # Check email verification
    try:
        profile = user.profile
        email_verified = profile.email_verified
    except UserProfile.DoesNotExist:
        email_verified = False
    
    if not email_verified:
        return JsonResponse({
            'success': False,
            'error': 'Please verify your email to access the dashboard',
            'requires_verification': True,
            'email': user.email
        }, status=403)
    
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
                'storage_used': total_storage,
                'storageTotal': 10737418240,
                'storage_total': 10737418240,
                'totalFiles': total_files,
                'total_files': total_files,
                'trashFiles': total_trash,
                'trash_files': total_trash,
                'sharedFiles': shared_count,
                'shared_count': shared_count,
                'sharedCount': shared_count,
                'recentFiles': recent_data,
                'recent_files': recent_data,
            },
            'user': {
                'id': user.id,
                'email': user.email,
                'name': f"{user.first_name} {user.last_name}".strip() or user.username,
                'email_verified': True,
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
    
    try:
        profile = user.profile
        email_verified = profile.email_verified
    except:
        email_verified = False
    
    return JsonResponse({
        'success': True,
        'data': {
            'id': user.id,
            'email': user.email,
            'name': f"{user.first_name} {user.last_name}".strip(),
            'has_password': user.has_usable_password(),
            'email_verified': email_verified,
        }
    })


@csrf_exempt
def api_check_auth(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if user:
        try:
            profile = user.profile
            email_verified = profile.email_verified
        except:
            email_verified = False
        
        return JsonResponse({
            'authenticated': True,
            'user': {
                'id': user.id,
                'email': user.email,
                'name': f"{user.first_name} {user.last_name}".strip() or user.username,
                'email_verified': email_verified,
            }
        })
    return JsonResponse({'authenticated': False})


@csrf_exempt
def api_user_storage(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        from files.models import File
        
        total_storage = File.objects.filter(
            user=user, 
            deleted=False
        ).aggregate(total=Sum('size'))['total'] or 0
        
        file_count = File.objects.filter(user=user, deleted=False).count()
        storage_limit = 10 * 1024 * 1024 * 1024
        
        return JsonResponse({
            'success': True,
            'storage': {
                'used': total_storage,
                'used_formatted': format_file_size(total_storage),
                'limit': storage_limit,
                'limit_formatted': format_file_size(storage_limit),
                'remaining': max(0, storage_limit - total_storage),
                'percentage': round((total_storage / storage_limit) * 100, 2),
                'file_count': file_count,
            }
        })
    except Exception as e:
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
        
        try:
            user = User.objects.get(email=email)
            
            reset_token = secrets.token_urlsafe(32)
            cache_key = f'password_reset:{reset_token}'
            cache.set(cache_key, {'user_id': user.id, 'email': email}, timeout=3600)
            
            frontend_url = os.environ.get('FRONTEND_URL', 'https://dropvault-frontend-1.onrender.com')
            reset_link = f"{frontend_url}/reset-password?token={reset_token}"
            
            # TODO: Send reset email
            logger.info(f"Password reset link for {email}: {reset_link}")
            
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

@csrf_exempt
def api_verify_email(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    return JsonResponse({'success': True})


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