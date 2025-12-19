# accounts/views.py

import re
import secrets
import json
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.core.cache import cache
from django.core.mail import send_mail, EmailMultiAlternatives
from django.conf import settings
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.template.loader import render_to_string
from django_otp import match_token
from django_otp.plugins.otp_totp.models import TOTPDevice

from .models import UserProfile, LoginAttempt
from .utils import verify_token, send_verification_email


# Get the User model
User = get_user_model()


# ═══════════════════════════════════════════════════════════
# 🏠 HOME VIEW
# ═══════════════════════════════════════════════════════════
def home(request):
    """Home page - redirect to dashboard if authenticated"""
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'home.html')


# ═══════════════════════════════════════════════════════════
# 📝 WEB SIGNUP VIEW (HTML Form)
# ═══════════════════════════════════════════════════════════
def signup_view(request):
    """Web-based signup - renders HTML form and handles form submission"""
    
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'GET':
        return render(request, 'signup.html')
    
    # POST request
    email = request.POST.get('email', '').strip().lower()
    password = request.POST.get('password', '').strip()
    confirm_password = request.POST.get('confirm_password', '').strip()
    name = request.POST.get('name', '').strip()
    
    form_data = {'email': email, 'name': name}
    
    # Validation
    if not email:
        messages.error(request, "Email is required.")
        return render(request, 'signup.html', form_data)
    
    if not password:
        messages.error(request, "Password is required.")
        return render(request, 'signup.html', form_data)
    
    if password != confirm_password:
        messages.error(request, "Passwords don't match.")
        return render(request, 'signup.html', form_data)
    
    # Validate email format
    try:
        validate_email(email)
    except ValidationError:
        messages.error(request, "Invalid email format.")
        return render(request, 'signup.html', form_data)
    
    # Check if user exists
    if User.objects.filter(email__iexact=email).exists():
        messages.error(request, "An account with this email already exists. Please sign in.")
        return render(request, 'signup.html', form_data)
    
    # Validate password strength
    try:
        validate_password(password)
    except ValidationError as e:
        for error in e.messages:
            messages.error(request, error)
        return render(request, 'signup.html', form_data)
    
    # Create user
    try:
        # Generate unique username
        base_username = email.split('@')[0]
        username = base_username
        counter = 1
        while User.objects.filter(username=username).exists():
            username = f"{base_username}_{counter}"
            counter += 1
        
        # Create user
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            first_name=name,
            is_active=True
        )
        
        # Create profile
        profile, created = UserProfile.objects.get_or_create(user=user)
        
        # Send verification email
        try:
            send_verification_email(user)
            messages.info(request, "Verification email sent! Please check your inbox.")
        except Exception as e:
            print(f"⚠️ Email send error: {e}")
        
        # Log user in
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        
        messages.success(request, "Account created successfully!")
        return redirect('dashboard')
        
    except Exception as e:
        messages.error(request, f"Error creating account: {str(e)}")
        return render(request, 'signup.html', form_data)


# ═══════════════════════════════════════════════════════════
# 🔐 WEB LOGIN VIEW (HTML Form)
# ═══════════════════════════════════════════════════════════
def login_view(request):
    """Web-based login - renders HTML form and handles authentication"""
    
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'GET':
        return render(request, 'login.html')
    
    # POST request
    email = request.POST.get('email', '').strip().lower()
    password = request.POST.get('password', '').strip()
    
    # Validate inputs
    if not email or not password:
        messages.error(request, "Email and password are required.")
        return render(request, 'login.html', {'email': email})
    
    # Find user by email
    try:
        user = User.objects.get(email__iexact=email)
    except User.DoesNotExist:
        messages.error(request, "No account found with this email. Please sign up.")
        return render(request, 'login.html', {'email': email})
    
    # Authenticate
    auth_user = authenticate(request, username=user.username, password=password)
    if auth_user is not None:
        # Login
        login(request, auth_user)
        
        # Check email verification (for web, redirect to verify page)
        profile = getattr(auth_user, 'userprofile', None)
        if profile and not profile.email_verified:
            try:
                send_verification_email(auth_user)
            except Exception:
                pass
            return redirect('verify_email_prompt')
        
        messages.success(request, f"Welcome back, {auth_user.first_name or auth_user.email}!")
        return redirect('dashboard')
    else:
        messages.error(request, "Invalid password. Please try again.")
        return render(request, 'login.html', {'email': email})


# ═══════════════════════════════════════════════════════════
# 🚪 LOGOUT VIEW
# ═══════════════════════════════════════════════════════════
@login_required
def logout_view(request):
    """Logout user"""
    if request.method == 'POST':
        logout(request)
        messages.success(request, "You have been logged out successfully.")
        return redirect('home')
    return render(request, 'logout_confirm.html')


# ═══════════════════════════════════════════════════════════
# 📊 DASHBOARD VIEW
# ═══════════════════════════════════════════════════════════
@login_required
def dashboard(request):
    """Main dashboard - requires authentication"""
    return render(request, 'dashboard.html')


# ═══════════════════════════════════════════════════════════
# 📧 EMAIL VERIFICATION VIEWS
# ═══════════════════════════════════════════════════════════
def verify_email(request, token):
    """Verify email using token from email link"""
    if not token:
        messages.error(request, "No verification token provided.")
        return redirect('home')
    
    try:
        profile = UserProfile.objects.get(verification_token=token)
        user = profile.user
        
        profile.email_verified = True
        profile.verification_token = ''
        profile.save(update_fields=['email_verified', 'verification_token'])
        
        if not request.user.is_authenticated:
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        
        messages.success(request, "Email verified successfully!")
        return redirect('dashboard')
        
    except UserProfile.DoesNotExist:
        messages.error(request, "Invalid or expired verification link.")
        return redirect('home')


@login_required
def verify_email_prompt(request):
    """Show page prompting user to verify email"""
    profile = getattr(request.user, 'userprofile', None)
    
    if profile and profile.email_verified:
        return redirect('dashboard')
    
    user_email = getattr(request.user, 'email', '').strip()
    if not user_email:
        messages.error(request, "No email associated with your account.")
        return render(request, 'verify_prompt.html')
    
    # Check if email service is configured
    import os
    email_configured = bool(os.environ.get('RESEND_API_KEY', '').strip())
    
    if request.method == 'POST':
        if not email_configured:
            messages.error(request, "Email service is not configured. Please contact support.")
            return redirect('verify_email_prompt')
        
        try:
            # Send synchronously to get real status
            success = send_verification_email(request.user, async_send=False)
            if success:
                messages.success(request, f"Verification email sent to {user_email}. Check your inbox and spam folder.")
            else:
                messages.error(request, "Failed to send verification email. Please try again later.")
        except Exception as e:
            messages.error(request, f"Error sending email: {str(e)}")
        return redirect('verify_email_prompt')
    
    context = {
        'email_configured': email_configured,
    }
    return render(request, 'verify_prompt.html', context)

# ═══════════════════════════════════════════════════════════
# 🔒 MFA VIEWS
# ═══════════════════════════════════════════════════════════
@login_required
def setup_mfa(request):
    """Setup TOTP-based MFA"""
    device, created = TOTPDevice.objects.get_or_create(
        user=request.user,
        confirmed=False,
        defaults={'name': 'Authenticator'}
    )
    
    if request.method == 'POST':
        token = request.POST.get('token', '').strip()
        
        if device.verify_token(token):
            device.confirmed = True
            device.save()
            messages.success(request, "MFA enabled successfully!")
            return redirect('dashboard')
        else:
            messages.error(request, "Invalid code. Please try again.")
    
    return render(request, 'setup_mfa.html', {'device': device})


@login_required
def otp_verify(request):
    """Verify OTP code"""
    if request.method == 'POST':
        token = request.POST.get('otp', '').strip()
        
        if match_token(request.user, token):
            messages.success(request, "OTP verified successfully!")
            return redirect('dashboard')
        else:
            messages.error(request, "Invalid OTP code.")
    
    return render(request, 'otp_verify.html')


@login_required
def disable_mfa(request):
    """Disable MFA for user"""
    if request.method == 'POST':
        confirm_token = request.POST.get('confirm_token', '').strip()
        expected = request.user.email[-4:] if request.user.email else ''
        
        if confirm_token != expected:
            messages.error(request, "Invalid confirmation. MFA not disabled.")
            return render(request, 'disable_mfa.html')
        
        TOTPDevice.objects.filter(user=request.user, confirmed=True).delete()
        messages.success(request, "MFA has been disabled.")
        return redirect('dashboard')
    
    return render(request, 'disable_mfa.html')


# ═══════════════════════════════════════════════════════════
# 🔌 API VIEWS (JSON Responses - NEVER redirect)
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def api_signup(request):
    """
    API endpoint for signup - returns JSON ONLY (never redirects)
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed. Use POST.'}, status=405)
    
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()
        password = data.get('password', '').strip()
        confirm_password = data.get('confirm_password', password).strip()
        name = data.get('name', '').strip()
        
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    
    # Validation
    if not email or not password:
        return JsonResponse({'error': 'Email and password are required.'}, status=400)
    
    if password != confirm_password:
        return JsonResponse({'error': 'Passwords do not match.'}, status=400)
    
    try:
        validate_email(email)
    except ValidationError:
        return JsonResponse({'error': 'Invalid email format.'}, status=400)
    
    if User.objects.filter(email__iexact=email).exists():
        return JsonResponse({
            'error': 'An account with this email already exists.',
            'action': 'login'
        }, status=400)
    
    try:
        validate_password(password)
    except ValidationError as e:
        return JsonResponse({'error': ' '.join(e.messages)}, status=400)
    
    # Create user
    try:
        base_username = email.split('@')[0]
        username = base_username
        counter = 1
        while User.objects.filter(username=username).exists():
            username = f"{base_username}_{counter}"
            counter += 1
        
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            first_name=name,
            is_active=True
        )
        
        profile, _ = UserProfile.objects.get_or_create(user=user)
        
        email_sent = False
        try:
            email_sent = send_verification_email(user)
        except Exception:
            pass
        
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        
        # ✅ Return JSON only - never redirect
        return JsonResponse({
            'status': 'success',
            'message': 'Account created successfully.',
            'user': {
                'id': user.id,
                'email': user.email,
                'name': user.first_name,
                'email_verified': False
            },
            'verification_email_sent': email_sent,
            'sessionid': request.session.session_key
        }, status=201)
        
    except Exception as e:
        return JsonResponse({'error': f'Error creating account: {str(e)}'}, status=500)


@csrf_exempt
def api_login(request):
    """
    API endpoint for login - returns JSON ONLY (never redirects)
    Works even if email is not verified
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed. Use POST.'}, status=405)
    
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()
        password = data.get('password', '').strip()
        
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    
    if not email or not password:
        return JsonResponse({'error': 'Email and password are required.'}, status=400)
    
    # Find user by email
    try:
        user = User.objects.get(email__iexact=email)
    except User.DoesNotExist:
        return JsonResponse({
            'error': 'No account found with this email.',
            'action': 'signup'
        }, status=401)
    
    # Authenticate using username (Django requires username)
    auth_user = authenticate(request, username=user.username, password=password)
    if auth_user is None:
        return JsonResponse({'error': 'Invalid password.'}, status=401)
    
    # Login user
    login(request, auth_user)
    
    # Get profile info
    profile = getattr(auth_user, 'userprofile', None)
    email_verified = profile.email_verified if profile else False
    
    # ✅ ALWAYS return JSON - never redirect (even if email not verified)
    return JsonResponse({
        'status': 'success',
        'message': 'Logged in successfully.',
        'user': {
            'id': auth_user.id,
            'email': auth_user.email,
            'name': auth_user.first_name,
            'email_verified': email_verified
        },
        'email_verified': email_verified,
        'sessionid': request.session.session_key
    }, status=200)


@csrf_exempt
def api_verify_email(request):
    """API endpoint for email verification"""
    if request.method == 'GET':
        token = request.GET.get('token')
    else:
        try:
            data = json.loads(request.body)
            token = data.get('token')
        except:
            token = request.POST.get('token')
    
    if not token:
        return JsonResponse({'error': 'Token is required.'}, status=400)
    
    try:
        profile = UserProfile.objects.get(verification_token=token)
        profile.email_verified = True
        profile.verification_token = ''
        profile.save()
        
        return JsonResponse({
            'status': 'success',
            'message': 'Email verified successfully.'
        })
        
    except UserProfile.DoesNotExist:
        return JsonResponse({'error': 'Invalid or expired token.'}, status=400)


# ═══════════════════════════════════════════════════════════
# 🛠️ UTILITY VIEWS
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def test_email(request):
    """Test email configuration - superuser only"""
    if not request.user.is_authenticated or not request.user.is_superuser:
        return HttpResponse("Access denied.", status=403)
    
    try:
        send_mail(
            subject='Test Email from DropVault',
            message='This is a test email.',
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[request.user.email],
            fail_silently=False,
        )
        return HttpResponse("Email sent successfully!")
    except Exception as e:
        return HttpResponse(f"Email failed: {str(e)}", status=500)


@login_required
def upload_test(request):
    """Upload test page"""
    return render(request, 'upload_test.html')