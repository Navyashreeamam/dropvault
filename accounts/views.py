import re
import secrets
import json
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.core.cache import cache
from django.core.mail import send_mail, EmailMultiAlternatives
from django.conf import settings
from django.http import HttpResponse, JsonResponse
from django_otp import match_token
from django_otp.plugins.otp_totp.models import TOTPDevice
from .models import UserProfile, LoginAttempt
from .utils import verify_token
from django.template.loader import render_to_string
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from .models import UserProfile
from django.contrib.auth.password_validation import validate_password
from django.views.decorators.http import require_http_methods
from .utils import send_verification_email

@csrf_exempt
def test_email(request):
    """Test email configuration (prod: restrict to superusers)"""
    if not request.user.is_superuser:
        return HttpResponse("Access denied.", status=403)
    try:
        send_mail(
            'Test Email from DropVault',
            'This is a test email. If you receive this, email configuration is working!',
            settings.DEFAULT_FROM_EMAIL,
            ['navyashreeamam@gmail.com'],
            fail_silently=False,
        )
        return HttpResponse("Email sent successfully! Check your inbox (and spam folder).")
    except Exception as e:
        return HttpResponse(f"Email failed: {str(e)}", status=500)


@csrf_exempt
def signup(request):
    if request.method != 'POST':
        return HttpResponse("Use POST to /accounts/api/signup/", status=405)

    # 🔄 Parse request data
    if request.content_type == 'application/json':
        try:
            data = json.loads(request.body)
            email = data.get('email', '').strip().lower()
            password = data.get('password', '').strip()
            confirm = data.get('confirm_password', password).strip()  # ← match frontend
            name = data.get('name', '').strip()
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
    else:
        email = request.POST.get('email', '').strip().lower()
        password = request.POST.get('password', '').strip()
        confirm = request.POST.get('confirm_password', password).strip()
        name = request.POST.get('name', '').strip()

    # ✅ 1. Required
    if not email or not password:
        return JsonResponse({'error': 'Email and password are required.'}, status=400)

    # ✅ 2. Password match
    if confirm != password:
        return JsonResponse({'error': 'Passwords don’t match.'}, status=400)

    # ✅ 3. Validate email format
    try:
        validate_email(email)
    except ValidationError:
        return JsonResponse({'error': 'Invalid email format.'}, status=400)

    # ✅ 4. Rate limit
    ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
    attempts = cache.get(f"signup_{ip}", 0)
    if attempts >= 3:
        return JsonResponse({
            'error': 'Too many attempts. Try again in 1 hour.'
        }, status=429)

    # 🔑 KEY CHANGE: Check if user exists
    try:
        user = User.objects.get(email__iexact=email)
        
        # ✅ Existing user → attempt login (like "sign up or log in")
        auth_user = authenticate(request, username=user.username, password=password)
        if auth_user:
            login(request, auth_user)
            profile = getattr(auth_user, 'userprofile', None)
            email_verified = profile.email_verified if profile else False
            
            return JsonResponse({
                'status': 'existing_user',
                'message': 'Logged in successfully.',
                'user_id': auth_user.id,
                'email': auth_user.email,
                'name': auth_user.first_name,
                'email_verified': email_verified,
                'sessionid': request.session.session_key
            }, status=200)
        else:
            return JsonResponse({'error': 'Invalid password.'}, status=401)

    except User.DoesNotExist:
        # ✅ New user — create + send verification
        try:
            validate_password(password)
        except ValidationError as e:
            return JsonResponse({'error': ' '.join(e.messages)}, status=400)

        # Create unique username
        base = email.split('@')[0]
        username = base
        n = 1
        while User.objects.filter(username=username).exists():
            username = f"{base}_{n}"
            n += 1

        # Create user
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            first_name=name,
            is_active=True
        )

        # Ensure profile exists
        profile, _ = UserProfile.objects.get_or_create(user=user)

        # Send verification
        email_sent = send_verification_email(user)

        return JsonResponse({
            'status': 'new_user',
            'message': 'Account created. Please verify your email.',
            'user_id': user.id,
            'email': user.email,
            'name': user.first_name,
            'email_verified': False,
            'verification_email_sent': email_sent
        }, status=201)


def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')

        if not email or not password:
            messages.error(request, "Email and password are required.")
            return render(request, 'login.html')

        try:
            user = User.objects.get(email__iexact=email)
            auth_user = authenticate(request, username=user.username, password=password)

            if auth_user:
                login(request, auth_user)
                
                # ✅ Redirect based on verification status
                if getattr(auth_user, 'userprofile', None) and auth_user.userprofile.email_verified:
                    return redirect('dashboard')
                else:
                    messages.warning(request, "Please verify your email to access all features.")
                    return redirect('verify_email_prompt')
            else:
                messages.error(request, "Invalid email or password.")
        except User.DoesNotExist:
            messages.error(request, "Invalid email or password.")

    return render(request, 'login.html')

# Change function signature to accept `token`
def verify_email(request, token):  # ← ADD `token` param
    # token = request.GET.get('token')  # ❌ remove this
    # keep rest same
    if not token:
        messages.error(request, "❌ No token provided.")
        return redirect('home')

    try:
        profile = UserProfile.objects.get(verification_token=token)
        user = profile.user
        profile.email_verified = True
        profile.verification_token = ''
        profile.save(update_fields=['email_verified', 'verification_token'])
        
        if not request.user.is_authenticated:
            login(request, user)
        messages.success(request, "✅ Email verified!")
        return redirect('dashboard')
        
    except UserProfile.DoesNotExist:
        messages.error(request, "❌ Invalid or expired verification link.")
        return redirect('home')

@csrf_exempt
@login_required
def setup_mfa(request):  # Merged enable_mfa logic here for DRY
    device, created = TOTPDevice.objects.get_or_create(
        user=request.user,
        confirmed=False,
        defaults={'name': 'Authenticator'}
    )
    if request.method == "POST":
        token = request.POST.get('token')
        if device.verify_token(token):
            device.confirmed = True
            device.save()
            messages.success(request, "MFA enabled!")
            return redirect('dashboard')
        else:
            messages.error(request, "Invalid code.")
    return render(request, 'setup_mfa.html', {'device': device})

@csrf_exempt
def otp_verify(request):
    if not request.user.is_authenticated:
        return redirect('login')
    if request.method == 'POST':
        token = request.POST.get('otp')
        if match_token(request.user, token):
            messages.success(request, "OTP verified successfully!")
            return redirect('dashboard')
        else:
            messages.error(request, "Invalid OTP code.")
    return render(request, 'otp_verify.html')

@login_required
def disable_mfa(request):
    if request.method == 'POST':
        # Security: Require a simple confirmation token (e.g., user's last 4 email digits)
        confirm_token = request.POST.get('confirm_token')
        if confirm_token != request.user.email[-4:]:
            messages.error(request, "Invalid confirmation. MFA not disabled.")
            return render(request, 'disable_mfa.html')
        TOTPDevice.objects.filter(user=request.user, confirmed=True).delete()
        messages.success(request, "MFA has been disabled.")
        return redirect('dashboard')
    return render(request, 'disable_mfa.html')


@login_required
def logout_view(request):
    # ✅ 1. Only POST for logout (prevent CSRF via GET)
    if request.method == 'POST':
        logout(request)
        messages.success(request, "You have been logged out successfully.")
        return redirect('home')
    
    # GET: show confirmation page (optional but safer)
    return render(request, 'logout_confirm.html')

@login_required
def dashboard(request):
    return render(request, 'dashboard.html')


@login_required
@csrf_exempt
def upload_test(request):
    return render(request, 'upload_test.html')

@login_required
def verify_email_prompt(request):
    profile = getattr(request.user, 'userprofile', None)
    if profile and profile.email_verified:
        return redirect('dashboard')

    user_email = getattr(request.user, 'email', '').strip()
    if not user_email:
        messages.error(request, "❌ No email associated with your account. Contact support.")
        return render(request, 'verify_prompt.html')

    if request.method == 'POST':
        success = send_verification_email(request.user)
        if success:
            messages.success(request, f"✅ Verification email sent to {user_email}. Check spam folder.")
        else:
            messages.error(request, f"❌ Failed to send email to {user_email}. Is the email correct?")
        return redirect('verify_email_prompt')

    return render(request, 'verify_prompt.html')

@csrf_exempt
def api_verify_email(request):
    token = request.GET.get('token')
    user = verify_token(token)
    if user:
        user.userprofile.email_verified = True
        user.userprofile.save()
        return JsonResponse({'success': True, 'message': 'Email verified'})
    return JsonResponse({'error': 'Invalid token'}, status=400)

@csrf_exempt
def api_login(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    try:
        data = json.loads(request.body)
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return JsonResponse({'error': 'Email and password required'}, status=400)

        # ✅ Case-insensitive email lookup
        try:
            user = User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            return JsonResponse({'error': 'Invalid credentials'}, status=401)

        # Authenticate with username
        auth_user = authenticate(request, username=user.username, password=password)
        if not auth_user:
            return JsonResponse({'error': 'Invalid credentials'}, status=401)

        # ✅ Login + get session ID
        login(request, auth_user)

        # ✅ Extract sessionid cookie value for frontend
        session_key = request.session.session_key

        return JsonResponse({
            'status': 'ok',
            'user_id': auth_user.id,
            'email': auth_user.email,
            'name': auth_user.first_name,
            'sessionid': session_key,  # ← frontend stores this in localStorage/cookie
        }, status=200)

    except Exception as e:
        return JsonResponse({'error': 'Login failed.'}, status=500)

# accounts/views.py
def home(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'home.html')