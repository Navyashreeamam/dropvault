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
def send_verification_email(user):
    try:
        token = secrets.token_urlsafe(32)
        # ✅ Safe: get or create profile
        profile, _ = UserProfile.objects.get_or_create(user=user)
        profile.verification_token = token
        profile.save(update_fields=['verification_token'])  # ⚡ explicit save

        link = f"http://127.0.0.1:8000/accounts/verify-email/?token={token}"

        text_content = render_to_string('verification_email.txt', {'link': link})
        html_content = render_to_string('verification_email.html', {'link': link})

        email = EmailMultiAlternatives(
            subject="Verify your DropVault email",
            body=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user.email]
        )
        email.attach_alternative(html_content, "text/html")
        email.send(fail_silently=False)

        print(f"✅ Verification email sent successfully to {user.email}")
        return True

    except Exception as e:
        print(f"❌ Failed to send verification email to {user.email}: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


def verify_email(request):
    token = request.GET.get('token')
    if not token:
        messages.error(request, "❌ No token provided.")
        return redirect('home')

    try:
        # ✅ Safe lookup
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
def signup(request):
    if request.method != 'POST':
        return HttpResponse("Use POST to /accounts/api/signup/", status=405)

    # 🔄 Parse request data (JSON or form-data)
    if request.content_type == 'application/json':
        try:
            data = json.loads(request.body)
            email = data.get('email', '').strip()
            password = data.get('password', '').strip()
            confirm = data.get('password2', password).strip()  # optional confirm
            name = data.get('name', '').strip()
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
    else:
        # Form-data (multipart/form-data or application/x-www-form-urlencoded)
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '').strip()
        confirm = request.POST.get('password2', password).strip()
        name = request.POST.get('name', '').strip()

    # ✅ 1. Required fields
    if not email:
        return JsonResponse({'error': 'Email is required.'}, status=400)
    if not password:
        return JsonResponse({'error': 'Password is required.'}, status=400)

    # ✅ 2. Password match (only if confirm was explicitly sent and differs)
    if confirm != password:
        return JsonResponse({'error': 'Passwords don’t match.'}, status=400)

    # ✅ 3. Email format
    try:
        validate_email(email)
    except ValidationError:
        return JsonResponse({'error': 'Invalid email format.'}, status=400)

    # ✅ 4. Rate limiting (3 attempts/hour/IP)
    ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
    attempts = cache.get(f"signup_{ip}", 0)
    if attempts >= 3:
        return JsonResponse({
            'error': 'Too many signup attempts. Try again in 1 hour.'
        }, status=429)

    # ✅ 5. Duplicate email
    if User.objects.filter(email__iexact=email).exists():
        return JsonResponse({
            'error': 'An account with this email already exists.'
        }, status=400)

    # ✅ 6. Password strength — use Django’s built-in validators (recommended)
    try:
        # Create dummy user for validation (no DB save yet)
        temp_user = User(email=email, username=email)
        validate_password(password, user=temp_user)
    except ValidationError as e:
        return JsonResponse({
            'error': ' '.join(e.messages)  # e.g., "This password is too short. It must contain at least 8 characters."
        }, status=400)

    # ✅ 7. Create user
    try:
        user = User.objects.create_user(
            username=email,  # or use uuid/email prefix if username clashes
            email=email,
            password=password,
            first_name=name,
            is_active=True
        )
        UserProfile.objects.get_or_create(user=user)
    except Exception as e:
        return JsonResponse({
            'error': 'Account creation failed. Please try again.'
        }, status=500)

    # ✅ 8. Update rate limit
    cache.set(f"signup_{ip}", attempts + 1, timeout=3600)

    # ✅ Success
    return JsonResponse({
        'message': 'Account created successfully!',
        'user_id': user.id,
        'email': user.email,
        'name': user.first_name
    }, status=201)

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


def login_view(request):
    # 🔐 Prevent already-logged-in users from accessing login page
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')

        # ✅ 1. Validate input
        if not email or not password:
            messages.error(request, "Email and password are required.")
            return render(request, 'login.html')

        try:
            # ✅ 2. Case-insensitive email lookup (critical!)
            user = User.objects.get(email__iexact=email)
            
            # ✅ 3. Authenticate (always use username for Django's backend)
            user = authenticate(request, username=user.username, password=password)
            
            if user is not None:
                # ✅ 4. Check active status (security)
                if user.is_active:
                    login(request, user)
                    return redirect('dashboard')
                else:
                    messages.error(request, "Account is inactive. Please verify your email.")
            else:
                # ❌ Auth failed (wrong password)
                messages.error(request, "Invalid email or password.")
                
        except User.DoesNotExist:
            # ❌ Email not found
            messages.error(request, "Invalid email or password.")

    return render(request, 'login.html')


@login_required
def logout_view(request):
    # ✅ 1. Only POST for logout (prevent CSRF via GET)
    if request.method == 'POST':
        logout(request)
        messages.success(request, "You have been logged out successfully.")
        return redirect('home')
    
    # GET: show confirmation page (optional but safer)
    return render(request, 'logout_confirm.html')

@csrf_exempt
@require_http_methods(["POST"])
def login_api(request):
    try:
        data = json.loads(request.body)
        email = data.get('email')
        password = data.get('password')

        user = authenticate(request, username=email, password=password)
        if user is not None:
            login(request, user)  # ✅ THIS sets the session & sends Set-Cookie
            return JsonResponse({
                "status": "ok",
                "email": user.email,
                "user_id": user.id
            })
        else:
            return JsonResponse({"error": "Invalid credentials"}, status=401)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)
    

@login_required
def dashboard(request):
    return render(request, 'dashboard.html')

def verify_email(request):
    """Handle email verification link click (web flow)"""
    token = request.GET.get('token')
    user = verify_token(token)
    
    if user:
        # Mark email as verified
        user.userprofile.email_verified = True
        user.userprofile.save()
        
        # Auto-login the user (optional but UX-friendly)
        if not request.user.is_authenticated:
            user.backend = 'django.contrib.auth.backends.ModelBackend'
            login(request, user)
        
        messages.success(request, "✅ Email verified successfully! Welcome to DropVault.")
        return redirect('dashboard')
    else:
        messages.error(request, "❌ Invalid or expired verification link.")
        return redirect('home')

@login_required
@csrf_exempt
def upload_test(request):
    return render(request, 'upload_test.html')

@login_required
def verify_email_prompt(request):
    if request.user.userprofile.email_verified:
        return redirect('dashboard')
    if request.method == 'POST':
        send_verification_email(request.user)
        messages.success(request, "Verification email sent!")
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
def api_signup(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    if request.content_type != 'application/json':
        return JsonResponse({'error': 'Content-Type must be application/json'}, status=400)

    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()
        name = data.get('name', '').strip()

        password = data.get('password', '').strip()
        confirm = data.get('password2', password).strip()
        if not password:
            password = data.get('password1', '').strip()
            confirm = data.get('password2', '').strip()
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    # ✅ 1. Required fields
    if not email:
        return JsonResponse({'error': 'Email is required.'}, status=400)
    if not password:
        return JsonResponse({'error': 'Password is required.'}, status=400)

    # ✅ 2. Password match
    if confirm != password:
        return JsonResponse({'error': 'Passwords don’t match.'}, status=400)

    # ✅ 3. Email format
    try:
        validate_email(email)
    except ValidationError:
        return JsonResponse({'error': 'Invalid email format.'}, status=400)

    # ✅ 4. Rate limit
    ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
    attempts = cache.get(f"signup_{ip}", 0)
    if attempts >= 3:
        return JsonResponse({
            'error': 'Too many signup attempts. Try again in 1 hour.'
        }, status=429)

    # ✅ 5. Duplicate email — ONLY ONCE (critical fix)
    if User.objects.filter(email__iexact=email).exists():
        return JsonResponse({
            'error': 'An account with this email already exists.'
        }, status=400)

    # ✅ 6. Password strength
    try:
        temp_user = User(email=email)
        validate_password(password, user=temp_user)
    except ValidationError as e:
        return JsonResponse({'error': ' '.join(e.messages)}, status=400)

    # ✅ 7. Create user
    try:
        base_username = email.split('@')[0].lower()
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

        # Safe profile creation
        UserProfile.objects.get_or_create(
            user=user,
            defaults={'email_verified': False}
        )
    except Exception as e:
        import traceback
        print("🚨 SIGNUP ERROR:", str(e))
        traceback.print_exc()
        return JsonResponse({'error': 'Account creation failed.'}, status=500)

    cache.set(f"signup_{ip}", attempts + 1, 3600)

    # Send verification
    email_sent = send_verification_email(user)

    return JsonResponse({
        'message': 'Account created successfully!',
        'user_id': user.id,
        'email': user.email,
        'name': user.first_name,
        'email_verified': False,
        'verification_email_sent': email_sent
    }, status=201)

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

        # Get user (email must be unique)
        user = User.objects.get(email=email)

        # Authenticate
        auth_user = authenticate(request, username=user.username, password=password)
        if not auth_user:
            return JsonResponse({'error': 'Invalid credentials'}, status=401)

        # 🔑 CRITICAL: Create session & set sessionid cookie
        login(request, auth_user)  # ← THIS sets the sessionid cookie

        return JsonResponse({
            'status': 'ok',
            'email': auth_user.email,
            'user_id': auth_user.id
        }, status=200)

    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
    
# accounts/views.py
def home(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'home.html')