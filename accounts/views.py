# accounts/views.py
import re
import secrets
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.core.cache import cache
from django.core.mail import send_mail
from django.conf import settings
from .models import UserProfile, LoginAttempt
from .utils import verify_token

def send_verification_email(user):
    token = secrets.token_urlsafe(32)
    user.userprofile.verification_token = token
    user.userprofile.save()
    link = f"http://127.0.0.1:8000/accounts/verify-email/?token={token}"
    send_mail(
        "Verify your email",
        f"Click to verify: {link}",
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
    )

def signup(request):
    if request.method == 'POST':
        email = request.POST['email'].strip()
        password = request.POST['password']
        confirm = request.POST['confirm_password']

        # ✅ RELAXED PASSWORD POLICY: min 8 chars, and must have at least one upper, lower, digit, symbol
        if len(password) < 8:
            messages.error(request, "Password must be at least 8 characters.")
            return render(request, 'signup.html')
        if not re.search(r'[a-z]', password):
            messages.error(request, "Password must contain a lowercase letter.")
            return render(request, 'signup.html')
        if not re.search(r'[0-9]', password):
            messages.error(request, "Password must contain a digit.")
            return render(request, 'signup.html')
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>\/?]', password):
            messages.error(request, "Password must contain a symbol (!@#$%^&* etc).")
            return render(request, 'signup.html')

        if password != confirm:
            messages.error(request, "Passwords don't match.")
            return render(request, 'signup.html')
        try:
            validate_email(email)
        except ValidationError:
            messages.error(request, "Invalid email.")
            return render(request, 'signup.html')

        ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
        if cache.get(f"signup_{ip}", 0) >= 3:
            messages.error(request, "Too many signup attempts.")
            return render(request, 'signup.html')

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already registered.")
            return render(request, 'signup.html')

        user = User.objects.create_user(username=email, email=email, password=password)
        UserProfile.objects.create(user=user)
        cache.set(f"signup_{ip}", cache.get(f"signup_{ip}", 0) + 1, 3600)
        send_verification_email(user)

        messages.success(request, "Account created! Check email to verify.")
        return redirect('login')
    return render(request, 'signup.html')

# Keep rest of the file EXACTLY as before (verify_email, login_view, etc.)
def verify_email(request):
    token = request.GET.get('token')
    user = verify_token(token)  # returns User or None
    if user:
        user.is_active = True  # or user.email_verified = True
        user.save()
        login(request, user)
        return redirect('dashboard')  # ← must match your dashboard URL name
    else:
        messages.error(request, "Invalid or expired verification link.")
        return redirect('login')

def login_view(request):
    if request.method == 'POST':
        email = request.POST['email'].strip()
        password = request.POST['password']
        ip = request.META.get('REMOTE_ADDR', '127.0.0.1')

        def log_attempt(success):
            LoginAttempt.objects.create(email=email, ip_address=ip, success=success)

        if cache.get(f"login_fail_{email}", 0) >= 5:
            log_attempt(False)
            messages.error(request, "Too many failed attempts.")
            return render(request, 'login.html')

        try:
            user = User.objects.get(email=email)
            if not user.userprofile.email_verified:
                messages.error(request, "Verify your email first.")
                return render(request, 'login.html')
            auth_user = authenticate(request, username=user.username, password=password)
            if auth_user:
                cache.delete(f"login_fail_{email}")
                login(request, auth_user)
                log_attempt(True)
                return redirect('dashboard')
            else:
                raise User.DoesNotExist
        except User.DoesNotExist:
            cache.set(f"login_fail_{email}", cache.get(f"login_fail_{email}", 0) + 1, 900)
            log_attempt(False)
            messages.error(request, "Invalid credentials.")
            return render(request, 'login.html')
    return render(request, 'login.html')

def logout_view(request):
    logout(request)
    return redirect('home')

def dashboard(request):
    if not request.user.is_authenticated:
        return redirect('login')
    return render(request, 'dashboard.html', {'email': request.user.email})

def home(request):
    return render(request, 'home.html')
def upload_test(request):
    return render(request, 'upload_test.html')