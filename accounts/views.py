import re
import secrets
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.core.cache import cache
from django.core.mail import send_mail, EmailMultiAlternatives
from django.conf import settings
from django.http import HttpResponse
from .models import UserProfile, LoginAttempt
from .utils import verify_token
from django.template.loader import render_to_string

def test_email(request):
    """Test email configuration"""
    try:
        send_mail(
            'Test Email from DropVault',
            'This is a test email. If you receive this, email configuration is working!',
            settings.DEFAULT_FROM_EMAIL,
            ['navyashreeamam@gmail.com'],  # Your email
            fail_silently=False,
        )
        return HttpResponse("Email sent successfully! Check your inbox (and spam folder).")
    except Exception as e:
        return HttpResponse(f"Email failed: {str(e)}")


def send_verification_email(user):
    try:
        token = secrets.token_urlsafe(32)
        user.userprofile.verification_token = token
        user.userprofile.save()
        
        link = f"http://127.0.0.1:8000/accounts/verify-email/?token={token}"
        
        # Render email content from templates
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

def signup(request):
    if request.method == 'POST':
        email = request.POST['email'].strip()
        password = request.POST['password']
        confirm = request.POST['confirm_password']

        # Password validation
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

        # Create user
        user = User.objects.create_user(username=email, email=email, password=password)
        profile = UserProfile.objects.create(user=user)
        cache.set(f"signup_{ip}", cache.get(f"signup_{ip}", 0) + 1, 3600)
        
        # Try to send verification email
        email_sent = send_verification_email(user)
        
        if email_sent:
            messages.success(request, 
                "Account created successfully! Please check your email (including spam folder) to verify your account.")
        else:
            # For development/testing - auto-verify if email fails
            profile.email_verified = True
            profile.save()
            messages.warning(request, 
                "Account created but verification email couldn't be sent. You can login now.")
        
        return redirect('login')
    
    return render(request, 'signup.html')

def verify_email(request):
    token = request.GET.get('token')
    user = verify_token(token)
    if user:
        user.userprofile.email_verified = True
        user.userprofile.save()
        login(request, user)
        messages.success(request, "Email verified successfully! Welcome to DropVault.")
        return redirect('dashboard')
    else:
        messages.error(request, "Invalid or expired verification link.")
        return redirect('login')

def login_view(request):
    if request.method == 'POST':
        email = request.POST['email'].strip()
        password = request.POST['password']
        ip = request.META.get('REMOTE_ADDR', '127.0.0.1')

        def log_attempt(success):
            try:
                LoginAttempt.objects.create(email=email, ip_address=ip, success=success)
            except Exception as e:
                print(f"Failed to log attempt: {e}")

        if cache.get(f"login_fail_{email}", 0) >= 5:
            log_attempt(False)
            messages.error(request, "Too many failed attempts. Please try again later.")
            return render(request, 'login.html')

        try:
            user = User.objects.get(email=email)
            if not user.userprofile.email_verified:
                messages.error(request, "Please verify your email first. Check your inbox.")
                return render(request, 'login.html')
            
            auth_user = authenticate(request, username=user.username, password=password)
            if auth_user:
                cache.delete(f"login_fail_{email}")
                login(request, auth_user)
                log_attempt(True)
                messages.success(request, f"Welcome back, {email}!")
                return redirect('dashboard')
            else:
                raise User.DoesNotExist
                
        except User.DoesNotExist:
            cache.set(f"login_fail_{email}", cache.get(f"login_fail_{email}", 0) + 1, 900)
            log_attempt(False)
            messages.error(request, "Invalid email or password.")
            return render(request, 'login.html')
    
    return render(request, 'login.html')

def logout_view(request):
    logout(request)
    messages.success(request, "You have been logged out successfully.")
    return redirect('home')

def dashboard(request):
    if not request.user.is_authenticated:
        return redirect('login')
    return render(request, 'dashboard.html', {'email': request.user.email})

def home(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'home.html')

def upload_test(request):
    if not request.user.is_authenticated:
        return redirect('login')
    return render(request, 'upload_test.html')