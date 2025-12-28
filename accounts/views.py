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

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status
from rest_framework import status
from django.contrib.auth import logout
from django.db import models
from files.models import File
from django.contrib.auth import update_session_auth_hash
import logging
logger = logging.getLogger(__name__)
from django.contrib.auth.hashers import make_password



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
# 🔐 GOOGLE OAUTH (PLACEHOLDER - Implement if needed)
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@require_http_methods(["POST", "OPTIONS"])
def api_google_login(request):
    """Handle Google OAuth login (placeholder)"""
    if request.method == "OPTIONS":
        return JsonResponse({'status': 'ok'})
    
    try:
        data = json.loads(request.body)
        code = data.get('code')
        
        # TODO: Implement Google OAuth
        logger.info(f"Google login attempt with code: {code[:10]}...")
        
        return JsonResponse({
            'success': False,
            'error': 'Google OAuth not yet implemented on backend'
        }, status=501)
        
    except Exception as e:
        logger.error(f"Google login error: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Google login failed'
        }, status=500)
    
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


@csrf_exempt
@require_http_methods(["POST", "OPTIONS"])
def api_signup(request):
    """Handle user registration"""
    if request.method == "OPTIONS":
        return JsonResponse({'status': 'ok'})
    
    try:
        data = json.loads(request.body)
        name = data.get('name', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        # Validate
        if not email or not password:
            return JsonResponse({
                'success': False,
                'error': 'Email and password are required'
            }, status=400)
        
        # Check if exists
        if User.objects.filter(email=email).exists():
            return JsonResponse({
                'success': False,
                'error': 'Email already registered'
            }, status=400)
        
        # Create user
        username = email.split('@')[0]
        counter = 1
        while User.objects.filter(username=username).exists():
            username = f"{email.split('@')[0]}{counter}"
            counter += 1
        
        name_parts = name.split() if name else [username]
        first_name = name_parts[0]
        last_name = ' '.join(name_parts[1:]) if len(name_parts) > 1 else ''
        
        user = User.objects.create(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            password=make_password(password)
        )
        
        # Auto-login
        login(request, user)
        
        return JsonResponse({
            'success': True,
            'token': 'session-based-auth',
            'user': {
                'id': user.id,
                'email': user.email,
                'name': f"{user.first_name} {user.last_name}".strip() or user.username,
                'username': user.username,
            }
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': 'Registration failed'
        }, status=500)



# accounts/views.py

@csrf_exempt
@require_http_methods(["POST", "OPTIONS"])
def api_login(request):
    """Handle user login"""
    if request.method == "OPTIONS":
        response = JsonResponse({'status': 'ok'})
        response["Access-Control-Allow-Origin"] = "https://dropvault-frontend-1.onrender.com"
        response["Access-Control-Allow-Credentials"] = "true"
        return response
    
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"Login attempt for: {email}")
        
        # Find user
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            logger.warning(f"User not found: {email}")
            return JsonResponse({
                'success': False,
                'error': 'Invalid email or password'
            }, status=401)
        
        # Authenticate
        user = authenticate(request, username=user.username, password=password)
        
        if user:
            # ✅ CRITICAL - Login to create session
            login(request, user)
            
            logger.info(f"Login successful for: {email}")
            logger.info(f"Session key: {request.session.session_key}")
            
            # ✅ Create response with proper headers
            response_data = {
                'success': True,
                'token': 'session-based-auth',
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'name': f"{user.first_name} {user.last_name}".strip() or user.username,
                    'username': user.username,
                }
            }
            
            response = JsonResponse(response_data)
            response["Access-Control-Allow-Origin"] = "https://dropvault-frontend-1.onrender.com"
            response["Access-Control-Allow-Credentials"] = "true"
            
            return response
        else:
            logger.warning(f"Invalid password for: {email}")
            return JsonResponse({
                'success': False,
                'error': 'Invalid email or password'
            }, status=401)
            
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Login error: {str(e)}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': 'Login failed'
        }, status=500)



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


# accounts/views.py

@csrf_exempt
@require_http_methods(["GET", "OPTIONS"])
def api_dashboard(request):
    """Get dashboard stats"""
    if request.method == "OPTIONS":
        response = JsonResponse({'status': 'ok'})
        response["Access-Control-Allow-Origin"] = "https://dropvault-frontend-1.onrender.com"
        response["Access-Control-Allow-Credentials"] = "true"
        return response
    
    # ✅ ADD LOGGING
    import logging
    logger = logging.getLogger(__name__)
    logger.info(f"Dashboard request - User authenticated: {request.user.is_authenticated}")
    logger.info(f"User: {request.user}")
    logger.info(f"Session key: {request.session.session_key}")
    
    if not request.user.is_authenticated:
        logger.warning("User not authenticated for dashboard")
        return JsonResponse({
            'success': False,
            'error': 'Not authenticated'
        }, status=401)  # ✅ Changed from 403 to 401
    
    try:
        # TODO: Calculate real stats from database
        response_data = {
            'success': True,
            'data': {
                'storageUsed': 2560,  # MB
                'storageTotal': 10240,  # MB
                'totalFiles': 0,
                'sharedFiles': 0,
                'recentFiles': [],
            }
        }
        
        response = JsonResponse(response_data)
        response["Access-Control-Allow-Origin"] = "https://dropvault-frontend-1.onrender.com"
        response["Access-Control-Allow-Credentials"] = "true"
        return response
        
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': 'Failed to load dashboard'
        }, status=500)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_user_profile(request):
    """
    Get current user profile
    GET /api/user/
    """
    user = request.user
    
    return Response({
        'success': True,
        'user': {
            'id': user.id,
            'email': user.email,
            'username': user.username,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'date_joined': user.date_joined.isoformat(),
            'is_verified': user.is_active,  # or your custom field
        }
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def api_logout(request):
    """
    Logout user
    POST /api/logout/
    """
    try:
        logout(request)
        return Response({
            'success': True,
            'message': 'Logged out successfully'
        })
    except Exception as e:
        return Response({
            'success': False,
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ═══════════════════════════════════════════════════════════
# ⚙️ SETTINGS - UPDATE PROFILE
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@require_http_methods(["PUT", "PATCH"])
def api_update_profile(request):
    """Update user profile"""
    if not request.user.is_authenticated:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        data = json.loads(request.body)
        user = request.user
        
        # Update fields
        if 'name' in data:
            user.first_name = data['name'].split()[0] if data['name'] else ''
            user.last_name = ' '.join(data['name'].split()[1:]) if len(data['name'].split()) > 1 else ''
        
        if 'email' in data and data['email'] != user.email:
            # Check if email already exists
            from django.contrib.auth import get_user_model
            User = get_user_model()
            if User.objects.filter(email=data['email']).exclude(pk=user.pk).exists():
                return JsonResponse({
                    'success': False,
                    'error': 'Email already in use'
                }, status=400)
            user.email = data['email']
        
        user.save()
        
        return JsonResponse({
            'success': True,
            'message': 'Profile updated successfully',
            'data': {
                'id': user.id,
                'name': f"{user.first_name} {user.last_name}".strip() or user.username,
                'email': user.email,
            }
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

# ═══════════════════════════════════════════════════════════
# ⚙️ SETTINGS - CHANGE PASSWORD
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@require_http_methods(["PUT", "PATCH"])
def api_change_password(request):
    """Change user password"""
    if not request.user.is_authenticated:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        data = json.loads(request.body)
        user = request.user
        
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        # Verify current password
        if not user.check_password(current_password):
            return JsonResponse({
                'success': False,
                'error': 'Current password is incorrect'
            }, status=400)
        
        # Validate new password
        if len(new_password) < 8:
            return JsonResponse({
                'success': False,
                'error': 'New password must be at least 8 characters'
            }, status=400)
        
        # Set new password
        user.set_password(new_password)
        user.save()
        
        # Keep user logged in
        update_session_auth_hash(request, user)
        
        return JsonResponse({
            'success': True,
            'message': 'Password updated successfully'
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


# ═══════════════════════════════════════════════════════════
# ⚙️ SETTINGS - PREFERENCES
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@require_http_methods(["GET", "PUT", "PATCH"])
def api_preferences(request):
    """Get or update user preferences"""
    if not request.user.is_authenticated:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    if request.method == 'GET':
        # Return default preferences (you can store these in a UserProfile model)
        return JsonResponse({
            'success': True,
            'data': {
                'emailNotifications': True,
                'twoFactorAuth': False,
                'darkMode': False,
            }
        })
    
    try:
        data = json.loads(request.body)
        # TODO: Save preferences to database
        
        return JsonResponse({
            'success': True,
            'message': 'Preferences saved successfully',
            'data': data
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@api_view(['GET'])
@permission_classes([AllowAny])
def api_check_auth(request):
    """
    Check if user is authenticated
    GET /api/auth/check/
    """
    if request.user.is_authenticated:
        return Response({
            'authenticated': True,
            'user': {
                'id': request.user.id,
                'email': request.user.email,
                'username': request.user.username,
            }
        })
    else:
        return Response({
            'authenticated': False,
            'user': None
        })


# Helper function
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

#####

@login_required
def upload_test(request):
    """Upload test page"""
    return render(request, 'upload_test.html')