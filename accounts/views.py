# accounts/views.py

import re
import secrets
import json
import logging
import os

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.hashers import make_password
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.core.cache import cache
from django.core.mail import send_mail
from django.conf import settings
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.db.models import Sum
from django.contrib.auth import update_session_auth_hash

from django_otp import match_token
from django_otp.plugins.otp_totp.models import TOTPDevice

from .models import UserProfile, LoginAttempt
from .utils import verify_token, send_verification_email
from files.models import File

from rest_framework.authtoken.models import Token
from django.contrib.sessions.models import Session

# Setup logger
logger = logging.getLogger(__name__)

# Get the User model
User = get_user_model()


# ═══════════════════════════════════════════════════════════
# 🔐 TOKEN AUTHENTICATION HELPER
# ═══════════════════════════════════════════════════════════

def authenticate_request(request):
    """
    Authenticate request using either:
    1. Token in Authorization header
    2. Session ID in X-Session-ID header
    3. Session cookie
    """
    # Already authenticated via session
    if request.user.is_authenticated:
        return request.user
    
    # Try Token authentication
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if auth_header.startswith('Token '):
        token_key = auth_header.split(' ')[1]
        try:
            token = Token.objects.get(key=token_key)
            return token.user
        except Token.DoesNotExist:
            pass
    
    # Try session ID from header
    session_id = request.META.get('HTTP_X_SESSION_ID', '')
    if session_id:
        try:
            session = Session.objects.get(session_key=session_id)
            session_data = session.get_decoded()
            user_id = session_data.get('_auth_user_id')
            if user_id:
                return User.objects.get(pk=user_id)
        except (Session.DoesNotExist, User.DoesNotExist):
            pass
    
    return None

# ═══════════════════════════════════════════════════════════
# 🔧 HELPER: Get allowed frontend origins
# ═══════════════════════════════════════════════════════════
ALLOWED_ORIGINS = [
    "https://dropvaultnew-frontend.onrender.com",
    "https://dropvault-frontend-1.onrender.com",
    "http://localhost:3000",
    "http://localhost:5173",
]

def get_cors_origin(request):
    """Get the origin from request and validate it"""
    origin = request.META.get('HTTP_ORIGIN', '')
    if origin in ALLOWED_ORIGINS:
        return origin
    # Default to the main frontend
    return "https://dropvaultnew-frontend.onrender.com"

def add_cors_headers(response, request):
    """Add CORS headers to response"""
    origin = get_cors_origin(request)
    response["Access-Control-Allow-Origin"] = origin
    response["Access-Control-Allow-Credentials"] = "true"
    response["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-CSRFToken"
    response["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
    return response




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
    """Web-based signup - renders HTML form"""
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
    
    try:
        validate_email(email)
    except ValidationError:
        messages.error(request, "Invalid email format.")
        return render(request, 'signup.html', form_data)
    
    if User.objects.filter(email__iexact=email).exists():
        messages.error(request, "An account with this email already exists.")
        return render(request, 'signup.html', form_data)
    
    try:
        validate_password(password)
    except ValidationError as e:
        for error in e.messages:
            messages.error(request, error)
        return render(request, 'signup.html', form_data)
    
    try:
        # Generate unique username
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
        
        UserProfile.objects.get_or_create(user=user)
        
        try:
            send_verification_email(user)
            messages.info(request, "Verification email sent!")
        except Exception as e:
            logger.warning(f"Email send error: {e}")
        
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
    """Web-based login"""
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'GET':
        return render(request, 'login.html')
    
    email = request.POST.get('email', '').strip().lower()
    password = request.POST.get('password', '').strip()
    
    if not email or not password:
        messages.error(request, "Email and password are required.")
        return render(request, 'login.html', {'email': email})
    
    try:
        user = User.objects.get(email__iexact=email)
    except User.DoesNotExist:
        messages.error(request, "No account found with this email.")
        return render(request, 'login.html', {'email': email})
    
    auth_user = authenticate(request, username=user.username, password=password)
    if auth_user:
        login(request, auth_user)
        
        profile = getattr(auth_user, 'userprofile', None)
        if profile and not profile.email_verified:
            try:
                send_verification_email(auth_user)
            except:
                pass
            return redirect('verify_email_prompt')
        
        messages.success(request, f"Welcome back!")
        return redirect('dashboard')
    else:
        messages.error(request, "Invalid password.")
        return render(request, 'login.html', {'email': email})


# ═══════════════════════════════════════════════════════════
# 🚪 WEB LOGOUT VIEW
# ═══════════════════════════════════════════════════════════
@login_required
def logout_view(request):
    """Logout user (web)"""
    if request.method == 'POST':
        logout(request)
        messages.success(request, "Logged out successfully.")
        return redirect('home')
    return render(request, 'logout_confirm.html')


# ═══════════════════════════════════════════════════════════
# 📊 WEB DASHBOARD VIEW
# ═══════════════════════════════════════════════════════════
@login_required
def dashboard(request):
    """Main dashboard page"""
    return render(request, 'dashboard.html')


# ═══════════════════════════════════════════════════════════
# 📧 EMAIL VERIFICATION VIEWS
# ═══════════════════════════════════════════════════════════
def verify_email(request, token):
    """Verify email using token"""
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
    email_configured = bool(os.environ.get('RESEND_API_KEY', '').strip())
    
    if request.method == 'POST':
        if not email_configured:
            messages.error(request, "Email service is not configured.")
            return redirect('verify_email_prompt')
        
        try:
            success = send_verification_email(request.user, async_send=False)
            if success:
                messages.success(request, f"Verification email sent to {user_email}.")
            else:
                messages.error(request, "Failed to send verification email.")
        except Exception as e:
            messages.error(request, f"Error sending email: {str(e)}")
        return redirect('verify_email_prompt')
    
    return render(request, 'verify_prompt.html', {'email_configured': email_configured})


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
            messages.error(request, "Invalid code.")
    
    return render(request, 'setup_mfa.html', {'device': device})


@login_required
def otp_verify(request):
    """Verify OTP code"""
    if request.method == 'POST':
        token = request.POST.get('otp', '').strip()
        if match_token(request.user, token):
            messages.success(request, "OTP verified!")
            return redirect('dashboard')
        else:
            messages.error(request, "Invalid OTP code.")
    return render(request, 'otp_verify.html')


@login_required
def disable_mfa(request):
    """Disable MFA"""
    if request.method == 'POST':
        confirm_token = request.POST.get('confirm_token', '').strip()
        expected = request.user.email[-4:] if request.user.email else ''
        
        if confirm_token != expected:
            messages.error(request, "Invalid confirmation.")
            return render(request, 'disable_mfa.html')
        
        TOTPDevice.objects.filter(user=request.user, confirmed=True).delete()
        messages.success(request, "MFA has been disabled.")
        return redirect('dashboard')
    
    return render(request, 'disable_mfa.html')




# ═══════════════════════════════════════════════════════════
# 🔐 GOOGLE OAUTH - FULL IMPLEMENTATION
# ═══════════════════════════════════════════════════════════
import requests

@csrf_exempt
def api_google_login(request):
    """
    Handle Google OAuth login
    Receives authorization code from frontend, exchanges for token, gets user info
    """
    if request.method == "OPTIONS":
        response = JsonResponse({'status': 'ok'})
        return add_cors_headers(response, request)
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        code = data.get('code')
        
        if not code:
            logger.error("No authorization code provided")
            response = JsonResponse({
                'success': False,
                'error': 'Authorization code is required'
            }, status=400)
            return add_cors_headers(response, request)
        
        logger.info(f"🔐 Google OAuth: Received authorization code")
        
        # Get Google OAuth credentials from environment
        google_client_id = os.environ.get('GOOGLE_CLIENT_ID', '')
        google_client_secret = os.environ.get('GOOGLE_CLIENT_SECRET', '')
        
        if not google_client_id or not google_client_secret:
            logger.error("Google OAuth credentials not configured")
            response = JsonResponse({
                'success': False,
                'error': 'Google OAuth is not configured on the server'
            }, status=501)
            return add_cors_headers(response, request)
        
        # Determine redirect URI based on request origin
        origin = request.META.get('HTTP_ORIGIN', '')
        if 'localhost' in origin or '127.0.0.1' in origin:
            redirect_uri = 'http://localhost:3000/google-callback'
        else:
            redirect_uri = 'https://dropvault-frontend-1.onrender.com/google-callback'
        
        logger.info(f"🔐 Using redirect_uri: {redirect_uri}")
        
        # Exchange authorization code for access token
        token_url = 'https://oauth2.googleapis.com/token'
        token_data = {
            'code': code,
            'client_id': google_client_id,
            'client_secret': google_client_secret,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code'
        }
        
        logger.info("🔐 Exchanging code for token...")
        token_response = requests.post(token_url, data=token_data, timeout=10)
        
        if token_response.status_code != 200:
            logger.error(f"Token exchange failed: {token_response.text}")
            response = JsonResponse({
                'success': False,
                'error': 'Failed to authenticate with Google'
            }, status=401)
            return add_cors_headers(response, request)
        
        token_info = token_response.json()
        access_token = token_info.get('access_token')
        
        if not access_token:
            logger.error("No access token in response")
            response = JsonResponse({
                'success': False,
                'error': 'Failed to get access token from Google'
            }, status=401)
            return add_cors_headers(response, request)
        
        logger.info("🔐 Got access token, fetching user info...")
        
        # Get user info from Google
        userinfo_url = 'https://www.googleapis.com/oauth2/v2/userinfo'
        headers = {'Authorization': f'Bearer {access_token}'}
        userinfo_response = requests.get(userinfo_url, headers=headers, timeout=10)
        
        if userinfo_response.status_code != 200:
            logger.error(f"Failed to get user info: {userinfo_response.text}")
            response = JsonResponse({
                'success': False,
                'error': 'Failed to get user information from Google'
            }, status=401)
            return add_cors_headers(response, request)
        
        google_user = userinfo_response.json()
        email = google_user.get('email')
        name = google_user.get('name', '')
        google_id = google_user.get('id')
        
        if not email:
            logger.error("No email in Google user info")
            response = JsonResponse({
                'success': False,
                'error': 'Could not get email from Google account'
            }, status=400)
            return add_cors_headers(response, request)
        
        logger.info(f"🔐 Google user: {email}")
        
        # Find or create user
        try:
            user = User.objects.get(email=email)
            logger.info(f"🔐 Found existing user: {user.email}")
        except User.DoesNotExist:
            # Create new user
            username = email.split('@')[0]
            counter = 1
            while User.objects.filter(username=username).exists():
                username = f"{email.split('@')[0]}{counter}"
                counter += 1
            
            name_parts = name.split() if name else [username]
            first_name = name_parts[0] if name_parts else ''
            last_name = ' '.join(name_parts[1:]) if len(name_parts) > 1 else ''
            
            user = User.objects.create(
                username=username,
                email=email,
                first_name=first_name,
                last_name=last_name,
                is_active=True
            )
            # Set unusable password for OAuth users
            user.set_unusable_password()
            user.save()
            
            # Create profile
            UserProfile.objects.get_or_create(user=user)
            
            logger.info(f"🔐 Created new user: {user.email}")
        
        # Login the user
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        
        logger.info(f"✅ Google OAuth successful for: {email}")
        
        response = JsonResponse({
            'success': True,
            'token': request.session.session_key or 'session-based',
            'sessionid': request.session.session_key,
            'user': {
                'id': user.id,
                'email': user.email,
                'name': f"{user.first_name} {user.last_name}".strip() or user.username,
                'username': user.username,
            }
        })
        return add_cors_headers(response, request)
        
    except json.JSONDecodeError:
        response = JsonResponse({
            'success': False,
            'error': 'Invalid request data'
        }, status=400)
        return add_cors_headers(response, request)
    except requests.Timeout:
        logger.error("Google OAuth request timeout")
        response = JsonResponse({
            'success': False,
            'error': 'Google authentication timed out. Please try again.'
        }, status=504)
        return add_cors_headers(response, request)
    except Exception as e:
        logger.error(f"Google OAuth error: {str(e)}")
        import traceback
        traceback.print_exc()
        response = JsonResponse({
            'success': False,
            'error': 'Google authentication failed. Please try again.'
        }, status=500)
        return add_cors_headers(response, request)
    
# ═══════════════════════════════════════════════════════════
# 🔌 API: SIGNUP
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def api_signup(request):
    """API endpoint for user registration"""
    if request.method == "OPTIONS":
        response = JsonResponse({'status': 'ok'})
        return add_cors_headers(response, request)
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        name = data.get('name', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not email or not password:
            response = JsonResponse({
                'success': False,
                'error': 'Email and password are required'
            }, status=400)
            return add_cors_headers(response, request)
        
        if User.objects.filter(email=email).exists():
            response = JsonResponse({
                'success': False,
                'error': 'Email already registered'
            }, status=400)
            return add_cors_headers(response, request)
        
        # Create username
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
        
        # Create profile
        UserProfile.objects.get_or_create(user=user)
        
        # Login user
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        
        logger.info(f"✅ New user registered: {email}")
        
        response = JsonResponse({
            'success': True,
            'token': request.session.session_key or 'session-based',
            'sessionid': request.session.session_key,
            'user': {
                'id': user.id,
                'email': user.email,
                'name': f"{user.first_name} {user.last_name}".strip() or user.username,
                'username': user.username,
            }
        })
        return add_cors_headers(response, request)
        
    except json.JSONDecodeError:
        response = JsonResponse({
            'success': False,
            'error': 'Invalid JSON data'
        }, status=400)
        return add_cors_headers(response, request)
    except Exception as e:
        logger.error(f"Signup error: {e}")
        response = JsonResponse({
            'success': False,
            'error': 'Registration failed'
        }, status=500)
        return add_cors_headers(response, request)


# ═══════════════════════════════════════════════════════════
# 🔌 API: LOGIN
# ═══════════════════════════════════════════════════════════

@csrf_exempt
def api_login(request):
    """API endpoint for user login"""
    if request.method == "OPTIONS":
        response = JsonResponse({'status': 'ok'})
        return add_cors_headers(response, request)
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        logger.info(f"🔐 Login attempt for: {email}")
        
        if not email or not password:
            response = JsonResponse({
                'success': False,
                'error': 'Email and password are required'
            }, status=400)
            return add_cors_headers(response, request)
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            logger.warning(f"❌ Login failed: User not found - {email}")
            response = JsonResponse({
                'success': False,
                'error': 'Invalid email or password'
            }, status=401)
            return add_cors_headers(response, request)
        
        auth_user = authenticate(request, username=user.username, password=password)
        
        if auth_user:
            login(request, auth_user)
            
            # ✅ CREATE OR GET TOKEN
            from rest_framework.authtoken.models import Token
            token, created = Token.objects.get_or_create(user=auth_user)
            
            profile = getattr(auth_user, 'userprofile', None)
            email_verified = profile.email_verified if profile else False
            
            logger.info(f"✅ Login successful: {email}")
            logger.info(f"   Token: {token.key[:10]}...")
            logger.info(f"   Session: {request.session.session_key}")
            
            response = JsonResponse({
                'success': True,
                'token': token.key,  # ✅ Send actual token
                'sessionid': request.session.session_key,
                'user': {
                    'id': auth_user.id,
                    'email': auth_user.email,
                    'name': f"{auth_user.first_name} {auth_user.last_name}".strip() or auth_user.username,
                    'username': auth_user.username,
                    'email_verified': email_verified,
                }
            })
            return add_cors_headers(response, request)
        else:
            logger.warning(f"❌ Login failed: Wrong password - {email}")
            response = JsonResponse({
                'success': False,
                'error': 'Invalid email or password'
            }, status=401)
            return add_cors_headers(response, request)
            
    except json.JSONDecodeError:
        response = JsonResponse({
            'success': False,
            'error': 'Invalid JSON data'
        }, status=400)
        return add_cors_headers(response, request)
    except Exception as e:
        logger.error(f"Login error: {e}")
        response = JsonResponse({
            'success': False,
            'error': 'Login failed'
        }, status=500)
        return add_cors_headers(response, request)

# ═══════════════════════════════════════════════════════════
# 🔌 API: LOGOUT
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def api_logout(request):
    """API endpoint for logout"""
    if request.method == "OPTIONS":
        response = JsonResponse({'status': 'ok'})
        return add_cors_headers(response, request)
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        logger.info(f"🚪 Logout request from: {request.user}")
        logout(request)
        
        response = JsonResponse({
            'success': True,
            'message': 'Logged out successfully'
        })
        return add_cors_headers(response, request)
        
    except Exception as e:
        logger.error(f"Logout error: {e}")
        response = JsonResponse({
            'success': False,
            'error': 'Logout failed'
        }, status=500)
        return add_cors_headers(response, request)


# ═══════════════════════════════════════════════════════════
# 🔌 API: DASHBOARD
# ═══════════════════════════════════════════════════════════

@csrf_exempt
def api_dashboard(request):
    """API endpoint for dashboard data"""
    if request.method == "OPTIONS":
        response = JsonResponse({'status': 'ok'})
        return add_cors_headers(response, request)
    
    if request.method != "GET":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    # ✅ USE HELPER TO AUTHENTICATE
    user = authenticate_request(request)
    
    logger.info(f"📊 Dashboard request")
    logger.info(f"   Session user: {request.user}")
    logger.info(f"   Token user: {user}")
    logger.info(f"   Is authenticated: {user is not None}")
    
    if not user:
        logger.warning("❌ Dashboard: Not authenticated")
        response = JsonResponse({
            'success': False,
            'error': 'Not authenticated'
        }, status=401)
        return add_cors_headers(response, request)
    
    try:
        # Get file statistics
        total_files = File.objects.filter(user=user, deleted=False).count()
        total_trash = File.objects.filter(user=user, deleted=True).count()
        
        # Get recent files
        recent_files = File.objects.filter(
            user=user, 
            deleted=False
        ).order_by('-uploaded_at')[:5]
        
        recent_files_data = []
        for f in recent_files:
            recent_files_data.append({
                'id': f.id,
                'name': f.original_name,
                'filename': f.original_name,
                'size': f.size,
                'uploaded_at': f.uploaded_at.isoformat(),
            })
        
        # Calculate storage
        from django.db.models import Sum
        total_storage = File.objects.filter(
            user=user, 
            deleted=False
        ).aggregate(total=Sum('size'))['total'] or 0
        
        logger.info(f"✅ Dashboard data for: {user.email}")
        
        response = JsonResponse({
            'success': True,
            'data': {
                'storageUsed': total_storage,
                'storageTotal': 10 * 1024 * 1024 * 1024,  # 10GB
                'totalFiles': total_files,
                'trashFiles': total_trash,
                'recentFiles': recent_files_data,
                'sharedCount': 0,
            },
            'user': {
                'id': user.id,
                'email': user.email,
                'name': f"{user.first_name} {user.last_name}".strip() or user.username,
            }
        })
        return add_cors_headers(response, request)
        
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        import traceback
        traceback.print_exc()
        response = JsonResponse({
            'success': False,
            'error': 'Failed to load dashboard'
        }, status=500)
        return add_cors_headers(response, request)

# ═══════════════════════════════════════════════════════════
# 🔌 API: USER PROFILE
# ═══════════════════════════════════════════════════════════

@csrf_exempt
def api_user_profile(request):
    """API endpoint for user profile"""
    if request.method == "OPTIONS":
        response = JsonResponse({'status': 'ok'})
        return add_cors_headers(response, request)
    
    user = authenticate_request(request)
    
    if not user:
        response = JsonResponse({
            'success': False,
            'error': 'Not authenticated'
        }, status=401)
        return add_cors_headers(response, request)
    
    try:
        profile = getattr(user, 'userprofile', None)
        
        response = JsonResponse({
            'success': True,
            'data': {
                'id': user.id,
                'email': user.email,
                'name': f"{user.first_name} {user.last_name}".strip() or user.username,
                'username': user.username,
                'email_verified': profile.email_verified if profile else False,
                'date_joined': user.date_joined.isoformat(),
            }
        })
        return add_cors_headers(response, request)
        
    except Exception as e:
        logger.error(f"Profile error: {e}")
        response = JsonResponse({
            'success': False,
            'error': 'Failed to fetch profile'
        }, status=500)
        return add_cors_headers(response, request)


@csrf_exempt
def api_check_auth(request):
    """API endpoint to check authentication status"""
    if request.method == "OPTIONS":
        response = JsonResponse({'status': 'ok'})
        return add_cors_headers(response, request)
    
    user = authenticate_request(request)
    
    logger.info(f"🔍 Auth check - User: {user}")
    
    if user:
        response_data = {
            'authenticated': True,
            'user': {
                'id': user.id,
                'email': user.email,
                'name': f"{user.first_name} {user.last_name}".strip() or user.username,
            }
        }
    else:
        response_data = {
            'authenticated': False,
            'user': None
        }
    
    response = JsonResponse(response_data)
    return add_cors_headers(response, request)

# ═══════════════════════════════════════════════════════════
# 🔌 API: CHECK AUTH
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def api_check_auth(request):
    """API endpoint to check authentication status"""
    if request.method == "OPTIONS":
        response = JsonResponse({'status': 'ok'})
        return add_cors_headers(response, request)
    
    logger.info(f"🔍 Auth check - User: {request.user}, Auth: {request.user.is_authenticated}")
    
    if request.user.is_authenticated:
        response_data = {
            'authenticated': True,
            'user': {
                'id': request.user.id,
                'email': request.user.email,
                'name': f"{request.user.first_name} {request.user.last_name}".strip() or request.user.username,
            }
        }
    else:
        response_data = {
            'authenticated': False,
            'user': None
        }
    
    response = JsonResponse(response_data)
    return add_cors_headers(response, request)


# ═══════════════════════════════════════════════════════════
# 🔌 API: GOOGLE LOGIN (Placeholder)
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def api_google_login(request):
    """API endpoint for Google OAuth (not yet implemented)"""
    if request.method == "OPTIONS":
        response = JsonResponse({'status': 'ok'})
        return add_cors_headers(response, request)
    
    logger.info("🔐 Google login attempt - not implemented")
    
    response = JsonResponse({
        'success': False,
        'error': 'Google login is not yet configured. Please use email/password login.',
        'message': 'Contact administrator to enable Google OAuth.'
    }, status=501)
    return add_cors_headers(response, request)


# ═══════════════════════════════════════════════════════════
# 🔌 API: VERIFY EMAIL
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def api_verify_email(request):
    """API endpoint for email verification"""
    if request.method == "OPTIONS":
        response = JsonResponse({'status': 'ok'})
        return add_cors_headers(response, request)
    
    if request.method == 'GET':
        token = request.GET.get('token')
    else:
        try:
            data = json.loads(request.body)
            token = data.get('token')
        except:
            token = request.POST.get('token')
    
    if not token:
        response = JsonResponse({'error': 'Token is required'}, status=400)
        return add_cors_headers(response, request)
    
    try:
        profile = UserProfile.objects.get(verification_token=token)
        profile.email_verified = True
        profile.verification_token = ''
        profile.save()
        
        response = JsonResponse({
            'success': True,
            'message': 'Email verified successfully'
        })
        return add_cors_headers(response, request)
        
    except UserProfile.DoesNotExist:
        response = JsonResponse({'error': 'Invalid or expired token'}, status=400)
        return add_cors_headers(response, request)


# ═══════════════════════════════════════════════════════════
# 🔌 API: UPDATE PROFILE
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def api_update_profile(request):
    """API endpoint to update user profile"""
    if request.method == "OPTIONS":
        response = JsonResponse({'status': 'ok'})
        return add_cors_headers(response, request)
    
    if request.method not in ["PUT", "PATCH"]:
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    if not request.user.is_authenticated:
        response = JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
        return add_cors_headers(response, request)
    
    try:
        data = json.loads(request.body)
        user = request.user
        
        if 'name' in data:
            parts = data['name'].split()
            user.first_name = parts[0] if parts else ''
            user.last_name = ' '.join(parts[1:]) if len(parts) > 1 else ''
        
        if 'email' in data and data['email'] != user.email:
            if User.objects.filter(email=data['email']).exclude(pk=user.pk).exists():
                response = JsonResponse({
                    'success': False,
                    'error': 'Email already in use'
                }, status=400)
                return add_cors_headers(response, request)
            user.email = data['email']
        
        user.save()
        
        response = JsonResponse({
            'success': True,
            'message': 'Profile updated successfully',
            'data': {
                'id': user.id,
                'name': f"{user.first_name} {user.last_name}".strip() or user.username,
                'email': user.email,
            }
        })
        return add_cors_headers(response, request)
        
    except Exception as e:
        response = JsonResponse({'success': False, 'error': str(e)}, status=500)
        return add_cors_headers(response, request)


# ═══════════════════════════════════════════════════════════
# 🔌 API: CHANGE PASSWORD
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def api_change_password(request):
    """API endpoint to change password"""
    if request.method == "OPTIONS":
        response = JsonResponse({'status': 'ok'})
        return add_cors_headers(response, request)
    
    if request.method not in ["PUT", "PATCH"]:
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    if not request.user.is_authenticated:
        response = JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
        return add_cors_headers(response, request)
    
    try:
        data = json.loads(request.body)
        user = request.user
        
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not user.check_password(current_password):
            response = JsonResponse({
                'success': False,
                'error': 'Current password is incorrect'
            }, status=400)
            return add_cors_headers(response, request)
        
        if len(new_password) < 8:
            response = JsonResponse({
                'success': False,
                'error': 'New password must be at least 8 characters'
            }, status=400)
            return add_cors_headers(response, request)
        
        user.set_password(new_password)
        user.save()
        update_session_auth_hash(request, user)
        
        response = JsonResponse({
            'success': True,
            'message': 'Password updated successfully'
        })
        return add_cors_headers(response, request)
        
    except Exception as e:
        response = JsonResponse({'success': False, 'error': str(e)}, status=500)
        return add_cors_headers(response, request)


# ═══════════════════════════════════════════════════════════
# 🔌 API: PREFERENCES
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def api_preferences(request):
    """API endpoint for user preferences"""
    if request.method == "OPTIONS":
        response = JsonResponse({'status': 'ok'})
        return add_cors_headers(response, request)
    
    if not request.user.is_authenticated:
        response = JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
        return add_cors_headers(response, request)
    
    if request.method == 'GET':
        response = JsonResponse({
            'success': True,
            'data': {
                'emailNotifications': True,
                'twoFactorAuth': False,
                'darkMode': False,
            }
        })
        return add_cors_headers(response, request)
    
    try:
        data = json.loads(request.body)
        response = JsonResponse({
            'success': True,
            'message': 'Preferences saved successfully',
            'data': data
        })
        return add_cors_headers(response, request)
        
    except Exception as e:
        response = JsonResponse({'success': False, 'error': str(e)}, status=500)
        return add_cors_headers(response, request)


# ═══════════════════════════════════════════════════════════
# 🛠️ UTILITY VIEWS
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def test_email(request):
    """Test email configuration"""
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


@login_required
def upload_test(request):
    """Upload test page"""
    return render(request, 'upload_test.html')