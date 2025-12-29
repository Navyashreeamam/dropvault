# accounts/views.py
# COMPLETE WORKING VERSION - DO NOT MODIFY PARTIALLY

import re
import os
import secrets
import json
import logging
import requests as http_requests

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.hashers import make_password
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.core.mail import send_mail
from django.conf import settings
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.db.models import Sum
from django.contrib.auth import update_session_auth_hash
from django.contrib.sessions.models import Session

from django_otp import match_token
from django_otp.plugins.otp_totp.models import TOTPDevice

from rest_framework.authtoken.models import Token

from .models import UserProfile, LoginAttempt
from .utils import verify_token, send_verification_email
from files.models import File

logger = logging.getLogger(__name__)
User = get_user_model()

# ═══════════════════════════════════════════════════════════
# 🔧 CORS HELPER - ADD HEADERS TO ALL RESPONSES
# ═══════════════════════════════════════════════════════════
ALLOWED_ORIGINS = [
    "https://dropvault-frontend-1.onrender.com",
    "https://dropvaultnew-frontend.onrender.com",
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:3000",
]

def get_cors_origin(request):
    """Get valid origin from request"""
    origin = request.META.get('HTTP_ORIGIN', '')
    if origin in ALLOWED_ORIGINS or '.onrender.com' in origin:
        return origin
    return "https://dropvault-frontend-1.onrender.com"

def add_cors_headers(response, request):
    """Add CORS headers to response"""
    origin = get_cors_origin(request)
    response["Access-Control-Allow-Origin"] = origin
    response["Access-Control-Allow-Credentials"] = "true"
    response["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Session-ID, X-CSRFToken"
    response["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
    response["Access-Control-Max-Age"] = "86400"
    return response

def cors_response(data, status=200, request=None):
    """Create JSON response with CORS headers"""
    response = JsonResponse(data, status=status)
    if request:
        add_cors_headers(response, request)
    return response


# ═══════════════════════════════════════════════════════════
# 🔐 TOKEN AUTHENTICATION HELPER
# ═══════════════════════════════════════════════════════════
def authenticate_request(request):
    """
    Authenticate request using Token header or Session
    Returns User object or None
    """
    # Method 1: Already authenticated via session
    if request.user.is_authenticated:
        logger.info(f"✅ Auth via session: {request.user.email}")
        return request.user
    
    # Method 2: Token in Authorization header
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if auth_header.startswith('Token '):
        token_key = auth_header.split(' ')[1]
        try:
            token = Token.objects.get(key=token_key)
            logger.info(f"✅ Auth via token: {token.user.email}")
            return token.user
        except Token.DoesNotExist:
            logger.warning(f"❌ Invalid token: {token_key[:10]}...")
    
    # Method 3: Session ID in custom header
    session_id = request.META.get('HTTP_X_SESSION_ID', '')
    if session_id:
        try:
            session = Session.objects.get(session_key=session_id)
            session_data = session.get_decoded()
            user_id = session_data.get('_auth_user_id')
            if user_id:
                user = User.objects.get(pk=user_id)
                logger.info(f"✅ Auth via session header: {user.email}")
                return user
        except (Session.DoesNotExist, User.DoesNotExist) as e:
            logger.warning(f"❌ Session header auth failed: {e}")
    
    logger.warning("❌ No valid authentication found")
    return None


# ═══════════════════════════════════════════════════════════
# 🏠 HOME VIEW
# ═══════════════════════════════════════════════════════════
def home(request):
    """Home page"""
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'home.html')


# ═══════════════════════════════════════════════════════════
# 📝 WEB SIGNUP VIEW
# ═══════════════════════════════════════════════════════════
def signup_view(request):
    """Web-based signup"""
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'GET':
        return render(request, 'signup.html')
    
    email = request.POST.get('email', '').strip().lower()
    password = request.POST.get('password', '').strip()
    confirm_password = request.POST.get('confirm_password', '').strip()
    name = request.POST.get('name', '').strip()
    
    form_data = {'email': email, 'name': name}
    
    if not email or not password:
        messages.error(request, "Email and password are required.")
        return render(request, 'signup.html', form_data)
    
    if password != confirm_password:
        messages.error(request, "Passwords don't match.")
        return render(request, 'signup.html', form_data)
    
    if User.objects.filter(email__iexact=email).exists():
        messages.error(request, "An account with this email already exists.")
        return render(request, 'signup.html', form_data)
    
    try:
        username = email.split('@')[0]
        counter = 1
        while User.objects.filter(username=username).exists():
            username = f"{email.split('@')[0]}_{counter}"
            counter += 1
        
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            first_name=name,
            is_active=True
        )
        
        UserProfile.objects.get_or_create(user=user)
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        messages.success(request, "Account created successfully!")
        return redirect('dashboard')
        
    except Exception as e:
        messages.error(request, f"Error creating account: {str(e)}")
        return render(request, 'signup.html', form_data)


# ═══════════════════════════════════════════════════════════
# 🔐 WEB LOGIN VIEW
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
        auth_user = authenticate(request, username=user.username, password=password)
        if auth_user:
            login(request, auth_user)
            messages.success(request, "Welcome back!")
            return redirect('dashboard')
        else:
            messages.error(request, "Invalid password.")
    except User.DoesNotExist:
        messages.error(request, "No account found with this email.")
    
    return render(request, 'login.html', {'email': email})


# ═══════════════════════════════════════════════════════════
# 🚪 WEB LOGOUT VIEW
# ═══════════════════════════════════════════════════════════
@login_required
def logout_view(request):
    """Logout user"""
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
    """Dashboard page"""
    return render(request, 'dashboard.html')


# ═══════════════════════════════════════════════════════════
# 📧 EMAIL VERIFICATION
# ═══════════════════════════════════════════════════════════
def verify_email(request, token):
    """Verify email"""
    try:
        profile = UserProfile.objects.get(verification_token=token)
        profile.email_verified = True
        profile.verification_token = ''
        profile.save()
        
        if not request.user.is_authenticated:
            login(request, profile.user, backend='django.contrib.auth.backends.ModelBackend')
        
        messages.success(request, "Email verified!")
        return redirect('dashboard')
    except UserProfile.DoesNotExist:
        messages.error(request, "Invalid verification link.")
        return redirect('home')


@login_required
def verify_email_prompt(request):
    """Prompt to verify email"""
    profile = getattr(request.user, 'userprofile', None)
    if profile and profile.email_verified:
        return redirect('dashboard')
    return render(request, 'verify_prompt.html')


# ═══════════════════════════════════════════════════════════
# 🔒 MFA VIEWS
# ═══════════════════════════════════════════════════════════
@login_required
def setup_mfa(request):
    device, _ = TOTPDevice.objects.get_or_create(
        user=request.user, confirmed=False, defaults={'name': 'Authenticator'}
    )
    if request.method == 'POST':
        token = request.POST.get('token', '').strip()
        if device.verify_token(token):
            device.confirmed = True
            device.save()
            messages.success(request, "MFA enabled!")
            return redirect('dashboard')
        messages.error(request, "Invalid code.")
    return render(request, 'setup_mfa.html', {'device': device})


@login_required
def otp_verify(request):
    if request.method == 'POST':
        token = request.POST.get('otp', '').strip()
        if match_token(request.user, token):
            return redirect('dashboard')
        messages.error(request, "Invalid OTP.")
    return render(request, 'otp_verify.html')


@login_required
def disable_mfa(request):
    if request.method == 'POST':
        TOTPDevice.objects.filter(user=request.user).delete()
        messages.success(request, "MFA disabled.")
        return redirect('dashboard')
    return render(request, 'disable_mfa.html')


# ═══════════════════════════════════════════════════════════
# 🔌 API: SIGNUP
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def api_signup(request):
    """API signup endpoint"""
    if request.method == "OPTIONS":
        return cors_response({'status': 'ok'}, request=request)
    
    if request.method != "POST":
        return cors_response({'error': 'Method not allowed'}, 405, request)
    
    try:
        data = json.loads(request.body)
        name = data.get('name', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not email or not password:
            return cors_response({'success': False, 'error': 'Email and password required'}, 400, request)
        
        if User.objects.filter(email=email).exists():
            return cors_response({'success': False, 'error': 'Email already registered'}, 400, request)
        
        username = email.split('@')[0]
        counter = 1
        while User.objects.filter(username=username).exists():
            username = f"{email.split('@')[0]}{counter}"
            counter += 1
        
        name_parts = name.split() if name else [username]
        
        user = User.objects.create(
            username=username,
            email=email,
            first_name=name_parts[0] if name_parts else '',
            last_name=' '.join(name_parts[1:]) if len(name_parts) > 1 else '',
            password=make_password(password)
        )
        
        UserProfile.objects.get_or_create(user=user)
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        
        token, _ = Token.objects.get_or_create(user=user)
        
        logger.info(f"✅ New user registered: {email}")
        
        return cors_response({
            'success': True,
            'token': token.key,
            'sessionid': request.session.session_key,
            'user': {
                'id': user.id,
                'email': user.email,
                'name': f"{user.first_name} {user.last_name}".strip() or user.username,
                'username': user.username,
            }
        }, request=request)
        
    except Exception as e:
        logger.error(f"Signup error: {e}")
        return cors_response({'success': False, 'error': 'Registration failed'}, 500, request)


# ═══════════════════════════════════════════════════════════
# 🔌 API: LOGIN
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def api_login(request):
    """API login endpoint"""
    if request.method == "OPTIONS":
        return cors_response({'status': 'ok'}, request=request)
    
    if request.method != "POST":
        return cors_response({'error': 'Method not allowed'}, 405, request)
    
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        logger.info(f"🔐 Login attempt for: {email}")
        
        if not email or not password:
            return cors_response({'success': False, 'error': 'Email and password required'}, 400, request)
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return cors_response({'success': False, 'error': 'Invalid email or password'}, 401, request)
        
        auth_user = authenticate(request, username=user.username, password=password)
        
        if auth_user:
            login(request, auth_user)
            token, _ = Token.objects.get_or_create(user=auth_user)
            
            profile = getattr(auth_user, 'userprofile', None)
            
            logger.info(f"✅ Login successful: {email}")
            logger.info(f"   Token: {token.key[:10]}...")
            logger.info(f"   Session: {request.session.session_key}")
            
            return cors_response({
                'success': True,
                'token': token.key,
                'sessionid': request.session.session_key,
                'user': {
                    'id': auth_user.id,
                    'email': auth_user.email,
                    'name': f"{auth_user.first_name} {auth_user.last_name}".strip() or auth_user.username,
                    'username': auth_user.username,
                    'email_verified': profile.email_verified if profile else False,
                }
            }, request=request)
        else:
            logger.warning(f"❌ Login failed: Wrong password - {email}")
            return cors_response({'success': False, 'error': 'Invalid email or password'}, 401, request)
            
    except Exception as e:
        logger.error(f"Login error: {e}")
        return cors_response({'success': False, 'error': 'Login failed'}, 500, request)


# ═══════════════════════════════════════════════════════════
# 🔌 API: LOGOUT
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def api_logout(request):
    """API logout endpoint"""
    if request.method == "OPTIONS":
        return cors_response({'status': 'ok'}, request=request)
    
    try:
        user = authenticate_request(request)
        if user:
            # Delete token
            Token.objects.filter(user=user).delete()
        logout(request)
        return cors_response({'success': True, 'message': 'Logged out'}, request=request)
    except Exception as e:
        return cors_response({'success': False, 'error': str(e)}, 500, request)


# ═══════════════════════════════════════════════════════════
# 🔌 API: DASHBOARD
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def api_dashboard(request):
    """API dashboard endpoint"""
    if request.method == "OPTIONS":
        return cors_response({'status': 'ok'}, request=request)
    
    if request.method != "GET":
        return cors_response({'error': 'Method not allowed'}, 405, request)
    
    user = authenticate_request(request)
    
    logger.info(f"📊 Dashboard request - User: {user}")
    
    if not user:
        return cors_response({'success': False, 'error': 'Not authenticated'}, 401, request)
    
    try:
        total_files = File.objects.filter(user=user, deleted=False).count()
        total_trash = File.objects.filter(user=user, deleted=True).count()
        
        recent_files = File.objects.filter(
            user=user, deleted=False
        ).order_by('-uploaded_at')[:5]
        
        recent_files_data = [{
            'id': f.id,
            'name': f.original_name,
            'filename': f.original_name,
            'size': f.size,
            'uploaded_at': f.uploaded_at.isoformat(),
        } for f in recent_files]
        
        total_storage = File.objects.filter(
            user=user, deleted=False
        ).aggregate(total=Sum('size'))['total'] or 0
        
        logger.info(f"✅ Dashboard data for: {user.email}")
        
        return cors_response({
            'success': True,
            'data': {
                'storageUsed': total_storage,
                'storageTotal': 10 * 1024 * 1024 * 1024,
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
        }, request=request)
        
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        import traceback
        traceback.print_exc()
        return cors_response({'success': False, 'error': 'Failed to load dashboard'}, 500, request)


# ═══════════════════════════════════════════════════════════
# 🔌 API: USER PROFILE
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def api_user_profile(request):
    """API user profile endpoint"""
    if request.method == "OPTIONS":
        return cors_response({'status': 'ok'}, request=request)
    
    user = authenticate_request(request)
    
    if not user:
        return cors_response({'success': False, 'error': 'Not authenticated'}, 401, request)
    
    try:
        profile = getattr(user, 'userprofile', None)
        
        return cors_response({
            'success': True,
            'data': {
                'id': user.id,
                'email': user.email,
                'name': f"{user.first_name} {user.last_name}".strip() or user.username,
                'username': user.username,
                'email_verified': profile.email_verified if profile else False,
            }
        }, request=request)
    except Exception as e:
        return cors_response({'success': False, 'error': str(e)}, 500, request)


# ═══════════════════════════════════════════════════════════
# 🔌 API: CHECK AUTH
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def api_check_auth(request):
    """API check auth endpoint"""
    if request.method == "OPTIONS":
        return cors_response({'status': 'ok'}, request=request)
    
    user = authenticate_request(request)
    
    if user:
        return cors_response({
            'authenticated': True,
            'user': {
                'id': user.id,
                'email': user.email,
                'name': f"{user.first_name} {user.last_name}".strip() or user.username,
            }
        }, request=request)
    
    return cors_response({'authenticated': False, 'user': None}, request=request)


# ═══════════════════════════════════════════════════════════
# 🔌 API: GOOGLE OAUTH - FULL IMPLEMENTATION
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def api_google_login(request):
    """API Google OAuth endpoint - FULL IMPLEMENTATION"""
    if request.method == "OPTIONS":
        return cors_response({'status': 'ok'}, request=request)
    
    if request.method != "POST":
        return cors_response({'error': 'Method not allowed'}, 405, request)
    
    try:
        data = json.loads(request.body)
        code = data.get('code')
        
        if not code:
            logger.error("No authorization code provided")
            return cors_response({
                'success': False,
                'error': 'Authorization code is required'
            }, 400, request)
        
        logger.info(f"🔐 Google OAuth: Received authorization code")
        
        # Get credentials from environment
        google_client_id = os.environ.get('GOOGLE_CLIENT_ID', '')
        google_client_secret = os.environ.get('GOOGLE_CLIENT_SECRET', '')
        
        if not google_client_id or not google_client_secret:
            logger.error("Google OAuth credentials not configured")
            logger.error(f"   GOOGLE_CLIENT_ID exists: {bool(google_client_id)}")
            logger.error(f"   GOOGLE_CLIENT_SECRET exists: {bool(google_client_secret)}")
            return cors_response({
                'success': False,
                'error': 'Google OAuth is not configured on the server. Please contact admin.'
            }, 501, request)
        
        # Determine redirect URI
        origin = request.META.get('HTTP_ORIGIN', '')
        if 'localhost' in origin or '127.0.0.1' in origin:
            redirect_uri = 'http://localhost:3000/google-callback'
        else:
            redirect_uri = 'https://dropvault-frontend-1.onrender.com/google-callback'
        
        logger.info(f"🔐 Using redirect_uri: {redirect_uri}")
        
        # Exchange code for token
        token_url = 'https://oauth2.googleapis.com/token'
        token_data = {
            'code': code,
            'client_id': google_client_id,
            'client_secret': google_client_secret,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code'
        }
        
        logger.info("🔐 Exchanging code for token...")
        
        try:
            token_response = http_requests.post(token_url, data=token_data, timeout=10)
            logger.info(f"🔐 Token response status: {token_response.status_code}")
        except http_requests.Timeout:
            logger.error("Token exchange timeout")
            return cors_response({
                'success': False,
                'error': 'Google authentication timed out'
            }, 504, request)
        
        if token_response.status_code != 200:
            logger.error(f"Token exchange failed: {token_response.text}")
            return cors_response({
                'success': False,
                'error': 'Failed to authenticate with Google'
            }, 401, request)
        
        token_info = token_response.json()
        access_token = token_info.get('access_token')
        
        if not access_token:
            logger.error("No access token in response")
            return cors_response({
                'success': False,
                'error': 'Failed to get access token'
            }, 401, request)
        
        logger.info("🔐 Got access token, fetching user info...")
        
        # Get user info
        userinfo_url = 'https://www.googleapis.com/oauth2/v2/userinfo'
        headers = {'Authorization': f'Bearer {access_token}'}
        
        try:
            userinfo_response = http_requests.get(userinfo_url, headers=headers, timeout=10)
        except http_requests.Timeout:
            return cors_response({
                'success': False,
                'error': 'Failed to get user info from Google'
            }, 504, request)
        
        if userinfo_response.status_code != 200:
            logger.error(f"Failed to get user info: {userinfo_response.text}")
            return cors_response({
                'success': False,
                'error': 'Failed to get user information'
            }, 401, request)
        
        google_user = userinfo_response.json()
        email = google_user.get('email')
        name = google_user.get('name', '')
        
        if not email:
            return cors_response({
                'success': False,
                'error': 'Could not get email from Google'
            }, 400, request)
        
        logger.info(f"🔐 Google user: {email}")
        
        # Find or create user
        try:
            user = User.objects.get(email=email)
            logger.info(f"🔐 Found existing user: {email}")
        except User.DoesNotExist:
            username = email.split('@')[0]
            counter = 1
            while User.objects.filter(username=username).exists():
                username = f"{email.split('@')[0]}{counter}"
                counter += 1
            
            name_parts = name.split() if name else [username]
            
            user = User.objects.create(
                username=username,
                email=email,
                first_name=name_parts[0] if name_parts else '',
                last_name=' '.join(name_parts[1:]) if len(name_parts) > 1 else '',
                is_active=True
            )
            user.set_unusable_password()
            user.save()
            
            UserProfile.objects.get_or_create(user=user)
            logger.info(f"🔐 Created new user: {email}")
        
        # Login and create token
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        token, _ = Token.objects.get_or_create(user=user)
        
        logger.info(f"✅ Google OAuth successful: {email}")
        
        return cors_response({
            'success': True,
            'token': token.key,
            'sessionid': request.session.session_key,
            'user': {
                'id': user.id,
                'email': user.email,
                'name': f"{user.first_name} {user.last_name}".strip() or user.username,
                'username': user.username,
            }
        }, request=request)
        
    except json.JSONDecodeError:
        return cors_response({'success': False, 'error': 'Invalid request'}, 400, request)
    except Exception as e:
        logger.error(f"Google OAuth error: {e}")
        import traceback
        traceback.print_exc()
        return cors_response({
            'success': False,
            'error': 'Google authentication failed'
        }, 500, request)


# ═══════════════════════════════════════════════════════════
# 🔌 API: VERIFY EMAIL
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def api_verify_email(request):
    """API verify email endpoint"""
    if request.method == "OPTIONS":
        return cors_response({'status': 'ok'}, request=request)
    
    token = request.GET.get('token') or request.POST.get('token')
    
    if not token:
        try:
            data = json.loads(request.body)
            token = data.get('token')
        except:
            pass
    
    if not token:
        return cors_response({'error': 'Token required'}, 400, request)
    
    try:
        profile = UserProfile.objects.get(verification_token=token)
        profile.email_verified = True
        profile.verification_token = ''
        profile.save()
        return cors_response({'success': True, 'message': 'Email verified'}, request=request)
    except UserProfile.DoesNotExist:
        return cors_response({'error': 'Invalid token'}, 400, request)


# ═══════════════════════════════════════════════════════════
# 🔌 API: UPDATE PROFILE
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def api_update_profile(request):
    """API update profile endpoint"""
    if request.method == "OPTIONS":
        return cors_response({'status': 'ok'}, request=request)
    
    user = authenticate_request(request)
    if not user:
        return cors_response({'success': False, 'error': 'Not authenticated'}, 401, request)
    
    try:
        data = json.loads(request.body)
        
        if 'name' in data:
            parts = data['name'].split()
            user.first_name = parts[0] if parts else ''
            user.last_name = ' '.join(parts[1:]) if len(parts) > 1 else ''
        
        if 'email' in data and data['email'] != user.email:
            if User.objects.filter(email=data['email']).exclude(pk=user.pk).exists():
                return cors_response({'success': False, 'error': 'Email in use'}, 400, request)
            user.email = data['email']
        
        user.save()
        
        return cors_response({
            'success': True,
            'message': 'Profile updated',
            'data': {'id': user.id, 'email': user.email}
        }, request=request)
    except Exception as e:
        return cors_response({'success': False, 'error': str(e)}, 500, request)


# ═══════════════════════════════════════════════════════════
# 🔌 API: CHANGE PASSWORD
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def api_change_password(request):
    """API change password endpoint"""
    if request.method == "OPTIONS":
        return cors_response({'status': 'ok'}, request=request)
    
    user = authenticate_request(request)
    if not user:
        return cors_response({'success': False, 'error': 'Not authenticated'}, 401, request)
    
    try:
        data = json.loads(request.body)
        current = data.get('current_password')
        new = data.get('new_password')
        
        if not user.check_password(current):
            return cors_response({'success': False, 'error': 'Current password incorrect'}, 400, request)
        
        if len(new) < 8:
            return cors_response({'success': False, 'error': 'Password too short'}, 400, request)
        
        user.set_password(new)
        user.save()
        update_session_auth_hash(request, user)
        
        return cors_response({'success': True, 'message': 'Password updated'}, request=request)
    except Exception as e:
        return cors_response({'success': False, 'error': str(e)}, 500, request)


# ═══════════════════════════════════════════════════════════
# 🔌 API: PREFERENCES
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def api_preferences(request):
    """API preferences endpoint"""
    if request.method == "OPTIONS":
        return cors_response({'status': 'ok'}, request=request)
    
    user = authenticate_request(request)
    if not user:
        return cors_response({'success': False, 'error': 'Not authenticated'}, 401, request)
    
    if request.method == 'GET':
        return cors_response({
            'success': True,
            'data': {'emailNotifications': True, 'twoFactorAuth': False, 'darkMode': False}
        }, request=request)
    
    try:
        data = json.loads(request.body)
        return cors_response({'success': True, 'data': data}, request=request)
    except Exception as e:
        return cors_response({'success': False, 'error': str(e)}, 500, request)


# ═══════════════════════════════════════════════════════════
# 🛠️ UTILITY
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def test_email(request):
    if not request.user.is_superuser:
        return HttpResponse("Access denied", status=403)
    try:
        send_mail('Test', 'Test email', settings.DEFAULT_FROM_EMAIL, [request.user.email])
        return HttpResponse("Email sent!")
    except Exception as e:
        return HttpResponse(f"Error: {e}", status=500)


def format_file_size(size_bytes):
    if size_bytes == 0:
        return "0 B"
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    i = 0
    size = float(size_bytes)
    while size >= 1024 and i < len(units) - 1:
        size /= 1024
        i += 1
    return f"{size:.2f} {units[i]}"


@login_required
def upload_test(request):
    return render(request, 'upload_test.html')