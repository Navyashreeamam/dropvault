# accounts/views.py
# SIMPLIFIED VERSION - Django CORS middleware handles headers

import os
import json
import logging
import requests as http_requests

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Sum
from django.contrib.auth import update_session_auth_hash
from django.contrib.sessions.models import Session

from django_otp import match_token
from django_otp.plugins.otp_totp.models import TOTPDevice
from rest_framework.authtoken.models import Token

from .models import UserProfile
from files.models import File

logger = logging.getLogger(__name__)
User = get_user_model()


# ═══════════════════════════════════════════════════════════
# 🔐 TOKEN AUTHENTICATION HELPER
# ═══════════════════════════════════════════════════════════
def authenticate_request(request):
    """Authenticate request using Token or Session"""
    # Session auth
    if request.user.is_authenticated:
        return request.user
    
    # Token auth
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if auth_header.startswith('Token '):
        token_key = auth_header.split(' ')[1]
        try:
            token = Token.objects.get(key=token_key)
            logger.info(f"✅ Token auth: {token.user.email}")
            return token.user
        except Token.DoesNotExist:
            logger.warning(f"❌ Invalid token")
    
    return None


# ═══════════════════════════════════════════════════════════
# 🏠 HOME VIEW
# ═══════════════════════════════════════════════════════════
def home(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'home.html')


# ═══════════════════════════════════════════════════════════
# 📝 WEB VIEWS
# ═══════════════════════════════════════════════════════════
def signup_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    if request.method == 'GET':
        return render(request, 'signup.html')
    
    email = request.POST.get('email', '').strip().lower()
    password = request.POST.get('password', '').strip()
    name = request.POST.get('name', '').strip()
    
    if User.objects.filter(email=email).exists():
        messages.error(request, "Email already exists.")
        return render(request, 'signup.html')
    
    username = email.split('@')[0]
    counter = 1
    while User.objects.filter(username=username).exists():
        username = f"{email.split('@')[0]}{counter}"
        counter += 1
    
    user = User.objects.create_user(username=username, email=email, password=password, first_name=name)
    UserProfile.objects.get_or_create(user=user)
    login(request, user, backend='django.contrib.auth.backends.ModelBackend')
    return redirect('dashboard')


def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    if request.method == 'GET':
        return render(request, 'login.html')
    
    email = request.POST.get('email', '').strip().lower()
    password = request.POST.get('password', '').strip()
    
    try:
        user = User.objects.get(email=email)
        auth_user = authenticate(request, username=user.username, password=password)
        if auth_user:
            login(request, auth_user)
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
    try:
        profile = UserProfile.objects.get(verification_token=token)
        profile.email_verified = True
        profile.verification_token = ''
        profile.save()
        login(request, profile.user, backend='django.contrib.auth.backends.ModelBackend')
        return redirect('dashboard')
    except UserProfile.DoesNotExist:
        return redirect('home')


@login_required
def verify_email_prompt(request):
    return render(request, 'verify_prompt.html')


@login_required
def setup_mfa(request):
    device, _ = TOTPDevice.objects.get_or_create(user=request.user, confirmed=False, defaults={'name': 'Auth'})
    if request.method == 'POST' and device.verify_token(request.POST.get('token', '')):
        device.confirmed = True
        device.save()
        return redirect('dashboard')
    return render(request, 'setup_mfa.html', {'device': device})


@login_required
def otp_verify(request):
    if request.method == 'POST' and match_token(request.user, request.POST.get('otp', '')):
        return redirect('dashboard')
    return render(request, 'otp_verify.html')


@login_required
def disable_mfa(request):
    if request.method == 'POST':
        TOTPDevice.objects.filter(user=request.user).delete()
        return redirect('dashboard')
    return render(request, 'disable_mfa.html')


# ═══════════════════════════════════════════════════════════
# 🔌 API: SIGNUP
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def api_signup(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        name = data.get('name', '').strip()
        
        if not email or not password:
            return JsonResponse({'success': False, 'error': 'Email and password required'}, status=400)
        
        if User.objects.filter(email=email).exists():
            return JsonResponse({'success': False, 'error': 'Email exists'}, status=400)
        
        username = email.split('@')[0]
        counter = 1
        while User.objects.filter(username=username).exists():
            username = f"{email.split('@')[0]}{counter}"
            counter += 1
        
        user = User.objects.create(
            username=username, email=email,
            first_name=name.split()[0] if name else '',
            password=make_password(password)
        )
        UserProfile.objects.get_or_create(user=user)
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        token, _ = Token.objects.get_or_create(user=user)
        
        return JsonResponse({
            'success': True, 'token': token.key,
            'user': {'id': user.id, 'email': user.email, 'name': user.first_name}
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


# ═══════════════════════════════════════════════════════════
# 🔌 API: LOGIN
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def api_login(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        logger.info(f"🔐 Login: {email}")
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Invalid credentials'}, status=401)
        
        auth_user = authenticate(request, username=user.username, password=password)
        if not auth_user:
            return JsonResponse({'success': False, 'error': 'Invalid credentials'}, status=401)
        
        login(request, auth_user)
        token, _ = Token.objects.get_or_create(user=auth_user)
        
        logger.info(f"✅ Login OK: {email}, Token: {token.key[:10]}...")
        
        return JsonResponse({
            'success': True,
            'token': token.key,
            'sessionid': request.session.session_key,
            'user': {
                'id': auth_user.id,
                'email': auth_user.email,
                'name': f"{auth_user.first_name} {auth_user.last_name}".strip() or auth_user.username,
            }
        })
    except Exception as e:
        logger.error(f"Login error: {e}")
        return JsonResponse({'success': False, 'error': 'Login failed'}, status=500)


# ═══════════════════════════════════════════════════════════
# 🔌 API: LOGOUT
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def api_logout(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if user:
        Token.objects.filter(user=user).delete()
    logout(request)
    return JsonResponse({'success': True})


# ═══════════════════════════════════════════════════════════
# 🔌 API: DASHBOARD
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def api_dashboard(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    logger.info(f"📊 Dashboard - User: {user}")
    
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        total_files = File.objects.filter(user=user, deleted=False).count()
        total_trash = File.objects.filter(user=user, deleted=True).count()
        total_storage = File.objects.filter(user=user, deleted=False).aggregate(total=Sum('size'))['total'] or 0
        
        recent_files = File.objects.filter(user=user, deleted=False).order_by('-uploaded_at')[:5]
        recent_data = [{'id': f.id, 'name': f.original_name, 'size': f.size} for f in recent_files]
        
        logger.info(f"✅ Dashboard OK: {user.email}")
        
        return JsonResponse({
            'success': True,
            'data': {
                'storageUsed': total_storage,
                'storageTotal': 10737418240,
                'totalFiles': total_files,
                'trashFiles': total_trash,
                'recentFiles': recent_data,
            }
        })
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


# ═══════════════════════════════════════════════════════════
# 🔌 API: USER PROFILE
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def api_user_profile(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    return JsonResponse({
        'success': True,
        'data': {'id': user.id, 'email': user.email, 'name': f"{user.first_name} {user.last_name}".strip()}
    })


# ═══════════════════════════════════════════════════════════
# 🔌 API: CHECK AUTH
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def api_check_auth(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if user:
        return JsonResponse({'authenticated': True, 'user': {'id': user.id, 'email': user.email}})
    return JsonResponse({'authenticated': False})


# ═══════════════════════════════════════════════════════════
# 🔌 API: GOOGLE OAUTH
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def api_google_login(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        code = data.get('code')
        
        if not code:
            return JsonResponse({'success': False, 'error': 'Code required'}, status=400)
        
        client_id = os.environ.get('GOOGLE_CLIENT_ID', '')
        client_secret = os.environ.get('GOOGLE_CLIENT_SECRET', '')
        
        if not client_id or not client_secret:
            logger.error("Google OAuth not configured")
            return JsonResponse({'success': False, 'error': 'Google OAuth not configured'}, status=501)
        
        origin = request.META.get('HTTP_ORIGIN', '')
        redirect_uri = 'http://localhost:3000/google-callback' if 'localhost' in origin else 'https://dropvault-frontend-1.onrender.com/google-callback'
        
        # Exchange code for token
        token_resp = http_requests.post('https://oauth2.googleapis.com/token', data={
            'code': code, 'client_id': client_id, 'client_secret': client_secret,
            'redirect_uri': redirect_uri, 'grant_type': 'authorization_code'
        }, timeout=10)
        
        if token_resp.status_code != 200:
            return JsonResponse({'success': False, 'error': 'Google auth failed'}, status=401)
        
        access_token = token_resp.json().get('access_token')
        
        # Get user info
        user_resp = http_requests.get('https://www.googleapis.com/oauth2/v2/userinfo',
            headers={'Authorization': f'Bearer {access_token}'}, timeout=10)
        
        if user_resp.status_code != 200:
            return JsonResponse({'success': False, 'error': 'Failed to get user info'}, status=401)
        
        google_user = user_resp.json()
        email = google_user.get('email')
        name = google_user.get('name', '')
        
        # Find or create user
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            username = email.split('@')[0]
            while User.objects.filter(username=username).exists():
                username = f"{username}1"
            user = User.objects.create(username=username, email=email, first_name=name.split()[0] if name else '')
            user.set_unusable_password()
            user.save()
            UserProfile.objects.get_or_create(user=user)
        
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        token, _ = Token.objects.get_or_create(user=user)
        
        logger.info(f"✅ Google OAuth: {email}")
        
        return JsonResponse({
            'success': True, 'token': token.key,
            'user': {'id': user.id, 'email': user.email, 'name': f"{user.first_name}".strip()}
        })
    except Exception as e:
        logger.error(f"Google OAuth error: {e}")
        return JsonResponse({'success': False, 'error': 'Google auth failed'}, status=500)


# ═══════════════════════════════════════════════════════════
# 🔌 OTHER API ENDPOINTS
# ═══════════════════════════════════════════════════════════
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


def format_file_size(size):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


@login_required
def upload_test(request):
    return render(request, 'upload_test.html')