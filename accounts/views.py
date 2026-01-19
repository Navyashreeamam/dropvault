# accounts/views.py - COMPLETE WITH ALL FIXES

import os
import json
import logging
import requests
import secrets

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password, check_password
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.db.models import Sum
from django.contrib.auth import update_session_auth_hash
from django.db import transaction
from django.utils import timezone
from django.conf import settings
from django.core.cache import cache

from django_otp import match_token
from django_otp.plugins.otp_totp.models import TOTPDevice
from rest_framework.authtoken.models import Token

from .models import UserProfile
from files.models import File

logger = logging.getLogger(__name__)
User = get_user_model()


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
    
    session_id = request.META.get('HTTP_X_SESSION_ID', '')
    if session_id:
        try:
            from django.contrib.sessions.models import Session
            session = Session.objects.get(session_key=session_id)
            session_data = session.get_decoded()
            user_id = session_data.get('_auth_user_id')
            if user_id:
                return User.objects.get(pk=user_id)
        except:
            pass
    
    return None


# ============================================================================
# WEB VIEWS
# ============================================================================

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
    password = request.POST.get('password', '')
    
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


# ============================================================================
# API: SIGNUP
# ============================================================================

@csrf_exempt
def api_signup(request):
    """API endpoint for user signup"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        name = data.get('name', '').strip()
        
        logger.info("=" * 70)
        logger.info(f"📝 SIGNUP ATTEMPT: {email}")
        logger.info(f"   Password length: {len(password)}")
        logger.info("=" * 70)
        
        if not email or not password:
            return JsonResponse({'success': False, 'error': 'Email and password are required'}, status=400)
        
        if len(password) < 8:
            return JsonResponse({'success': False, 'error': 'Password must be at least 8 characters'}, status=400)
        
        if User.objects.filter(email=email).exists():
            return JsonResponse({'success': False, 'error': 'Email already exists. Please login or reset password.'}, status=400)
        
        username = email.split('@')[0]
        counter = 1
        base_username = username
        while User.objects.filter(username=username).exists():
            username = f"{base_username}{counter}"
            counter += 1
        
        name_parts = name.split() if name else [username]
        first_name = name_parts[0] if name_parts else ''
        last_name = ' '.join(name_parts[1:]) if len(name_parts) > 1 else ''
        
        with transaction.atomic():
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name
            )
            UserProfile.objects.get_or_create(user=user)
        
        # Verify password was set correctly
        verified = check_password(password, user.password)
        logger.info(f"   Password verification: {verified}")
        
        if not verified:
            user.set_password(password)
            user.save()
        
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        token, _ = Token.objects.get_or_create(user=user)
        
        logger.info(f"✅ SIGNUP SUCCESS: {email}")
        
        return JsonResponse({
            'success': True,
            'message': 'Account created successfully',
            'token': token.key,
            'sessionid': request.session.session_key,
            'user': {
                'id': user.id,
                'email': user.email,
                'username': user.username,
                'name': f"{user.first_name} {user.last_name}".strip() or user.username,
            }
        })
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"❌ Signup error: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


# ============================================================================
# API: LOGIN
# ============================================================================

@csrf_exempt
def api_login(request):
    """API endpoint for user login"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        logger.info("=" * 70)
        logger.info(f"🔐 LOGIN ATTEMPT: {email}")
        logger.info(f"   Password length: {len(password)}")
        logger.info("=" * 70)
        
        if not email or not password:
            return JsonResponse({'success': False, 'error': 'Email and password are required'}, status=400)
        
        # Find user
        try:
            user = User.objects.get(email=email)
            logger.info(f"   ✅ User found: {user.username} (ID: {user.id})")
            logger.info(f"   Has usable password: {user.has_usable_password()}")
        except User.DoesNotExist:
            logger.warning(f"   ❌ User NOT FOUND: {email}")
            return JsonResponse({'success': False, 'error': 'Invalid email or password'}, status=401)
        
        if not user.is_active:
            return JsonResponse({'success': False, 'error': 'Account is disabled'}, status=403)
        
        if not user.has_usable_password():
            return JsonResponse({
                'success': False,
                'error': 'This account uses Google Sign-In. Please use Google login or reset your password.',
                'oauth_account': True
            }, status=401)
        
        # Check password
        logger.info(f"   Verifying password...")
        password_matches = check_password(password, user.password)
        logger.info(f"   Password check result: {password_matches}")
        
        if not password_matches:
            logger.warning(f"   ❌ INCORRECT PASSWORD for {email}")
            return JsonResponse({'success': False, 'error': 'Invalid email or password'}, status=401)
        
        # Password correct - login
        logger.info(f"   Password correct, authenticating...")
        
        auth_user = authenticate(request, username=user.username, password=password)
        if auth_user is None:
            auth_user = user
        
        login(request, auth_user, backend='django.contrib.auth.backends.ModelBackend')
        token, _ = Token.objects.get_or_create(user=auth_user)
        
        logger.info(f"✅ LOGIN SUCCESS: {email}")
        logger.info(f"   Token: {token.key[:15]}...")
        logger.info(f"   Session: {request.session.session_key}")
        logger.info("=" * 70)
        
        return JsonResponse({
            'success': True,
            'message': 'Login successful',
            'token': token.key,
            'sessionid': request.session.session_key,
            'user': {
                'id': auth_user.id,
                'email': auth_user.email,
                'username': auth_user.username,
                'name': f"{auth_user.first_name} {auth_user.last_name}".strip() or auth_user.username,
            }
        })
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"❌ Login error: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({'success': False, 'error': 'Login failed'}, status=500)


# ============================================================================
# API: LOGOUT
# ============================================================================

@csrf_exempt
def api_logout(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if user:
        Token.objects.filter(user=user).delete()
    logout(request)
    return JsonResponse({'success': True})


# ============================================================================
# API: GOOGLE OAUTH
# ============================================================================

@csrf_exempt
def api_google_login(request):
    """Handle Google OAuth login"""
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
        
        token_response = requests.post(
            'https://oauth2.googleapis.com/token',
            data={
                'code': code,
                'client_id': client_id,
                'client_secret': client_secret,
                'redirect_uri': redirect_uri,
                'grant_type': 'authorization_code'
            },
            timeout=15
        )
        
        if token_response.status_code != 200:
            return JsonResponse({'success': False, 'error': 'Failed to authenticate with Google'}, status=401)
        
        token_data = token_response.json()
        access_token = token_data.get('access_token')
        
        if not access_token:
            return JsonResponse({'success': False, 'error': 'No access token'}, status=401)
        
        user_response = requests.get(
            'https://www.googleapis.com/oauth2/v2/userinfo',
            headers={'Authorization': f'Bearer {access_token}'},
            timeout=10
        )
        
        if user_response.status_code != 200:
            return JsonResponse({'success': False, 'error': 'Failed to get user info'}, status=401)
        
        google_user = user_response.json()
        email = google_user.get('email', '').lower()
        name = google_user.get('name', '')
        
        if not email:
            return JsonResponse({'success': False, 'error': 'No email from Google'}, status=400)
        
        logger.info(f"🔐 Google OAuth: {email}")
        
        user_created = False
        
        try:
            user = User.objects.get(email=email)
            logger.info(f"   Found existing user")
            # DON'T overwrite existing password
        except User.DoesNotExist:
            username = email.split('@')[0]
            counter = 1
            while User.objects.filter(username=username).exists():
                username = f"{email.split('@')[0]}{counter}"
                counter += 1
            
            name_parts = name.split() if name else [username]
            
            # Create with a known password pattern for OAuth users
            # Using email prefix + fixed suffix
            default_password = secrets.token_urlsafe(16)
            
            user = User.objects.create_user(
                username=username,
                email=email,
                password=default_password,
                first_name=name_parts[0] if name_parts else '',
                last_name=' '.join(name_parts[1:]) if len(name_parts) > 1 else '',
            )
            UserProfile.objects.get_or_create(user=user)
            user_created = True
            logger.info(f"   Created new user")
        
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        token, _ = Token.objects.get_or_create(user=user)
        
        logger.info(f"✅ Google OAuth SUCCESS: {email}")
        
        return JsonResponse({
            'success': True,
            'token': token.key,
            'sessionid': request.session.session_key,
            'user': {
                'id': user.id,
                'email': user.email,
                'name': f"{user.first_name} {user.last_name}".strip() or user.username,
            },
            'first_time': user_created
        })
        
    except Exception as e:
        logger.error(f"❌ Google OAuth error: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({'success': False, 'error': 'Google authentication failed'}, status=500)


# ============================================================================
# API: DASHBOARD
# ============================================================================

@csrf_exempt
def api_dashboard(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    logger.info(f"📊 Dashboard - User: {user}")
    
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        from files.models import SharedLink
        
        total_files = File.objects.filter(user=user, deleted=False).count()
        total_trash = File.objects.filter(user=user, deleted=True).count()
        
        shared_links = SharedLink.objects.filter(owner=user, is_active=True)
        shared_count = sum(1 for link in shared_links if not link.is_expired())
        
        total_storage = File.objects.filter(user=user, deleted=False).aggregate(total=Sum('size'))['total'] or 0
        
        recent_files = File.objects.filter(user=user, deleted=False).order_by('-uploaded_at')[:5]
        recent_data = [{'id': f.id, 'name': f.original_name, 'filename': f.original_name, 'size': f.size} for f in recent_files]
        
        logger.info(f"✅ Dashboard OK: {user.email} - Files: {total_files}, Shared: {shared_count}")
        
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
            }
        })
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


# ============================================================================
# API: USER
# ============================================================================

@csrf_exempt
def api_user_profile(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    return JsonResponse({
        'success': True,
        'data': {
            'id': user.id,
            'email': user.email,
            'name': f"{user.first_name} {user.last_name}".strip(),
            'username': user.username,
            'has_password': user.has_usable_password(),
        }
    })


@csrf_exempt
def api_check_auth(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if user:
        return JsonResponse({
            'authenticated': True,
            'user': {'id': user.id, 'email': user.email, 'name': f"{user.first_name} {user.last_name}".strip() or user.username}
        })
    return JsonResponse({'authenticated': False})


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
    
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            if 'first_name' in data:
                user.first_name = data['first_name'].strip()
            if 'last_name' in data:
                user.last_name = data['last_name'].strip()
            user.save()
            return JsonResponse({'success': True, 'message': 'Profile updated'})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=500)
    
    return JsonResponse({'success': True})


@csrf_exempt
def api_change_password(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        data = json.loads(request.body)
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')
        confirm_password = data.get('confirm_password', '')
        
        if len(new_password) < 8:
            return JsonResponse({'success': False, 'error': 'Password must be at least 8 characters'}, status=400)
        
        if new_password != confirm_password:
            return JsonResponse({'success': False, 'error': 'Passwords do not match'}, status=400)
        
        if user.has_usable_password() and current_password:
            if not check_password(current_password, user.password):
                return JsonResponse({'success': False, 'error': 'Current password is incorrect'}, status=400)
        
        user.set_password(new_password)
        user.save()
        update_session_auth_hash(request, user)
        
        return JsonResponse({'success': True, 'message': 'Password changed successfully'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
def api_preferences(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    return JsonResponse({'success': True, 'data': {}})


# ============================================================================
# API: PASSWORD RESET
# ============================================================================

@csrf_exempt
def api_forgot_password(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()
        
        if not email:
            return JsonResponse({'success': False, 'error': 'Email required'}, status=400)
        
        try:
            user = User.objects.get(email=email)
            reset_token = secrets.token_urlsafe(32)
            cache.set(f'password_reset:{reset_token}', {'user_id': user.id, 'email': email}, timeout=3600)
            
            site_url = getattr(settings, 'SITE_URL', 'http://localhost:8000')
            reset_link = f"{site_url}/reset-password?token={reset_token}"
            
            logger.info(f"🔐 Password reset: {email}")
            logger.info(f"   Link: {reset_link}")
            
            try:
                from .utils import send_password_reset_email
                send_password_reset_email(user.email, user.first_name or user.username, reset_link)
            except Exception as e:
                logger.error(f"Email failed: {e}")
        except User.DoesNotExist:
            pass
        
        return JsonResponse({'success': True, 'message': 'If account exists, reset link has been sent'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': 'Request failed'}, status=500)


@csrf_exempt
def api_verify_reset_token(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    token = request.GET.get('token', '')
    if not token:
        return JsonResponse({'valid': False, 'error': 'Token required'}, status=400)
    
    reset_data = cache.get(f'password_reset:{token}')
    if reset_data:
        email = reset_data.get('email', '')
        masked = email[:3] + '***@' + email.split('@')[1] if '@' in email else '***'
        return JsonResponse({'valid': True, 'email': masked})
    
    return JsonResponse({'valid': False, 'error': 'Invalid or expired token'})


@csrf_exempt
def api_reset_password(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        token = data.get('token', '').strip()
        new_password = data.get('password', '')
        confirm_password = data.get('confirm_password', '')
        
        if not token:
            return JsonResponse({'success': False, 'error': 'Token required'}, status=400)
        
        if len(new_password) < 8:
            return JsonResponse({'success': False, 'error': 'Password must be at least 8 characters'}, status=400)
        
        if new_password != confirm_password:
            return JsonResponse({'success': False, 'error': 'Passwords do not match'}, status=400)
        
        reset_data = cache.get(f'password_reset:{token}')
        if not reset_data:
            return JsonResponse({'success': False, 'error': 'Invalid or expired token'}, status=400)
        
        try:
            user = User.objects.get(id=reset_data['user_id'])
            user.set_password(new_password)
            user.save()
            cache.delete(f'password_reset:{token}')
            Token.objects.filter(user=user).delete()
            
            logger.info(f"✅ Password reset: {user.email}")
            return JsonResponse({'success': True, 'message': 'Password reset successfully'})
        except User.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'User not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'error': 'Reset failed'}, status=500)


@csrf_exempt
@require_http_methods(["POST", "OPTIONS"])
def api_set_password(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Must be logged in'}, status=401)
    
    try:
        data = json.loads(request.body)
        new_password = data.get('password', '')
        confirm_password = data.get('confirm_password', '')
        
        if len(new_password) < 8:
            return JsonResponse({'success': False, 'error': 'Password must be at least 8 characters'}, status=400)
        
        if new_password != confirm_password:
            return JsonResponse({'success': False, 'error': 'Passwords do not match'}, status=400)
        
        user.set_password(new_password)
        user.save()
        update_session_auth_hash(request, user)
        
        return JsonResponse({'success': True, 'message': 'Password set successfully'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


# ============================================================================
# API: NOTIFICATIONS
# ============================================================================

@csrf_exempt
def api_notifications(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        from .models import Notification
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
        
        logger.info(f"🔔 Notifications: {len(notification_list)} total, {unread_count} unread")
        
        return JsonResponse({
            'success': True,
            'notifications': notification_list,
            'unread_count': unread_count,
            'total_count': len(notification_list)
        })
    except Exception as e:
        logger.error(f"Notification error: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
def api_notification_read(request, notification_id):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        from .models import Notification
        notification = Notification.objects.get(id=notification_id, user=user)
        notification.mark_as_read()
        return JsonResponse({'success': True})
    except:
        return JsonResponse({'success': False, 'error': 'Not found'}, status=404)


@csrf_exempt
def api_notifications_read_all(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        from .models import Notification
        updated = Notification.objects.filter(user=user, is_read=False).update(is_read=True, read_at=timezone.now())
        return JsonResponse({'success': True, 'count': updated})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
def api_notification_delete(request, notification_id):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "DELETE":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        from .models import Notification
        Notification.objects.get(id=notification_id, user=user).delete()
        return JsonResponse({'success': True})
    except:
        return JsonResponse({'success': False, 'error': 'Not found'}, status=404)


# ============================================================================
# API: STORAGE
# ============================================================================

@csrf_exempt
def api_user_storage(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        total_storage = File.objects.filter(user=user, deleted=False).aggregate(total=Sum('size'))['total'] or 0
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
                'remaining_formatted': format_file_size(max(0, storage_limit - total_storage)),
                'percentage': round((total_storage / storage_limit) * 100, 2) if storage_limit > 0 else 0,
                'file_count': file_count,
            }
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


# ============================================================================
# API: DEBUG ENDPOINTS (REMOVE IN PRODUCTION!)
# ============================================================================

@csrf_exempt
def api_debug_user(request):
    """Check user details"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    email = request.GET.get('email', '').strip().lower()
    if not email:
        return JsonResponse({'error': 'Email required'}, status=400)
    
    try:
        user = User.objects.get(email=email)
        return JsonResponse({
            'success': True,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_active': user.is_active,
                'has_usable_password': user.has_usable_password(),
            }
        })
    except User.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'User not found'}, status=404)


@csrf_exempt
def api_debug_fix_password(request):
    """Fix password for a user"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'POST required'}, status=405)
    
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
        logger.info(f"🔧 Password fixed for {email}, verified: {verified}")
        
        return JsonResponse({
            'success': True,
            'email': email,
            'password_verified': verified,
            'message': f'Password set successfully'
        })
    except User.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'User not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
def api_debug_list_users(request):
    """List all users"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    users = User.objects.all().order_by('id')
    user_list = []
    
    for user in users:
        user_list.append({
            'id': user.id,
            'email': user.email,
            'username': user.username,
            'has_password': user.has_usable_password(),
            'is_active': user.is_active,
        })
    
    return JsonResponse({
        'success': True,
        'count': len(user_list),
        'users': user_list
    })


# ============================================================================
# HELPERS
# ============================================================================

def format_file_size(size_bytes):
    if size_bytes == 0:
        return "0 B"
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    unit_index = 0
    size = float(size_bytes)
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1
    return f"{size:.2f} {units[unit_index]}"


def test_email(request):
    return HttpResponse("OK")


@login_required
def upload_test(request):
    return render(request, 'upload_test.html')

# accounts/views.py - ADD this endpoint temporarily

@csrf_exempt
def api_fix_all_oauth_users(request):
    """
    FIX ALL OAuth users by setting a known password.
    This is a ONE-TIME fix for existing users.
    REMOVE THIS AFTER USE!
    """
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'POST required'}, status=405)
    
    try:
        data = json.loads(request.body)
        default_password = data.get('default_password', '')
        
        if not default_password or len(default_password) < 8:
            return JsonResponse({
                'success': False,
                'error': 'Provide default_password (min 8 chars)'
            }, status=400)
        
        # Get all users
        users = User.objects.all()
        fixed = []
        skipped = []
        
        for user in users:
            # Check if user has a real password (not random OAuth password)
            # OAuth users typically have random 16+ char passwords
            if not user.has_usable_password():
                # No password - set one
                user.set_password(default_password)
                user.save()
                fixed.append(user.email)
            else:
                skipped.append(user.email)
        
        return JsonResponse({
            'success': True,
            'message': f'Fixed {len(fixed)} users',
            'fixed_users': fixed,
            'skipped_users': skipped,
            'note': f'Fixed users can now login with password: {default_password}'
        })
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)