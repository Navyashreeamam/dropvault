# accounts/views.py

import os
import json
import logging
import requests

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Sum
from django.contrib.auth import update_session_auth_hash

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
    
    return None


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
        
        logger.info(f"✅ Login OK: {email}")
        
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

@csrf_exempt
def api_logout(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if user:
        Token.objects.filter(user=user).delete()
    logout(request)
    return JsonResponse({'success': True})


@csrf_exempt
def api_dashboard(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    logger.info(f"📊 Dashboard - User: {user}")
    
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        # Import SharedLink here to avoid circular imports
        from files.models import SharedLink
        
        # Count files
        total_files = File.objects.filter(user=user, deleted=False).count()
        total_trash = File.objects.filter(user=user, deleted=True).count()
        
        # ✅ FIX: Count shared links (active and not expired)
        shared_links = SharedLink.objects.filter(owner=user, is_active=True)
        shared_count = 0
        for link in shared_links:
            if not link.is_expired():
                shared_count += 1
        
        # Calculate storage
        total_storage = File.objects.filter(user=user, deleted=False).aggregate(total=Sum('size'))['total'] or 0
        
        # Get recent files
        recent_files = File.objects.filter(user=user, deleted=False).order_by('-uploaded_at')[:5]
        recent_data = [
            {
                'id': f.id,
                'name': f.original_name,
                'filename': f.original_name,
                'size': f.size
            } for f in recent_files
        ]
        
        logger.info(f"✅ Dashboard OK: {user.email} - Files: {total_files}, Shared: {shared_count}")
        
        return JsonResponse({
            'success': True,
            'data': {
                'storageUsed': total_storage,
                'storage_used': total_storage,
                'storageTotal': 10737418240,  # 10GB
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

@csrf_exempt
def api_check_auth(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if user:
        return JsonResponse({'authenticated': True, 'user': {'id': user.id, 'email': user.email}})
    return JsonResponse({'authenticated': False})

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
            logger.error("❌ No authorization code provided")
            return JsonResponse({'success': False, 'error': 'Authorization code required'}, status=400)
        
        # Get credentials from environment
        client_id = os.environ.get('GOOGLE_CLIENT_ID', '').strip()
        client_secret = os.environ.get('GOOGLE_CLIENT_SECRET', '').strip()
        
        logger.info("=" * 50)
        logger.info("🔐 GOOGLE OAUTH REQUEST")
        logger.info(f"   Client ID exists: {bool(client_id)}")
        logger.info(f"   Client Secret exists: {bool(client_secret)}")
        
        if not client_id or not client_secret:
            logger.error("❌ Google OAuth credentials not configured!")
            return JsonResponse({
                'success': False, 
                'error': 'Google OAuth is not configured. Please contact admin.'
            }, status=501)
        
        # Determine redirect URI based on origin
        origin = request.META.get('HTTP_ORIGIN', '')
        logger.info(f"   Origin: {origin}")
        
        if 'localhost' in origin or '127.0.0.1' in origin:
            redirect_uri = 'http://localhost:3000/google-callback'
        else:
            redirect_uri = 'https://dropvault-frontend-1.onrender.com/google-callback'
        
        logger.info(f"   Redirect URI: {redirect_uri}")
        
        # Exchange code for token
        logger.info("🔐 Exchanging code for token...")
        
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
        
        logger.info(f"   Token response status: {token_response.status_code}")
        
        if token_response.status_code != 200:
            logger.error(f"❌ Token exchange failed: {token_response.text}")
            return JsonResponse({
                'success': False,
                'error': 'Failed to authenticate with Google'
            }, status=401)
        
        token_data = token_response.json()
        access_token = token_data.get('access_token')
        
        if not access_token:
            logger.error("❌ No access token received")
            return JsonResponse({'success': False, 'error': 'No access token'}, status=401)
        
        logger.info("✅ Got access token, fetching user info...")
        
        # Get user info from Google
        user_response = requests.get(
            'https://www.googleapis.com/oauth2/v2/userinfo',
            headers={'Authorization': f'Bearer {access_token}'},
            timeout=10
        )
        
        if user_response.status_code != 200:
            logger.error(f"❌ User info failed: {user_response.text}")
            return JsonResponse({'success': False, 'error': 'Failed to get user info'}, status=401)
        
        google_user = user_response.json()
        email = google_user.get('email')
        name = google_user.get('name', '')
        
        logger.info(f"   Google email: {email}")
        
        if not email:
            return JsonResponse({'success': False, 'error': 'No email from Google'}, status=400)
        
        # Find or create user
        try:
            user = User.objects.get(email=email)
            logger.info(f"   Found existing user")
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
            logger.info(f"   Created new user")
        
        # Login user
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        token, _ = Token.objects.get_or_create(user=user)
        
        logger.info(f"✅ Google OAuth SUCCESS: {email}")
        logger.info("=" * 50)
        
        return JsonResponse({
            'success': True,
            'token': token.key,
            'sessionid': request.session.session_key,
            'user': {
                'id': user.id,
                'email': user.email,
                'name': f"{user.first_name} {user.last_name}".strip() or user.username,
            }
        })
        
    except requests.Timeout:
        logger.error("❌ Google OAuth timeout")
        return JsonResponse({'success': False, 'error': 'Request timed out'}, status=504)
    except json.JSONDecodeError:
        logger.error("❌ Invalid JSON")
        return JsonResponse({'success': False, 'error': 'Invalid request'}, status=400)
    except Exception as e:
        logger.error(f"❌ Google OAuth error: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({'success': False, 'error': 'Google authentication failed'}, status=500)


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

@csrf_exempt
def api_notifications(request):
    """Get all visible notifications for the user"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        from .models import Notification
        
        # Cleanup old read notifications first
        Notification.cleanup_old_notifications(user)
        
        # Get visible notifications
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
        
        logger.info(f"🔔 Notifications for {user.email}: {len(notification_list)} total, {unread_count} unread")
        
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
    """Mark a single notification as read"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        from .models import Notification
        
        notification = Notification.objects.get(id=notification_id, user=user)
        notification.mark_as_read()
        
        logger.info(f"🔔 Marked notification {notification_id} as read for {user.email}")
        
        return JsonResponse({
            'success': True,
            'message': 'Notification marked as read'
        })
        
    except Notification.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Notification not found'}, status=404)
    except Exception as e:
        logger.error(f"Mark read error: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
def api_notifications_read_all(request):
    """Mark all notifications as read"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        from .models import Notification
        from django.utils import timezone
        
        # Mark all unread as read
        updated = Notification.objects.filter(
            user=user,
            is_read=False
        ).update(
            is_read=True,
            read_at=timezone.now()
        )
        
        logger.info(f"🔔 Marked {updated} notifications as read for {user.email}")
        
        return JsonResponse({
            'success': True,
            'message': f'{updated} notifications marked as read',
            'count': updated
        })
        
    except Exception as e:
        logger.error(f"Mark all read error: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
def api_notification_delete(request, notification_id):
    """Delete a specific notification"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "DELETE":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        from .models import Notification
        
        notification = Notification.objects.get(id=notification_id, user=user)
        notification.delete()
        
        logger.info(f"🔔 Deleted notification {notification_id} for {user.email}")
        
        return JsonResponse({
            'success': True,
            'message': 'Notification deleted'
        })
        
    except Notification.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Notification not found'}, status=404)
    except Exception as e:
        logger.error(f"Delete notification error: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
def upload_test(request):
    return render(request, 'upload_test.html')


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


@csrf_exempt
def api_user_storage(request):
    """Return user's storage information"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        # Calculate storage from files
        from files.models import File
        from django.db.models import Sum
        
        # Get total storage used (only non-deleted files)
        total_storage = File.objects.filter(
            user=user, 
            deleted=False
        ).aggregate(total=Sum('size'))['total'] or 0
        
        # Get file count
        file_count = File.objects.filter(user=user, deleted=False).count()
        
        # Storage limit (10GB default)
        storage_limit = 10 * 1024 * 1024 * 1024  # 10GB in bytes
        storage_remaining = max(0, storage_limit - total_storage)
        storage_percentage = round((total_storage / storage_limit) * 100, 2) if storage_limit > 0 else 0
        
        logger.info(f"📊 Storage for {user.email}: {total_storage} bytes, {file_count} files")
        
        return JsonResponse({
            'success': True,
            'storage': {
                'used': total_storage,
                'used_formatted': format_file_size(total_storage),
                'limit': storage_limit,
                'limit_formatted': format_file_size(storage_limit),
                'remaining': storage_remaining,
                'remaining_formatted': format_file_size(storage_remaining),
                'percentage': storage_percentage,
                'file_count': file_count,
            }
        })
        
    except Exception as e:
        logger.error(f"Storage API error: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({'success': False, 'error': str(e)}, status=500)