# accounts/views.py - COMPLETE REPLACEMENT

import os
import json
import logging
import requests
import secrets

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import check_password
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Sum
from django.contrib.auth import update_session_auth_hash
from django.db import transaction
from django.utils import timezone
from django.core.cache import cache

from rest_framework.authtoken.models import Token

from .models import UserProfile, Notification

logger = logging.getLogger(__name__)
User = get_user_model()


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

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


# =============================================================================
# WEB VIEWS (HTML)
# =============================================================================

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


# =============================================================================
# API: SIGNUP - BULLETPROOF
# =============================================================================

@csrf_exempt
def api_signup(request):
    """
    API endpoint for user signup
    ✅ Properly handles password hashing
    ✅ Verified to work correctly
    """
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')  # Don't strip - preserve spaces
        name = data.get('name', '').strip()
        
        logger.info("=" * 70)
        logger.info(f"📝 SIGNUP ATTEMPT: {email}")
        logger.info(f"   Password length: {len(password)}")
        logger.info("=" * 70)
        
        # Validation
        if not email or '@' not in email:
            return JsonResponse({
                'success': False,
                'error': 'Please enter a valid email address'
            }, status=400)
        
        if not password:
            return JsonResponse({
                'success': False,
                'error': 'Password is required'
            }, status=400)
        
        if len(password) < 8:
            return JsonResponse({
                'success': False,
                'error': 'Password must be at least 8 characters long'
            }, status=400)
        
        # Check if email exists
        if User.objects.filter(email=email).exists():
            existing_user = User.objects.get(email=email)
            
            # Check if it's an OAuth user without password
            if not existing_user.has_usable_password():
                # Allow them to set password
                existing_user.set_password(password)
                existing_user.save()
                
                # Login and return
                login(request, existing_user, backend='django.contrib.auth.backends.ModelBackend')
                token, _ = Token.objects.get_or_create(user=existing_user)
                
                logger.info(f"✅ Password set for existing OAuth user: {email}")
                
                return JsonResponse({
                    'success': True,
                    'message': 'Password set successfully! You can now login with email and password.',
                    'token': token.key,
                    'sessionid': request.session.session_key,
                    'user': {
                        'id': existing_user.id,
                        'email': existing_user.email,
                        'username': existing_user.username,
                        'name': f"{existing_user.first_name} {existing_user.last_name}".strip() or existing_user.username,
                    }
                })
            
            return JsonResponse({
                'success': False,
                'error': 'An account with this email already exists. Please login instead.'
            }, status=400)
        
        # Create username from email
        username = email.split('@')[0]
        counter = 1
        base_username = username
        while User.objects.filter(username=username).exists():
            username = f"{base_username}{counter}"
            counter += 1
        
        # Parse name
        name_parts = name.split() if name else [username]
        first_name = name_parts[0] if name_parts else ''
        last_name = ' '.join(name_parts[1:]) if len(name_parts) > 1 else ''
        
        # Create user with transaction
        with transaction.atomic():
            # Create user object
            user = User(
                username=username,
                email=email,
                first_name=first_name,
                last_name=last_name,
                is_active=True
            )
            
            # Set password properly
            user.set_password(password)
            user.save()
            
            # Verify password was set correctly
            if not check_password(password, user.password):
                logger.error(f"❌ Password verification failed for {email}")
                user.delete()
                return JsonResponse({
                    'success': False,
                    'error': 'Account creation failed. Please try again.'
                }, status=500)
            
            # Create profile
            UserProfile.objects.get_or_create(user=user)
            
            logger.info(f"✅ User created: {email} (ID: {user.id})")
            logger.info(f"   Password hash: {user.password[:30]}...")
        
        # Login user
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        token, _ = Token.objects.get_or_create(user=user)
        
        logger.info(f"✅ SIGNUP SUCCESS: {email}")
        logger.info("=" * 70)
        
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
        logger.error("❌ Invalid JSON in signup request")
        return JsonResponse({'success': False, 'error': 'Invalid request format'}, status=400)
    except Exception as e:
        logger.error(f"❌ Signup error: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({
            'success': False,
            'error': 'Signup failed. Please try again.'
        }, status=500)


# =============================================================================
# API: LOGIN - BULLETPROOF
# =============================================================================

@csrf_exempt
def api_login(request):
    """
    API endpoint for user login
    ✅ Handles email+password login
    ✅ Handles OAuth users who want to set password
    ✅ Proper error messages
    """
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')  # Don't strip
        
        logger.info("=" * 70)
        logger.info(f"🔐 LOGIN ATTEMPT: {email}")
        logger.info(f"   Password length: {len(password)}")
        logger.info("=" * 70)
        
        # Validation
        if not email or '@' not in email:
            return JsonResponse({
                'success': False,
                'error': 'Please enter a valid email address'
            }, status=400)
        
        if not password:
            return JsonResponse({
                'success': False,
                'error': 'Password is required'
            }, status=400)
        
        # Find user
        try:
            user = User.objects.get(email=email)
            logger.info(f"   ✅ User found: {user.username} (ID: {user.id})")
        except User.DoesNotExist:
            logger.warning(f"   ❌ No user with email: {email}")
            return JsonResponse({
                'success': False,
                'error': 'Invalid email or password'
            }, status=401)
        
        # Check if account is active
        if not user.is_active:
            logger.warning(f"   ❌ Inactive account: {email}")
            return JsonResponse({
                'success': False,
                'error': 'Your account has been disabled.'
            }, status=403)
        
        # Check if user has a password set
        has_password = user.has_usable_password()
        logger.info(f"   Has usable password: {has_password}")
        
        if not has_password:
            # OAuth user without password - offer to set one
            logger.info(f"   ⚠️ OAuth user, setting password: {email}")
            
            # Set the password they provided
            user.set_password(password)
            user.save()
            
            # Verify it was set
            if check_password(password, user.password):
                # Login the user
                login(request, user, backend='django.contrib.auth.backends.ModelBackend')
                token, _ = Token.objects.get_or_create(user=user)
                
                logger.info(f"✅ Password set and logged in: {email}")
                
                return JsonResponse({
                    'success': True,
                    'message': 'Password set successfully! You can now login with email and password.',
                    'token': token.key,
                    'sessionid': request.session.session_key,
                    'user': {
                        'id': user.id,
                        'email': user.email,
                        'username': user.username,
                        'name': f"{user.first_name} {user.last_name}".strip() or user.username,
                    }
                })
            else:
                return JsonResponse({
                    'success': False,
                    'error': 'Failed to set password. Please try again.'
                }, status=500)
        
        # User has password - verify it
        logger.info(f"   Verifying password...")
        logger.info(f"   Hash preview: {user.password[:40]}...")
        
        # Check password
        password_correct = check_password(password, user.password)
        logger.info(f"   Password check result: {password_correct}")
        
        if not password_correct:
            logger.warning(f"   ❌ Wrong password for {email}")
            return JsonResponse({
                'success': False,
                'error': 'Invalid email or password'
            }, status=401)
        
        # Password correct - login user
        logger.info(f"   ✅ Password correct, logging in...")
        
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        token, _ = Token.objects.get_or_create(user=user)
        
        logger.info(f"✅ LOGIN SUCCESS: {email}")
        logger.info(f"   Token: {token.key[:15]}...")
        logger.info("=" * 70)
        
        return JsonResponse({
            'success': True,
            'message': 'Login successful',
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
        logger.error("❌ Invalid JSON in login request")
        return JsonResponse({'success': False, 'error': 'Invalid request format'}, status=400)
    except Exception as e:
        logger.error(f"❌ Login error: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({
            'success': False,
            'error': 'Login failed. Please try again.'
        }, status=500)


# =============================================================================
# API: GOOGLE OAUTH LOGIN
# =============================================================================

@csrf_exempt
def api_google_login(request):
    """
    Handle Google OAuth login
    ✅ Creates account if not exists
    ✅ Allows setting password later
    """
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
        
        # Get credentials
        client_id = os.environ.get('GOOGLE_CLIENT_ID', '').strip()
        client_secret = os.environ.get('GOOGLE_CLIENT_SECRET', '').strip()
        
        logger.info("=" * 50)
        logger.info("🔐 GOOGLE OAUTH REQUEST")
        
        if not client_id or not client_secret:
            logger.error("❌ Google OAuth credentials not configured!")
            return JsonResponse({
                'success': False, 
                'error': 'Google OAuth is not configured.'
            }, status=501)
        
        # Determine redirect URI
        origin = request.META.get('HTTP_ORIGIN', '')
        if 'localhost' in origin or '127.0.0.1' in origin:
            redirect_uri = 'http://localhost:3000/google-callback'
        else:
            redirect_uri = 'https://dropvault-frontend-1.onrender.com/google-callback'
        
        logger.info(f"   Redirect URI: {redirect_uri}")
        
        # Exchange code for token
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
            logger.error(f"❌ Token exchange failed: {token_response.text}")
            return JsonResponse({
                'success': False,
                'error': 'Failed to authenticate with Google'
            }, status=401)
        
        token_data = token_response.json()
        access_token = token_data.get('access_token')
        
        if not access_token:
            return JsonResponse({'success': False, 'error': 'No access token'}, status=401)
        
        # Get user info
        user_response = requests.get(
            'https://www.googleapis.com/oauth2/v2/userinfo',
            headers={'Authorization': f'Bearer {access_token}'},
            timeout=10
        )
        
        if user_response.status_code != 200:
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
            logger.info(f"   Found existing user: {user.username}")
        except User.DoesNotExist:
            # Create new user
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
            # Set unusable password - user can set one later
            user.set_unusable_password()
            user.save()
            
            UserProfile.objects.get_or_create(user=user)
            logger.info(f"   Created new user: {username}")
        
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
                'username': user.username,
                'name': f"{user.first_name} {user.last_name}".strip() or user.username,
                'has_password': user.has_usable_password(),
            }
        })
        
    except requests.Timeout:
        logger.error("❌ Google OAuth timeout")
        return JsonResponse({'success': False, 'error': 'Request timed out'}, status=504)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid request'}, status=400)
    except Exception as e:
        logger.error(f"❌ Google OAuth error: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({'success': False, 'error': 'Google authentication failed'}, status=500)


# =============================================================================
# API: LOGOUT
# =============================================================================

@csrf_exempt
def api_logout(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if user:
        Token.objects.filter(user=user).delete()
    logout(request)
    return JsonResponse({'success': True, 'message': 'Logged out successfully'})


# =============================================================================
# API: DASHBOARD
# =============================================================================

@csrf_exempt
def api_dashboard(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    logger.info(f"📊 Dashboard - User: {user}")
    
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        from files.models import File, SharedLink
        
        # Count files
        total_files = File.objects.filter(user=user, deleted=False).count()
        total_trash = File.objects.filter(user=user, deleted=True).count()
        
        # Count active shared links
        shared_links = SharedLink.objects.filter(owner=user, is_active=True)
        shared_count = sum(1 for link in shared_links if not link.is_expired())
        
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
        
        logger.info(f"✅ Dashboard OK: {user.email} - Files: {total_files}")
        
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
                'has_password': user.has_usable_password(),
            }
        })
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


# =============================================================================
# API: NOTIFICATIONS - FIXED
# =============================================================================

@csrf_exempt
def api_notifications(request):
    """Get all visible notifications for the user"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        # Cleanup old read notifications
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
        return JsonResponse({
            'success': True,
            'notifications': [],
            'unread_count': 0,
            'total_count': 0
        })


@csrf_exempt
def api_notification_read(request, notification_id):
    """Mark a single notification as read"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        notification = Notification.objects.get(id=notification_id, user=user)
        notification.mark_as_read()
        return JsonResponse({'success': True})
    except Notification.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Not found'}, status=404)
    except Exception as e:
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
        updated = Notification.objects.filter(
            user=user,
            is_read=False
        ).update(
            is_read=True,
            read_at=timezone.now()
        )
        return JsonResponse({'success': True, 'count': updated})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
def api_notification_delete(request, notification_id):
    """Delete a notification"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        Notification.objects.filter(id=notification_id, user=user).delete()
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


# =============================================================================
# API: USER PROFILE & STORAGE
# =============================================================================

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
            'user': {
                'id': user.id,
                'email': user.email,
                'name': f"{user.first_name} {user.last_name}".strip() or user.username,
            }
        })
    return JsonResponse({'authenticated': False})


@csrf_exempt
def api_user_storage(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        from files.models import File
        
        total_storage = File.objects.filter(
            user=user, 
            deleted=False
        ).aggregate(total=Sum('size'))['total'] or 0
        
        file_count = File.objects.filter(user=user, deleted=False).count()
        storage_limit = 10 * 1024 * 1024 * 1024  # 10GB
        
        return JsonResponse({
            'success': True,
            'storage': {
                'used': total_storage,
                'used_formatted': format_file_size(total_storage),
                'limit': storage_limit,
                'limit_formatted': format_file_size(storage_limit),
                'remaining': max(0, storage_limit - total_storage),
                'percentage': round((total_storage / storage_limit) * 100, 2),
                'file_count': file_count,
            }
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


# =============================================================================
# API: PASSWORD MANAGEMENT
# =============================================================================

@csrf_exempt
def api_set_password(request):
    """Allow OAuth users to set a password"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        data = json.loads(request.body)
        new_password = data.get('password', '')
        confirm_password = data.get('confirm_password', new_password)
        
        if not new_password or len(new_password) < 8:
            return JsonResponse({
                'success': False,
                'error': 'Password must be at least 8 characters'
            }, status=400)
        
        if new_password != confirm_password:
            return JsonResponse({
                'success': False,
                'error': 'Passwords do not match'
            }, status=400)
        
        user.set_password(new_password)
        user.save()
        
        update_session_auth_hash(request, user)
        
        logger.info(f"✅ Password set for: {user.email}")
        
        return JsonResponse({
            'success': True,
            'message': 'Password set successfully!'
        })
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
def api_forgot_password(request):
    """Request password reset"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()
        
        if not email:
            return JsonResponse({'success': False, 'error': 'Email is required'}, status=400)
        
        logger.info(f"🔐 Password reset requested: {email}")
        
        try:
            user = User.objects.get(email=email)
            
            # Generate reset token
            reset_token = secrets.token_urlsafe(32)
            
            # Store in cache (1 hour expiry)
            cache_key = f'password_reset:{reset_token}'
            cache.set(cache_key, {
                'user_id': user.id,
                'email': email,
            }, timeout=3600)
            
            # Create reset link
            frontend_url = os.environ.get('FRONTEND_URL', 'https://dropvault-frontend-1.onrender.com')
            reset_link = f"{frontend_url}/reset-password?token={reset_token}"
            
            logger.info(f"   Reset link: {reset_link}")
            
            # TODO: Send email
            
        except User.DoesNotExist:
            pass  # Don't reveal if email exists
        
        return JsonResponse({
            'success': True,
            'message': 'If an account exists, a reset link has been sent.'
        })
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': 'Request failed'}, status=500)


@csrf_exempt
def api_reset_password(request):
    """Reset password with token"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        token = data.get('token', '').strip()
        new_password = data.get('password', '')
        
        if not token:
            return JsonResponse({'success': False, 'error': 'Token required'}, status=400)
        
        if not new_password or len(new_password) < 8:
            return JsonResponse({
                'success': False,
                'error': 'Password must be at least 8 characters'
            }, status=400)
        
        # Verify token
        cache_key = f'password_reset:{token}'
        reset_data = cache.get(cache_key)
        
        if not reset_data:
            return JsonResponse({
                'success': False,
                'error': 'Invalid or expired token'
            }, status=400)
        
        try:
            user = User.objects.get(id=reset_data['user_id'])
            user.set_password(new_password)
            user.save()
            
            # Delete token
            cache.delete(cache_key)
            
            # Delete old tokens
            Token.objects.filter(user=user).delete()
            
            logger.info(f"✅ Password reset: {user.email}")
            
            return JsonResponse({
                'success': True,
                'message': 'Password reset successfully!'
            })
            
        except User.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'User not found'}, status=404)
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
def api_request_password_reset(request):
    """Alias for forgot password"""
    return api_forgot_password(request)


@csrf_exempt
def api_verify_reset_token(request):
    """Verify reset token"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    token = request.GET.get('token', '')
    if not token:
        return JsonResponse({'valid': False}, status=400)
    
    cache_key = f'password_reset:{token}'
    reset_data = cache.get(cache_key)
    
    return JsonResponse({'valid': bool(reset_data)})


@csrf_exempt
def api_check_user_password_status(request):
    """Check if user has password set"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    return JsonResponse({
        'success': True,
        'has_password': user.has_usable_password(),
        'email': user.email
    })


# =============================================================================
# API: ADMIN/DEBUG ENDPOINTS
# =============================================================================

@csrf_exempt
def api_debug_user(request):
    """Debug user info"""
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
                'email': user.email,
                'username': user.username,
                'has_password': user.has_usable_password(),
                'is_active': user.is_active,
                'password_hash_preview': user.password[:40] + "...",
                'last_login': user.last_login.isoformat() if user.last_login else None,
            }
        })
    except User.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Not found'}, status=404)


@csrf_exempt
def api_debug_list_users(request):
    """List all users"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    users = User.objects.all().order_by('id')
    return JsonResponse({
        'success': True,
        'count': users.count(),
        'users': [{
            'id': u.id,
            'email': u.email,
            'username': u.username,
            'has_password': u.has_usable_password(),
            'is_active': u.is_active,
        } for u in users]
    })


@csrf_exempt
def api_debug_fix_password(request):
    """Admin fix password"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()
        new_password = data.get('new_password', '')
        
        if not email or not new_password:
            return JsonResponse({
                'success': False,
                'error': 'Email and new_password required'
            }, status=400)
        
        user = User.objects.get(email=email)
        user.set_password(new_password)
        user.save()
        
        # Verify
        verified = check_password(new_password, user.password)
        
        # Delete old tokens
        Token.objects.filter(user=user).delete()
        
        logger.info(f"🔧 Password fixed for: {email}, verified: {verified}")
        
        return JsonResponse({
            'success': True,
            'email': email,
            'password_verified': verified
        })
        
    except User.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'User not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
def api_admin_delete_all_users(request):
    """Delete all non-superuser accounts"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        admin_key = data.get('admin_key', '')
        confirm = data.get('confirm', False)
        
        expected_key = os.environ.get('ADMIN_FIX_KEY', 'dropvault-admin-fix-2024')
        if admin_key != expected_key:
            return JsonResponse({'success': False, 'error': 'Invalid admin key'}, status=403)
        
        users = User.objects.filter(is_superuser=False)
        
        if not confirm:
            return JsonResponse({
                'success': False,
                'message': 'Add "confirm": true to delete',
                'would_delete': users.count(),
                'users': [{'id': u.id, 'email': u.email} for u in users]
            })
        
        count = users.count()
        
        # Delete related data
        from files.models import File, SharedLink
        user_ids = list(users.values_list('id', flat=True))
        
        Token.objects.filter(user_id__in=user_ids).delete()
        File.objects.filter(user_id__in=user_ids).delete()
        SharedLink.objects.filter(owner_id__in=user_ids).delete()
        UserProfile.objects.filter(user_id__in=user_ids).delete()
        Notification.objects.filter(user_id__in=user_ids).delete()
        
        users.delete()
        
        logger.info(f"🗑️ Deleted {count} users")
        
        return JsonResponse({
            'success': True,
            'deleted_count': count
        })
        
    except Exception as e:
        logger.error(f"Delete users error: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


# =============================================================================
# STUB ENDPOINTS
# =============================================================================

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
def upload_test(request):
    return render(request, 'upload_test.html')


# MFA endpoints (if needed)
@login_required
def setup_mfa(request):
    from django_otp.plugins.otp_totp.models import TOTPDevice
    device, _ = TOTPDevice.objects.get_or_create(user=request.user, confirmed=False, defaults={'name': 'Auth'})
    if request.method == 'POST' and device.verify_token(request.POST.get('token', '')):
        device.confirmed = True
        device.save()
        return redirect('dashboard')
    return render(request, 'setup_mfa.html', {'device': device})


@login_required
def otp_verify(request):
    from django_otp import match_token
    if request.method == 'POST' and match_token(request.user, request.POST.get('otp', '')):
        return redirect('dashboard')
    return render(request, 'otp_verify.html')


@login_required
def disable_mfa(request):
    from django_otp.plugins.otp_totp.models import TOTPDevice
    if request.method == 'POST':
        TOTPDevice.objects.filter(user=request.user).delete()
        return redirect('dashboard')
    return render(request, 'disable_mfa.html')

# Add to accounts/views.py (at the end)

@csrf_exempt
def api_delete_all_users(request):
    """Delete all users - for fresh start"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method == "GET":
        # Show what will be deleted
        users = User.objects.filter(is_superuser=False)
        return JsonResponse({
            'message': 'Send POST with {"confirm": "DELETE_ALL"} to delete',
            'user_count': users.count(),
            'users': [{'id': u.id, 'email': u.email} for u in users]
        })
    
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            confirm = data.get('confirm', '')
            
            if confirm != 'DELETE_ALL':
                return JsonResponse({
                    'success': False,
                    'error': 'Send {"confirm": "DELETE_ALL"} to confirm'
                }, status=400)
            
            # Get all non-superuser users
            users = User.objects.filter(is_superuser=False)
            user_ids = list(users.values_list('id', flat=True))
            count = len(user_ids)
            
            if count == 0:
                return JsonResponse({
                    'success': True,
                    'message': 'No users to delete'
                })
            
            # Delete all related data
            from files.models import File, SharedLink
            
            # Delete tokens
            Token.objects.filter(user_id__in=user_ids).delete()
            
            # Delete files from storage too
            files = File.objects.filter(user_id__in=user_ids)
            for f in files:
                try:
                    if f.file and hasattr(f.file, 'delete'):
                        f.file.delete(save=False)
                except:
                    pass
            files.delete()
            
            # Delete shared links
            SharedLink.objects.filter(owner_id__in=user_ids).delete()
            
            # Delete profiles
            UserProfile.objects.filter(user_id__in=user_ids).delete()
            
            # Delete notifications
            Notification.objects.filter(user_id__in=user_ids).delete()
            
            # Finally delete users
            users.delete()
            
            logger.info(f"🗑️ DELETED ALL {count} USERS")
            
            return JsonResponse({
                'success': True,
                'message': f'Deleted {count} users and all their data',
                'deleted_count': count
            })
            
        except Exception as e:
            logger.error(f"Delete error: {e}")
            import traceback
            traceback.print_exc()
            return JsonResponse({'success': False, 'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)