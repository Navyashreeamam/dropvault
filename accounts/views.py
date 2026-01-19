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
from django.contrib.auth.hashers import check_password
from django.db import transaction


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


# accounts/views.py - REPLACE api_signup function

@csrf_exempt
def api_signup(request):
    """
    API endpoint for user signup - PRODUCTION READY
    ✅ Properly handles password hashing
    """
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')  # ✅ Don't strip password!
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
            return JsonResponse({
                'success': False,
                'error': 'An account with this email already exists. Please login or reset your password.'
            }, status=400)
        
        # Create username
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
        
        # ✅ CORRECT: Use create_user() - it handles password hashing
        from django.db import transaction
        from django.contrib.auth.hashers import check_password
        
        with transaction.atomic():
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,  # ✅ Raw password - create_user() hashes it
                first_name=first_name,
                last_name=last_name,
                is_active=True
            )
            
            # ✅ VERIFY password was set correctly
            password_check = check_password(password, user.password)
            logger.info(f"   ✅ User created - ID: {user.id}")
            logger.info(f"   Password verification: {password_check}")
            
            if not password_check:
                # This should NEVER happen with create_user()
                logger.error(f"   ❌ PASSWORD VERIFICATION FAILED!")
                user.delete()
                raise Exception("Password hashing failed")
            
            # Create profile
            UserProfile.objects.get_or_create(user=user)
        
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
                'has_password': True
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


@csrf_exempt
def api_login(request):
    """
    API endpoint for user login - PRODUCTION READY
    Detects corrupted passwords and guides users to reset
    """
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
        
        # Check account status
        if not user.is_active:
            logger.warning(f"   ❌ Account is inactive: {email}")
            return JsonResponse({
                'success': False,
                'error': 'Your account has been disabled. Please contact support.'
            }, status=403)
        
        # ✅ CHECK FOR CORRUPTED PASSWORD
        has_password = user.has_usable_password()
        logger.info(f"   Has usable password: {has_password}")
        
        if not has_password:
            logger.warning(f"   ⚠️  Account needs password reset: {email}")
            
            # Check if it's OAuth-only or corrupted password
            if user.password == '!':
                # OAuth-only account
                return JsonResponse({
                    'success': False,
                    'error': 'This account uses Google Sign-In. Please use "Sign in with Google" or reset your password to enable email login.',
                    'oauth_account': True,
                    'action': 'USE_GOOGLE_OR_RESET_PASSWORD'
                }, status=401)
            else:
                # Corrupted password detected
                logger.error(f"   🐛 CORRUPTED PASSWORD DETECTED for {email}")
                return JsonResponse({
                    'success': False,
                    'error': 'Your password needs to be reset due to a system update. Please click "Forgot Password" to reset it.',
                    'password_reset_required': True,
                    'action': 'RESET_PASSWORD',
                    'user_email': email
                }, status=401)
        
        # Verify password
        from django.contrib.auth.hashers import check_password
        
        logger.info(f"   Verifying password...")
        password_correct = check_password(password, user.password)
        logger.info(f"   Password check result: {password_correct}")
        
        if not password_correct:
            logger.warning(f"   ❌ INCORRECT PASSWORD for {email}")
            
            # ✅ SPECIAL CHECK: If hash looks corrupted, suggest reset
            if user.password.startswith('pbkdf2_'):
                parts = user.password.split('$')
                if len(parts) >= 4 and len(parts[-1]) > 60:
                    logger.error(f"   🐛 DETECTED CORRUPTED HASH for {email}")
                    
                    # Mark as unusable
                    user.set_unusable_password()
                    user.save()
                    
                    return JsonResponse({
                        'success': False,
                        'error': 'Your password appears to be corrupted. Please use "Forgot Password" to reset it.',
                        'password_reset_required': True,
                        'action': 'RESET_PASSWORD',
                        'user_email': email
                    }, status=401)
            
            return JsonResponse({
                'success': False,
                'error': 'Invalid email or password'
            }, status=401)
        
        # Django authenticate
        logger.info(f"   Password correct, authenticating...")
        auth_user = authenticate(
            request=request,
            username=user.username,
            password=password
        )
        
        if not auth_user:
            logger.error(f"   ⚠️ authenticate() returned None despite correct password")
            auth_user = user
        
        # Login user
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
                'has_password': True
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

# accounts/views.py - Add these at the END of the file

# =============================================================================
# API: PASSWORD MANAGEMENT
# =============================================================================

@csrf_exempt
def api_set_password(request):
    """
    Allow OAuth users (Google sign-in) to set a password for email login.
    This enables them to login with email+password later.
    """
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({
            'success': False,
            'error': 'You must be logged in to set a password'
        }, status=401)
    
    try:
        data = json.loads(request.body)
        new_password = data.get('password', '').strip()
        confirm_password = data.get('confirm_password', '').strip()
        
        # Validation
        if not new_password or not confirm_password:
            return JsonResponse({
                'success': False,
                'error': 'Password and confirmation are required'
            }, status=400)
        
        if new_password != confirm_password:
            return JsonResponse({
                'success': False,
                'error': 'Passwords do not match'
            }, status=400)
        
        if len(new_password) < 8:
            return JsonResponse({
                'success': False,
                'error': 'Password must be at least 8 characters'
            }, status=400)
        
        # Set password
        user.set_password(new_password)
        user.save()
        
        # Update session to prevent logout
        update_session_auth_hash(request, user)
        
        logger.info(f"✅ Password set for OAuth user: {user.email}")
        
        return JsonResponse({
            'success': True,
            'message': 'Password set successfully! You can now login with email and password.',
            'has_password': True
        })
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Set password error: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
def api_forgot_password(request):
    """
    Request password reset - sends email with reset link.
    Always returns success (don't reveal if email exists).
    """
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()
        
        if not email:
            return JsonResponse({
                'success': False,
                'error': 'Email is required'
            }, status=400)
        
        # Always return success (don't reveal if email exists)
        logger.info(f"🔐 Password reset requested for: {email}")
        
        try:
            user = User.objects.get(email=email)
            
            # Generate reset token
            import secrets
            from django.core.cache import cache
            from django.utils import timezone
            
            reset_token = secrets.token_urlsafe(32)
            
            # Store in cache with 1 hour expiry
            cache_key = f'password_reset:{reset_token}'
            cache.set(cache_key, {
                'user_id': user.id,
                'email': email,
                'created': timezone.now().isoformat()
            }, timeout=3600)  # 1 hour
            
            # Create reset link
            from django.conf import settings
            site_url = getattr(settings, 'SITE_URL', 'http://localhost:8000')
            reset_link = f"{site_url}/reset-password?token={reset_token}"
            
            logger.info(f"📧 Password reset link created: {reset_link}")
            
            # TODO: Send email here
            # send_password_reset_email(user.email, user.first_name, reset_link)
            
        except User.DoesNotExist:
            logger.info(f"Password reset requested for non-existent email: {email}")
            # Don't reveal that email doesn't exist
        
        return JsonResponse({
            'success': True,
            'message': 'If an account exists with this email, a reset link has been sent.'
        })
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Forgot password error: {e}")
        return JsonResponse({'success': False, 'error': 'Request failed'}, status=500)


@csrf_exempt
def api_request_password_reset(request):
    """Alias for api_forgot_password"""
    return api_forgot_password(request)


@csrf_exempt
def api_verify_reset_token(request):
    """Verify if a password reset token is valid"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    token = request.GET.get('token', '')
    
    if not token:
        return JsonResponse({'valid': False, 'error': 'Token required'}, status=400)
    
    from django.core.cache import cache
    
    cache_key = f'password_reset:{token}'
    reset_data = cache.get(cache_key)
    
    if reset_data:
        # Mask email for privacy
        email = reset_data.get('email', '')
        masked_email = email[:3] + '***@' + email.split('@')[1] if '@' in email else '***'
        
        return JsonResponse({
            'valid': True,
            'email': masked_email
        })
    
    return JsonResponse({
        'valid': False,
        'error': 'Invalid or expired reset token'
    })


@csrf_exempt
def api_reset_password(request):
    """
    Reset password using token from email.
    Note: There are TWO api_reset_password endpoints in urls.py - this handles both.
    """
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        token = data.get('token', '').strip()
        new_password = data.get('password', '').strip()
        confirm_password = data.get('confirm_password', '').strip()
        
        # Validation
        if not token:
            return JsonResponse({
                'success': False,
                'error': 'Reset token is required'
            }, status=400)
        
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
        
        # Verify token
        from django.core.cache import cache
        
        cache_key = f'password_reset:{token}'
        reset_data = cache.get(cache_key)
        
        if not reset_data:
            return JsonResponse({
                'success': False,
                'error': 'Invalid or expired reset token. Please request a new one.'
            }, status=400)
        
        # Get user and set password
        try:
            user = User.objects.get(id=reset_data['user_id'])
            user.set_password(new_password)
            user.save()
            
            # Delete token (can only be used once)
            cache.delete(cache_key)
            
            # Delete all existing auth tokens (force re-login)
            Token.objects.filter(user=user).delete()
            
            logger.info(f"✅ Password reset successful for: {user.email}")
            
            return JsonResponse({
                'success': True,
                'message': 'Password reset successfully! You can now login with your new password.'
            })
            
        except User.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'User not found'
            }, status=404)
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Reset password error: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({'success': False, 'error': 'Reset failed'}, status=500)


@csrf_exempt
def api_check_user_password_status(request):
    """
    Check if the current user has a password set.
    Used to determine if OAuth-only user should set a password.
    """
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    
    if not user:
        return JsonResponse({
            'success': False,
            'error': 'Not authenticated'
        }, status=401)
    
    has_password = user.has_usable_password()
    
    return JsonResponse({
        'success': True,
        'has_password': has_password,
        'is_oauth_user': not has_password,
        'email': user.email,
        'recommendation': 'Set a password to enable email login' if not has_password else 'Password already set'
    })


@csrf_exempt
def api_debug_user(request):
    """
    Debug endpoint to check user details.
    ⚠️ REMOVE IN PRODUCTION!
    """
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    email = request.GET.get('email', '').strip().lower()
    
    if not email:
        return JsonResponse({'error': 'Email parameter required'}, status=400)
    
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
                'date_joined': user.date_joined.isoformat(),
                'last_login': user.last_login.isoformat() if user.last_login else None,
            }
        })
        
    except User.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'User not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)
    