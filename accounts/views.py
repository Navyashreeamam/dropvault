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

from django.views.decorators.http import require_http_methods
from django.db import transaction
from django.utils import timezone
from django.conf import settings

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


@csrf_exempt
@require_http_methods(["POST", "OPTIONS"])
def api_set_password(request):
    """
    Allow OAuth users to set a password for email+password login.
    Can be called while user is logged in via OAuth.
    """
    if request.method == "OPTIONS":
        return JsonResponse({}, status=200)
    
    # Must be authenticated (logged in via Google)
    if not request.user.is_authenticated:
        return JsonResponse({
            'success': False,
            'error': 'You must be logged in to set a password'
        }, status=401)
    
    try:
        data = json.loads(request.body)
        new_password = data.get('password')
        confirm_password = data.get('confirm_password')
        
        # Validate input
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
                'error': 'Password must be at least 8 characters long'
            }, status=400)
        
        # Set the password
        request.user.set_password(new_password)
        request.user.save()
        
        # Update session to prevent logout
        from django.contrib.auth import update_session_auth_hash
        update_session_auth_hash(request, request.user)
        
        logger.info(f"✅ Password set for user: {request.user.email}")
        
        return JsonResponse({
            'success': True,
            'message': 'Password set successfully! You can now login with email and password.',
            'has_password': True
        })
        
    except Exception as e:
        logger.error(f"❌ Set password error: {str(e)}")
        import traceback
        traceback.print_exc()
        return JsonResponse({
            'success': False,
            'error': f'Failed to set password: {str(e)}'
        }, status=500)


@require_http_methods(["GET", "OPTIONS"])
def api_check_user_password_status(request):
    """
    Check if the current logged-in user has a password set.
    Used by frontend to show "Set Password" option.
    """
    if request.method == "OPTIONS":
        return JsonResponse({}, status=200)
    
    if not request.user.is_authenticated:
        return JsonResponse({
            'success': False,
            'error': 'Not authenticated'
        }, status=401)
    
    return JsonResponse({
        'success': True,
        'has_password': request.user.has_usable_password(),
        'email': request.user.email,
        'username': request.user.username,
        'login_methods': {
            'google': True,  # If they're logged in, Google worked
            'password': request.user.has_usable_password()
        }
    })

@login_required
def disable_mfa(request):
    if request.method == 'POST':
        TOTPDevice.objects.filter(user=request.user).delete()
        return redirect('dashboard')
    return render(request, 'disable_mfa.html')

@csrf_exempt
def api_signup(request):
    """API endpoint for user signup - WITH DEBUG LOGGING"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')  # Don't strip
        name = data.get('name', '').strip()
        
        logger.info("=" * 60)
        logger.info(f"📝 SIGNUP ATTEMPT")
        logger.info(f"   Email: {email}")
        logger.info(f"   Password length: {len(password)}")
        logger.info(f"   Password (first 2 chars): {password[:2] if len(password) >= 2 else 'too short'}...")
        logger.info("=" * 60)
        
        if not email or not password:
            return JsonResponse({
                'success': False,
                'error': 'Email and password are required'
            }, status=400)
        
        if len(password) < 8:
            return JsonResponse({
                'success': False,
                'error': 'Password must be at least 8 characters'
            }, status=400)
        
        if User.objects.filter(email=email).exists():
            return JsonResponse({
                'success': False,
                'error': 'An account with this email already exists'
            }, status=400)
        
        # Create username
        username = email.split('@')[0]
        counter = 1
        while User.objects.filter(username=username).exists():
            username = f"{email.split('@')[0]}{counter}"
            counter += 1
        
        # Parse name
        name_parts = name.split() if name else [username]
        first_name = name_parts[0] if name_parts else ''
        last_name = ' '.join(name_parts[1:]) if len(name_parts) > 1 else ''
        
        # Create user
        logger.info(f"   Creating user with username: {username}")
        
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name
        )
        
        logger.info(f"   ✅ User created - ID: {user.id}")
        logger.info(f"   Password hash: {user.password[:30]}...")
        logger.info(f"   Has usable password: {user.has_usable_password()}")
        
        # Verify password was set correctly
        from django.contrib.auth.hashers import check_password
        password_check = check_password(password, user.password)
        logger.info(f"   Password verification: {password_check}")
        
        UserProfile.objects.get_or_create(user=user)
        
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        token, _ = Token.objects.get_or_create(user=user)
        
        logger.info(f"✅ Signup successful: {email}")
        logger.info("=" * 60)
        
        return JsonResponse({
            'success': True,
            'message': 'Account created successfully',
            'token': token.key,
            'user': {
                'id': user.id,
                'email': user.email,
                'username': user.username,
                'name': f"{user.first_name} {user.last_name}".strip() or user.username,
                'has_password': True
            }
        })
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"❌ Signup error: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@csrf_exempt
def api_login(request):
    """API endpoint for user login - WITH DEBUG LOGGING"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')  # Don't strip
        
        logger.info("=" * 60)
        logger.info(f"🔐 LOGIN ATTEMPT")
        logger.info(f"   Email: {email}")
        logger.info(f"   Password length: {len(password)}")
        logger.info(f"   Password (first 2 chars): {password[:2] if len(password) >= 2 else 'too short'}...")
        logger.info("=" * 60)
        
        if not email or not password:
            return JsonResponse({
                'success': False,
                'error': 'Email and password are required'
            }, status=400)
        
        # Find user
        try:
            user = User.objects.get(email=email)
            logger.info(f"   ✅ Found user: {user.username} (ID: {user.id})")
            logger.info(f"   Has usable password: {user.has_usable_password()}")
            logger.info(f"   Password hash starts with: {user.password[:30]}...")
        except User.DoesNotExist:
            logger.warning(f"   ❌ User NOT FOUND: {email}")
            # List all users for debugging
            all_users = User.objects.all().values_list('email', flat=True)[:10]
            logger.info(f"   Available users: {list(all_users)}")
            return JsonResponse({
                'success': False,
                'error': 'Invalid email or password'
            }, status=401)
        
        # Check if user is active
        if not user.is_active:
            logger.warning(f"   ❌ User is inactive")
            return JsonResponse({
                'success': False,
                'error': 'Account is disabled'
            }, status=403)
        
        # Check if OAuth-only user
        if not user.has_usable_password():
            logger.warning(f"   ⚠️ OAuth user without password")
            return JsonResponse({
                'success': False,
                'error': 'This account uses Google Sign-In. Please sign in with Google.',
                'oauth_account': True
            }, status=401)
        
        # Try to authenticate
        logger.info(f"   🔑 Attempting authentication...")
        logger.info(f"   Using username: {user.username}")
        
        auth_user = authenticate(request, username=user.username, password=password)
        
        if not auth_user:
            logger.warning(f"   ❌ Authentication FAILED")
            
            # Debug: Try to check password manually
            from django.contrib.auth.hashers import check_password
            password_matches = check_password(password, user.password)
            logger.info(f"   Manual password check: {password_matches}")
            
            # Check if password was set correctly
            logger.info(f"   Password hash algorithm: {user.password.split('$')[0] if '$' in user.password else 'unknown'}")
            
            return JsonResponse({
                'success': False,
                'error': 'Invalid email or password'
            }, status=401)
        
        # Success!
        logger.info(f"   ✅ Authentication SUCCESSFUL")
        
        login(request, auth_user)
        token, _ = Token.objects.get_or_create(user=auth_user)
        
        logger.info(f"✅ LOGIN SUCCESS: {email}")
        logger.info("=" * 60)
        
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
        logger.error("❌ Invalid JSON in request body")
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"❌ Login error: {e}")
        import traceback
        traceback.print_exc()
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


@login_required
@require_http_methods(["GET", "OPTIONS"])
def api_user(request):
    """Get current user details"""
    if request.method == "OPTIONS":
        return JsonResponse({}, status=200)
    
    user = request.user
    
    # Get user profile if exists
    profile = None
    try:
        profile = user.profile
    except:
        # Create profile if missing
        from accounts.models import UserProfile
        profile = UserProfile.objects.create(user=user)
    
    return JsonResponse({
        'success': True,
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'has_password': user.has_usable_password(),  # ← ADD THIS
            'storage_used': profile.storage_used if profile else 0,
            'storage_limit': profile.storage_limit if profile else 1073741824,
            'storage_percentage': profile.storage_percentage if profile else 0,
        }
    })

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
        user_created = False
        try:
            user = User.objects.get(email=email)
            logger.info(f"   Found existing user")
            
            # ✅ FIX EXISTING OAUTH USERS - If they don't have a password, set one
            if not user.has_usable_password():
                import secrets
                random_password = secrets.token_urlsafe(16)
                user.set_password(random_password)
                user.save()
                logger.info(f"   ✅ Set random password for existing OAuth user")
                
        except User.DoesNotExist:
            username = email.split('@')[0]
            counter = 1
            while User.objects.filter(username=username).exists():
                username = f"{email.split('@')[0]}{counter}"
                counter += 1
            
            name_parts = name.split() if name else [username]
            
            # ✅ FIX: Create user WITH a random password (not unusable)
            import secrets
            random_password = secrets.token_urlsafe(16)
            
            user = User.objects.create_user(
                username=username,
                email=email,
                password=random_password,  # ✅ Random password instead of unusable
                first_name=name_parts[0] if name_parts else '',
                last_name=' '.join(name_parts[1:]) if len(name_parts) > 1 else '',
                is_active=True
            )
            
            UserProfile.objects.get_or_create(user=user)
            user_created = True
            logger.info(f"   Created new user with random password")
        
        # Login user
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        token, _ = Token.objects.get_or_create(user=user)
        
        logger.info(f"✅ Google OAuth SUCCESS: {email}")
        logger.info("=" * 50)
        
        response_data = {
            'success': True,
            'token': token.key,
            'sessionid': request.session.session_key,
            'user': {
                'id': user.id,
                'email': user.email,
                'name': f"{user.first_name} {user.last_name}".strip() or user.username,
                'has_password': user.has_usable_password(),
            }
        }
        
        # ✅ If user was just created, prompt them to set their own password
        if user_created:
            response_data['first_time'] = True
            response_data['message'] = 'Welcome! Please set a password in Settings to enable email login.'
        
        return JsonResponse(response_data)
        
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
        from files.models import File
        from django.db.models import Sum
        
        total_storage = File.objects.filter(
            user=user, 
            deleted=False
        ).aggregate(total=Sum('size'))['total'] or 0
        
        file_count = File.objects.filter(user=user, deleted=False).count()
        
        storage_limit = 10 * 1024 * 1024 * 1024
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


@require_http_methods(["GET", "OPTIONS"])
def api_debug_user(request):
    """Debug endpoint to check user details"""
    if request.method == "OPTIONS":
        return JsonResponse({}, status=200)
    
    email = request.GET.get('email')
    
    if not email:
        return JsonResponse({
            'success': False,
            'error': 'Email parameter required'
        }, status=400)
    
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
                'password_field': user.password[:50] + '...' if user.password else 'None',
                'date_joined': user.date_joined.isoformat(),
                'last_login': user.last_login.isoformat() if user.last_login else None,
            }
        })
        
    except User.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': 'User not found'
        }, status=404)

@csrf_exempt
@require_http_methods(["POST", "OPTIONS"])
def api_fix_oauth_user(request):
    """
    Temporary endpoint to fix OAuth users without passwords.
    Admin/debug use only.
    """
    if request.method == "OPTIONS":
        return JsonResponse({}, status=200)
    
    try:
        data = json.loads(request.body)
        email = data.get('email')
        
        if not email:
            return JsonResponse({
                'success': False,
                'error': 'Email required'
            }, status=400)
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'User not found'
            }, status=404)
        
        # Check if user needs fixing
        if user.has_usable_password():
            return JsonResponse({
                'success': True,
                'message': 'User already has a password',
                'fixed': False
            })
        
        # Set random password
        import secrets
        random_password = secrets.token_urlsafe(16)
        user.set_password(random_password)
        user.save()
        
        logger.info(f"✅ Fixed OAuth user: {email}")
        
        return JsonResponse({
            'success': True,
            'message': f'Password set for {email}. User can now login with Google and set custom password.',
            'fixed': True,
            'has_password': user.has_usable_password()
        })
        
    except Exception as e:
        logger.error(f"Fix user error: {e}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@csrf_exempt
@require_http_methods(["POST", "OPTIONS"])
def api_request_password_reset(request):
    """
    Allow OAuth users to request a password reset link.
    Temporary solution for users who don't know their random password.
    """
    if request.method == "OPTIONS":
        return JsonResponse({}, status=200)
    
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()
        
        if not email:
            return JsonResponse({
                'success': False,
                'error': 'Email is required'
            }, status=400)
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            # Don't reveal if email exists or not (security)
            return JsonResponse({
                'success': True,
                'message': 'If this email exists, a password reset link has been sent.'
            })
        
        # Generate temporary token
        import secrets
        from django.utils import timezone
        from datetime import timedelta
        
        reset_token = secrets.token_urlsafe(32)
        
        # Store token in user profile
        profile, created = UserProfile.objects.get_or_create(user=user)
        profile.verification_token = reset_token  # Reuse this field
        profile.save()
        
        # Create reset link
        reset_link = f"{settings.SITE_URL}/reset-password/{reset_token}/"
        
        # Send email (or just return link for testing)
        logger.info(f"📧 Password reset requested for: {email}")
        logger.info(f"🔗 Reset link: {reset_link}")
        
        return JsonResponse({
            'success': True,
            'message': 'Password reset link generated',
            'reset_link': reset_link,  # Remove this in production
            'note': 'In production, this would be sent via email'
        })
        
    except Exception as e:
        logger.error(f"Password reset error: {e}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@csrf_exempt
@require_http_methods(["POST", "OPTIONS"])
def api_reset_password(request):
    """
    Reset password using token from email.
    """
    if request.method == "OPTIONS":
        return JsonResponse({}, status=200)
    
    try:
        data = json.loads(request.body)
        token = data.get('token')
        new_password = data.get('password')
        confirm_password = data.get('confirm_password')
        
        if not all([token, new_password, confirm_password]):
            return JsonResponse({
                'success': False,
                'error': 'Token and passwords are required'
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
        
        # Find user with this token
        try:
            profile = UserProfile.objects.get(verification_token=token)
            user = profile.user
        except UserProfile.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Invalid or expired reset link'
            }, status=400)
        
        # Set new password
        user.set_password(new_password)
        user.save()
        
        # Clear token
        profile.verification_token = ''
        profile.save()
        
        logger.info(f"✅ Password reset successful for: {user.email}")
        
        return JsonResponse({
            'success': True,
            'message': 'Password reset successfully! You can now login with your new password.'
        })
        
    except Exception as e:
        logger.error(f"Password reset error: {e}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)