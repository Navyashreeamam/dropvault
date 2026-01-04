# files/sharingviews.py
import os
import secrets
import json
import sys
import traceback
import requests
from django.http import JsonResponse, FileResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, redirect
from django.utils import timezone
from datetime import timedelta
from .models import File, SharedLink
from django.shortcuts import get_object_or_404
from django.conf import settings
import mimetypes

# Import the email function
from accounts.utils import send_file_share_email, get_resend_api_key


def log_info(msg):
    print(f"[INFO] {msg}", file=sys.stdout, flush=True)


def log_error(msg):
    print(f"[ERROR] {msg}", file=sys.stdout, flush=True)


def json_response(data, status=200):
    response = JsonResponse(data, status=status)
    response['Content-Type'] = 'application/json'
    return response


def auth_error():
    return json_response({
        'error': 'Please login to continue',
        'login_required': True
    }, status=401)


def generate_slug():
    for _ in range(10):
        slug = secrets.token_urlsafe(8)[:12]
        if not SharedLink.objects.filter(slug=slug).exists():
            return slug
    return secrets.token_urlsafe(12)


def get_site_url(request):
    """Get the correct site URL for share links"""
    site_url = os.environ.get('SITE_URL', '').strip()
    
    if not site_url or 'localhost' in site_url:
        render_host = os.environ.get('RENDER_EXTERNAL_HOSTNAME', '')
        if render_host:
            site_url = f'https://{render_host}'
    
    if not site_url:
        site_url = request.build_absolute_uri('/')[:-1]
    
    return site_url


def is_cloudinary_storage():
    """Check if Cloudinary storage is enabled - SAFE VERSION"""
    try:
        # Check if CLOUDINARY_STORAGE exists and has values
        cloudinary_storage = getattr(settings, 'CLOUDINARY_STORAGE', None)
        
        if not cloudinary_storage:
            return False
        
        if not isinstance(cloudinary_storage, dict):
            return False
            
        return all([
            cloudinary_storage.get('CLOUD_NAME'),
            cloudinary_storage.get('API_KEY'),
            cloudinary_storage.get('API_SECRET')
        ])
    except Exception as e:
        log_error(f"is_cloudinary_storage error: {e}")
        return False


def create_user_notification(user, notification_type, title, message, file_name=None, file_id=None):
    """Helper to create notifications"""
    try:
        from accounts.models import Notification
        Notification.objects.create(
            user=user,
            notification_type=notification_type,
            title=title,
            message=message,
            file_name=file_name,
            file_id=file_id
        )
        log_info(f"🔔 Notification created: {notification_type}")
    except Exception as e:
        log_error(f"🔔 Failed to create notification: {e}")


# ═══════════════════════════════════════════════════════════
# 🔗 CREATE SHARE LINK
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def create_share_link(request, file_id):
    """Create a shareable link for a file"""
    if request.method == "OPTIONS":
        return json_response({'status': 'ok'})
    
    log_info(f"🔗 CREATE LINK - File: {file_id}, Auth: {request.user.is_authenticated}")
    
    try:
        if not request.user.is_authenticated:
            return auth_error()
        
        file_obj = File.objects.get(id=file_id, user=request.user)
        
        if file_obj.deleted:
            return json_response({'error': 'Cannot share deleted file'}, status=400)
        
        existing = SharedLink.objects.filter(
            file=file_obj, owner=request.user, is_active=True
        ).first()
        
        if existing and not existing.is_expired():
            site_url = get_site_url(request)
            share_url = f"{site_url}/s/{existing.slug}/"
            return json_response({
                'status': 'success',
                'share_url': share_url,
                'slug': existing.slug,
                'link': share_url
            })
        
        slug = generate_slug()
        SharedLink.objects.create(
            file=file_obj,
            owner=request.user,
            slug=slug,
            token=secrets.token_urlsafe(48),
            max_downloads=5,
            is_active=True
        )
        
        site_url = get_site_url(request)
        share_url = f"{site_url}/s/{slug}/"
        
        log_info(f"🔗 ✅ Created: {share_url}")
        
        create_user_notification(
            user=request.user,
            notification_type='FILE_SHARE',
            title='Share Link Created',
            message=f'A share link was created for "{file_obj.original_name}".',
            file_name=file_obj.original_name,
            file_id=file_obj.id
        )
        
        return json_response({
            'status': 'success',
            'share_url': share_url,
            'slug': slug,
            'link': share_url
        }, status=201)
        
    except File.DoesNotExist:
        return json_response({'error': 'File not found'}, status=404)
    except Exception as e:
        log_error(f"🔗 Error: {e}")
        traceback.print_exc()
        return json_response({'error': str(e)}, status=500)


# ═══════════════════════════════════════════════════════════
# 📧 SHARE VIA EMAIL
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def share_via_email(request, file_id):
    """Share a file via email"""
    if request.method == "OPTIONS":
        return json_response({'status': 'ok'})
    
    log_info(f"📧 SHARE VIA EMAIL - File: {file_id}")
    
    try:
        if not request.user.is_authenticated:
            return auth_error()
        
        api_key = get_resend_api_key()
        if not api_key:
            log_error("📧 RESEND_API_KEY not configured!")
            return json_response({
                'status': 'error',
                'error': 'Email service not configured',
                'email_sent': False
            }, status=500)
        
        file_obj = File.objects.get(id=file_id, user=request.user)
        
        if file_obj.deleted:
            return json_response({'error': 'Cannot share deleted file'}, status=400)
        
        # Parse request body
        recipient_email = ''
        message = ''
        
        if request.body:
            try:
                data = json.loads(request.body.decode('utf-8'))
                recipient_email = data.get('recipient_email', '').strip().lower()
                message = data.get('message', '').strip()
            except json.JSONDecodeError:
                pass
        
        if not recipient_email:
            recipient_email = request.POST.get('recipient_email', '').strip().lower()
            message = request.POST.get('message', '').strip()
        
        if not recipient_email or '@' not in recipient_email:
            return json_response({
                'status': 'error',
                'error': 'Valid email address required'
            }, status=400)
        
        # Create share link
        slug = generate_slug()
        SharedLink.objects.create(
            file=file_obj,
            owner=request.user,
            slug=slug,
            token=secrets.token_urlsafe(48),
            max_downloads=5,
            is_active=True
        )
        
        site_url = get_site_url(request)
        share_url = f"{site_url}/s/{slug}/"
        
        success, error_msg = send_file_share_email(
            to_email=recipient_email,
            from_user=request.user,
            file_name=file_obj.original_name,
            share_url=share_url,
            message=message if message else None
        )
        
        if success:
            create_user_notification(
                user=request.user,
                notification_type='FILE_SHARE',
                title='File Shared via Email',
                message=f'"{file_obj.original_name}" was shared with {recipient_email}.',
                file_name=file_obj.original_name,
                file_id=file_obj.id
            )
            return json_response({
                'status': 'success',
                'share_url': share_url,
                'email_sent': True,
                'message': f'File shared! Email sent to {recipient_email}.'
            })
        else:
            return json_response({
                'status': 'partial',
                'share_url': share_url,
                'email_sent': False,
                'error': error_msg,
                'message': f'Share link created! Copy: {share_url}'
            }, status=200)
        
    except File.DoesNotExist:
        return json_response({'error': 'File not found'}, status=404)
    except Exception as e:
        log_error(f"📧 Error: {e}")
        traceback.print_exc()
        return json_response({'error': str(e)}, status=500)


# ═══════════════════════════════════════════════════════════
# 📄 SHARED FILE VIEW - FIXED
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def shared_file_view(request, slug):
    """View a shared file - Returns JSON for API, HTML for browser"""
    log_info(f"📄 SHARED FILE VIEW - Slug: {slug}")
    
    try:
        # Get the shared link
        try:
            link = SharedLink.objects.select_related('file', 'file__user').get(slug=slug)
        except SharedLink.DoesNotExist:
            log_error(f"📄 Link not found: {slug}")
            return json_response({
                'error': 'Share link not found or has expired',
                'slug': slug
            }, status=404)
        
        # Check if active
        if not link.is_active:
            log_error(f"📄 Link inactive: {slug}")
            return json_response({
                'error': 'This share link is no longer active'
            }, status=410)
        
        # Check if expired
        if link.is_expired():
            log_error(f"📄 Link expired: {slug}")
            link.is_active = False
            link.save(update_fields=['is_active'])
            return json_response({
                'error': 'This share link has expired'
            }, status=410)
        
        file_obj = link.file
        
        # Check if file is deleted
        if file_obj.deleted:
            log_error(f"📄 File deleted: {file_obj.id}")
            return json_response({
                'error': 'This file is no longer available'
            }, status=404)
        
        # Set first access time if not set
        if not link.first_accessed_at:
            link.first_accessed_at = timezone.now()
            link.expires_at = timezone.now() + timedelta(hours=24)
            link.save(update_fields=['first_accessed_at', 'expires_at'])
        
        # Increment view count
        link.view_count = (link.view_count or 0) + 1
        link.save(update_fields=['view_count'])
        
        site_url = get_site_url(request)
        download_url = f"{site_url}/s/{slug}/download/"
        
        # Return JSON response (for API/frontend)
        response_data = {
            'success': True,
            'file': {
                'name': file_obj.original_name,
                'size': file_obj.size,
                'size_formatted': format_file_size(file_obj.size),
            },
            'share': {
                'slug': link.slug,
                'download_url': download_url,
                'view_count': link.view_count,
                'download_count': link.download_count,
                'max_downloads': link.max_downloads,
                'downloads_remaining': max(0, link.max_downloads - link.download_count),
                'expires_at': link.expires_at.isoformat() if link.expires_at else None,
            }
        }
        
        log_info(f"📄 ✅ Returning file info: {file_obj.original_name}")
        return json_response(response_data)
        
    except Exception as e:
        log_error(f"📄 Error: {e}")
        traceback.print_exc()
        return json_response({
            'error': 'Failed to load shared file',
            'details': str(e)
        }, status=500)


def format_file_size(size_bytes):
    """Convert bytes to human-readable format"""
    if size_bytes == 0:
        return "0 B"
    
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    unit_index = 0
    size = float(size_bytes)
    
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1
    
    return f"{size:.2f} {units[unit_index]}"


# ═══════════════════════════════════════════════════════════
# 📥 DOWNLOAD SHARED FILE - COMPLETELY FIXED
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def download_shared_file(request, slug):
    """Download a shared file - Works with Cloudinary and local storage"""
    log_info("=" * 60)
    log_info(f"📥 DOWNLOAD SHARED FILE")
    log_info(f"📥 Slug: {slug}")
    log_info(f"📥 Cloudinary enabled: {is_cloudinary_storage()}")
    log_info("=" * 60)
    
    try:
        # Get the shared link
        try:
            link = SharedLink.objects.select_related('file').get(slug=slug)
        except SharedLink.DoesNotExist:
            log_error(f"📥 SharedLink not found: {slug}")
            return json_response({
                'error': 'Invalid or expired share link',
                'slug': slug
            }, status=404)
        
        # Check if active
        if not link.is_active:
            log_error(f"📥 Link inactive: {slug}")
            return json_response({
                'error': 'This share link is no longer active'
            }, status=403)
        
        # Check if expired
        if link.is_expired():
            log_error(f"📥 Link expired: {slug}")
            link.is_active = False
            link.save(update_fields=['is_active'])
            return json_response({
                'error': 'This share link has expired'
            }, status=410)
        
        file_obj = link.file
        log_info(f"📥 File: {file_obj.original_name} (ID: {file_obj.id})")
        
        # Check if file is deleted
        if file_obj.deleted:
            log_error(f"📥 File is deleted")
            return json_response({
                'error': 'This file is no longer available'
            }, status=404)
        
        # Check download limit
        if link.download_count >= link.max_downloads:
            log_error(f"📥 Download limit reached: {link.download_count}/{link.max_downloads}")
            return json_response({
                'error': 'Download limit reached for this share link',
                'download_count': link.download_count,
                'max_downloads': link.max_downloads
            }, status=403)
        
        # Set first access time if not set
        if not link.first_accessed_at:
            link.first_accessed_at = timezone.now()
            link.expires_at = timezone.now() + timedelta(hours=24)
            link.save(update_fields=['first_accessed_at', 'expires_at'])
        
        # Check if file field exists
        if not file_obj.file:
            log_error(f"📥 No file attached to record")
            return json_response({
                'error': 'File not found',
                'details': 'No file is attached to this record'
            }, status=404)
        
        log_info(f"📥 File field: {file_obj.file.name}")
        
        # Try to get file URL
        try:
            file_url = file_obj.file.url
            log_info(f"📥 File URL: {file_url}")
        except Exception as e:
            log_error(f"📥 Cannot get file URL: {e}")
            return json_response({
                'error': 'File URL not available',
                'details': str(e)
            }, status=500)
        
        # ════════════════════════════════════════════════════
        # DOWNLOAD FROM REMOTE (Cloudinary or any HTTP URL)
        # ════════════════════════════════════════════════════
        if file_url.startswith('http://') or file_url.startswith('https://'):
            log_info(f"📥 Downloading from remote URL...")
            
            try:
                # Fetch file from remote URL
                response = requests.get(file_url, stream=True, timeout=60)
                
                if response.status_code != 200:
                    log_error(f"📥 Remote fetch failed: HTTP {response.status_code}")
                    return json_response({
                        'error': 'Could not fetch file from storage',
                        'status_code': response.status_code
                    }, status=503)
                
                # Increment download count
                link.download_count += 1
                link.save(update_fields=['download_count'])
                log_info(f"📥 Download count: {link.download_count}/{link.max_downloads}")
                
                # Get content type
                content_type = response.headers.get('Content-Type', 'application/octet-stream')
                
                # Create streaming response
                django_response = HttpResponse(
                    response.iter_content(chunk_size=8192),
                    content_type=content_type
                )
                django_response['Content-Disposition'] = f'attachment; filename="{file_obj.original_name}"'
                
                if 'Content-Length' in response.headers:
                    django_response['Content-Length'] = response.headers['Content-Length']
                
                log_info(f"📥 ✅ SUCCESS - Streaming: {file_obj.original_name}")
                return django_response
                
            except requests.exceptions.Timeout:
                log_error(f"📥 Timeout fetching file")
                return json_response({
                    'error': 'File download timed out. Please try again.'
                }, status=504)
            except requests.exceptions.RequestException as e:
                log_error(f"📥 Request error: {e}")
                return json_response({
                    'error': f'Download failed: {str(e)}'
                }, status=500)
        
        # ════════════════════════════════════════════════════
        # DOWNLOAD FROM LOCAL STORAGE
        # ════════════════════════════════════════════════════
        else:
            log_info(f"📥 Using local storage...")
            
            try:
                file_path = file_obj.file.path
                log_info(f"📥 File path: {file_path}")
                
                if not os.path.exists(file_path):
                    log_error(f"📥 File not on disk: {file_path}")
                    return json_response({
                        'error': 'File no longer available on server',
                        'details': 'Render uses ephemeral storage. Files are deleted on restart.',
                        'solution': 'Configure Cloudinary for persistent file storage.',
                        'help': 'Add CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET to environment'
                    }, status=404)
                
                # Increment download count
                link.download_count += 1
                link.save(update_fields=['download_count'])
                log_info(f"📥 Download count: {link.download_count}/{link.max_downloads}")
                
                # Get content type
                content_type, _ = mimetypes.guess_type(file_obj.original_name)
                if not content_type:
                    content_type = 'application/octet-stream'
                
                # Create file response
                response = FileResponse(
                    file_obj.file.open('rb'),
                    as_attachment=True,
                    filename=file_obj.original_name,
                    content_type=content_type
                )
                
                log_info(f"📥 ✅ SUCCESS - Local file: {file_obj.original_name}")
                return response
                
            except Exception as e:
                log_error(f"📥 Local storage error: {e}")
                traceback.print_exc()
                return json_response({
                    'error': 'Download failed',
                    'details': str(e)
                }, status=500)
    
    except Exception as e:
        log_error(f"📥 Unexpected error: {e}")
        traceback.print_exc()
        return json_response({
            'error': 'Download failed',
            'details': str(e)
        }, status=500)


# ═══════════════════════════════════════════════════════════
# 🔧 DEBUG ENDPOINTS
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def debug_shared_file(request, slug):
    """Debug endpoint to check file status"""
    log_info(f"🔧 DEBUG - Slug: {slug}")
    
    try:
        # Get shared link
        try:
            shared_link = SharedLink.objects.select_related('file').get(slug=slug)
        except SharedLink.DoesNotExist:
            return json_response({
                'error': 'Shared link not found',
                'slug': slug
            }, status=404)
        
        file_obj = shared_link.file
        cloudinary_enabled = is_cloudinary_storage()
        
        debug_info = {
            'shared_link': {
                'slug': shared_link.slug,
                'is_active': shared_link.is_active,
                'is_expired': shared_link.is_expired(),
                'expires_at': str(shared_link.expires_at) if shared_link.expires_at else None,
                'first_accessed_at': str(shared_link.first_accessed_at) if shared_link.first_accessed_at else None,
                'download_count': shared_link.download_count,
                'max_downloads': shared_link.max_downloads,
                'downloads_remaining': max(0, shared_link.max_downloads - shared_link.download_count),
            },
            'file': {
                'id': file_obj.id,
                'original_name': file_obj.original_name,
                'size': file_obj.size,
                'size_formatted': format_file_size(file_obj.size),
                'deleted': file_obj.deleted,
                'file_field_exists': bool(file_obj.file),
                'file_field_name': str(file_obj.file.name) if file_obj.file else None,
            },
            'storage': {
                'cloudinary_enabled': cloudinary_enabled,
                'storage_backend': 'cloudinary' if cloudinary_enabled else 'local',
            },
            'environment': {
                'RENDER': bool(os.environ.get('RENDER')),
                'CLOUDINARY_CLOUD_NAME_SET': bool(os.environ.get('CLOUDINARY_CLOUD_NAME')),
                'CLOUDINARY_API_KEY_SET': bool(os.environ.get('CLOUDINARY_API_KEY')),
                'CLOUDINARY_API_SECRET_SET': bool(os.environ.get('CLOUDINARY_API_SECRET')),
            }
        }
        
        # Try to get file URL
        if file_obj.file:
            try:
                file_url = file_obj.file.url
                debug_info['file']['url'] = file_url
                debug_info['file']['url_type'] = 'remote' if file_url.startswith('http') else 'local'
            except Exception as e:
                debug_info['file']['url_error'] = str(e)
            
            # Check if local file exists
            if not cloudinary_enabled and not file_url.startswith('http'):
                try:
                    file_path = file_obj.file.path
                    debug_info['file']['local_path'] = file_path
                    debug_info['file']['local_exists'] = os.path.exists(file_path)
                except Exception as e:
                    debug_info['file']['path_error'] = str(e)
        
        return json_response(debug_info, status=200)
        
    except Exception as e:
        log_error(f"🔧 Debug error: {e}")
        traceback.print_exc()
        return json_response({
            'error': str(e),
            'type': type(e).__name__
        }, status=500)


@csrf_exempt
def test_email_config(request):
    """Test endpoint to check email and storage configuration"""
    api_key = get_resend_api_key()
    cloudinary_enabled = is_cloudinary_storage()
    
    return json_response({
        'email': {
            'resend_configured': bool(api_key),
            'api_key_preview': f"{api_key[:15]}..." if api_key else None,
            'api_key_valid_format': api_key.startswith('re_') if api_key else False,
        },
        'storage': {
            'cloudinary_enabled': cloudinary_enabled,
            'cloudinary_cloud_name_set': bool(os.environ.get('CLOUDINARY_CLOUD_NAME')),
            'cloudinary_api_key_set': bool(os.environ.get('CLOUDINARY_API_KEY')),
            'cloudinary_api_secret_set': bool(os.environ.get('CLOUDINARY_API_SECRET')),
        },
        'environment': {
            'RENDER': bool(os.environ.get('RENDER')),
            'RENDER_EXTERNAL_HOSTNAME': os.environ.get('RENDER_EXTERNAL_HOSTNAME', 'Not set'),
        }
    })