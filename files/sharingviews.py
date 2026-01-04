# files/sharingviews.py
import os
import secrets
import json
import sys
import traceback
import requests
from django.http import JsonResponse, FileResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
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
        return json_response({'error': str(e)}, status=500)


# ═══════════════════════════════════════════════════════════
# 📧 SHARE VIA EMAIL - FIXED (No restriction)
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def share_via_email(request, file_id):
    """Share a file via email - NO RESTRICTION"""
    if request.method == "OPTIONS":
        return json_response({'status': 'ok'})
    
    log_info("=" * 60)
    log_info(f"📧 SHARE VIA EMAIL - File: {file_id}")
    log_info(f"📧 User: {request.user}, Auth: {request.user.is_authenticated}")
    log_info("=" * 60)
    
    try:
        if not request.user.is_authenticated:
            log_error("📧 NOT AUTHENTICATED")
            return auth_error()
        
        # Check if email service is configured
        api_key = get_resend_api_key()
        if not api_key:
            log_error("📧 RESEND_API_KEY not configured!")
            return json_response({
                'status': 'error',
                'error': 'Email service not configured',
                'message': 'Please add RESEND_API_KEY to environment variables',
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
                log_info(f"📧 Parsed JSON body")
            except json.JSONDecodeError as e:
                log_error(f"📧 JSON decode error: {e}")
        
        if not recipient_email:
            recipient_email = request.POST.get('recipient_email', '').strip().lower()
            message = request.POST.get('message', '').strip()
            log_info(f"📧 Using POST data")
        
        log_info(f"📧 Recipient: {recipient_email}")
        
        if not recipient_email or '@' not in recipient_email:
            return json_response({
                'status': 'error',
                'error': 'Valid email address required'
            }, status=400)
        
        # ✅ REMOVED: Email restriction code
        # Now allows sending to ANY email address
        # Note: Resend free tier may still limit emails to verified addresses
        # To send to any email, verify a domain at https://resend.com/domains
        
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
        
        log_info(f"📧 Share URL: {share_url}")
        
        # Send email using Resend
        success, error_msg = send_file_share_email(
            to_email=recipient_email,
            from_user=request.user,
            file_name=file_obj.original_name,
            share_url=share_url,
            message=message if message else None
        )
        
        log_info(f"📧 Email result: success={success}, error={error_msg}")
        
        if success:
            return json_response({
                'status': 'success',
                'share_url': share_url,
                'email_sent': True,
                'message': f'File shared! Email sent to {recipient_email}. Check spam folder.'
            })
        else:
            # ✅ IMPROVED: Better error message for Resend test mode
            error_detail = error_msg or 'Email sending failed'
            
            # Check if it's a Resend test mode error
            if 'test' in error_detail.lower() or 'verify' in error_detail.lower():
                error_detail = (
                    f"Resend Test Mode: Can only send to verified email. "
                    f"To send to {recipient_email}, verify a domain at resend.com/domains"
                )
            
            create_user_notification(
                user=request.user,
                notification_type='FILE_SHARE',
                title='File Shared via Email',
                message=f'"{file_obj.original_name}" was shared with {recipient_email}.',
                file_name=file_obj.original_name,
                file_id=file_obj.id
            )

            return json_response({
                'status': 'partial',
                'share_url': share_url,
                'email_sent': False,
                'error': error_detail,
                'message': f'Share link created! Copy this link: {share_url}',
                'note': 'Email failed but you can share the link manually'
            }, status=200)
        
    except File.DoesNotExist:
        return json_response({'error': 'File not found'}, status=404)
    except Exception as e:
        log_error(f"📧 Error: {e}")
        log_error(traceback.format_exc())
        return json_response({'error': str(e)}, status=500)


@csrf_exempt
def shared_file_view(request, slug, action=None):
    """View or download a shared file"""
    log_info(f"📥 SHARED FILE - Slug: {slug}, Action: {action}")
    
    try:
        link = SharedLink.objects.select_related('file').get(slug=slug, is_active=True)
    except SharedLink.DoesNotExist:
        if 'text/html' in request.META.get('HTTP_ACCEPT', ''):
            return render(request, 'shared_file_error.html', {'error': 'Link not found or expired'}, status=404)
        return json_response({'error': 'Link not found or expired'}, status=404)
    
    if link.is_expired():
        link.is_active = False
        link.save()
        if 'text/html' in request.META.get('HTTP_ACCEPT', ''):
            return render(request, 'shared_file_error.html', {'error': 'This link has expired'}, status=410)
        return json_response({'error': 'Link has expired'}, status=410)
    
    file_obj = link.file
    
    if file_obj.deleted:
        return json_response({'error': 'File is no longer available'}, status=404)
    
    if not link.first_accessed_at:
        link.first_accessed_at = timezone.now()
        link.expires_at = timezone.now() + timedelta(hours=24)
        link.save()
    
    link.view_count = (link.view_count or 0) + 1
    link.save(update_fields=['view_count'])
    
    # Handle download
    if action == 'download':
        return download_shared_file(request, slug)
    
    # Show preview page
    if 'text/html' in request.META.get('HTTP_ACCEPT', ''):
        site_url = get_site_url(request)
        return render(request, 'shared_file.html', {
            'file': file_obj,
            'link': link,
            'download_url': f"{site_url}/s/{slug}/download/",
            'downloads_remaining': link.max_downloads - link.download_count
        })
    
    return json_response({
        'file': {
            'name': file_obj.original_name,
            'size': file_obj.size
        },
        'download_url': f"/s/{slug}/download/",
        'downloads_remaining': link.max_downloads - link.download_count
    })


# ═══════════════════════════════════════════════════════════
# 📥 DOWNLOAD SHARED FILE - FIXED FOR CLOUDINARY
# ═══════════════════════════════════════════════════════════

@csrf_exempt
def download_shared_file(request, slug):
    """Download a shared file - Works with Cloudinary and local storage"""
    log_info("=" * 60)
    log_info(f"📥 DOWNLOAD SHARED FILE - Slug: {slug}")
    log_info("=" * 60)
    
    try:
        # Get the shared link
        try:
            link = SharedLink.objects.select_related('file').get(slug=slug, is_active=True)
        except SharedLink.DoesNotExist:
            log_error(f"📥 SharedLink not found: {slug}")
            return JsonResponse({'error': 'Invalid or expired share link'}, status=404)
        
        # Check if expired
        if link.is_expired():
            log_error(f"📥 Link expired: {slug}")
            link.is_active = False
            link.save()
            return JsonResponse({'error': 'This link has expired'}, status=410)
        
        file_obj = link.file
        log_info(f"📥 File: {file_obj.original_name} (ID: {file_obj.id})")
        
        # Check if file is deleted
        if file_obj.deleted:
            log_error(f"📥 File is deleted")
            return JsonResponse({'error': 'File is no longer available'}, status=404)
        
        # Check download limit
        if link.download_count >= link.max_downloads:
            log_error(f"📥 Download limit reached: {link.download_count}/{link.max_downloads}")
            return JsonResponse({'error': 'Download limit reached'}, status=403)
        
        # Set first access time if not set
        if not link.first_accessed_at:
            link.first_accessed_at = timezone.now()
            link.expires_at = timezone.now() + timedelta(hours=24)
            link.save(update_fields=['first_accessed_at', 'expires_at'])
        
        # Check if file field exists
        if not file_obj.file:
            log_error(f"📥 No file attached to record")
            return JsonResponse({'error': 'File not found'}, status=404)
        
        # Get file URL
        try:
            file_url = file_obj.file.url
            log_info(f"📥 File URL: {file_url}")
        except Exception as e:
            log_error(f"📥 Cannot get file URL: {e}")
            return JsonResponse({'error': 'File URL not available'}, status=500)
        
        # ════════════════════════════════════════════════════
        # CLOUDINARY / REMOTE URL - Stream the file
        # ════════════════════════════════════════════════════
        if file_url.startswith('http://') or file_url.startswith('https://'):
            log_info(f"📥 Downloading from remote URL: {file_url}")
            
            try:
                # Fetch file from Cloudinary
                response = requests.get(file_url, stream=True, timeout=60)
                
                if response.status_code != 200:
                    log_error(f"📥 Remote fetch failed: HTTP {response.status_code}")
                    return JsonResponse({
                        'error': 'Could not fetch file from storage',
                        'status': response.status_code
                    }, status=503)
                
                # Increment download count
                link.download_count += 1
                link.save(update_fields=['download_count'])
                log_info(f"📥 Download #{link.download_count}/{link.max_downloads}")
                
                # Get content type
                content_type = response.headers.get('Content-Type', 'application/octet-stream')
                
                # Create streaming response with proper filename
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
                return JsonResponse({'error': 'Download timed out. Please try again.'}, status=504)
            except requests.exceptions.RequestException as e:
                log_error(f"📥 Request error: {e}")
                return JsonResponse({'error': f'Download failed: {str(e)}'}, status=500)
        
        # ════════════════════════════════════════════════════
        # LOCAL STORAGE
        # ════════════════════════════════════════════════════
        else:
            log_info(f"📥 Using local storage")
            
            try:
                file_path = file_obj.file.path
                log_info(f"📥 File path: {file_path}")
                
                if not os.path.exists(file_path):
                    log_error(f"📥 File not on disk: {file_path}")
                    return JsonResponse({
                        'error': 'File no longer available on server',
                        'reason': 'Render uses ephemeral storage - files deleted on restart',
                        'solution': 'Configure Cloudinary for persistent storage'
                    }, status=404)
                
                # Increment download count
                link.download_count += 1
                link.save(update_fields=['download_count'])
                log_info(f"📥 Download #{link.download_count}/{link.max_downloads}")
                
                # Get content type
                content_type, _ = mimetypes.guess_type(file_obj.original_name)
                if not content_type:
                    content_type = 'application/octet-stream'
                
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
                return JsonResponse({'error': f'Download failed: {str(e)}'}, status=500)
    
    except Exception as e:
        log_error(f"📥 Unexpected error: {e}")
        traceback.print_exc()
        return JsonResponse({'error': f'Download failed: {str(e)}'}, status=500)


# ═══════════════════════════════════════════════════════════
# 🔧 DEBUG ENDPOINTS
# ═══════════════════════════════════════════════════════════
def debug_shared_file(request, slug):
    """Debug endpoint to check file status"""
    try:
        shared_link = get_object_or_404(SharedLink, slug=slug)
        file_obj = shared_link.file
        
        debug_info = {
            'shared_link': {
                'slug': shared_link.slug,
                'is_active': shared_link.is_active,
                'expires_at': str(shared_link.expires_at) if shared_link.expires_at else None,
                'download_count': shared_link.download_count,
            },
            'file': {
                'id': file_obj.id,
                'original_name': file_obj.original_name,
                'file_field': str(file_obj.file) if file_obj.file else None,
                'size': file_obj.size,
            },
            'storage': {
                'cloudinary_enabled': is_cloudinary_storage(),
                'cloudinary_cloud_name': settings.CLOUDINARY_STORAGE.get('CLOUD_NAME', 'Not set'),
            }
        }
        
        # Check file availability
        if file_obj.file:
            try:
                file_url = file_obj.file.url
                debug_info['file']['url'] = file_url
                debug_info['file']['url_accessible'] = True
            except Exception as e:
                debug_info['file']['url_error'] = str(e)
                debug_info['file']['url_accessible'] = False
        
        return JsonResponse(debug_info, status=200)
        
    except Exception as e:
        return JsonResponse({
            'error': str(e),
            'type': type(e).__name__
        }, status=500)


@csrf_exempt
def test_email_config(request):
    """Test endpoint to check email configuration"""
    api_key = get_resend_api_key()
    
    return json_response({
        'resend_configured': bool(api_key),
        'api_key_preview': f"{api_key[:15]}..." if api_key else None,
        'api_key_valid_format': api_key.startswith('re_') if api_key else False,
        'default_from_email': os.environ.get('DEFAULT_FROM_EMAIL', 'Not set'),
        'render_hostname': os.environ.get('RENDER_EXTERNAL_HOSTNAME', 'Not set'),
        'cloudinary_enabled': is_cloudinary_storage(),
        'note': 'Email restriction removed - Resend will handle test mode limits'
    })