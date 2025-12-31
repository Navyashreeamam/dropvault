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
    """Check if Cloudinary storage is enabled"""
    return all([
        settings.CLOUDINARY_STORAGE.get('CLOUD_NAME'),
        settings.CLOUDINARY_STORAGE.get('API_KEY'),
        settings.CLOUDINARY_STORAGE.get('API_SECRET')
    ])


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
    log_info(f"📥 DOWNLOAD SHARED - Slug: {slug}")
    
    try:
        link = SharedLink.objects.select_related('file').get(slug=slug, is_active=True)
        
        if link.is_expired():
            log_error(f"📥 Link expired: {slug}")
            link.is_active = False
            link.save()
            return JsonResponse({'error': 'This link has expired'}, status=410)
        
        if not link.is_active:
            log_error(f"📥 Link inactive: {slug}")
            return JsonResponse({'error': 'This link is no longer active'}, status=403)
        
        file_obj = link.file
        
        if file_obj.deleted:
            log_error(f"📥 File deleted: {file_obj.original_name}")
            return JsonResponse({'error': 'File is no longer available'}, status=404)
        
        if not link.first_accessed_at:
            link.first_accessed_at = timezone.now()
            link.expires_at = timezone.now() + timedelta(hours=24)
            link.save(update_fields=['first_accessed_at', 'expires_at'])
        
        if link.download_count >= link.max_downloads:
            log_error(f"📥 Download limit reached: {slug}")
            return JsonResponse({'error': 'Download limit reached'}, status=403)
        
        # Check if file field exists
        if not file_obj.file:
            log_error(f"📥 No file attached to record")
            return JsonResponse({
                'error': 'File not found',
                'details': 'The file record exists but no file is attached'
            }, status=404)
        
        # ✅ FIXED: Handle both Cloudinary and local storage
        try:
            # Check if using Cloudinary
            if is_cloudinary_storage():
                log_info(f"📥 Using Cloudinary storage")
                
                # Get the Cloudinary URL
                try:
                    file_url = file_obj.file.url
                    log_info(f"📥 Cloudinary URL: {file_url}")
                    
                    # Increment download count BEFORE redirect
                    link.download_count += 1
                    link.save(update_fields=['download_count'])
                    
                    log_info(f"📥 Download #{link.download_count}: {file_obj.original_name}")
                    
                    # Option 1: Redirect to Cloudinary URL (faster, but shows Cloudinary URL)
                    # from django.shortcuts import redirect
                    # return redirect(file_url)
                    
                    # Option 2: Stream from Cloudinary (hides URL, proper filename)
                    response = requests.get(file_url, stream=True, timeout=30)
                    
                    if response.status_code != 200:
                        log_error(f"📥 Cloudinary fetch failed: {response.status_code}")
                        return JsonResponse({
                            'error': 'File temporarily unavailable',
                            'details': 'Could not fetch file from storage'
                        }, status=503)
                    
                    # Get content type
                    content_type = response.headers.get('Content-Type', 'application/octet-stream')
                    
                    # Create streaming response
                    django_response = HttpResponse(
                        response.iter_content(chunk_size=8192),
                        content_type=content_type
                    )
                    django_response['Content-Disposition'] = f'attachment; filename="{file_obj.original_name}"'
                    
                    # Set content length if available
                    if 'Content-Length' in response.headers:
                        django_response['Content-Length'] = response.headers['Content-Length']
                    
                    log_info(f"📥 ✅ Streaming from Cloudinary: {file_obj.original_name}")
                    return django_response
                    
                except Exception as e:
                    log_error(f"📥 Cloudinary error: {e}")
                    return JsonResponse({
                        'error': 'Download failed',
                        'details': str(e)
                    }, status=500)
            
            else:
                # Local storage
                log_info(f"📥 Using local storage")
                
                try:
                    file_path = file_obj.file.path
                    
                    if not os.path.exists(file_path):
                        log_error(f"📥 File not found on disk: {file_path}")
                        return JsonResponse({
                            'error': 'File no longer available',
                            'details': 'File was deleted from server storage',
                            'reason': 'Render free tier uses ephemeral storage - files are deleted on restart',
                            'solution': 'Configure Cloudinary for persistent storage'
                        }, status=404)
                    
                    # Increment download count
                    link.download_count += 1
                    link.save(update_fields=['download_count'])
                    
                    log_info(f"📥 Download #{link.download_count}: {file_obj.original_name}")
                    
                    content_type, _ = mimetypes.guess_type(file_obj.original_name)
                    if not content_type:
                        content_type = 'application/octet-stream'
                    
                    response = FileResponse(
                        file_obj.file.open('rb'),
                        as_attachment=True,
                        filename=file_obj.original_name,
                        content_type=content_type
                    )
                    
                    log_info(f"📥 ✅ Download started: {file_obj.original_name}")
                    return response
                    
                except Exception as e:
                    log_error(f"📥 Local storage error: {e}")
                    return JsonResponse({
                        'error': 'Download failed',
                        'details': str(e)
                    }, status=500)
                    
        except Exception as e:
            log_error(f"📥 Storage check error: {e}")
            return JsonResponse({
                'error': 'Storage error',
                'details': str(e)
            }, status=500)
        
    except SharedLink.DoesNotExist:
        log_error(f"📥 Invalid slug: {slug}")
        return JsonResponse({
            'error': 'Invalid or expired share link',
            'slug': slug
        }, status=404)
        
    except Exception as e:
        log_error(f"📥 Download error: {e}")
        traceback.print_exc()
        return JsonResponse({
            'error': 'Download failed',
            'details': str(e)
        }, status=500)


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