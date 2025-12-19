# files/sharingviews.py
import os
import secrets
import json
import sys
import traceback
from django.http import JsonResponse, FileResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
from django.utils import timezone
from datetime import timedelta
from .models import File, SharedLink

# Import the working email function from accounts
from accounts.utils import send_file_share_email


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
    # First check environment variable
    site_url = os.environ.get('SITE_URL', '').strip()
    
    # Auto-detect from Render
    if not site_url or 'localhost' in site_url:
        render_host = os.environ.get('RENDER_EXTERNAL_HOSTNAME', '')
        if render_host:
            site_url = f'https://{render_host}'
    
    # Fallback to request
    if not site_url:
        site_url = request.build_absolute_uri('/')[:-1]
    
    return site_url


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
        
        # Check existing active link
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
        
        # Create new link
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


@csrf_exempt
def share_via_email(request, file_id):
    """Share a file via email"""
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
        
        file_obj = File.objects.get(id=file_id, user=request.user)
        
        if file_obj.deleted:
            return json_response({'error': 'Cannot share deleted file'}, status=400)
        
        # Parse request body
        recipient_email = ''
        message = ''
        
        if request.body:
            try:
                data = json.loads(request.body.decode('utf-8'))
                recipient_email = data.get('recipient_email', '').strip()
                message = data.get('message', '').strip()
            except json.JSONDecodeError:
                pass
        
        # Fallback to POST data
        if not recipient_email:
            recipient_email = request.POST.get('recipient_email', '').strip()
            message = request.POST.get('message', '').strip()
        
        log_info(f"📧 Recipient: {recipient_email}")
        log_info(f"📧 Message: {message[:50] if message else 'None'}...")
        
        if not recipient_email or '@' not in recipient_email:
            return json_response({
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
        
        log_info(f"📧 Share URL: {share_url}")
        
        # Send email using the working Resend function
        email_sent = send_file_share_email(
            to_email=recipient_email,
            from_user=request.user,
            file_name=file_obj.original_name,
            share_url=share_url,
            message=message if message else None
        )
        
        log_info(f"📧 Email sent: {email_sent}")
        
        if email_sent:
            return json_response({
                'status': 'success',
                'share_url': share_url,
                'email_sent': True,
                'message': f'File shared successfully! Email sent to {recipient_email}'
            })
        else:
            return json_response({
                'status': 'partial',
                'share_url': share_url,
                'email_sent': False,
                'message': 'Share link created but email could not be sent. You can copy the link manually.',
                'warning': 'Email service may not be configured. Check RESEND_API_KEY.'
            })
        
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
    
    # Set first access time and expiry
    if not link.first_accessed_at:
        link.first_accessed_at = timezone.now()
        link.expires_at = timezone.now() + timedelta(hours=24)
        link.save()
    
    # Increment view count
    link.view_count = (link.view_count or 0) + 1
    link.save(update_fields=['view_count'])
    
    # Handle download
    if action == 'download':
        if link.download_count >= link.max_downloads:
            return json_response({'error': 'Download limit reached'}, status=403)
        
        link.download_count += 1
        link.save(update_fields=['download_count'])
        
        log_info(f"📥 Download #{link.download_count} for {file_obj.original_name}")
        
        try:
            response = FileResponse(
                file_obj.file.open('rb'),
                as_attachment=True,
                filename=file_obj.original_name
            )
            return response
        except Exception as e:
            log_error(f"📥 Download error: {e}")
            return json_response({'error': 'Download failed'}, status=500)
    
    # Show preview page for HTML requests
    if 'text/html' in request.META.get('HTTP_ACCEPT', ''):
        site_url = get_site_url(request)
        return render(request, 'shared_file.html', {
            'file': file_obj,
            'link': link,
            'download_url': f"{site_url}/s/{slug}/download/",
            'downloads_remaining': link.max_downloads - link.download_count
        })
    
    # JSON response for API
    return json_response({
        'file': {
            'name': file_obj.original_name,
            'size': file_obj.size
        },
        'download_url': f"/s/{slug}/download/",
        'downloads_remaining': link.max_downloads - link.download_count
    })


def download_shared_file(request, slug):
    """Direct download endpoint"""
    return shared_file_view(request, slug, action='download')