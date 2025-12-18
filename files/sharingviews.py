# files/sharingviews.py

import logging
import os
import secrets
import json
import sys
from django.http import JsonResponse, FileResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import get_object_or_404
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from .models import File, SharedLink
from datetime import timedelta
from django.core.mail import send_mail
from django.conf import settings

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════
# 🔧 LOGGING HELPERS
# ═══════════════════════════════════════════════════════════
def log_info(message):
    print(f"[INFO] {message}", flush=True)
    sys.stdout.flush()
    logger.info(message)


def log_error(message):
    print(f"[ERROR] {message}", flush=True)
    sys.stdout.flush()
    logger.error(message)


# ═══════════════════════════════════════════════════════════
# 🔧 HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════
def generate_unique_slug():
    """Generate unique slug for share links"""
    for _ in range(10):
        slug = secrets.token_urlsafe(8)[:12]
        if not SharedLink.objects.filter(slug=slug).exists():
            return slug
    return secrets.token_urlsafe(12)


def is_file_deleted(file_obj):
    """Check if file is deleted"""
    if hasattr(file_obj, 'deleted') and file_obj.deleted:
        return True
    if hasattr(file_obj, 'deleted_at') and file_obj.deleted_at:
        return True
    return False


def send_share_email(recipient_email, subject, body):
    """Send email - returns True if successful"""
    try:
        # Try Resend API first
        resend_key = os.environ.get('RESEND_API_KEY', '')
        if resend_key:
            try:
                import resend
                resend.api_key = resend_key
                resend.Emails.send({
                    "from": "DropVault <onboarding@resend.dev>",
                    "to": [recipient_email],
                    "subject": subject,
                    "text": body,
                })
                log_info(f"✅ Email sent via Resend to {recipient_email}")
                return True
            except Exception as e:
                log_error(f"❌ Resend failed: {e}")
        
        # Fallback to Django mail
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@dropvault.app')
        send_mail(
            subject=subject,
            message=body,
            from_email=from_email,
            recipient_list=[recipient_email],
            fail_silently=True
        )
        log_info(f"✅ Email sent via Django to {recipient_email}")
        return True
        
    except Exception as e:
        log_error(f"❌ Email failed: {e}")
        return False


# ═══════════════════════════════════════════════════════════
# 🔗 CREATE SHARE LINK
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@login_required
@require_http_methods(["POST"])
def create_share_link(request, file_id):
    """
    Create a shareable link for a file
    POST /files/share/<file_id>/
    """
    log_info(f"🔗 CREATE SHARE LINK: file={file_id}, user={request.user.id}")
    
    try:
        file_obj = File.objects.get(id=file_id, user=request.user)
        if is_file_deleted(file_obj):
            return JsonResponse({'error': 'Cannot share deleted file'}, status=400)
    except File.DoesNotExist:
        return JsonResponse({'error': 'File not found'}, status=404)
    
    # Generate unique slug
    slug = generate_unique_slug()
    
    # Create share link
    link = SharedLink.objects.create(
        file=file_obj,
        owner=request.user,
        slug=slug,
        token=secrets.token_urlsafe(48),
        max_downloads=5,
        is_active=True
    )
    
    # Build share URL
    site_url = os.environ.get('SITE_URL', 'https://dropvault-2.onrender.com')
    share_url = f"{site_url}/s/{slug}/"
    
    log_info(f"✅ Share link created: {share_url}")
    
    return JsonResponse({
        'status': 'success',
        'share_url': share_url,
        'slug': slug,
        'link': share_url,
    }, status=201)


# ═══════════════════════════════════════════════════════════
# 📧 SHARE VIA EMAIL
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@require_http_methods(["POST"])
def share_via_email(request, file_id):
    """
    Share file via email
    POST /files/share/<file_id>/email/
    """
    log_info(f"📧 SHARE VIA EMAIL: file={file_id}")
    
    # Check authentication - return JSON, not redirect
    if not request.user.is_authenticated:
        log_error("📧 User not authenticated")
        return JsonResponse({'error': 'Please login first'}, status=401)
    
    log_info(f"📧 User: {request.user.email}")
    
    # Get file
    try:
        file_obj = File.objects.get(id=file_id, user=request.user)
        if is_file_deleted(file_obj):
            return JsonResponse({'error': 'Cannot share deleted file'}, status=400)
    except File.DoesNotExist:
        log_error(f"📧 File {file_id} not found")
        return JsonResponse({'error': 'File not found'}, status=404)
    
    # Parse request body
    recipient_email = ''
    message = ''
    
    # Try to parse JSON body
    try:
        if request.body:
            log_info(f"📧 Body received: {request.body[:200]}")
            data = json.loads(request.body.decode('utf-8'))
            recipient_email = data.get('recipient_email', '').strip()
            message = data.get('message', '')
            log_info(f"📧 Parsed JSON: email={recipient_email}")
    except Exception as e:
        log_error(f"📧 JSON parse error: {e}")
    
    # Fallback to POST form data
    if not recipient_email:
        recipient_email = request.POST.get('recipient_email', '').strip()
        message = request.POST.get('message', '')
        log_info(f"📧 From POST: email={recipient_email}")
    
    # Validate email
    if not recipient_email:
        log_error("📧 No recipient email provided")
        return JsonResponse({'error': 'Recipient email is required'}, status=400)
    
    if '@' not in recipient_email or '.' not in recipient_email:
        log_error(f"📧 Invalid email: {recipient_email}")
        return JsonResponse({'error': 'Invalid email format'}, status=400)
    
    try:
        # Create share link
        slug = generate_unique_slug()
        
        SharedLink.objects.create(
            file=file_obj,
            owner=request.user,
            slug=slug,
            token=secrets.token_urlsafe(48),
            max_downloads=5,
            is_active=True
        )
        
        # Build share URL
        site_url = os.environ.get('SITE_URL', 'https://dropvault-2.onrender.com')
        share_url = f"{site_url}/s/{slug}/"
        
        log_info(f"📧 Share URL created: {share_url}")
        
        # Prepare email
        subject = f"{file_obj.original_name} shared with you - DropVault"
        
        body = f"""Hi,

{request.user.email} shared '{file_obj.original_name}' with you.

"""
        if message:
            body += f"Message: {message}\n\n"
        
        body += f"""Access link: {share_url}

This link expires 24 hours after first access.
Max 5 downloads allowed.

- DropVault
"""
        
        # Send email
        email_sent = send_share_email(recipient_email, subject, body)
        
        log_info(f"📧 Share completed: email_sent={email_sent}")
        
        # Return response
        response_data = {
            'status': 'success',
            'message': f'Share link created for {recipient_email}',
            'share_url': share_url,
            'email_sent': email_sent
        }
        
        if not email_sent:
            response_data['warning'] = 'Email could not be sent. Please share the link manually.'
        
        return JsonResponse(response_data)
        
    except Exception as e:
        log_error(f"📧 Share via email failed: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({'error': str(e)}, status=500)


# ═══════════════════════════════════════════════════════════
# 📥 SHARED FILE VIEW (Public Access)
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@require_http_methods(["GET"])
def shared_file_view(request, slug, action=None):
    """
    Access shared file
    GET /s/<slug>/          - Preview
    GET /s/<slug>/download/ - Download
    """
    log_info(f"📥 SHARED FILE VIEW: slug={slug}, action={action}")
    
    try:
        link = SharedLink.objects.select_related('file', 'file__user').get(
            slug=slug,
            is_active=True
        )
    except SharedLink.DoesNotExist:
        log_error(f"❌ Share link not found: {slug}")
        return JsonResponse({'error': 'Link not found or inactive'}, status=404)
    
    # Check expiry
    if link.is_expired():
        link.is_active = False
        link.save()
        return JsonResponse({'error': 'Link expired'}, status=410)
    
    file_obj = link.file
    
    # Check file availability
    if not file_obj.user.is_active or is_file_deleted(file_obj):
        link.is_active = False
        link.save()
        return JsonResponse({'error': 'File unavailable'}, status=404)
    
    # First access - start 24h timer
    if not link.first_accessed_at:
        now = timezone.now()
        link.first_accessed_at = now
        link.expires_at = now + timedelta(hours=24)
        link.save()
    
    # Increment view count
    link.view_count = (link.view_count or 0) + 1
    link.save()
    
    # Download action
    if action == 'download':
        if link.download_count >= link.max_downloads:
            return JsonResponse({'error': 'Download limit reached'}, status=403)
        
        link.download_count = (link.download_count or 0) + 1
        link.save()
        
        try:
            response = FileResponse(
                file_obj.file.open('rb'),
                content_type='application/octet-stream',
                as_attachment=True,
                filename=file_obj.original_name
            )
            response['Content-Length'] = file_obj.size
            log_info(f"✅ File downloaded: {file_obj.original_name}")
            return response
        except FileNotFoundError:
            log_error(f"❌ File not found: {file_obj.file.name}")
            return JsonResponse({'error': 'File not found on server'}, status=500)
        except Exception as e:
            log_error(f"❌ Download error: {e}")
            return JsonResponse({'error': 'Download failed'}, status=500)
    
    # Preview - return JSON info
    ext = os.path.splitext(file_obj.original_name)[1].lstrip('.').lower() or 'unknown'
    
    return JsonResponse({
        'success': True,
        'file': {
            'name': file_obj.original_name,
            'size': file_obj.size,
            'type': ext,
            'uploaded_at': file_obj.uploaded_at.isoformat(),
        },
        'link': {
            'slug': link.slug,
            'view_count': link.view_count,
            'download_count': link.download_count,
            'max_downloads': link.max_downloads,
            'first_accessed_at': link.first_accessed_at.isoformat() if link.first_accessed_at else None,
            'expires_at': link.expires_at.isoformat() if link.expires_at else None,
            'owner_email': link.owner.email,
        },
        'download_url': request.build_absolute_uri(f"/s/{slug}/download/"),
    })


# ═══════════════════════════════════════════════════════════
# 📥 DOWNLOAD SHARED FILE (Alternate endpoint)
# ═══════════════════════════════════════════════════════════
@require_http_methods(["GET"])
def download_shared_file(request, slug):
    """Direct download endpoint"""
    return shared_file_view(request, slug, action='download')