# dropvault/files/sharingviews.py

import logging
import os
import secrets
import json
import sys
import re
from django.http import JsonResponse, FileResponse
from django.views.decorators.csrf import csrf_exempt
from django.db import models
from django.shortcuts import get_object_or_404
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from .models import File, SharedLink
from .serializers import SharedLinkSerializer
from datetime import timedelta
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.response import Response

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════
# 🔧 LOGGING HELPERS
# ═══════════════════════════════════════════════════════════
def log_info(message):
    """Log info message to console and logger"""
    timestamp = timezone.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] [INFO] {message}", flush=True)
    sys.stdout.flush()
    logger.info(message)


def log_error(message):
    """Log error message to console and logger"""
    timestamp = timezone.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] [ERROR] {message}", flush=True)
    sys.stdout.flush()
    logger.error(message)


# ═══════════════════════════════════════════════════════════
# 🔧 HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════
def api_error(message, status=400):
    """Return JSON error response"""
    return JsonResponse({'error': message}, status=status)


def generate_unique_slug():
    """Generate a unique slug for share links"""
    while True:
        slug = secrets.token_urlsafe(8)[:12]
        if not SharedLink.objects.filter(slug=slug).exists():
            return slug


def is_file_deleted(file_obj):
    """Helper to check if file is deleted"""
    if hasattr(file_obj, 'deleted_at') and file_obj.deleted_at is not None:
        return True
    if hasattr(file_obj, 'deleted') and file_obj.deleted:
        return True
    return False


def send_share_email(recipient_email, subject, text_content):
    """
    Send email - tries Resend API first, then Django mail
    Returns True if successful, False otherwise
    """
    # Try Resend API first
    resend_api_key = getattr(settings, 'RESEND_API_KEY', '') or os.environ.get('RESEND_API_KEY', '')
    
    if resend_api_key:
        try:
            import resend
            resend.api_key = resend_api_key
            
            from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'DropVault <onboarding@resend.dev>')
            
            resend.Emails.send({
                "from": from_email,
                "to": [recipient_email],
                "subject": subject,
                "text": text_content,
            })
            log_info(f"✅ Email sent via Resend to {recipient_email}")
            return True
            
        except Exception as e:
            log_error(f"❌ Resend email failed: {str(e)}")
    
    # Try Django's send_mail as fallback
    try:
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@dropvault.app')
        send_mail(
            subject=subject,
            message=text_content,
            from_email=from_email,
            recipient_list=[recipient_email],
            fail_silently=True
        )
        log_info(f"✅ Email sent via Django to {recipient_email}")
        return True
    except Exception as e:
        log_error(f"❌ Django email failed: {str(e)}")
        return False


# ═══════════════════════════════════════════════════════════
# 🔗 SHARED FILE VIEW
# ═══════════════════════════════════════════════════════════
@require_http_methods(["GET"])
@csrf_exempt
def shared_file_view(request, slug, action=None):
    """
    Handles:
      - GET /s/<slug>/          → renders JSON preview
      - GET /s/<slug>/download/ → streams encrypted file
    """
    log_info(f"📥 SHARED FILE VIEW request for slug: {slug}, action: {action}")
    
    try:
        link = SharedLink.objects.select_related('file', 'file__user').get(
            slug=slug,
            is_active=True
        )
    except SharedLink.DoesNotExist:
        log_error(f"❌ Share link not found: {slug}")
        return api_error('Link not found or inactive.', status=404)

    # Check expiry
    if link.is_expired():
        link.is_active = False
        link.save(update_fields=['is_active'])
        return api_error('Link expired.', status=410)

    # Validate file & owner
    file_obj = link.file
    owner = file_obj.user
    
    if not owner.is_active or is_file_deleted(file_obj):
        link.is_active = False
        link.save(update_fields=['is_active'])
        return api_error('File unavailable.', status=404)

    # First access → activate 24h timer
    if link.first_accessed_at is None:
        now = timezone.now()
        SharedLink.objects.filter(id=link.id).update(
            first_accessed_at=now,
            expires_at=now + timedelta(hours=24)
        )
        link.refresh_from_db()

    # Increment view count
    SharedLink.objects.filter(id=link.id).update(view_count=models.F('view_count') + 1)
    link.refresh_from_db()

    # Download action
    if action == 'download':
        if link.download_count >= link.max_downloads:
            return api_error('Download limit reached.', status=403)

        SharedLink.objects.filter(id=link.id).update(download_count=models.F('download_count') + 1)
        link.refresh_from_db()

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
            return api_error('File missing on server.', status=500)

    else:
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
                'is_expired': link.is_expired(),
                'owner_email': link.owner.email,
            },
            'download_url': request.build_absolute_uri(f"/s/{slug}/download/"),
        })


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
    log_info(f"🔗 CREATE SHARE LINK request for file {file_id} from user {request.user.id}")
    
    file_obj = get_object_or_404(File, id=file_id, user=request.user)
    
    if is_file_deleted(file_obj):
        return JsonResponse({'error': 'Cannot share deleted file'}, status=400)

    slug = generate_unique_slug()
    token = secrets.token_urlsafe(48)

    link = SharedLink.objects.create(
        file=file_obj,
        owner=request.user,
        slug=slug,
        token=token,
        max_downloads=5,
        is_active=True
    )

    serializer = SharedLinkSerializer(link, context={'request': request})
    log_info(f"✅ Share link created: {slug}")
    return JsonResponse(serializer.data, status=201)


# ═══════════════════════════════════════════════════════════
# 📧 SHARE VIA EMAIL (COMPLETE FIXED VERSION)
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@require_http_methods(["POST"])
def share_via_email(request, file_id):
    """
    Share file via email
    POST /files/share/<file_id>/email/
    """
    log_info(f"📧 SHARE VIA EMAIL request for file {file_id}")
    
    # Check authentication - return JSON, not redirect
    if not request.user.is_authenticated:
        log_error("📧 User not authenticated")
        return JsonResponse({
            'error': 'Authentication required',
            'message': 'Please login first'
        }, status=401)
    
    log_info(f"📧 User: {request.user.id} ({request.user.email})")
    log_info(f"📧 Content-Type: {request.content_type}")
    log_info(f"📧 Body: {request.body[:200] if request.body else 'EMPTY'}")
    
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
    
    # Method 1: JSON body
    if request.body:
        try:
            data = json.loads(request.body.decode('utf-8'))
            recipient_email = data.get('recipient_email', '').strip()
            message = data.get('message', '')
            log_info(f"📧 Parsed from JSON: email={recipient_email}")
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            log_info(f"📧 JSON parse failed: {e}")
    
    # Method 2: POST form data
    if not recipient_email:
        recipient_email = request.POST.get('recipient_email', '').strip()
        message = request.POST.get('message', '')
        log_info(f"📧 Parsed from POST: email={recipient_email}")
    
    # Method 3: Alternative field name
    if not recipient_email:
        recipient_email = request.POST.get('email', '').strip()
        log_info(f"📧 Parsed from POST (email): email={recipient_email}")
    
    # Validate email
    if not recipient_email:
        log_error("📧 No recipient email provided")
        return JsonResponse({'error': 'Recipient email is required'}, status=400)
    
    # Simple email validation
    if '@' not in recipient_email or '.' not in recipient_email:
        log_error(f"📧 Invalid email format: {recipient_email}")
        return JsonResponse({'error': 'Invalid email format'}, status=400)
    
    try:
        # Create share link
        slug = generate_unique_slug()
        token = secrets.token_urlsafe(48)
        
        share_link = SharedLink.objects.create(
            file=file_obj,
            owner=request.user,
            slug=slug,
            token=token,
            max_downloads=5,
            is_active=True
        )
        
        # Build share URL
        site_url = os.environ.get('SITE_URL', 'https://dropvault-2.onrender.com')
        share_url = f"{site_url}/s/{share_link.slug}/"
        
        log_info(f"📧 Share link created: {share_url}")
        
        # Prepare email content
        subject = f"{file_obj.original_name} shared with you - DropVault"
        
        email_body = f"""Hi,

{request.user.email} shared '{file_obj.original_name}' with you.

"""
        if message:
            email_body += f"Message: {message}\n\n"
        
        email_body += f"""Access link: {share_url}

This link expires 24 hours after first access.
Max 5 downloads allowed.

- DropVault
"""
        
        # Try to send email
        email_sent = False
        try:
            email_sent = send_share_email(recipient_email, subject, email_body)
        except Exception as email_error:
            log_error(f"📧 Email error: {str(email_error)}")
        
        log_info(f"📧 Share completed - email_sent: {email_sent}")
        
        # Return success response
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
        log_error(f"📧 Share via email failed: {str(e)}")
        import traceback
        log_error(traceback.format_exc())
        return JsonResponse({'error': str(e)}, status=500)


# ═══════════════════════════════════════════════════════════
# 📥 ACCESS SHARED FILE BY SLUG (API)
# ═══════════════════════════════════════════════════════════
@api_view(['GET'])
@permission_classes([AllowAny])
def access_shared_file_by_slug(request, slug):
    """API endpoint to access shared file metadata"""
    link = get_object_or_404(SharedLink, slug=slug, is_active=True)

    if link.is_expired():
        return Response({'error': 'Link expired.'}, status=410)
    
    file_obj = link.file
    if not file_obj.user.is_active or is_file_deleted(file_obj):
        return Response({'error': 'File unavailable.'}, status=404)

    SharedLink.objects.filter(id=link.id).update(view_count=models.F('view_count') + 1)
    link.refresh_from_db()
    
    return Response({
        'file_name': link.file.original_name,
        'file_size': link.file.size,
        'view_count': link.view_count,
        'download_count': link.download_count,
        'expires_at': link.expires_at,
        'owner': link.file.user.email
    })


# ═══════════════════════════════════════════════════════════
# 📥 GET SHARED FILE METADATA
# ═══════════════════════════════════════════════════════════
@api_view(['GET'])
@permission_classes([AllowAny])
def get_shared_file_metadata(request, slug):
    """Get metadata for a shared file"""
    link = get_object_or_404(SharedLink, slug=slug, is_active=True)

    if link.is_expired():
        return api_error('Link expired.', status=410)

    if link.first_accessed_at is None:
        now = timezone.now()
        SharedLink.objects.filter(id=link.id).update(
            first_accessed_at=now,
            expires_at=now + timedelta(hours=24)
        )
        link.refresh_from_db()

    SharedLink.objects.filter(id=link.id).update(view_count=models.F('view_count') + 1)
    link.refresh_from_db()

    serializer = SharedLinkSerializer(link, context={'request': request})
    return JsonResponse(serializer.data)


# ═══════════════════════════════════════════════════════════
# 📥 DOWNLOAD SHARED FILE
# ═══════════════════════════════════════════════════════════
@require_http_methods(["GET"])
def download_shared_file(request, slug):
    """Public endpoint: GET /s/<slug>/download/"""
    log_info(f"📥 DOWNLOAD request for slug: {slug}")
    
    try:
        link = SharedLink.objects.select_related('file', 'file__user').get(
            slug=slug,
            is_active=True
        )
    except SharedLink.DoesNotExist:
        log_error(f"❌ Download attempt for invalid slug: {slug}")
        return JsonResponse({'error': 'Link not found or inactive.'}, status=404)

    if link.is_expired():
        link.is_active = False
        link.save(update_fields=['is_active'])
        return JsonResponse({'error': 'Link expired.'}, status=410)

    file_obj = link.file
    owner = file_obj.user
    
    if not owner.is_active or is_file_deleted(file_obj):
        link.is_active = False
        link.save(update_fields=['is_active'])
        return JsonResponse({'error': 'File unavailable.'}, status=404)

    if link.first_accessed_at is None:
        now = timezone.now()
        SharedLink.objects.filter(id=link.id).update(
            first_accessed_at=now,
            expires_at=now + timedelta(hours=24)
        )
        link.refresh_from_db()

    if link.download_count >= link.max_downloads:
        return JsonResponse({'error': 'Download limit reached.'}, status=403)

    SharedLink.objects.filter(id=link.id).update(
        view_count=models.F('view_count') + 1,
        download_count=models.F('download_count') + 1
    )
    link.refresh_from_db()

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
        log_error(f"❌ File not found on disk: {file_obj.file.name}")
        return JsonResponse({'error': 'File missing. Contact support.'}, status=500)
    except Exception as e:
        log_error(f"❌ Download error: {str(e)}")
        return JsonResponse({'error': 'Download failed. Try again.'}, status=500)