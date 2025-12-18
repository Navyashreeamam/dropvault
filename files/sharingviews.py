# files/sharingviews.py
import logging
import os
import secrets
import json
import sys
from django.http import JsonResponse, FileResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import get_object_or_404, render
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from .models import File, SharedLink
from datetime import timedelta
from django.core.mail import send_mail
from django.conf import settings
import threading

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════
# 🔧 LOGGING HELPERS
# ═══════════════════════════════════════════════════════════
def log_info(message):
    timestamp = timezone.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] [INFO] {message}", file=sys.stdout, flush=True)
    sys.stdout.flush()
    logger.info(message)


def log_error(message):
    timestamp = timezone.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] [ERROR] {message}", file=sys.stdout, flush=True)
    sys.stdout.flush()
    logger.error(message)


def log_warning(message):
    timestamp = timezone.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] [WARNING] {message}", file=sys.stdout, flush=True)
    sys.stdout.flush()
    logger.warning(message)


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


def send_email_async(recipient_email, subject, body, callback=None):
    """Send email in background thread"""
    def _send():
        result = False
        try:
            # Try Resend API first
            resend_key = os.environ.get('RESEND_API_KEY', '').strip()
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
                    result = True
                except Exception as e:
                    log_error(f"❌ Resend failed: {e}")
            
            if not result:
                # Fallback to Django mail
                from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@dropvault.app')
                send_mail(
                    subject=subject,
                    message=body,
                    from_email=from_email,
                    recipient_list=[recipient_email],
                    fail_silently=False
                )
                log_info(f"✅ Email sent via Django SMTP to {recipient_email}")
                result = True
                
        except Exception as e:
            log_error(f"❌ All email methods failed: {e}")
            result = False
        
        if callback:
            callback(result)
    
    thread = threading.Thread(target=_send, daemon=True)
    thread.start()
    return True  # Return immediately


def send_share_email_sync(recipient_email, subject, body):
    """Send email synchronously - returns True if successful"""
    try:
        # Try Resend API first
        resend_key = os.environ.get('RESEND_API_KEY', '').strip()
        if resend_key:
            try:
                import resend
                resend.api_key = resend_key
                result = resend.Emails.send({
                    "from": "DropVault <onboarding@resend.dev>",
                    "to": [recipient_email],
                    "subject": subject,
                    "text": body,
                })
                log_info(f"✅ Email sent via Resend to {recipient_email}")
                return True
            except ImportError:
                log_warning("⚠️ Resend library not installed")
            except Exception as e:
                log_error(f"❌ Resend failed: {e}")
        
        # Fallback to Django mail
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@dropvault.app')
        send_mail(
            subject=subject,
            message=body,
            from_email=from_email,
            recipient_list=[recipient_email],
            fail_silently=False
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
    log_info(f"🔗 ═══════════════════════════════════════════════════════")
    log_info(f"🔗 CREATE SHARE LINK")
    log_info(f"🔗 File ID: {file_id}")
    log_info(f"🔗 User: {request.user.email}")
    log_info(f"🔗 ═══════════════════════════════════════════════════════")
    
    try:
        file_obj = File.objects.get(id=file_id, user=request.user)
        if is_file_deleted(file_obj):
            return JsonResponse({'error': 'Cannot share deleted file'}, status=400)
    except File.DoesNotExist:
        log_error(f"❌ File {file_id} not found")
        return JsonResponse({'error': 'File not found'}, status=404)
    
    # Check for existing active link
    existing_link = SharedLink.objects.filter(
        file=file_obj,
        owner=request.user,
        is_active=True
    ).first()
    
    if existing_link and not existing_link.is_expired():
        site_url = os.environ.get('SITE_URL', request.build_absolute_uri('/')[:-1])
        share_url = f"{site_url}/s/{existing_link.slug}/"
        log_info(f"🔗 Returning existing share link: {share_url}")
        return JsonResponse({
            'status': 'success',
            'share_url': share_url,
            'slug': existing_link.slug,
            'link': share_url,
        })
    
    # Generate new link
    slug = generate_unique_slug()
    
    link = SharedLink.objects.create(
        file=file_obj,
        owner=request.user,
        slug=slug,
        token=secrets.token_urlsafe(48),
        max_downloads=5,
        is_active=True
    )
    
    # Build share URL
    site_url = os.environ.get('SITE_URL', request.build_absolute_uri('/')[:-1])
    share_url = f"{site_url}/s/{slug}/"
    
    log_info(f"✅ Share link created: {share_url}")
    
    return JsonResponse({
        'status': 'success',
        'share_url': share_url,
        'slug': slug,
        'link': share_url,
    }, status=201)


# ═══════════════════════════════════════════════════════════
# 📧 SHARE VIA EMAIL (FIXED - No more "sending" forever)
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@require_http_methods(["POST"])
def share_via_email(request, file_id):
    """
    Share file via email
    POST /files/share/<file_id>/email/
    """
    log_info(f"📧 ═══════════════════════════════════════════════════════")
    log_info(f"📧 SHARE VIA EMAIL REQUEST")
    log_info(f"📧 File ID: {file_id}")
    log_info(f"📧 ═══════════════════════════════════════════════════════")
    
    # Check authentication
    if not request.user.is_authenticated:
        log_error("📧 User not authenticated")
        return JsonResponse({
            'error': 'Authentication required',
            'message': 'Please login first'
        }, status=401)
    
    log_info(f"📧 User: {request.user.email}")
    
    # Get file
    try:
        file_obj = File.objects.get(id=file_id, user=request.user)
        if is_file_deleted(file_obj):
            return JsonResponse({'error': 'Cannot share deleted file'}, status=400)
        log_info(f"📧 File found: {file_obj.original_name}")
    except File.DoesNotExist:
        log_error(f"📧 File {file_id} not found")
        return JsonResponse({'error': 'File not found'}, status=404)
    
    # Parse request body
    recipient_email = ''
    message = ''
    
    # Try JSON body first
    try:
        if request.body:
            body_str = request.body.decode('utf-8')
            log_info(f"📧 Request body: {body_str[:200]}")
            data = json.loads(body_str)
            recipient_email = data.get('recipient_email', '').strip()
            message = data.get('message', '')
    except json.JSONDecodeError as e:
        log_warning(f"📧 JSON parse error: {e}")
    except Exception as e:
        log_error(f"📧 Body parse error: {e}")
    
    # Fallback to POST data
    if not recipient_email:
        recipient_email = request.POST.get('recipient_email', '').strip()
        message = request.POST.get('message', '')
    
    log_info(f"📧 Recipient: {recipient_email}")
    
    # Validate email
    if not recipient_email:
        log_error("📧 No recipient email")
        return JsonResponse({
            'error': 'Recipient email is required',
            'message': 'Please provide a recipient email address'
        }, status=400)
    
    if '@' not in recipient_email or '.' not in recipient_email:
        log_error(f"📧 Invalid email format: {recipient_email}")
        return JsonResponse({
            'error': 'Invalid email format',
            'message': 'Please provide a valid email address'
        }, status=400)
    
    try:
        # Create share link
        slug = generate_unique_slug()
        
        link = SharedLink.objects.create(
            file=file_obj,
            owner=request.user,
            slug=slug,
            token=secrets.token_urlsafe(48),
            max_downloads=5,
            is_active=True,
            is_email_only=True
        )
        
        # Build share URL
        site_url = os.environ.get('SITE_URL', request.build_absolute_uri('/')[:-1])
        share_url = f"{site_url}/s/{slug}/"
        
        log_info(f"📧 Share link created: {share_url}")
        
        # Prepare email content
        subject = f"📎 {file_obj.original_name} - Shared via DropVault"
        
        body = f"""Hello,

{request.user.email} has shared a file with you via DropVault.

📄 File: {file_obj.original_name}
📦 Size: {file_obj.size / 1024:.1f} KB

"""
        if message:
            body += f"💬 Message:\n{message}\n\n"
        
        body += f"""🔗 Access your file here:
{share_url}

⚠️ Important:
- This link will expire 24 hours after first access
- Maximum 5 downloads allowed
- Link is valid for 30 days if not accessed

Powered by DropVault 🔒
"""
        
        # Send email (with timeout protection)
        log_info(f"📧 Attempting to send email to {recipient_email}...")
        
        email_sent = False
        try:
            email_sent = send_share_email_sync(recipient_email, subject, body)
        except Exception as e:
            log_error(f"📧 Email send exception: {e}")
            email_sent = False
        
        log_info(f"📧 Email result: sent={email_sent}")
        
        # Return response immediately
        response_data = {
            'status': 'success',
            'message': f'Share link created for {recipient_email}',
            'share_url': share_url,
            'slug': slug,
            'email_sent': email_sent
        }
        
        if email_sent:
            response_data['message'] = f'File shared successfully with {recipient_email}'
        else:
            response_data['warning'] = 'Email could not be sent. Please share the link manually.'
            response_data['message'] = f'Link created but email failed. Share manually: {share_url}'
        
        log_info(f"📧 ✅ Share via email completed")
        
        return JsonResponse(response_data)
        
    except Exception as e:
        log_error(f"📧 ❌ Share via email failed: {e}")
        import traceback
        log_error(traceback.format_exc())
        return JsonResponse({
            'error': 'Failed to share file',
            'message': str(e)
        }, status=500)


# ═══════════════════════════════════════════════════════════
# 📥 SHARED FILE VIEW (Public Access)
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@require_http_methods(["GET"])
def shared_file_view(request, slug, action=None):
    """
    Access shared file
    GET /s/<slug>/          - Preview page
    GET /s/<slug>/download/ - Download file
    """
    log_info(f"📥 SHARED FILE VIEW - Slug: {slug}, Action: {action}")
    
    try:
        link = SharedLink.objects.select_related('file', 'file__user').get(
            slug=slug,
            is_active=True
        )
    except SharedLink.DoesNotExist:
        log_error(f"❌ Share link not found: {slug}")
        # Return HTML page for browser requests
        if 'text/html' in request.META.get('HTTP_ACCEPT', ''):
            return render(request, 'shared_file_error.html', {
                'error': 'Link not found or expired'
            }, status=404)
        return JsonResponse({'error': 'Link not found or inactive'}, status=404)
    
    # Check expiry
    if link.is_expired():
        link.is_active = False
        link.save(update_fields=['is_active'])
        log_warning(f"⚠️ Link expired: {slug}")
        if 'text/html' in request.META.get('HTTP_ACCEPT', ''):
            return render(request, 'shared_file_error.html', {
                'error': 'This link has expired'
            }, status=410)
        return JsonResponse({'error': 'Link expired'}, status=410)
    
    file_obj = link.file
    
    # Check file availability
    if not file_obj.user.is_active or is_file_deleted(file_obj):
        link.is_active = False
        link.save(update_fields=['is_active'])
        log_error(f"❌ File unavailable: {file_obj.original_name}")
        return JsonResponse({'error': 'File unavailable'}, status=404)
    
    # First access - start 24h timer
    if not link.first_accessed_at:
        now = timezone.now()
        link.first_accessed_at = now
        link.expires_at = now + timedelta(hours=24)
        link.save(update_fields=['first_accessed_at', 'expires_at'])
        log_info(f"📥 First access - Timer started for {slug}")
    
    # Increment view count
    link.view_count = (link.view_count or 0) + 1
    link.save(update_fields=['view_count'])
    
    # Download action
    if action == 'download':
        if link.download_count >= link.max_downloads:
            log_warning(f"⚠️ Download limit reached for {slug}")
            return JsonResponse({'error': 'Download limit reached'}, status=403)
        
        link.download_count = (link.download_count or 0) + 1
        link.save(update_fields=['download_count'])
        
        try:
            response = FileResponse(
                file_obj.file.open('rb'),
                content_type='application/octet-stream',
                as_attachment=True,
                filename=file_obj.original_name
            )
            response['Content-Length'] = file_obj.size
            log_info(f"✅ File downloaded via share link: {file_obj.original_name}")
            return response
        except FileNotFoundError:
            log_error(f"❌ Physical file not found: {file_obj.file.name}")
            return JsonResponse({'error': 'File not found on server'}, status=500)
        except Exception as e:
            log_error(f"❌ Download error: {e}")
            return JsonResponse({'error': 'Download failed'}, status=500)
    
    # Preview - return HTML page for browsers, JSON for API
    if 'text/html' in request.META.get('HTTP_ACCEPT', ''):
        return render(request, 'shared_file.html', {
            'file': file_obj,
            'link': link,
            'download_url': f"/s/{slug}/download/"
        })
    
    # JSON response for API
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
            'downloads_remaining': link.max_downloads - link.download_count,
            'first_accessed_at': link.first_accessed_at.isoformat() if link.first_accessed_at else None,
            'expires_at': link.expires_at.isoformat() if link.expires_at else None,
        },
        'download_url': request.build_absolute_uri(f"/s/{slug}/download/"),
    })


# ═══════════════════════════════════════════════════════════
# 📥 DOWNLOAD SHARED FILE
# ═══════════════════════════════════════════════════════════
@require_http_methods(["GET"])
def download_shared_file(request, slug):
    """Direct download endpoint"""
    return shared_file_view(request, slug, action='download')