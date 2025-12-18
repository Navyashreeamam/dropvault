# files/sharingviews.py
import os
import secrets
import json
import sys
from django.http import JsonResponse, FileResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from .models import File, SharedLink
from datetime import timedelta
from django.core.mail import send_mail
from django.conf import settings


# ═══════════════════════════════════════════════════════════
# 🔧 LOGGING
# ═══════════════════════════════════════════════════════════
def log_info(msg):
    print(f"[INFO] {msg}", flush=True)

def log_error(msg):
    print(f"[ERROR] {msg}", flush=True)


# ═══════════════════════════════════════════════════════════
# 🔧 HELPERS
# ═══════════════════════════════════════════════════════════
def generate_slug():
    """Generate unique slug"""
    for _ in range(10):
        slug = secrets.token_urlsafe(8)[:12]
        if not SharedLink.objects.filter(slug=slug).exists():
            return slug
    return secrets.token_urlsafe(12)


def send_share_email(to_email, subject, body):
    """Send email"""
    log_info(f"📧 Sending to: {to_email}")
    
    try:
        # Try Resend API first
        resend_key = os.environ.get('RESEND_API_KEY', '').strip()
        if resend_key:
            try:
                import resend
                resend.api_key = resend_key
                resend.Emails.send({
                    "from": "DropVault <onboarding@resend.dev>",
                    "to": [to_email],
                    "subject": subject,
                    "text": body,
                })
                log_info(f"📧 ✅ Sent via Resend")
                return True
            except Exception as e:
                log_error(f"📧 Resend error: {e}")
        
        # Fallback to Django SMTP
        send_mail(
            subject=subject,
            message=body,
            from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@dropvault.app'),
            recipient_list=[to_email],
            fail_silently=False
        )
        log_info(f"📧 ✅ Sent via SMTP")
        return True
        
    except Exception as e:
        log_error(f"📧 ❌ Failed: {e}")
        return False


# ═══════════════════════════════════════════════════════════
# 🔗 CREATE SHARE LINK
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@require_http_methods(["POST", "OPTIONS"])
def create_share_link(request, file_id):
    """Create shareable link"""
    
    if request.method == "OPTIONS":
        return JsonResponse({'status': 'ok'})
    
    log_info(f"🔗 CREATE LINK - File: {file_id}")
    log_info(f"🔗 User: {request.user}, Auth: {request.user.is_authenticated}")
    
    # Check auth - return JSON not redirect
    if not request.user.is_authenticated:
        log_error("🔗 Not authenticated")
        return JsonResponse({
            'error': 'Please login to share files',
            'login_required': True
        }, status=401)
    
    try:
        file_obj = File.objects.get(id=file_id, user=request.user)
        
        if file_obj.deleted:
            return JsonResponse({'error': 'Cannot share deleted file'}, status=400)
        
        # Check for existing link
        existing = SharedLink.objects.filter(
            file=file_obj, 
            owner=request.user, 
            is_active=True
        ).first()
        
        if existing and not existing.is_expired():
            site_url = os.environ.get('SITE_URL', request.build_absolute_uri('/')[:-1])
            share_url = f"{site_url}/s/{existing.slug}/"
            log_info(f"🔗 Returning existing: {share_url}")
            return JsonResponse({
                'status': 'success',
                'share_url': share_url,
                'slug': existing.slug,
                'link': share_url
            })
        
        # Create new link
        slug = generate_slug()
        link = SharedLink.objects.create(
            file=file_obj,
            owner=request.user,
            slug=slug,
            token=secrets.token_urlsafe(48),
            max_downloads=5,
            is_active=True
        )
        
        site_url = os.environ.get('SITE_URL', request.build_absolute_uri('/')[:-1])
        share_url = f"{site_url}/s/{slug}/"
        
        log_info(f"🔗 ✅ Created: {share_url}")
        
        return JsonResponse({
            'status': 'success',
            'share_url': share_url,
            'slug': slug,
            'link': share_url
        }, status=201)
        
    except File.DoesNotExist:
        log_error(f"🔗 File not found: {file_id}")
        return JsonResponse({'error': 'File not found'}, status=404)
    except Exception as e:
        log_error(f"🔗 Error: {e}")
        return JsonResponse({'error': str(e)}, status=500)


# ═══════════════════════════════════════════════════════════
# 📧 SHARE VIA EMAIL - FIXED
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@require_http_methods(["POST", "OPTIONS"])
def share_via_email(request, file_id):
    """Share file via email"""
    
    if request.method == "OPTIONS":
        return JsonResponse({'status': 'ok'})
    
    log_info("=" * 60)
    log_info(f"📧 SHARE VIA EMAIL")
    log_info(f"📧 File ID: {file_id}")
    log_info(f"📧 User: {request.user}")
    log_info(f"📧 Authenticated: {request.user.is_authenticated}")
    log_info("=" * 60)
    
    # ✅ CRITICAL: Check authentication and return JSON
    if not request.user.is_authenticated:
        log_error("📧 ❌ NOT AUTHENTICATED")
        return JsonResponse({
            'error': 'Please login to share files',
            'message': 'Your session may have expired. Please login again.',
            'login_required': True,
            'redirect': '/accounts/login/'
        }, status=401)
    
    log_info(f"📧 User verified: {request.user.email}")
    
    # Get file
    try:
        file_obj = File.objects.get(id=file_id, user=request.user)
        
        if file_obj.deleted:
            return JsonResponse({'error': 'Cannot share deleted file'}, status=400)
            
        log_info(f"📧 File: {file_obj.original_name}")
        
    except File.DoesNotExist:
        log_error(f"📧 File not found: {file_id}")
        return JsonResponse({'error': 'File not found'}, status=404)
    
    # Parse request body
    recipient_email = ''
    message = ''
    
    try:
        if request.body:
            body_text = request.body.decode('utf-8')
            log_info(f"📧 Body: {body_text[:200]}")
            data = json.loads(body_text)
            recipient_email = data.get('recipient_email', '').strip()
            message = data.get('message', '').strip()
    except json.JSONDecodeError as e:
        log_error(f"📧 JSON error: {e}")
        # Try form data
        recipient_email = request.POST.get('recipient_email', '').strip()
        message = request.POST.get('message', '').strip()
    except Exception as e:
        log_error(f"📧 Parse error: {e}")
    
    log_info(f"📧 Recipient: {recipient_email}")
    
    # Validate email
    if not recipient_email:
        return JsonResponse({
            'error': 'Email required',
            'message': 'Please enter a recipient email address'
        }, status=400)
    
    if '@' not in recipient_email or '.' not in recipient_email:
        return JsonResponse({
            'error': 'Invalid email',
            'message': 'Please enter a valid email address'
        }, status=400)
    
    try:
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
        
        # Build URL
        site_url = os.environ.get('SITE_URL', request.build_absolute_uri('/')[:-1])
        share_url = f"{site_url}/s/{slug}/"
        
        log_info(f"📧 Share URL: {share_url}")
        
        # Email content
        subject = f"📎 {file_obj.original_name} - Shared via DropVault"
        body = f"""Hello,

{request.user.email} shared a file with you.

📄 File: {file_obj.original_name}
📦 Size: {file_obj.size / 1024:.1f} KB

"""
        if message:
            body += f"💬 Message: {message}\n\n"
        
        body += f"""🔗 Download: {share_url}

• Expires 24 hours after first access
• Maximum 5 downloads

- DropVault
"""
        
        # Send email
        email_sent = send_share_email(recipient_email, subject, body)
        
        log_info(f"📧 Email sent: {email_sent}")
        
        return JsonResponse({
            'status': 'success',
            'share_url': share_url,
            'slug': slug,
            'email_sent': email_sent,
            'recipient': recipient_email,
            'message': f"{'Email sent to ' + recipient_email if email_sent else 'Link created but email failed. Share manually.'}"
        })
        
    except Exception as e:
        log_error(f"📧 ❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({
            'error': 'Share failed',
            'message': str(e)
        }, status=500)


# ═══════════════════════════════════════════════════════════
# 📥 SHARED FILE VIEW (Public)
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@require_http_methods(["GET"])
def shared_file_view(request, slug, action=None):
    """Access shared file - public endpoint"""
    
    log_info(f"📥 SHARED FILE - Slug: {slug}, Action: {action}")
    
    try:
        link = SharedLink.objects.select_related('file', 'file__user').get(
            slug=slug,
            is_active=True
        )
    except SharedLink.DoesNotExist:
        log_error(f"📥 Link not found: {slug}")
        if 'text/html' in request.META.get('HTTP_ACCEPT', ''):
            return render(request, 'shared_file_error.html', {'error': 'Link not found or expired'}, status=404)
        return JsonResponse({'error': 'Link not found'}, status=404)
    
    # Check expiry
    if link.is_expired():
        link.is_active = False
        link.save(update_fields=['is_active'])
        if 'text/html' in request.META.get('HTTP_ACCEPT', ''):
            return render(request, 'shared_file_error.html', {'error': 'Link has expired'}, status=410)
        return JsonResponse({'error': 'Link expired'}, status=410)
    
    file_obj = link.file
    
    # Check file available
    if file_obj.deleted:
        return JsonResponse({'error': 'File unavailable'}, status=404)
    
    # Start 24h timer on first access
    if not link.first_accessed_at:
        link.first_accessed_at = timezone.now()
        link.expires_at = timezone.now() + timedelta(hours=24)
        link.save(update_fields=['first_accessed_at', 'expires_at'])
    
    # Increment view count
    link.view_count = (link.view_count or 0) + 1
    link.save(update_fields=['view_count'])
    
    # Download action
    if action == 'download':
        if link.download_count >= link.max_downloads:
            if 'text/html' in request.META.get('HTTP_ACCEPT', ''):
                return render(request, 'shared_file_error.html', {'error': 'Download limit reached'}, status=403)
            return JsonResponse({'error': 'Download limit reached'}, status=403)
        
        link.download_count = (link.download_count or 0) + 1
        link.save(update_fields=['download_count'])
        
        try:
            log_info(f"📥 Downloading: {file_obj.original_name}")
            return FileResponse(
                file_obj.file.open('rb'),
                as_attachment=True,
                filename=file_obj.original_name
            )
        except Exception as e:
            log_error(f"📥 Download error: {e}")
            return JsonResponse({'error': 'Download failed'}, status=500)
    
    # Show preview page
    if 'text/html' in request.META.get('HTTP_ACCEPT', ''):
        return render(request, 'shared_file.html', {
            'file': file_obj,
            'link': link,
            'download_url': f"/s/{slug}/download/"
        })
    
    return JsonResponse({
        'file': {'name': file_obj.original_name, 'size': file_obj.size},
        'download_url': f"/s/{slug}/download/"
    })


def download_shared_file(request, slug):
    """Download shared file"""
    return shared_file_view(request, slug, action='download')