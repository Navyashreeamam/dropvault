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
    """Send email via available method"""
    log_info(f"📧 Sending email to: {to_email}")
    
    try:
        # Try Resend first
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
                log_error(f"📧 Resend failed: {e}")
        
        # Fallback to SMTP
        send_mail(
            subject=subject,
            message=body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[to_email],
            fail_silently=False
        )
        log_info(f"📧 ✅ Sent via SMTP")
        return True
        
    except Exception as e:
        log_error(f"📧 ❌ All methods failed: {e}")
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
    
    log_info(f"🔗 CREATE LINK - File: {file_id}, Auth: {request.user.is_authenticated}")
    
    # ✅ Return JSON 401, not HTML redirect
    if not request.user.is_authenticated:
        log_error("🔗 ❌ Not authenticated")
        return JsonResponse({
            'error': 'Not authenticated',
            'message': 'Please login to share files',
            'login_required': True
        }, status=401)
    
    try:
        file_obj = File.objects.get(id=file_id, user=request.user)
        
        if file_obj.deleted:
            return JsonResponse({'error': 'Cannot share deleted file'}, status=400)
        
        # Check existing
        existing = SharedLink.objects.filter(
            file=file_obj, owner=request.user, is_active=True
        ).first()
        
        if existing and not existing.is_expired():
            site_url = os.environ.get('SITE_URL', request.build_absolute_uri('/')[:-1])
            share_url = f"{site_url}/s/{existing.slug}/"
            return JsonResponse({
                'status': 'success',
                'share_url': share_url,
                'slug': existing.slug,
                'link': share_url
            })
        
        # Create new
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
        return JsonResponse({'error': 'File not found'}, status=404)
    except Exception as e:
        log_error(f"🔗 ❌ Error: {e}")
        return JsonResponse({'error': str(e)}, status=500)


# ═══════════════════════════════════════════════════════════
# 📧 SHARE VIA EMAIL
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@require_http_methods(["POST", "OPTIONS"])
def share_via_email(request, file_id):
    """Share file via email"""
    
    if request.method == "OPTIONS":
        return JsonResponse({'status': 'ok'})
    
    log_info("=" * 60)
    log_info(f"📧 SHARE VIA EMAIL - File: {file_id}")
    log_info(f"📧 Auth: {request.user.is_authenticated}")
    log_info(f"📧 User: {request.user}")
    log_info("=" * 60)
    
    # ✅ Return JSON 401, not HTML redirect!
    if not request.user.is_authenticated:
        log_error("📧 ❌ Not authenticated")
        return JsonResponse({
            'error': 'Not authenticated',
            'message': 'Please login to share files',
            'login_required': True
        }, status=401)
    
    # Get file
    try:
        file_obj = File.objects.get(id=file_id, user=request.user)
        if file_obj.deleted:
            return JsonResponse({'error': 'Cannot share deleted file'}, status=400)
        log_info(f"📧 File: {file_obj.original_name}")
    except File.DoesNotExist:
        return JsonResponse({'error': 'File not found'}, status=404)
    
    # Parse body
    recipient_email = ''
    message = ''
    
    try:
        if request.body:
            data = json.loads(request.body.decode('utf-8'))
            recipient_email = data.get('recipient_email', '').strip()
            message = data.get('message', '').strip()
            log_info(f"📧 Recipient: {recipient_email}")
    except:
        recipient_email = request.POST.get('recipient_email', '').strip()
        message = request.POST.get('message', '').strip()
    
    # Validate
    if not recipient_email:
        return JsonResponse({
            'error': 'Email required',
            'message': 'Please enter recipient email'
        }, status=400)
    
    if '@' not in recipient_email or '.' not in recipient_email:
        return JsonResponse({
            'error': 'Invalid email',
            'message': 'Please enter a valid email address'
        }, status=400)
    
    try:
        # Create link
        slug = generate_slug()
        SharedLink.objects.create(
            file=file_obj,
            owner=request.user,
            slug=slug,
            token=secrets.token_urlsafe(48),
            max_downloads=5,
            is_active=True
        )
        
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

• Link expires 24 hours after first access
• Maximum 5 downloads

- DropVault
"""
        
        # Send
        email_sent = send_share_email(recipient_email, subject, body)
        
        log_info(f"📧 Email sent: {email_sent}")
        
        return JsonResponse({
            'status': 'success',
            'share_url': share_url,
            'slug': slug,
            'email_sent': email_sent,
            'recipient': recipient_email,
            'message': f"{'Email sent to ' + recipient_email if email_sent else 'Link created (email failed)'}"
        })
        
    except Exception as e:
        log_error(f"📧 ❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({'error': str(e)}, status=500)


# ═══════════════════════════════════════════════════════════
# 📥 SHARED FILE VIEW (Public)
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@require_http_methods(["GET"])
def shared_file_view(request, slug, action=None):
    """Access shared file"""
    
    log_info(f"📥 SHARED FILE - Slug: {slug}, Action: {action}")
    
    try:
        link = SharedLink.objects.select_related('file', 'file__user').get(
            slug=slug, is_active=True
        )
    except SharedLink.DoesNotExist:
        if 'text/html' in request.META.get('HTTP_ACCEPT', ''):
            return render(request, 'shared_file_error.html', {'error': 'Link not found'}, status=404)
        return JsonResponse({'error': 'Link not found'}, status=404)
    
    if link.is_expired():
        link.is_active = False
        link.save()
        if 'text/html' in request.META.get('HTTP_ACCEPT', ''):
            return render(request, 'shared_file_error.html', {'error': 'Link expired'}, status=410)
        return JsonResponse({'error': 'Link expired'}, status=410)
    
    file_obj = link.file
    
    if file_obj.deleted:
        return JsonResponse({'error': 'File unavailable'}, status=404)
    
    # First access timer
    if not link.first_accessed_at:
        link.first_accessed_at = timezone.now()
        link.expires_at = timezone.now() + timedelta(hours=24)
        link.save()
    
    link.view_count = (link.view_count or 0) + 1
    link.save()
    
    # Download
    if action == 'download':
        if link.download_count >= link.max_downloads:
            return JsonResponse({'error': 'Download limit reached'}, status=403)
        
        link.download_count += 1
        link.save()
        
        try:
            return FileResponse(
                file_obj.file.open('rb'),
                as_attachment=True,
                filename=file_obj.original_name
            )
        except:
            return JsonResponse({'error': 'File not found on server'}, status=500)
    
    # Preview
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
    return shared_file_view(request, slug, action='download')