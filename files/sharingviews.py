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
from .models import File, SharedLink
from datetime import timedelta
from django.core.mail import send_mail
from django.conf import settings


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


def send_share_email(to_email, subject, body):
    log_info(f"📧 Sending to: {to_email}")
    try:
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
                log_info("📧 ✅ Sent via Resend")
                return True
            except Exception as e:
                log_error(f"📧 Resend error: {e}")
        
        send_mail(
            subject=subject,
            message=body,
            from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@dropvault.app'),
            recipient_list=[to_email],
            fail_silently=False
        )
        log_info("📧 ✅ Sent via SMTP")
        return True
    except Exception as e:
        log_error(f"📧 ❌ Failed: {e}")
        return False


@csrf_exempt
def create_share_link(request, file_id):
    if request.method == "OPTIONS":
        return json_response({'status': 'ok'})
    
    log_info(f"🔗 CREATE LINK - File: {file_id}, Auth: {request.user.is_authenticated}")
    
    try:
        if not request.user.is_authenticated:
            return auth_error()
        
        file_obj = File.objects.get(id=file_id, user=request.user)
        
        if file_obj.deleted:
            return json_response({'error': 'Cannot share deleted file'}, status=400)
        
        # Check existing
        existing = SharedLink.objects.filter(
            file=file_obj, owner=request.user, is_active=True
        ).first()
        
        if existing and not existing.is_expired():
            site_url = os.environ.get('SITE_URL', request.build_absolute_uri('/')[:-1])
            share_url = f"{site_url}/s/{existing.slug}/"
            return json_response({
                'status': 'success',
                'share_url': share_url,
                'slug': existing.slug,
                'link': share_url
            })
        
        # Create new
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
        
        # Parse body
        recipient_email = ''
        message = ''
        
        if request.body:
            try:
                data = json.loads(request.body.decode('utf-8'))
                recipient_email = data.get('recipient_email', '').strip()
                message = data.get('message', '').strip()
            except:
                pass
        
        if not recipient_email:
            recipient_email = request.POST.get('recipient_email', '').strip()
            message = request.POST.get('message', '').strip()
        
        log_info(f"📧 Recipient: {recipient_email}")
        
        if not recipient_email or '@' not in recipient_email:
            return json_response({
                'error': 'Valid email required'
            }, status=400)
        
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
        
        # Send email
        subject = f"📎 {file_obj.original_name} - Shared via DropVault"
        body = f"""Hello,

{request.user.email} shared a file with you.

📄 File: {file_obj.original_name}
🔗 Download: {share_url}

"""
        if message:
            body += f"Message: {message}\n\n"
        
        body += "- DropVault"
        
        email_sent = send_share_email(recipient_email, subject, body)
        
        log_info(f"📧 Result: email_sent={email_sent}")
        
        return json_response({
            'status': 'success',
            'share_url': share_url,
            'email_sent': email_sent,
            'message': 'Shared successfully' if email_sent else 'Link created (email failed)'
        })
        
    except File.DoesNotExist:
        return json_response({'error': 'File not found'}, status=404)
    except Exception as e:
        log_error(f"📧 Error: {e}")
        log_error(traceback.format_exc())
        return json_response({'error': str(e)}, status=500)


@csrf_exempt
def shared_file_view(request, slug, action=None):
    log_info(f"📥 SHARED FILE - Slug: {slug}, Action: {action}")
    
    try:
        link = SharedLink.objects.select_related('file').get(slug=slug, is_active=True)
    except SharedLink.DoesNotExist:
        if 'text/html' in request.META.get('HTTP_ACCEPT', ''):
            return render(request, 'shared_file_error.html', {'error': 'Link not found'}, status=404)
        return json_response({'error': 'Link not found'}, status=404)
    
    if link.is_expired():
        link.is_active = False
        link.save()
        return json_response({'error': 'Link expired'}, status=410)
    
    file_obj = link.file
    
    if file_obj.deleted:
        return json_response({'error': 'File unavailable'}, status=404)
    
    if not link.first_accessed_at:
        link.first_accessed_at = timezone.now()
        link.expires_at = timezone.now() + timedelta(hours=24)
        link.save()
    
    link.view_count = (link.view_count or 0) + 1
    link.save()
    
    if action == 'download':
        if link.download_count >= link.max_downloads:
            return json_response({'error': 'Download limit reached'}, status=403)
        
        link.download_count += 1
        link.save()
        
        try:
            return FileResponse(
                file_obj.file.open('rb'),
                as_attachment=True,
                filename=file_obj.original_name
            )
        except Exception as e:
            return json_response({'error': 'Download failed'}, status=500)
    
    if 'text/html' in request.META.get('HTTP_ACCEPT', ''):
        return render(request, 'shared_file.html', {
            'file': file_obj,
            'link': link,
            'download_url': f"/s/{slug}/download/"
        })
    
    return json_response({
        'file': {'name': file_obj.original_name, 'size': file_obj.size},
        'download_url': f"/s/{slug}/download/"
    })


def download_shared_file(request, slug):
    return shared_file_view(request, slug, action='download')