# DropVault/files/sharingviews.py
import secrets
import os
import json
from django.conf import settings
from django.http import JsonResponse, HttpResponse, Http404
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.db import models
from django.shortcuts import get_object_or_404, render
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from django.core.files.storage import default_storage
from .models import File, SharedLink
from django.core.mail import send_mail
from django.core.validators import validate_email
from django.core.exceptions import ValidationError


@login_required
@require_http_methods(["POST"])
def create_share_link(request, file_id):
    file_obj = get_object_or_404(File, id=file_id, user=request.user, deleted=False)
    
    slug = secrets.token_urlsafe(8)[:12]
    token = secrets.token_urlsafe(48)
    
    link = SharedLink.objects.create(
        file=file_obj,
        owner=request.user,
        slug=slug,
        token=token,
        max_downloads=5
    )
    
    share_url = request.build_absolute_uri(f"/s/{slug}/")
    return JsonResponse({'link': share_url})

def access_shared_file(request, slug):
    link = get_object_or_404(SharedLink, slug=slug)

    if link.is_expired():
        raise Http404("This shared link has expired or been deactivated.")

    # Activate 24h timer only if first access
    if link.first_accessed_at is None:
        link.activate_expiry()

    # Increment view count safely
    SharedLink.objects.filter(id=link.id).update(view_count=models.F('view_count') + 1)
    # Refresh from DB to reflect count
    link.refresh_from_db()

    return render(request, 'shared_file.html', {
        'link': link,
        'file': link.file
    })


def download_shared_file(request, slug):
    link = get_object_or_404(SharedLink, slug=slug)

    if link.is_expired():
        return HttpResponse("Link expired.", status=410)

    if link.download_count >= link.max_downloads:
        return HttpResponse("Download limit reached.", status=403)

    # Safely increment download count (atomic)
    updated = SharedLink.objects.filter(
        id=link.id,
        download_count__lt=models.F('max_downloads')
    ).update(download_count=models.F('download_count') + 1)

    if updated == 0:
        return HttpResponse("Download limit reached.", status=403)

    link.refresh_from_db()

    # Ensure file exists on disk
    file_path = link.file.file.path
    if not default_storage.exists(file_path):
        return HttpResponse("File not found on server.", status=404)

    try:
        with default_storage.open(file_path, 'rb') as f:
            response = HttpResponse(f.read(), content_type='application/octet-stream')
    except (OSError, IOError):
        return HttpResponse("Error reading file.", status=500)

    filename = link.file.original_name
    if filename.lower().endswith('.pdf'):
        response['Content-Disposition'] = f'inline; filename="{filename}"'
    else:
        response['Content-Disposition'] = f'attachment; filename="{filename}"'

    return response


@login_required
@require_http_methods(["POST"])
def share_via_email(request, file_id):
    file_obj = get_object_or_404(File, id=file_id, user=request.user, deleted=False)

    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip()
        role = data.get('role', 'viewer')  # unused for now, but preserved
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    # Validate email
    try:
        validate_email(email)
    except ValidationError:
        return JsonResponse({'error': 'Invalid email address'}, status=400)

    # Generate secure email-only link (no public slug)
    token = secrets.token_urlsafe(48)
    link = SharedLink.objects.create(
        file=file_obj,
        owner=request.user,
        slug=None,  # critical: no public slug
        token=token,
        max_downloads=5,
        is_active=True
    )

    # Build link: /s/email/<token>/ (we'll add this URL next)
    email_url = request.build_absolute_uri(f"/s/email/{token}/")

    # Send email
    subject = f"{request.user.email} shared a file with you on Dropvault"
    message = f"""
Hi,

{request.user.email} shared a file with you:

📄 {file_obj.original_name} ({file_obj.size} bytes)

👉 Access it here: {email_url}

This link expires after 5 downloads or 24 hours after first access.

— Dropvault
    """.strip()

    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=False,
        )
    except Exception as e:
        print(f"[EMAIL ERROR] {e}") 
        return JsonResponse({'error': 'Failed to send email. Check server logs.'}, status=500)

    return JsonResponse({'status': 'sent'})


def access_shared_via_email(request, token):
    link = get_object_or_404(SharedLink, token=token, slug__isnull=True)
    
    if link.is_expired():
        raise Http404("Link expired.")
    
    if link.first_accessed_at is None:
        link.activate_expiry()

    SharedLink.objects.filter(id=link.id).update(view_count=models.F('view_count') + 1)
    link.refresh_from_db()

    return render(request, 'shared_file.html', {'link': link, 'file': link.file})