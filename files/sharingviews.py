# dropvault/files/sharingviews.py

import logging
import os
import secrets
import json
from django.http import JsonResponse, FileResponse
from django.views.decorators.csrf import csrf_exempt
from django.db import models
from django.shortcuts import get_object_or_404
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from .models import File, SharedLink
from .serializers import SharedLinkSerializer
from datetime import timedelta
from django.core.mail import send_mail
from django.conf import settings
from django_ratelimit.decorators import ratelimit
from rest_framework.response import Response

logger = logging.getLogger(__name__)

def api_error(message, status=400):
    return JsonResponse({'error': message}, status=status)


def is_file_deleted(file_obj):
    """Helper to check if file is deleted (handles both deleted and deleted_at fields)"""
    if hasattr(file_obj, 'deleted_at'):
        return file_obj.deleted_at is not None
    elif hasattr(file_obj, 'deleted'):
        return file_obj.deleted
    return False


@ratelimit(key='ip', rate='20/m', block=True)
@require_http_methods(["GET"])
@csrf_exempt
def shared_file_view(request, slug, action=None):
    """
    Handles:
      - GET /s/<slug>/          → renders JSON preview
      - GET /s/<slug>/download/ → streams encrypted file
    """
    try:
        link = SharedLink.objects.select_related('file', 'file__user').get(
            slug=slug,
            is_active=True
        )
    except SharedLink.DoesNotExist:
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

        # Log download
        SharedLink.objects.filter(id=link.id).update(download_count=models.F('download_count') + 1)
        link.refresh_from_db()

        # Stream encrypted file
        try:
            response = FileResponse(
                file_obj.file.open('rb'),
                content_type='application/octet-stream',
                as_attachment=True,
                filename=file_obj.original_name
            )
            response['Content-Length'] = file_obj.size
            return response
        except FileNotFoundError:
            return api_error('File missing on server.', status=500)

    else:
        # JSON preview
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


@api_view(['GET'])
@permission_classes([AllowAny])
def access_shared_file_by_slug(request, slug):
    link = get_object_or_404(SharedLink, slug=slug, is_active=True)

    if link.is_expired():
        return Response({'error': 'Link expired.'}, status=410)
    
    file_obj = link.file
    if not file_obj.user.is_active or is_file_deleted(file_obj):
        return Response({'error': 'File unavailable.'}, status=404)

    # Increment view count
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


@csrf_exempt
@login_required
@require_http_methods(["POST"])
def create_share_link(request, file_id):
    file_obj = get_object_or_404(File, id=file_id, user=request.user)
    
    # Check if file is deleted
    if is_file_deleted(file_obj):
        return JsonResponse({'error': 'Cannot share deleted file'}, status=400)

    # Generate & save
    slug = secrets.token_urlsafe(8)[:12]
    token = secrets.token_urlsafe(48)

    link = SharedLink.objects.create(
        file=file_obj,
        owner=request.user,
        slug=slug,
        token=token,
        max_downloads=5,
        is_active=True
    )

    # Serialize and return
    serializer = SharedLinkSerializer(link, context={'request': request})
    return JsonResponse(serializer.data, status=201)


@api_view(['GET'])
@permission_classes([AllowAny])
def get_shared_file_metadata(request, slug):
    link = get_object_or_404(SharedLink, slug=slug, is_active=True)

    if link.is_expired():
        return api_error('Link expired.', status=410)

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

    serializer = SharedLinkSerializer(link, context={'request': request})
    return JsonResponse(serializer.data)


@require_http_methods(["GET"])
def download_shared_file(request, slug):
    """Public endpoint: GET /s/<slug>/download/"""
    try:
        link = SharedLink.objects.select_related('file', 'file__user').get(
            slug=slug,
            is_active=True
        )
    except SharedLink.DoesNotExist:
        logger.warning(f"Download attempt for invalid slug: {slug}")
        return JsonResponse({'error': 'Link not found or inactive.'}, status=404)

    # Check expiry
    if link.is_expired():
        link.is_active = False
        link.save(update_fields=['is_active'])
        logger.info(f"Expired link download attempt: {slug}")
        return JsonResponse({'error': 'Link expired.'}, status=410)

    # Validate file & owner
    file_obj = link.file
    owner = file_obj.user
    
    if not owner.is_active or is_file_deleted(file_obj):
        link.is_active = False
        link.save(update_fields=['is_active'])
        logger.warning(f"Download blocked: file deleted or owner inactive (slug={slug})")
        return JsonResponse({'error': 'File unavailable.'}, status=404)

    # Activate 24h timer on first access
    if link.first_accessed_at is None:
        now = timezone.now()
        SharedLink.objects.filter(id=link.id).update(
            first_accessed_at=now,
            expires_at=now + timedelta(hours=24)
        )
        link.refresh_from_db()

    # Enforce download limit
    if link.download_count >= link.max_downloads:
        logger.info(f"Download limit reached for slug: {slug}")
        return JsonResponse({'error': 'Download limit reached.'}, status=403)

    # Log access
    ip = request.META.get('REMOTE_ADDR', 'unknown')
    logger.info(f"Shared file download: slug={slug}, file_id={file_obj.id}, IP={ip}")

    # Increment counters
    SharedLink.objects.filter(id=link.id).update(
        view_count=models.F('view_count') + 1,
        download_count=models.F('download_count') + 1
    )
    link.refresh_from_db()

    # Stream encrypted file
    try:
        response = FileResponse(
            file_obj.file.open('rb'),
            content_type='application/octet-stream',
            as_attachment=True,
            filename=file_obj.original_name
        )
        response['Content-Length'] = file_obj.size
        return response

    except FileNotFoundError:
        logger.error(f"File not found on disk: {file_obj.file.name} (slug={slug})")
        return JsonResponse({'error': 'File missing. Contact support.'}, status=500)
    except Exception as e:
        logger.error(f"Download error (slug={slug}): {str(e)}", exc_info=True)
        return JsonResponse({'error': 'Download failed. Try again.'}, status=500)


@csrf_exempt
@login_required
@require_http_methods(["POST"])
@ratelimit(key='user', rate='5/m', method='POST', block=True)
def share_via_email(request, file_id):
    file_obj = get_object_or_404(File, id=file_id, user=request.user)
    
    # Check if file is deleted
    if is_file_deleted(file_obj):
        return JsonResponse({'error': 'Cannot share deleted file'}, status=400)

    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip()
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    # Validate email format
    try:
        validate_email(email)
    except ValidationError:
        return JsonResponse({'error': 'Invalid email address.'}, status=400)

    # Block self-share
    if email.lower() == request.user.email.lower():
        return JsonResponse({'error': 'You cannot share with yourself.'}, status=400)

    # Generate secure slug & token
    slug = secrets.token_urlsafe(8)[:12]
    token = secrets.token_urlsafe(48)

    # Create share link
    link = SharedLink.objects.create(
        file=file_obj,
        owner=request.user,
        slug=slug,
        token=token,
        is_email_only=True,
        max_downloads=5,
        is_active=True
    )

    # Build public link
    link_url = request.build_absolute_uri(f"/s/{slug}/")

    # Send email
    try:
        send_mail(
            subject=f"📁 {file_obj.original_name} shared with you",
            message=(
                f"Hi,\n\n"
                f"{request.user.email} shared '{file_obj.original_name}' with you.\n\n"
                f"Access link: {link_url}\n\n"
                f"🔒 This link expires 24 hours after first access.\n"
                f"⬇️ Max 5 downloads allowed.\n\n"
                f"– DropVault"
            ),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=False
        )
    except Exception as e:
        logger.error(f"Email send failed to {email}: {e}")
        return JsonResponse({
            'error': 'Failed to send email. Please try again.',
            'recipient': email
        }, status=500)

    return JsonResponse({
        'status': 'success',
        'message': f'Share link sent to {email}',
        'slug': slug
    }, status=200)