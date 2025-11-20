# dropvault/files/sharingviews.py — API-ONLY VERSION

import logging
from os import link
import secrets
import json
from django.http import JsonResponse, HttpResponse, Http404
from django.views.decorators.csrf import csrf_exempt
from django.db import models
from django.shortcuts import get_object_or_404, render
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.core.files.storage import default_storage
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from django.shortcuts import render
from .models import File, SharedLink
from .serializers import SharedLinkSerializer
from django.http import HttpResponseForbidden
from django.utils.decorators import method_decorator
from django.views import View
from django.http import FileResponse
from datetime import timedelta

logger = logging.getLogger(__name__)

def api_error(message, status=400):
    return JsonResponse({'error': message}, status=status)

@method_decorator(require_http_methods(["GET"]), name='dispatch')
@method_decorator(csrf_exempt, name='dispatch')  # only if needed for public access
class SharedFileView(View):


    def get(self, request, slug, action=None):
        # 🔐 STEP 1: Fetch ACTIVE, NON-EXPIRED SharedLink by slug
        try:
            link = SharedLink.objects.select_related('file', 'file__user').get(
                slug=slug,
                is_active=True
            )
        except SharedLink.DoesNotExist:
            raise Http404("Link not found or inactive.")

        # 🔐 STEP 2: Enforce security *before* any side effect
        if link.is_expired():
            link.is_active = False
            link.save(update_fields=['is_active'])
            return api_error('Link expired.', status=410)

        # 🔐 STEP 3: Ownership & file validity check
        file_obj = link.file
        owner = file_obj.user
        if not owner.is_active or file_obj.deleted:
            link.is_active = False
            link.save(update_fields=['is_active'])
            return api_error('File unavailable.', status=404)

        # 🔐 STEP 4: First access → activate 24h timer
        if link.first_accessed_at is None:
            now = timezone.now()
            SharedLink.objects.filter(id=link.id).update(
                first_accessed_at=now,
                expires_at=now + timedelta(hours=24)
            )
            link.refresh_from_db()

        # 🔐 STEP 5: Increment view count
        SharedLink.objects.filter(id=link.id).update(view_count=models.F('view_count') + 1)
        link.refresh_from_db()

        # ➡️ Action routing
        if action == 'download':
            # Optional: enforce max_downloads here
            if link.download_count >= link.max_downloads:
                return JsonResponse({'error': 'Download limit reached.'}, status=403)

            # Log download
            SharedLink.objects.filter(id=link.id).update(download_count=models.F('download_count') + 1)

            # Stream encrypted file (do NOT decrypt here — frontend handles decryption)
            file_path = file_obj.file.path
            response = FileResponse(
                open(file_path, 'rb'),
                content_type='application/octet-stream',
                as_attachment=True,
                filename=file_obj.original_name
            )
            response['Content-Length'] = file_obj.size
            return response

        else:
            # Render preview HTML
            context = {
                'link': link,
                'file': file_obj,
                'preview_url': None,  # frontend decrypts & previews
                'download_url': request.build_absolute_uri(f"/s/{slug}/download/")
            }
            return render(request, 'files/shared_file.html', context)



# For email-only links: /s/email/<token>/
@api_view(['GET'])
@permission_classes([AllowAny])
def access_shared_file_by_token(request, token):
    try:
        link = SharedLink.objects.select_related('file', 'file__user').get(
            token=token,
            is_active=True,
            slug__isnull=True  # email-only: no public slug
        )
    except SharedLink.DoesNotExist:
        raise Http404("Invalid or expired token.")

    if link.is_expired():
        return api_error('Link expired.', status=410)

    # Same security checks as above (owner active, file not deleted)
    file_obj = link.file
    if not file_obj.user.is_active or file_obj.deleted:
        return api_error('File unavailable.', status=404)

    # Activate + increment (same as slug-based)
    if link.first_accessed_at is None:
        SharedLink.objects.filter(id=link.id).update(
            first_accessed_at=timezone.now(),
            expires_at=timezone.now() + timedelta(hours=24)
        )
    SharedLink.objects.filter(id=link.id).update(view_count=models.F('view_count') + 1)
    link.refresh_from_db()

    # Redirect to slug-based view? Or render same template.
    # Simpler: redirect (preserves logic)
    return JsonResponse({
        'redirect': request.build_absolute_uri(f"/s/{link.slug}/")  # but slug is null for email links!
    }, status=302)


# ── 1. CREATE SHARE LINK (authenticated)
@login_required
@require_http_methods(["POST"])
def create_share_link(request, file_id):
    file_obj = get_object_or_404(File, id=file_id, user=request.user, deleted=False)

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


# ── 2. GET SHARE METADATA (public, JSON)
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
            expires_at=now + timezone.timedelta(hours=24)
        )
        link.refresh_from_db()

    # Increment view count
    SharedLink.objects.filter(id=link.id).update(view_count=models.F('view_count') + 1)
    link.refresh_from_db()

    serializer = SharedLinkSerializer(link, context={'request': request})
    return JsonResponse(serializer.data)


# ── 3. DOWNLOAD FILE (public, streaming)
@require_http_methods(["GET"])
def download_shared_file(request, slug):
    """
    Public endpoint: GET /s/<slug>/download/
    Securely streams encrypted file after validating link & file status.
    """
    try:
        # 🔐 STEP 1: Fetch active SharedLink by slug
        link = SharedLink.objects.select_related('file', 'file__user').get(
            slug=slug,
            is_active=True
        )
    except SharedLink.DoesNotExist:
        logger.warning(f"Download attempt for invalid slug: {slug}")
        return JsonResponse({'error': 'Link not found or inactive.'}, status=404)

    # 🔐 STEP 2: Check expiry
    if link.is_expired():
        link.is_active = False
        link.save(update_fields=['is_active'])
        logger.info(f"Expired link download attempt: {slug}")
        return JsonResponse({'error': 'Link expired.'}, status=410)

    # 🔐 STEP 3: Validate file & owner
    file_obj = link.file
    owner = file_obj.user
    if not owner.is_active or file_obj.deleted:
        link.is_active = False
        link.save(update_fields=['is_active'])
        logger.warning(f"Download blocked: file deleted or owner inactive (slug={slug})")
        return JsonResponse({'error': 'File unavailable.'}, status=404)

    # 🔐 STEP 4: Activate 24h timer on first access
    if link.first_accessed_at is None:
        now = timezone.now()
        SharedLink.objects.filter(id=link.id).update(
            first_accessed_at=now,
            expires_at=now + timezone.timedelta(hours=24)
        )
        link.refresh_from_db()

    # 🔐 STEP 5: Enforce download limit
    if link.download_count >= link.max_downloads:
        logger.info(f"Download limit reached for slug: {slug}")
        return JsonResponse({'error': 'Download limit reached.'}, status=403)

    # ✅ Log access
    ip = request.META.get('REMOTE_ADDR', 'unknown')
    logger.info(f"Shared file download: slug={slug}, file_id={file_obj.id}, IP={ip}")

    # ✅ Increment counters
    SharedLink.objects.filter(id=link.id).update(
        view_count=models.F('view_count') + 1,
        download_count=models.F('download_count') + 1
    )
    link.refresh_from_db()

    # 📥 Stream encrypted file (do NOT decrypt — client handles decryption)
    try:
        # Use FileResponse for efficient streaming + proper headers
        response = FileResponse(
            file_obj.file.open('rb'),
            content_type='application/octet-stream',
            as_attachment=True,
            filename=file_obj.original_name  # ← correct field!
        )
        response['Content-Length'] = file_obj.size
        return response

    except FileNotFoundError:
        logger.error(f"File not found on disk: {file_obj.file.name} (slug={slug})")
        return JsonResponse({'error': 'File missing. Contact support.'}, status=500)
    except Exception as e:
        logger.error(f"Download error (slug={slug}): {str(e)}", exc_info=True)
        return JsonResponse({'error': 'Download failed. Try again.'}, status=500)


# ── 4. SHARE VIA EMAIL (authenticated, JSON-only)

@login_required
@require_http_methods(["POST"])
def share_via_email(request, file_id):
    file_obj = get_object_or_404(File, id=file_id, user=request.user, deleted=False)

    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip()
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    try:
        validate_email(email)
    except ValidationError:
        return JsonResponse({'error': 'Invalid email'}, status=400)

    # ✅ Generate BOTH slug (for access) and token (for audit/email uniqueness)
    slug = secrets.token_urlsafe(8)[:12]
    token = secrets.token_urlsafe(48)

    # ✅ Mark as email-shared (optional flag)
    link = SharedLink.objects.create(
        file=file_obj,
        owner=request.user,
        slug=slug,           # ← now has slug!
        token=token,
        is_email_only=True,  # ← add this field to model if needed (or infer via `token__isnull=False`)
        max_downloads=5,
        is_active=True
    )

    # Email link is /s/<slug>/ — same as public, but recipient is trusted
    link_url = request.build_absolute_uri(f"/s/{slug}/")
    print(f"[EMAIL] Sending to {email}: {link_url}")

    # Later: send_email_async(
    #   to=email,
    #   subject="DropVault: File Shared With You",
    #   body=f"<p>{request.user.email} shared {file_obj.original_name} with you.</p><p><a href='{link_url}'>Download</a></p>"
    # )

    return JsonResponse({'status': 'email_sent'}, status=202)
    