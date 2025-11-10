# dropvault/files/sharingviews.py — API-ONLY VERSION
import logging
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
        return JsonResponse({'error': 'Link expired or deactivated.'}, status=410)

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
    Public view to download a shared file by slug.
    Forces download with proper MIME type and filename.
    """
    try:
        # Same lookup as access
        file_obj = get_object_or_404(
            File,
            share_slug=slug,
            is_shared=True,
            expires_at__gt=timezone.now()
        )
        
        # Log download
        logger.info(f"Shared file downloaded: {slug} by IP {request.META.get('REMOTE_ADDR')}")
        file_obj.download_count = getattr(file_obj, 'download_count', 0) + 1
        file_obj.save(update_fields=['download_count'])
        
        # Stream file response
        response = HttpResponse(
            file_obj.file.open('rb'),  # Assuming FileField; use .read() for small files
            content_type=file_obj.file.content_type or 'application/octet-stream'
        )
        response['Content-Disposition'] = f'attachment; filename="{file_obj.original_filename or file_obj.file.name}"'
        response['Content-Length'] = file_obj.file.size
        return response
    
    except (File.DoesNotExist, ValueError):
        raise Http404("Shared file not found or expired.")
    except Exception as e:
        logger.error(f"Error downloading shared file {slug}: {e}")
        raise HttpResponseForbidden("Download failed.")


# ── 4. SHARE VIA EMAIL (authenticated, JSON-only)
@login_required
@require_http_methods(["POST"])
def share_via_email(request, file_id):
    file_obj = get_object_or_404(File, id=file_id, user=request.user, deleted=False)

    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip()
        # role = data.get('role')  # optional, unused for now
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    try:
        validate_email(email)
    except ValidationError:
        return JsonResponse({'error': 'Invalid email'}, status=400)

    # Email-only link: no slug (private)
    token = secrets.token_urlsafe(48)
    link = SharedLink.objects.create(
        file=file_obj,
        owner=request.user,
        slug=None,           # ← critical: no public slug
        token=token,
        max_downloads=5,
        is_active=True
    )

    # Email link (not returned — frontend should not expose it)
    email_url = request.build_absolute_uri(f"/s/email/{token}/")
    # ⚠️ Later: add async email + log — for now, stub
    print(f"[EMAIL] Send to {email}: {email_url}")

    return JsonResponse({'status': 'email_sent'}, status=202)

# Add this BACK to sharingviews.py (for HTML rendering)
logger = logging.getLogger(__name__)

@require_http_methods(["GET"])
def access_shared_file(request, slug):
    """
    Public view to access/preview a shared file by slug.
    Renders a template (e.g., shared_file.html) with file details.
    """
    try:
        # Fetch file; filter for shared + not expired
        file_obj = get_object_or_404(
            File,
            share_slug=slug,
            is_shared=True,
            expires_at__gt=timezone.now()  # Assumes expires_at is timezone-aware
        )
        
        # Log access (for auditing; extend with IP/user if needed)
        logger.info(f"Shared file accessed: {slug} by IP {request.META.get('REMOTE_ADDR')}")
        file_obj.view_count = getattr(file_obj, 'view_count', 0) + 1
        file_obj.save(update_fields=['view_count'])
        
        # Context for template (e.g., file name, preview URL, owner info)
        context = {
            'file': file_obj,
            'preview_url': request.build_absolute_uri(file_obj.file.url),  # Assuming file is FileField
            'share_slug': slug,
        }
        return render(request, 'files/shared_file.html', context)  # Create this template
    
    except (File.DoesNotExist, ValueError):
        raise Http404("Shared file not found or expired.")
    except Exception as e:
        logger.error(f"Error accessing shared file {slug}: {e}")
        raise Http404("Unable to access file.")