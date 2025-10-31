# DropVault/files/sharingviews.py
import secrets
from django.shortcuts import get_object_or_404, render
from django.http import JsonResponse, HttpResponse, Http404
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from .models import File, SharedLink

@login_required
@require_http_methods(["POST"])
def create_share_link(request, file_id):
    # Ensure user owns the file and it's not deleted
    file_obj = get_object_or_404(File, id=file_id, user=request.user, deleted=False)
    
    # Generate short slug (10 chars) and secure token
    slug = secrets.token_urlsafe(8)[:10]
    token = secrets.token_urlsafe(64)
    
    # Create share link
    link = SharedLink.objects.create(
        file=file_obj,
        owner=request.user,
        slug=slug,
        token=token,
        max_downloads=5
    )
    
    # Build full share URL (works on localhost or prod)
    share_url = request.build_absolute_uri(f"/s/{slug}/")
    return JsonResponse({'url': share_url})


def access_shared_file(request, slug):
    link = get_object_or_404(SharedLink, slug=slug)
    
    if link.is_expired():
        raise Http404("This shared link has expired.")
    
    # 🔥 ACTIVATE 24-HOUR TIMER ON FIRST ACCESS
    if link.first_accessed_at is None:
        link.activate_expiry()
    
    # Increment view count
    link.view_count += 1
    link.save(update_fields=['view_count'])

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
    
    # Increment download count
    link.download_count += 1
    link.save(update_fields=['download_count'])
    
    # Serve file securely (never expose /media/ directly)
    file_path = link.file.file.path
    response = HttpResponse(
        open(file_path, 'rb'),
        content_type='application/octet-stream'
    )
    # ✅ FIX: Preview PDFs inline, others as attachment
    filename = link.file.original_name
    if filename.lower().endswith('.pdf'):
        response['Content-Disposition'] = f'inline; filename="{filename}"'
    else:
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
    
    return response