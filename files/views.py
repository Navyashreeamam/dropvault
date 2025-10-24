# files/views.py
import os
from django.shortcuts import get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.conf import settings
from .models import File, Trash, FileLog

# Validation constants
ALLOWED_EXTENSIONS = {'.pdf', '.jpg', '.jpeg', '.png', '.docx', '.txt', '.mp4'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB

def validate_file(file):
    """Validate file type and size"""
    ext = os.path.splitext(file.name)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False, "Invalid file type"
    if file.size > MAX_FILE_SIZE:
        return False, "File too large (max 50MB)"
    return True, ""

@login_required
@require_http_methods(["POST"])
def upload_file(request):
    file = request.FILES.get('file')
    if not file:
        return JsonResponse({'error': 'No file provided'}, status=400)
    
    valid, msg = validate_file(file)
    if not valid:
        return JsonResponse({'error': msg}, status=400)
    
    # Save to DB + disk
    file_obj = File.objects.create(
        user=request.user,
        file=file,
        original_name=file.name,
        size=file.size
    )
    FileLog.objects.create(user=request.user, file=file_obj, action='UPLOAD')
    return JsonResponse({
        'id': file_obj.id,
        'name': file_obj.original_name,
        'size': file_obj.size
    })

@login_required
def list_files(request):
    files = File.objects.filter(
        user=request.user, 
        deleted=False
    ).values('id', 'original_name', 'size', 'uploaded_at')
    return JsonResponse(list(files), safe=False)

@login_required
@require_http_methods(["POST"])
def delete_file(request, file_id):
    # 🔒 Critical: Filter by user
    file_obj = get_object_or_404(File, id=file_id, user=request.user, deleted=False)
    file_obj.deleted = True
    file_obj.save()
    Trash.objects.create(file=file_obj)
    FileLog.objects.create(user=request.user, file=file_obj, action='DELETE')
    return JsonResponse({'status': 'deleted'})

@login_required
def trash_list(request):
    files = File.objects.filter(
        user=request.user,
        deleted=True
    ).values('id', 'original_name', 'size')
    return JsonResponse(list(files), safe=False)