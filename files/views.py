# files/views.py
import logging
import sys
import os
import hashlib
import secrets
import json
from functools import wraps
from django.utils import timezone
from datetime import timedelta
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, FileResponse
from django.views.decorators.http import require_http_methods
from django.conf import settings
from django.core.files.base import ContentFile
from django.views.decorators.csrf import csrf_exempt
from django.middleware.csrf import get_token

from .models import File, Trash, FileLog, SharedLink


# ═══════════════════════════════════════════════════════════
# 🔧 LOGGING
# ═══════════════════════════════════════════════════════════
def log_info(msg):
    print(f"[INFO] {msg}", flush=True)

def log_error(msg):
    print(f"[ERROR] {msg}", flush=True)


# ═══════════════════════════════════════════════════════════
# 🛠️ CONSTANTS
# ═══════════════════════════════════════════════════════════
ALLOWED_EXTENSIONS = {
    '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp',
    '.doc', '.docx', '.txt', '.rtf', '.odt',
    '.xls', '.xlsx', '.csv',
    '.ppt', '.pptx',
    '.mp4', '.mp3', '.wav', '.avi', '.mov',
    '.zip', '.rar', '.7z', '.tar', '.gz'
}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB


def validate_file(file):
    """Validate file type and size"""
    if not file:
        return False, "No file provided"
    
    ext = os.path.splitext(file.name)[1].lower()
    if ext and ext not in ALLOWED_EXTENSIONS:
        return False, f"File type '{ext}' not allowed"
    
    if file.size > MAX_FILE_SIZE:
        return False, "File too large (max 50MB)"
    
    return True, ""


def get_file_hash(file):
    """Calculate SHA-256 hash"""
    hasher = hashlib.sha256()
    file.seek(0)
    for chunk in file.chunks():
        hasher.update(chunk)
    file.seek(0)
    return hasher.hexdigest()


# ═══════════════════════════════════════════════════════════
# 📤 UPLOAD FILE - FIXED FOR AUTHENTICATION
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@require_http_methods(["POST", "OPTIONS"])
def upload_file(request):
    """Upload a file"""
    
    # Handle preflight OPTIONS request
    if request.method == "OPTIONS":
        response = JsonResponse({'status': 'ok'})
        response["Access-Control-Allow-Origin"] = "*"
        response["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        response["Access-Control-Allow-Headers"] = "Content-Type, X-CSRFToken"
        return response
    
    log_info("=" * 60)
    log_info("📤 UPLOAD REQUEST")
    log_info(f"📤 User: {request.user}")
    log_info(f"📤 Authenticated: {request.user.is_authenticated}")
    log_info(f"📤 Session: {request.session.session_key}")
    log_info(f"📤 FILES: {list(request.FILES.keys())}")
    log_info("=" * 60)
    
    # Check authentication
    if not request.user.is_authenticated:
        log_error("📤 NOT AUTHENTICATED")
        return JsonResponse({
            'error': 'Please login to upload files',
            'login_required': True,
            'redirect': '/accounts/login/'
        }, status=401)
    
    # Check for file in request
    if 'file' not in request.FILES:
        log_error("📤 No file in request")
        return JsonResponse({
            'error': 'No file provided',
            'message': 'Please select a file to upload'
        }, status=400)
    
    file = request.FILES['file']
    log_info(f"📤 File received: {file.name} ({file.size} bytes)")
    
    # Validate file
    valid, error_msg = validate_file(file)
    if not valid:
        log_error(f"📤 Validation failed: {error_msg}")
        return JsonResponse({'error': error_msg}, status=400)
    
    try:
        # Calculate hash for deduplication
        file_hash = get_file_hash(file)
        
        # Check for duplicate
        existing = File.objects.filter(
            user=request.user,
            sha256=file_hash,
            deleted=False
        ).first()
        
        if existing:
            log_info("📤 Duplicate file detected")
            return JsonResponse({
                'error': 'Duplicate file',
                'message': 'You already uploaded this file'
            }, status=409)
        
        # Create file record
        file_obj = File.objects.create(
            user=request.user,
            file=file,
            original_name=file.name,
            size=file.size,
            sha256=file_hash,
            deleted=False,
            deleted_at=None
        )
        
        # Log action
        try:
            FileLog.objects.create(
                user=request.user,
                file=file_obj,
                action='UPLOAD'
            )
        except Exception as e:
            log_error(f"📤 Log error: {e}")
        
        log_info(f"📤 ✅ SUCCESS - ID: {file_obj.id}, Name: {file.name}")
        
        return JsonResponse({
            'status': 'success',
            'message': 'File uploaded successfully',
            'file': {
                'id': file_obj.id,
                'filename': file_obj.original_name,
                'size': file_obj.size,
                'uploaded_at': file_obj.uploaded_at.isoformat()
            }
        }, status=201)
        
    except Exception as e:
        log_error(f"📤 ❌ ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        return JsonResponse({
            'error': 'Upload failed',
            'message': str(e)
        }, status=500)


# ═══════════════════════════════════════════════════════════
# 📂 LIST FILES
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@require_http_methods(["GET", "OPTIONS"])
def list_files(request):
    """List user's active files"""
    
    if request.method == "OPTIONS":
        return JsonResponse({'status': 'ok'})
    
    log_info(f"📂 LIST - User: {request.user}, Auth: {request.user.is_authenticated}")
    
    if not request.user.is_authenticated:
        return JsonResponse({
            'error': 'Please login',
            'login_required': True
        }, status=401)
    
    try:
        files = File.objects.filter(
            user=request.user,
            deleted=False
        ).order_by('-uploaded_at')
        
        file_list = [{
            'id': f.id,
            'filename': f.original_name,
            'original_name': f.original_name,
            'size': f.size,
            'uploaded_at': f.uploaded_at.isoformat()
        } for f in files]
        
        log_info(f"📂 Returning {len(file_list)} files")
        return JsonResponse(file_list, safe=False)
        
    except Exception as e:
        log_error(f"📂 Error: {e}")
        return JsonResponse([], safe=False)


# ═══════════════════════════════════════════════════════════
# 🗑️ DELETE FILE (Move to Trash)
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@require_http_methods(["POST", "DELETE", "OPTIONS"])
def delete_file(request, file_id):
    """Soft delete - move to trash"""
    
    if request.method == "OPTIONS":
        return JsonResponse({'status': 'ok'})
    
    log_info(f"🗑️ DELETE - File: {file_id}, Auth: {request.user.is_authenticated}")
    
    if not request.user.is_authenticated:
        return JsonResponse({
            'error': 'Please login',
            'login_required': True
        }, status=401)
    
    try:
        file_obj = File.objects.get(id=file_id, user=request.user)
        
        if file_obj.deleted:
            return JsonResponse({'error': 'Already in trash'}, status=400)
        
        # Soft delete
        file_obj.deleted = True
        file_obj.deleted_at = timezone.now()
        file_obj.save(update_fields=['deleted', 'deleted_at'])
        
        # Create trash entry
        Trash.objects.update_or_create(
            file=file_obj,
            defaults={'deleted_at': timezone.now()}
        )
        
        log_info(f"🗑️ ✅ Moved to trash: {file_obj.original_name}")
        
        return JsonResponse({
            'status': 'success',
            'message': 'File moved to trash'
        })
        
    except File.DoesNotExist:
        return JsonResponse({'error': 'File not found'}, status=404)
    except Exception as e:
        log_error(f"🗑️ Error: {e}")
        return JsonResponse({'error': str(e)}, status=500)


# ═══════════════════════════════════════════════════════════
# 🗑️ TRASH LIST
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@require_http_methods(["GET", "OPTIONS"])
def trash_list(request):
    """List files in trash"""
    
    if request.method == "OPTIONS":
        return JsonResponse({'status': 'ok'})
    
    log_info(f"🗑️ TRASH LIST - Auth: {request.user.is_authenticated}")
    
    if not request.user.is_authenticated:
        return JsonResponse({
            'error': 'Please login',
            'login_required': True
        }, status=401)
    
    try:
        files = File.objects.filter(
            user=request.user,
            deleted=True
        ).order_by('-deleted_at')
        
        data = []
        for f in files:
            deleted_at = f.deleted_at or timezone.now()
            days_remaining = max(0, 30 - (timezone.now() - deleted_at).days)
            
            data.append({
                'id': f.id,
                'filename': f.original_name,
                'original_name': f.original_name,
                'size': f.size,
                'deleted_at': deleted_at.isoformat(),
                'days_remaining': days_remaining
            })
        
        log_info(f"🗑️ Returning {len(data)} trash items")
        return JsonResponse(data, safe=False)
        
    except Exception as e:
        log_error(f"🗑️ Error: {e}")
        return JsonResponse([], safe=False)


# ═══════════════════════════════════════════════════════════
# ♻️ RESTORE FILE
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@require_http_methods(["POST", "OPTIONS"])
def restore_file(request, file_id):
    """Restore file from trash"""
    
    if request.method == "OPTIONS":
        return JsonResponse({'status': 'ok'})
    
    log_info(f"♻️ RESTORE - File: {file_id}, Auth: {request.user.is_authenticated}")
    
    if not request.user.is_authenticated:
        return JsonResponse({
            'error': 'Please login',
            'login_required': True
        }, status=401)
    
    try:
        file_obj = File.objects.get(id=file_id, user=request.user)
        
        if not file_obj.deleted:
            return JsonResponse({'error': 'File is not in trash'}, status=400)
        
        # Restore
        file_obj.deleted = False
        file_obj.deleted_at = None
        file_obj.save(update_fields=['deleted', 'deleted_at'])
        
        # Remove trash entry
        Trash.objects.filter(file=file_obj).delete()
        
        log_info(f"♻️ ✅ Restored: {file_obj.original_name}")
        
        return JsonResponse({
            'status': 'success',
            'success': True,
            'message': 'File restored'
        })
        
    except File.DoesNotExist:
        return JsonResponse({'error': 'File not found'}, status=404)
    except Exception as e:
        log_error(f"♻️ Error: {e}")
        return JsonResponse({'error': str(e)}, status=500)


# ═══════════════════════════════════════════════════════════
# 🔍 DEBUG FILES
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@require_http_methods(["GET"])
def debug_files(request):
    """Debug endpoint"""
    
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Not authenticated'}, status=401)
    
    files = File.objects.filter(user=request.user)
    
    return JsonResponse({
        'user': request.user.email,
        'total': files.count(),
        'active': files.filter(deleted=False).count(),
        'deleted': files.filter(deleted=True).count()
    })


# ═══════════════════════════════════════════════════════════
# 📊 DASHBOARD (HTML Page)
# ═══════════════════════════════════════════════════════════
@login_required
def dashboard(request):
    """Dashboard page"""
    log_info(f"📊 DASHBOARD - User: {request.user.email}")
    
    # Force refresh CSRF token
    get_token(request)
    
    files = File.objects.filter(user=request.user, deleted=False).order_by('-uploaded_at')
    shared_links = SharedLink.objects.filter(owner=request.user).select_related('file')
    
    return render(request, 'dashboard.html', {
        'files': files,
        'shared_links': shared_links
    })