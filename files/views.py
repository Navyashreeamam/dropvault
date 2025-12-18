# files/views.py
import logging
import sys
import os
import hashlib
import secrets
import base64
import json
from functools import wraps
from django.utils import timezone
from datetime import datetime, timedelta
from django.shortcuts import render
from django.shortcuts import get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse, FileResponse
from django.views.decorators.http import require_http_methods
from django.conf import settings
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Q
from django.db import IntegrityError

# Import encryption only if available
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

from .models import File, Trash, FileLog, SharedLink

# Try to import bloom filter
try:
    from .bloomfilter import BloomFilter
    _bloom = BloomFilter(m=1_000_000, k=5)
except:
    _bloom = None


# ═══════════════════════════════════════════════════════════
# 🔧 LOGGING - Force output to console
# ═══════════════════════════════════════════════════════════
def log_info(msg):
    print(f"[INFO] {msg}", flush=True)

def log_error(msg):
    print(f"[ERROR] {msg}", flush=True)

def log_debug(msg):
    print(f"[DEBUG] {msg}", flush=True)


# ═══════════════════════════════════════════════════════════
# 🔐 API AUTH DECORATOR - Returns JSON, NOT HTML redirect!
# ═══════════════════════════════════════════════════════════
def api_login_required(view_func):
    """Returns JSON 401 instead of redirecting to login page"""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            log_error(f"🔒 Auth failed for {request.path}")
            return JsonResponse({
                'error': 'Not authenticated',
                'message': 'Please login to continue',
                'login_url': '/accounts/login/'
            }, status=401)
        return view_func(request, *args, **kwargs)
    return wrapper


# ═══════════════════════════════════════════════════════════
# 🛠️ CONSTANTS & HELPERS
# ═══════════════════════════════════════════════════════════
ALLOWED_EXTENSIONS = {'.pdf', '.jpg', '.jpeg', '.png', '.docx', '.txt', '.mp4', '.gif', '.zip', '.doc', '.xlsx', '.csv', '.mp3', '.rar', '.ppt', '.pptx'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
CHUNK_SIZE = 4 * 1024 * 1024       # 4 MB


def validate_file(file):
    """Validate file type and size"""
    if not file:
        return False, "No file provided"
    
    ext = os.path.splitext(file.name)[1].lower()
    if ext and ext not in ALLOWED_EXTENSIONS:
        return False, f"File type '{ext}' not allowed"
    
    if file.size > MAX_FILE_SIZE:
        return False, f"File too large (max 50MB)"
    
    return True, ""


def get_file_hash(file):
    """Calculate SHA-256 hash of file"""
    hasher = hashlib.sha256()
    file.seek(0)
    for chunk in file.chunks():
        hasher.update(chunk)
    file.seek(0)
    return hasher.hexdigest()


# ═══════════════════════════════════════════════════════════
# 📤 UPLOAD FILE
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@require_http_methods(["POST", "OPTIONS"])
def upload_file(request):
    """Upload a file - handles both authenticated and session issues"""
    
    # Handle preflight
    if request.method == "OPTIONS":
        response = JsonResponse({'status': 'ok'})
        response["Access-Control-Allow-Origin"] = "*"
        response["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        response["Access-Control-Allow-Headers"] = "Content-Type, X-CSRFToken"
        return response
    
    log_info("=" * 60)
    log_info("📤 UPLOAD REQUEST RECEIVED")
    log_info(f"📤 User authenticated: {request.user.is_authenticated}")
    log_info(f"📤 User: {request.user}")
    log_info(f"📤 Session key: {request.session.session_key}")
    log_info("=" * 60)
    
    # ✅ Check authentication - return JSON, not redirect!
    if not request.user.is_authenticated:
        log_error("📤 ❌ User not authenticated!")
        return JsonResponse({
            'error': 'Not authenticated',
            'message': 'Your session has expired. Please login again.',
            'login_required': True
        }, status=401)
    
    log_info(f"📤 User verified: {request.user.email}")
    
    # Check for file
    if 'file' not in request.FILES:
        log_error("📤 ❌ No file in request")
        log_info(f"📤 FILES keys: {list(request.FILES.keys())}")
        log_info(f"📤 POST keys: {list(request.POST.keys())}")
        return JsonResponse({
            'error': 'No file provided',
            'message': 'Please select a file to upload'
        }, status=400)
    
    file = request.FILES['file']
    log_info(f"📤 File: {file.name} ({file.size} bytes)")
    
    # Validate
    valid, error_msg = validate_file(file)
    if not valid:
        log_error(f"📤 ❌ Validation failed: {error_msg}")
        return JsonResponse({'error': error_msg}, status=400)
    
    try:
        # Calculate hash
        file_hash = get_file_hash(file)
        log_info(f"📤 Hash: {file_hash[:16]}...")
        
        # Check for duplicate
        existing = File.objects.filter(
            user=request.user,
            sha256=file_hash,
            deleted=False
        ).first()
        
        if existing:
            log_info(f"📤 ⚠️ Duplicate file found")
            return JsonResponse({
                'error': 'Duplicate file',
                'message': 'You already uploaded this file'
            }, status=409)
        
        # Save file
        original_name = file.name
        safe_name = f"{secrets.token_urlsafe(16)}.{original_name.split('.')[-1].lower()}"
        
        file_obj = File.objects.create(
            user=request.user,
            file=file,
            original_name=original_name,
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
        except:
            pass
        
        log_info(f"📤 ✅ SUCCESS - File ID: {file_obj.id}, Name: {original_name}")
        
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
        log_error(f"📤 ❌ Upload failed: {str(e)}")
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
    """List user's files"""
    
    if request.method == "OPTIONS":
        response = JsonResponse({'status': 'ok'})
        return response
    
    log_info(f"📂 LIST FILES - Auth: {request.user.is_authenticated}")
    
    if not request.user.is_authenticated:
        return JsonResponse({
            'error': 'Not authenticated',
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
        log_error(f"📂 ❌ Error: {e}")
        return JsonResponse([], safe=False)


# ═══════════════════════════════════════════════════════════
# 🗑️ DELETE FILE
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@require_http_methods(["POST", "DELETE", "OPTIONS"])
def delete_file(request, file_id):
    """Move file to trash"""
    
    if request.method == "OPTIONS":
        return JsonResponse({'status': 'ok'})
    
    log_info(f"🗑️ DELETE - File: {file_id}, Auth: {request.user.is_authenticated}")
    
    if not request.user.is_authenticated:
        return JsonResponse({
            'error': 'Not authenticated',
            'login_required': True
        }, status=401)
    
    try:
        file_obj = File.objects.get(id=file_id, user=request.user)
        
        if file_obj.deleted:
            return JsonResponse({
                'error': 'Already in trash',
                'message': 'File is already in trash'
            }, status=400)
        
        # Soft delete
        file_obj.deleted = True
        file_obj.deleted_at = timezone.now()
        file_obj.save(update_fields=['deleted', 'deleted_at'])
        
        # Create trash entry
        Trash.objects.update_or_create(
            file=file_obj,
            defaults={'deleted_at': timezone.now()}
        )
        
        log_info(f"🗑️ ✅ File {file_id} moved to trash")
        
        return JsonResponse({
            'status': 'success',
            'message': f'File moved to trash'
        })
        
    except File.DoesNotExist:
        return JsonResponse({'error': 'File not found'}, status=404)
    except Exception as e:
        log_error(f"🗑️ ❌ Error: {e}")
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
            'error': 'Not authenticated',
            'login_required': True
        }, status=401)
    
    try:
        files = File.objects.filter(
            user=request.user,
            deleted=True
        ).order_by('-deleted_at')
        
        log_info(f"🗑️ Found {files.count()} files in trash")
        
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
        log_error(f"🗑️ ❌ Error: {e}")
        import traceback
        traceback.print_exc()
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
            'error': 'Not authenticated',
            'login_required': True
        }, status=401)
    
    try:
        file_obj = File.objects.get(id=file_id, user=request.user)
        
        if not file_obj.deleted:
            return JsonResponse({
                'error': 'Not in trash',
                'message': 'File is not in trash'
            }, status=400)
        
        # Restore
        file_obj.deleted = False
        file_obj.deleted_at = None
        file_obj.save(update_fields=['deleted', 'deleted_at'])
        
        # Remove trash entry
        Trash.objects.filter(file=file_obj).delete()
        
        log_info(f"♻️ ✅ File {file_id} restored")
        
        return JsonResponse({
            'status': 'success',
            'success': True,
            'message': 'File restored successfully'
        })
        
    except File.DoesNotExist:
        return JsonResponse({'error': 'File not found'}, status=404)
    except Exception as e:
        log_error(f"♻️ ❌ Error: {e}")
        return JsonResponse({'error': str(e)}, status=500)


# ═══════════════════════════════════════════════════════════
# 📥 DOWNLOAD FILE
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@require_http_methods(["GET"])
def download_file(request, file_id):
    """Download a file"""
    
    log_info(f"📥 DOWNLOAD - File: {file_id}")
    
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Not authenticated'}, status=401)
    
    try:
        file_obj = File.objects.get(id=file_id, user=request.user, deleted=False)
        
        response = FileResponse(
            file_obj.file.open('rb'),
            as_attachment=True,
            filename=file_obj.original_name
        )
        return response
        
    except File.DoesNotExist:
        return JsonResponse({'error': 'File not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# ═══════════════════════════════════════════════════════════
# 🔍 DEBUG ENDPOINT
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@require_http_methods(["GET"])
def debug_files(request):
    """Debug endpoint to check file status"""
    
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Not authenticated'}, status=401)
    
    files = File.objects.filter(user=request.user)
    
    return JsonResponse({
        'user': request.user.email,
        'total_files': files.count(),
        'active_files': files.filter(deleted=False).count(),
        'deleted_files': files.filter(deleted=True).count(),
        'files': [{
            'id': f.id,
            'name': f.original_name,
            'deleted': f.deleted,
            'deleted_at': f.deleted_at.isoformat() if f.deleted_at else None
        } for f in files[:20]]
    })


# ═══════════════════════════════════════════════════════════
# 📊 DASHBOARD (HTML Page)
# ═══════════════════════════════════════════════════════════
@login_required
def dashboard(request):
    """Dashboard HTML page"""
    log_info(f"📊 DASHBOARD - User: {request.user.email}")
    
    files = File.objects.filter(user=request.user, deleted=False).order_by('-uploaded_at')
    shared_links = SharedLink.objects.filter(owner=request.user).select_related('file')
    
    return render(request, 'dashboard.html', {
        'files': files,
        'shared_links': shared_links
    })