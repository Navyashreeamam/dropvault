# DropVault/files/views.py
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
from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_http_methods
from django.conf import settings
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from .models import File, Trash, FileLog, SharedLink
from .bloomfilter import BloomFilter
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Q
from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError

# ═══════════════════════════════════════════════════════════
# 🔧 FORCE LOGGING TO CONSOLE (Fix for Docker/Gunicorn)
# ═══════════════════════════════════════════════════════════
def log_message(level, message):
    """Force print to stdout for Docker visibility"""
    timestamp = timezone.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] [{level}] {message}", flush=True)
    sys.stdout.flush()

def log_info(message):
    log_message("INFO", message)

def log_error(message):
    log_message("ERROR", message)

def log_debug(message):
    if settings.DEBUG:
        log_message("DEBUG", message)

# Constants
ALLOWED_EXTENSIONS = {'.pdf', '.jpg', '.jpeg', '.png', '.docx', '.txt', '.mp4'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
CHUNK_SIZE = 4 * 1024 * 1024       # 4 MB

# Global Bloom filter
_bloom = BloomFilter(m=1_000_000, k=5)


# ═══════════════════════════════════════════════════════════
# 🔐 CUSTOM API AUTH DECORATOR (Returns JSON, not redirect)
# ═══════════════════════════════════════════════════════════
def api_login_required(view_func):
    """
    Custom decorator for API views - returns JSON 401 instead of HTML redirect
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            log_info(f"🔒 Unauthorized access attempt to {request.path}")
            return JsonResponse({
                'error': 'Authentication required',
                'message': 'Please login first using /api/login/',
                'status': 'unauthorized',
                'login_url': '/api/login/'
            }, status=401)
        return view_func(request, *args, **kwargs)
    return wrapper


# ═══════════════════════════════════════════════════════════
# 🛠️ HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════
def validate_file(file):
    """Validate uploaded file type and size"""
    if not file:
        return False, "No file provided"
    ext = os.path.splitext(file.name)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"Invalid file type. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
    if file.size > MAX_FILE_SIZE:
        return False, "File too large (max 50MB)"
    return True, ""


def create_file_chunks_with_hash(django_file, chunk_size=CHUNK_SIZE):
    """Returns list of raw byte chunks and their SHA-256 hashes."""
    chunks = []
    hashes = []
    django_file.seek(0)
    while True:
        chunk = django_file.read(chunk_size)
        if not chunk:
            break
        chunks.append(chunk)
        hashes.append(hashlib.sha256(chunk).hexdigest())
    return chunks, hashes


def _encrypt_chunk(plaintext_chunk):
    """Encrypt chunk using AES-256-GCM. Returns (ciphertext, key, nonce, tag)."""
    nonce = secrets.token_bytes(12)
    key = secrets.token_bytes(32)

    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(plaintext_chunk) + encryptor.finalize()
    tag = encryptor.tag
    return ciphertext, key, nonce, tag


# ═══════════════════════════════════════════════════════════
# 📤 UPLOAD FILE API
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@api_login_required
@require_http_methods(["POST"])
def upload_file(request):
    """
    API: Upload a file
    POST /api/upload/
    """
    log_info(f"📤 UPLOAD REQUEST from user {request.user.id} ({request.user.email})")
    
    file = request.FILES.get('file')
    valid, msg = validate_file(file)
    if not valid:
        log_error(f"❌ Upload validation failed: {msg}")
        return JsonResponse({'error': msg}, status=400)

    try:
        log_info(f"📤 Processing file: {file.name} ({file.size} bytes)")
        
        chunks, chunk_hashes = create_file_chunks_with_hash(file, CHUNK_SIZE)

        # Compute file-level SHA-256
        file_hasher = hashlib.sha256()
        for h in chunk_hashes:
            file_hasher.update(h.encode('utf-8'))
        file_sha256 = file_hasher.hexdigest()
        
        log_debug(f"🔐 File SHA256: {file_sha256}")

        # Deduplication check - only check active files
        if _bloom.contains(file_sha256):
            existing = File.objects.filter(
                user=request.user, 
                sha256=file_sha256,
                deleted=False
            )
            if existing.exists():
                log_info(f"⚠️ Duplicate file detected: {file.name}")
                return JsonResponse({
                    'error': 'Duplicate file',
                    'message': 'You already uploaded this file.'
                }, status=409)

        _bloom.add(file_sha256)

        # Encrypt all chunks
        encrypted_data = bytearray()
        chunk_keys_nonces_tags = []
        for i, chunk in enumerate(chunks):
            ciphertext, key, nonce, tag = _encrypt_chunk(chunk)
            encrypted_data.extend(ciphertext)
            chunk_keys_nonces_tags.append({
                'key': base64.b64encode(key).decode(),
                'nonce': base64.b64encode(nonce).decode(),
                'tag': base64.b64encode(tag).decode()
            })
        
        log_debug(f"🔐 Encrypted {len(chunks)} chunks")

        # Save encrypted file
        encrypted_file = ContentFile(encrypted_data)
        original_name = file.name
        safe_name = f"{secrets.token_urlsafe(12)}.{original_name.split('.')[-1].lower()}"
        encrypted_file.name = safe_name

        # Create file object - explicitly set deleted=False
        file_obj = File.objects.create(
            user=request.user,
            file=encrypted_file,
            original_name=original_name,
            size=len(encrypted_data),
            sha256=file_sha256,
            encryption_meta=json.dumps(chunk_keys_nonces_tags),
            deleted=False,
            deleted_at=None
        )
        
        FileLog.objects.create(user=request.user, file=file_obj, action='UPLOAD')
        
        log_info(f"✅ FILE UPLOADED: ID={file_obj.id}, Name={file_obj.original_name}, User={request.user.email}")

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
        log_error(f"❌ Upload failed: {str(e)}")
        import traceback
        log_error(traceback.format_exc())
        return JsonResponse({
            'error': 'Upload failed',
            'message': str(e)
        }, status=500)


# ═══════════════════════════════════════════════════════════
# 📂 LIST FILES API (Returns ARRAY for frontend)
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@api_login_required
@require_http_methods(["GET"])
def list_files(request):
    """
    API: List user's active (non-deleted) files
    GET /api/list/
    """
    log_info(f"📂 LIST FILES request from user {request.user.id} ({request.user.email})")
    
    try:
        # Get only non-deleted files
        files = File.objects.filter(
            user=request.user,
            deleted=False
        ).order_by('-uploaded_at')
        
        file_list = [
            {
                'id': f.id,
                'filename': f.original_name,
                'size': f.size,
                'uploaded_at': f.uploaded_at.isoformat()
            }
            for f in files
        ]
        
        log_info(f"📂 Returning {len(file_list)} active files for user {request.user.email}")
        
        return JsonResponse(file_list, safe=False)
        
    except Exception as e:
        log_error(f"❌ List files failed: {str(e)}")
        return JsonResponse([], safe=False)


# ═══════════════════════════════════════════════════════════
# 🗑️ DELETE FILE API
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@api_login_required
@require_http_methods(["DELETE", "POST"])
def delete_file(request, file_id):
    """
    API: Soft delete a file (move to trash)
    DELETE /api/delete/<file_id>/
    POST /api/delete/<file_id>/
    """
    log_info(f"🗑️ DELETE REQUEST for file {file_id} from user {request.user.id} ({request.user.email})")
    
    try:
        file_obj = File.objects.get(id=file_id, user=request.user)
        log_info(f"🗑️ Found file: ID={file_obj.id}, Name={file_obj.original_name}, deleted={file_obj.deleted}")
        
        if file_obj.deleted:
            log_info(f"⚠️ File {file_id} is already in trash")
            return JsonResponse({
                'error': 'Already deleted',
                'message': 'File is already in trash'
            }, status=400)
            
    except File.DoesNotExist:
        log_error(f"❌ File {file_id} not found for user {request.user.id}")
        return JsonResponse({
            'error': 'File not found',
            'message': 'File does not exist or you do not have permission'
        }, status=404)

    try:
        # Mark file as deleted
        now = timezone.now()
        file_obj.deleted = True
        file_obj.deleted_at = now
        file_obj.save(update_fields=['deleted', 'deleted_at'])
        
        log_info(f"🗑️ Updated file: deleted={file_obj.deleted}, deleted_at={file_obj.deleted_at}")

        # Create or update trash entry
        trash_entry, created = Trash.objects.update_or_create(
            file=file_obj,
            defaults={'deleted_at': now}
        )
        log_info(f"🗑️ Trash entry {'created' if created else 'updated'} for file {file_id}")
        
        # Log the action
        FileLog.objects.create(user=request.user, file=file_obj, action='DELETE')
        
        log_info(f"✅ FILE DELETED: ID={file_id}, Name={file_obj.original_name} moved to trash")

        return JsonResponse({
            'status': 'success',
            'message': f'File "{file_obj.original_name}" moved to trash',
            'file_id': file_obj.id
        })

    except Exception as e:
        log_error(f"❌ Delete failed for file {file_id}: {str(e)}")
        import traceback
        log_error(traceback.format_exc())
        return JsonResponse({
            'error': 'Delete failed',
            'message': str(e)
        }, status=500)


# ═══════════════════════════════════════════════════════════
# 🗑️ TRASH LIST API (Returns ARRAY for frontend)
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@api_login_required
@require_http_methods(["GET"])
def trash_list(request):
    """
    API: List deleted files in trash
    GET /api/trash/
    """
    log_info(f"🗑️ TRASH LIST request from user {request.user.id} ({request.user.email})")
    
    try:
        # Get all deleted files for this user
        trashed_files = File.objects.filter(
            user=request.user,
            deleted=True
        ).order_by('-deleted_at')
        
        log_info(f"🗑️ Found {trashed_files.count()} trashed files in database")

        data = []
        for f in trashed_files:
            # Get deletion date
            deletion_date = f.deleted_at
            
            if deletion_date is None:
                # Try to get from Trash model as fallback
                try:
                    trash_entry = Trash.objects.get(file=f)
                    deletion_date = trash_entry.deleted_at
                except Trash.DoesNotExist:
                    deletion_date = timezone.now()
            
            # Calculate days remaining (30-day retention)
            permanent_delete_date = deletion_date + timedelta(days=30)
            days_remaining = max(0, (permanent_delete_date - timezone.now()).days)

            file_data = {
                'id': f.id,
                'filename': f.original_name,
                'size': f.size,
                'deleted_at': deletion_date.isoformat() if deletion_date else None,
                'days_remaining': days_remaining,
                'permanent_delete_date': permanent_delete_date.isoformat()
            }
            data.append(file_data)
            log_debug(f"🗑️ Trash item: {file_data}")

        log_info(f"🗑️ Returning {len(data)} trashed files for user {request.user.email}")

        return JsonResponse(data, safe=False)
        
    except Exception as e:
        log_error(f"❌ Trash list failed: {str(e)}")
        import traceback
        log_error(traceback.format_exc())
        return JsonResponse([], safe=False)


# ═══════════════════════════════════════════════════════════
# ♻️ RESTORE FILE API
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@api_login_required
@require_http_methods(["POST"])
def restore_file(request, file_id):
    """
    API: Restore a deleted file from trash
    POST /api/restore/<file_id>/
    """
    log_info(f"♻️ RESTORE REQUEST for file {file_id} from user {request.user.id} ({request.user.email})")
    
    try:
        file_obj = File.objects.get(id=file_id, user=request.user)
        log_info(f"♻️ Found file: ID={file_obj.id}, Name={file_obj.original_name}, deleted={file_obj.deleted}")
        
        if not file_obj.deleted:
            log_info(f"⚠️ File {file_id} is not in trash")
            return JsonResponse({
                'error': 'Not in trash',
                'message': 'File is not in trash'
            }, status=400)
            
    except File.DoesNotExist:
        log_error(f"❌ File {file_id} not found for user {request.user.id}")
        return JsonResponse({
            'error': 'File not found',
            'message': 'File does not exist or you do not have permission'
        }, status=404)

    try:
        # Restore the file
        file_obj.deleted = False
        file_obj.deleted_at = None
        file_obj.save(update_fields=['deleted', 'deleted_at'])
        
        log_info(f"♻️ Updated file: deleted={file_obj.deleted}, deleted_at={file_obj.deleted_at}")
        
        # Remove trash entry
        deleted_count, _ = Trash.objects.filter(file=file_obj).delete()
        log_info(f"♻️ Deleted {deleted_count} trash entries for file {file_id}")
        
        # Log the action
        FileLog.objects.create(user=request.user, file=file_obj, action='RESTORE')
        
        log_info(f"✅ FILE RESTORED: ID={file_id}, Name={file_obj.original_name}")

        return JsonResponse({
            'status': 'success',
            'message': f'File "{file_obj.original_name}" restored successfully',
            'file_id': file_obj.id
        })
        
    except Exception as e:
        log_error(f"❌ Restore failed for file {file_id}: {str(e)}")
        import traceback
        log_error(traceback.format_exc())
        return JsonResponse({
            'error': 'Restore failed',
            'message': str(e)
        }, status=500)


# ═══════════════════════════════════════════════════════════
# 🔍 DEBUG ENDPOINT - Check database status
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@api_login_required
@require_http_methods(["GET"])
def debug_files(request):
    """
    DEBUG: Show all files with their deletion status
    GET /api/debug/files/
    """
    log_info(f"🔍 DEBUG FILES request from user {request.user.id}")
    
    try:
        all_files = File.objects.filter(user=request.user).order_by('-uploaded_at')
        
        data = []
        for f in all_files:
            data.append({
                'id': f.id,
                'filename': f.original_name,
                'size': f.size,
                'deleted': f.deleted,
                'deleted_at': f.deleted_at.isoformat() if f.deleted_at else None,
                'uploaded_at': f.uploaded_at.isoformat(),
                'has_trash_entry': Trash.objects.filter(file=f).exists()
            })
        
        active_count = len([f for f in data if not f['deleted']])
        deleted_count = len([f for f in data if f['deleted']])
        
        log_info(f"🔍 Debug: {len(data)} total files, {active_count} active, {deleted_count} deleted")
        
        return JsonResponse({
            'total': len(data),
            'active': active_count,
            'deleted': deleted_count,
            'files': data
        })
        
    except Exception as e:
        log_error(f"❌ Debug failed: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)


# ═══════════════════════════════════════════════════════════
# 📊 DASHBOARD VIEW (Web - HTML)
# ═══════════════════════════════════════════════════════════
@login_required
def dashboard(request):
    """
    Dashboard page - HTML view
    """
    log_info(f"📊 DASHBOARD request from user {request.user.id} ({request.user.email})")
    
    try:
        files = File.objects.filter(
            user=request.user,
            deleted=False
        ).order_by('-uploaded_at')
        
        shared_links = SharedLink.objects.filter(
            owner=request.user
        ).select_related('file')
        
        log_info(f"📊 Dashboard: {files.count()} files, {shared_links.count()} shared links")

        return render(request, 'dashboard.html', {
            'files': files,
            'shared_links': shared_links
        })
        
    except Exception as e:
        log_error(f"❌ Dashboard error: {str(e)}")
        return render(request, 'dashboard.html', {
            'files': [],
            'shared_links': [],
            'error': str(e)
        })