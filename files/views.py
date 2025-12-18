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
class ForceFlushHandler(logging.StreamHandler):
    """Custom handler that forces flush after every log"""
    def emit(self, record):
        super().emit(record)
        self.flush()

# Setup logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Remove existing handlers
for handler in logger.handlers[:]:
    logger.removeHandler(handler)

# Add force-flush handler
console_handler = ForceFlushHandler(sys.stdout)
console_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


def log_message(level, message):
    """Force print to stdout for Docker visibility"""
    timestamp = timezone.now().strftime('%Y-%m-%d %H:%M:%S')
    log_line = f"[{timestamp}] [{level}] {message}"
    print(log_line, file=sys.stdout, flush=True)
    sys.stdout.flush()
    
    # Also log to logger
    if level == "INFO":
        logger.info(message)
    elif level == "ERROR":
        logger.error(message)
    elif level == "DEBUG":
        logger.debug(message)
    elif level == "WARNING":
        logger.warning(message)


def log_info(message):
    log_message("INFO", message)


def log_error(message):
    log_message("ERROR", message)


def log_debug(message):
    log_message("DEBUG", message)


def log_warning(message):
    log_message("WARNING", message)


# Constants
ALLOWED_EXTENSIONS = {'.pdf', '.jpg', '.jpeg', '.png', '.docx', '.txt', '.mp4', '.gif', '.zip', '.doc', '.xlsx', '.csv'}
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
            log_warning(f"🔒 Unauthorized access attempt to {request.path}")
            return JsonResponse({
                'error': 'Authentication required',
                'message': 'Please login first',
                'status': 'unauthorized'
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
        return False, f"Invalid file type '{ext}'. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
    
    if file.size > MAX_FILE_SIZE:
        return False, f"File too large ({file.size / (1024*1024):.1f}MB). Maximum: 50MB"
    
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


def get_client_ip(request):
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', 'unknown')


# ═══════════════════════════════════════════════════════════
# 📤 UPLOAD FILE API
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@api_login_required
@require_http_methods(["POST"])
def upload_file(request):
    """
    API: Upload a file
    POST /api/upload/ or /files/upload/
    """
    log_info(f"📤 ═══════════════════════════════════════════════════════")
    log_info(f"📤 UPLOAD REQUEST RECEIVED")
    log_info(f"📤 User: {request.user.id} ({request.user.email})")
    log_info(f"📤 IP: {get_client_ip(request)}")
    log_info(f"📤 Files in request: {list(request.FILES.keys())}")
    log_info(f"📤 ═══════════════════════════════════════════════════════")
    
    # Check if file exists in request
    if 'file' not in request.FILES:
        log_error(f"❌ No file in request. Available keys: {list(request.FILES.keys())}")
        return JsonResponse({
            'error': 'No file provided',
            'message': 'Please select a file to upload'
        }, status=400)
    
    file = request.FILES.get('file')
    log_info(f"📤 File received: {file.name} ({file.size} bytes, type: {file.content_type})")
    
    # Validate file
    valid, msg = validate_file(file)
    if not valid:
        log_error(f"❌ Upload validation failed: {msg}")
        return JsonResponse({'error': msg}, status=400)

    try:
        log_info(f"📤 Processing file: {file.name}")
        
        # Create chunks and hashes
        chunks, chunk_hashes = create_file_chunks_with_hash(file, CHUNK_SIZE)
        log_info(f"📤 Created {len(chunks)} chunks")

        # Compute file-level SHA-256
        file_hasher = hashlib.sha256()
        for h in chunk_hashes:
            file_hasher.update(h.encode('utf-8'))
        file_sha256 = file_hasher.hexdigest()
        
        log_info(f"📤 File SHA256: {file_sha256[:16]}...")

        # Deduplication check - only check active files
        if _bloom.contains(file_sha256):
            existing = File.objects.filter(
                user=request.user, 
                sha256=file_sha256,
                deleted=False
            )
            if existing.exists():
                log_warning(f"⚠️ Duplicate file detected: {file.name}")
                return JsonResponse({
                    'error': 'Duplicate file',
                    'message': 'You already uploaded this file.'
                }, status=409)

        _bloom.add(file_sha256)

        # Encrypt all chunks
        log_info(f"📤 Encrypting {len(chunks)} chunks...")
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
        
        log_info(f"📤 Encryption complete. Encrypted size: {len(encrypted_data)} bytes")

        # Save encrypted file
        encrypted_file = ContentFile(encrypted_data)
        original_name = file.name
        safe_name = f"{secrets.token_urlsafe(12)}.{original_name.split('.')[-1].lower()}"
        encrypted_file.name = safe_name

        # Create file object
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
        
        # Log the action
        FileLog.objects.create(
            user=request.user, 
            file=file_obj, 
            action='UPLOAD',
            ip_address=get_client_ip(request)
        )
        
        log_info(f"✅ ═══════════════════════════════════════════════════════")
        log_info(f"✅ FILE UPLOADED SUCCESSFULLY")
        log_info(f"✅ ID: {file_obj.id}")
        log_info(f"✅ Name: {file_obj.original_name}")
        log_info(f"✅ Size: {file_obj.size} bytes")
        log_info(f"✅ User: {request.user.email}")
        log_info(f"✅ ═══════════════════════════════════════════════════════")

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
# 📂 LIST FILES API
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@api_login_required
@require_http_methods(["GET"])
def list_files(request):
    """
    API: List user's active (non-deleted) files
    GET /api/list/
    """
    log_info(f"📂 LIST FILES - User: {request.user.email}")
    
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
                'original_name': f.original_name,
                'size': f.size,
                'uploaded_at': f.uploaded_at.isoformat()
            }
            for f in files
        ]
        
        log_info(f"📂 Returning {len(file_list)} active files")
        
        return JsonResponse(file_list, safe=False)
        
    except Exception as e:
        log_error(f"❌ List files failed: {str(e)}")
        return JsonResponse([], safe=False)


# ═══════════════════════════════════════════════════════════
# 🗑️ DELETE FILE API (Move to Trash)
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@api_login_required
@require_http_methods(["DELETE", "POST"])
def delete_file(request, file_id):
    """
    API: Soft delete a file (move to trash)
    DELETE/POST /api/delete/<file_id>/
    """
    log_info(f"🗑️ ═══════════════════════════════════════════════════════")
    log_info(f"🗑️ DELETE REQUEST")
    log_info(f"🗑️ File ID: {file_id}")
    log_info(f"🗑️ User: {request.user.email}")
    log_info(f"🗑️ ═══════════════════════════════════════════════════════")
    
    try:
        file_obj = File.objects.get(id=file_id, user=request.user)
        log_info(f"🗑️ Found file: {file_obj.original_name}, deleted={file_obj.deleted}")
        
        if file_obj.deleted:
            log_warning(f"⚠️ File {file_id} is already in trash")
            return JsonResponse({
                'error': 'Already deleted',
                'message': 'File is already in trash'
            }, status=400)
            
    except File.DoesNotExist:
        log_error(f"❌ File {file_id} not found")
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
        
        log_info(f"🗑️ File marked as deleted: deleted={file_obj.deleted}, deleted_at={file_obj.deleted_at}")

        # Create or update trash entry
        trash_entry, created = Trash.objects.update_or_create(
            file=file_obj,
            defaults={'deleted_at': now}
        )
        log_info(f"🗑️ Trash entry {'created' if created else 'updated'}")
        
        # Log the action
        FileLog.objects.create(
            user=request.user, 
            file=file_obj, 
            action='DELETE',
            ip_address=get_client_ip(request)
        )
        
        log_info(f"✅ FILE DELETED: {file_obj.original_name} moved to trash")

        return JsonResponse({
            'status': 'success',
            'message': f'File "{file_obj.original_name}" moved to trash',
            'file_id': file_obj.id
        })

    except Exception as e:
        log_error(f"❌ Delete failed: {str(e)}")
        import traceback
        log_error(traceback.format_exc())
        return JsonResponse({
            'error': 'Delete failed',
            'message': str(e)
        }, status=500)


# ═══════════════════════════════════════════════════════════
# 🗑️ TRASH LIST API
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@api_login_required
@require_http_methods(["GET"])
def trash_list(request):
    """
    API: List deleted files in trash
    GET /api/trash/
    """
    log_info(f"🗑️ ═══════════════════════════════════════════════════════")
    log_info(f"🗑️ TRASH LIST REQUEST")
    log_info(f"🗑️ User: {request.user.email}")
    log_info(f"🗑️ ═══════════════════════════════════════════════════════")
    
    try:
        # Get all deleted files for this user
        trashed_files = File.objects.filter(
            user=request.user,
            deleted=True
        ).order_by('-deleted_at')
        
        total_count = trashed_files.count()
        log_info(f"🗑️ Found {total_count} trashed files in database")

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
                    # Update the file with deletion date
                    f.deleted_at = deletion_date
                    f.save(update_fields=['deleted_at'])
            
            # Calculate days remaining (30-day retention)
            if deletion_date:
                permanent_delete_date = deletion_date + timedelta(days=30)
                days_remaining = max(0, (permanent_delete_date - timezone.now()).days)
            else:
                permanent_delete_date = timezone.now() + timedelta(days=30)
                days_remaining = 30

            file_data = {
                'id': f.id,
                'filename': f.original_name,
                'original_name': f.original_name,
                'size': f.size,
                'deleted_at': deletion_date.isoformat() if deletion_date else None,
                'days_remaining': days_remaining,
                'permanent_delete_date': permanent_delete_date.isoformat()
            }
            data.append(file_data)

        log_info(f"🗑️ Returning {len(data)} trashed files")

        # Return as array (not object) for frontend compatibility
        return JsonResponse(data, safe=False)
        
    except Exception as e:
        log_error(f"❌ Trash list failed: {str(e)}")
        import traceback
        log_error(traceback.format_exc())
        # Return empty array on error
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
    log_info(f"♻️ ═══════════════════════════════════════════════════════")
    log_info(f"♻️ RESTORE REQUEST")
    log_info(f"♻️ File ID: {file_id}")
    log_info(f"♻️ User: {request.user.email}")
    log_info(f"♻️ ═══════════════════════════════════════════════════════")
    
    try:
        file_obj = File.objects.get(id=file_id, user=request.user)
        log_info(f"♻️ Found file: {file_obj.original_name}, deleted={file_obj.deleted}")
        
        if not file_obj.deleted:
            log_warning(f"⚠️ File {file_id} is not in trash")
            return JsonResponse({
                'error': 'Not in trash',
                'message': 'File is not in trash'
            }, status=400)
            
    except File.DoesNotExist:
        log_error(f"❌ File {file_id} not found")
        return JsonResponse({
            'error': 'File not found',
            'message': 'File does not exist or you do not have permission'
        }, status=404)

    try:
        # Restore the file
        file_obj.deleted = False
        file_obj.deleted_at = None
        file_obj.save(update_fields=['deleted', 'deleted_at'])
        
        log_info(f"♻️ File restored: deleted={file_obj.deleted}")
        
        # Remove trash entry
        deleted_count, _ = Trash.objects.filter(file=file_obj).delete()
        log_info(f"♻️ Deleted {deleted_count} trash entries")
        
        # Log the action
        FileLog.objects.create(
            user=request.user, 
            file=file_obj, 
            action='RESTORE',
            ip_address=get_client_ip(request)
        )
        
        log_info(f"✅ FILE RESTORED: {file_obj.original_name}")

        return JsonResponse({
            'status': 'success',
            'success': True,
            'message': f'File "{file_obj.original_name}" restored successfully',
            'file_id': file_obj.id
        })
        
    except Exception as e:
        log_error(f"❌ Restore failed: {str(e)}")
        import traceback
        log_error(traceback.format_exc())
        return JsonResponse({
            'error': 'Restore failed',
            'message': str(e)
        }, status=500)


# ═══════════════════════════════════════════════════════════
# 🔥 PERMANENT DELETE API
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@api_login_required
@require_http_methods(["POST", "DELETE"])
def permanent_delete(request, file_id):
    """
    API: Permanently delete a file
    POST/DELETE /api/permanent-delete/<file_id>/
    """
    log_info(f"🔥 PERMANENT DELETE - File ID: {file_id}, User: {request.user.email}")
    
    try:
        file_obj = File.objects.get(id=file_id, user=request.user)
        file_name = file_obj.original_name
        
        # Delete physical file
        if file_obj.file:
            try:
                file_obj.file.delete(save=False)
                log_info(f"🔥 Physical file deleted")
            except Exception as e:
                log_warning(f"⚠️ Could not delete physical file: {e}")
        
        # Delete trash entry
        Trash.objects.filter(file=file_obj).delete()
        
        # Delete file record
        file_obj.delete()
        
        log_info(f"✅ FILE PERMANENTLY DELETED: {file_name}")

        return JsonResponse({
            'status': 'success',
            'message': f'File "{file_name}" permanently deleted'
        })
        
    except File.DoesNotExist:
        return JsonResponse({'error': 'File not found'}, status=404)
    except Exception as e:
        log_error(f"❌ Permanent delete failed: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)


# ═══════════════════════════════════════════════════════════
# 📥 DOWNLOAD FILE API
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@api_login_required
@require_http_methods(["GET"])
def download_file(request, file_id):
    """
    API: Download a file
    GET /api/download/<file_id>/
    """
    log_info(f"📥 DOWNLOAD REQUEST - File ID: {file_id}, User: {request.user.email}")
    
    try:
        file_obj = File.objects.get(id=file_id, user=request.user, deleted=False)
        
        if not file_obj.file:
            return JsonResponse({'error': 'File not found on server'}, status=404)
        
        # Log download
        FileLog.objects.create(
            user=request.user,
            file=file_obj,
            action='DOWNLOAD',
            ip_address=get_client_ip(request)
        )
        
        log_info(f"✅ FILE DOWNLOAD: {file_obj.original_name}")
        
        response = FileResponse(
            file_obj.file.open('rb'),
            as_attachment=True,
            filename=file_obj.original_name
        )
        return response
        
    except File.DoesNotExist:
        return JsonResponse({'error': 'File not found'}, status=404)
    except Exception as e:
        log_error(f"❌ Download failed: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)


# ═══════════════════════════════════════════════════════════
# 🔍 DEBUG ENDPOINT
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@api_login_required
@require_http_methods(["GET"])
def debug_files(request):
    """
    DEBUG: Show all files with their deletion status
    GET /api/debug/files/
    """
    log_info(f"🔍 DEBUG FILES - User: {request.user.email}")
    
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
        
        log_info(f"🔍 Debug: {len(data)} total, {active_count} active, {deleted_count} deleted")
        
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
    log_info(f"📊 DASHBOARD - User: {request.user.email}")
    
    try:
        files = File.objects.filter(
            user=request.user,
            deleted=False
        ).order_by('-uploaded_at')
        
        shared_links = SharedLink.objects.filter(
            owner=request.user
        ).select_related('file')
        
        log_info(f"📊 Dashboard loaded: {files.count()} files, {shared_links.count()} shares")

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