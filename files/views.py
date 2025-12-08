# DropVault/files/views.py
import logging
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

logger = logging.getLogger(__name__)

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


def is_file_deleted(file_obj):
    """Check if file is deleted (handles both field types)"""
    if hasattr(file_obj, 'deleted') and file_obj.deleted:
        return True
    if hasattr(file_obj, 'deleted_at') and file_obj.deleted_at:
        return True
    return False


def mark_file_deleted(file_obj):
    """Mark file as deleted (handles both field types)"""
    if hasattr(file_obj, 'deleted'):
        file_obj.deleted = True
    if hasattr(file_obj, 'deleted_at'):
        file_obj.deleted_at = timezone.now()
    file_obj.save()


def mark_file_restored(file_obj):
    """Mark file as restored (handles both field types)"""
    if hasattr(file_obj, 'deleted'):
        file_obj.deleted = False
    if hasattr(file_obj, 'deleted_at'):
        file_obj.deleted_at = None
    file_obj.save()


def get_active_files_query(user):
    """Get query for non-deleted files"""
    query = File.objects.filter(user=user)
    if hasattr(File, 'deleted'):
        query = query.filter(deleted=False)
    else:
        query = query.filter(deleted_at__isnull=True)
    return query


def get_deleted_files_query(user):
    """Get query for deleted files"""
    query = File.objects.filter(user=user)
    if hasattr(File, 'deleted'):
        query = query.filter(deleted=True)
    else:
        query = query.filter(deleted_at__isnull=False)
    return query


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
    file = request.FILES.get('file')
    valid, msg = validate_file(file)
    if not valid:
        return JsonResponse({'error': msg}, status=400)

    try:
        chunks, chunk_hashes = create_file_chunks_with_hash(file, CHUNK_SIZE)

        # Compute file-level SHA-256
        file_hasher = hashlib.sha256()
        for h in chunk_hashes:
            file_hasher.update(h.encode('utf-8'))
        file_sha256 = file_hasher.hexdigest()

        # Deduplication check
        if _bloom.contains(file_sha256):
            existing = get_active_files_query(request.user).filter(sha256=file_sha256)
            if existing.exists():
                return JsonResponse({
                    'error': 'Duplicate file',
                    'message': 'You already uploaded this file.'
                }, status=409)

        _bloom.add(file_sha256)

        # Encrypt all chunks
        encrypted_data = bytearray()
        chunk_keys_nonces_tags = []
        for chunk in chunks:
            ciphertext, key, nonce, tag = _encrypt_chunk(chunk)
            encrypted_data.extend(ciphertext)
            chunk_keys_nonces_tags.append({
                'key': base64.b64encode(key).decode(),
                'nonce': base64.b64encode(nonce).decode(),
                'tag': base64.b64encode(tag).decode()
            })

        # Save encrypted file
        encrypted_file = ContentFile(encrypted_data)
        original_name = file.name
        safe_name = f"{secrets.token_urlsafe(12)}.{original_name.split('.')[-1].lower()}"
        encrypted_file.name = safe_name

        # Create file object
        file_data = {
            'user': request.user,
            'file': encrypted_file,
            'original_name': original_name,
            'size': len(encrypted_data),
            'sha256': file_sha256,
            'encryption_meta': json.dumps(chunk_keys_nonces_tags)
        }
        
        if hasattr(File, 'deleted'):
            file_data['deleted'] = False
            
        file_obj = File.objects.create(**file_data)
        FileLog.objects.create(user=request.user, file=file_obj, action='UPLOAD')

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
        logger.error(f"Upload failed: {str(e)}")
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
    API: List user's files
    GET /api/list/
    
    Returns: JSON ARRAY (not object) for frontend compatibility
    """
    try:
        files = get_active_files_query(request.user).order_by('-uploaded_at')
        
        file_list = [
            {
                'id': f.id,
                'filename': f.original_name,
                'size': f.size,
                'uploaded_at': f.uploaded_at.isoformat()
            }
            for f in files
        ]
        
        # ✅ Return ARRAY directly (frontend expects array.map())
        return JsonResponse(file_list, safe=False)
        
    except Exception as e:
        logger.error(f"List files failed: {str(e)}")
        return JsonResponse([], safe=False)


# ═══════════════════════════════════════════════════════════
# 🗑️ DELETE FILE API
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@api_login_required
@require_http_methods(["DELETE", "POST"])
def delete_file(request, file_id):
    """
    API: Soft delete a file
    DELETE /api/delete/<file_id>/
    """
    try:
        file_obj = File.objects.get(id=file_id, user=request.user)
        
        if is_file_deleted(file_obj):
            return JsonResponse({
                'error': 'Already deleted',
                'message': 'File is already in trash'
            }, status=400)
            
    except File.DoesNotExist:
        return JsonResponse({
            'error': 'File not found',
            'message': 'File does not exist or you do not have permission'
        }, status=404)

    try:
        mark_file_deleted(file_obj)

        Trash.objects.update_or_create(
            file=file_obj,
            defaults={'deleted_at': timezone.now()}
        )
        
        FileLog.objects.create(user=request.user, file=file_obj, action='DELETE')

        return JsonResponse({
            'status': 'success',
            'message': f'File "{file_obj.original_name}" moved to trash',
            'file_id': file_obj.id
        })

    except Exception as e:
        logger.error(f"Delete failed: {str(e)}")
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
    API: List deleted files
    GET /api/trash/
    
    Returns: JSON ARRAY (not object) for frontend compatibility
    """
    try:
        trashed_files = get_deleted_files_query(request.user).order_by('-uploaded_at')

        data = []
        for f in trashed_files:
            deletion_date = None
            if hasattr(f, 'deleted_at') and f.deleted_at:
                deletion_date = f.deleted_at
            else:
                try:
                    trash_entry = Trash.objects.get(file=f)
                    deletion_date = trash_entry.deleted_at
                except Trash.DoesNotExist:
                    deletion_date = timezone.now()
            
            days_remaining = 30
            permanent_delete_date = None
            
            if deletion_date:
                permanent_delete_date = deletion_date + timedelta(days=30)
                days_remaining = max(0, (permanent_delete_date - timezone.now()).days)

            data.append({
                'id': f.id,
                'filename': f.original_name,
                'size': f.size,
                'deleted_at': deletion_date.isoformat() if deletion_date else None,
                'days_remaining': days_remaining,
                'permanent_delete_date': permanent_delete_date.isoformat() if permanent_delete_date else None
            })

        # ✅ Return ARRAY directly (frontend expects array.map())
        return JsonResponse(data, safe=False)
        
    except Exception as e:
        logger.error(f"Trash list failed: {str(e)}")
        return JsonResponse([], safe=False)


# ═══════════════════════════════════════════════════════════
# ♻️ RESTORE FILE API
# ═══════════════════════════════════════════════════════════
@csrf_exempt
@api_login_required
@require_http_methods(["POST"])
def restore_file(request, file_id):
    """
    API: Restore a deleted file
    POST /api/restore/<file_id>/
    """
    try:
        file_obj = File.objects.get(id=file_id, user=request.user)
        
        if not is_file_deleted(file_obj):
            return JsonResponse({
                'error': 'Not in trash',
                'message': 'File is not in trash'
            }, status=400)
            
    except File.DoesNotExist:
        return JsonResponse({
            'error': 'File not found',
            'message': 'File does not exist or you do not have permission'
        }, status=404)

    try:
        mark_file_restored(file_obj)
        Trash.objects.filter(file=file_obj).delete()
        FileLog.objects.create(user=request.user, file=file_obj, action='RESTORE')

        return JsonResponse({
            'status': 'success',
            'message': f'File "{file_obj.original_name}" restored successfully',
            'file_id': file_obj.id
        })
        
    except Exception as e:
        logger.error(f"Restore failed: {str(e)}")
        return JsonResponse({
            'error': 'Restore failed',
            'message': str(e)
        }, status=500)


# ═══════════════════════════════════════════════════════════
# 📊 DASHBOARD VIEW (Web - HTML)
# ═══════════════════════════════════════════════════════════
@login_required
def dashboard(request):
    """
    Dashboard page - HTML view
    """
    try:
        files = get_active_files_query(request.user).order_by('-uploaded_at')
        
        shared_links = SharedLink.objects.filter(
            owner=request.user
        ).select_related('file')

        return render(request, 'dashboard.html', {
            'files': files,
            'shared_links': shared_links
        })
        
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        return render(request, 'dashboard.html', {
            'files': [],
            'shared_links': [],
            'error': str(e)
        })