# DropVault/files/views.py
from asyncio.log import logger
import logging
import os
import hashlib
import secrets
import base64
import json
from django.utils import timezone
from datetime import datetime, timedelta
from django.shortcuts import render
from .models import SharedLink
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
from django.utils import timezone
from django.contrib.auth import authenticate
from django.db.models import Q
from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError
from django.conf import settings

logger = logging.getLogger(__name__)

# Constants
ALLOWED_EXTENSIONS = {'.pdf', '.jpg', '.jpeg', '.png', '.docx', '.txt', '.mp4'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
CHUNK_SIZE = 4 * 1024 * 1024       # 4 MB

# Global Bloom filter
_bloom = BloomFilter(m=1_000_000, k=5)


def validate_file(file):
    if not file:
        return False, "No file provided"
    ext = os.path.splitext(file.name)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False, "Invalid file type"
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
    nonce = secrets.token_bytes(12)   # 96-bit GCM nonce
    key = secrets.token_bytes(32)     # 256-bit key

    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(plaintext_chunk) + encryptor.finalize()
    tag = encryptor.tag
    return ciphertext, key, nonce, tag


@csrf_exempt
@login_required
@require_http_methods(["POST"])
def upload_file(request):
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

        # Deduplication: check if identical file already exists for this user
        if _bloom.contains(file_sha256):
            # Check for non-deleted files
            existing = File.objects.filter(
                sha256=file_sha256, 
                user=request.user
            )
            # Handle both deleted (boolean) and deleted_at (timestamp)
            if hasattr(File, 'deleted'):
                existing = existing.filter(deleted=False)
            else:
                existing = existing.filter(deleted_at__isnull=True)
            
            if existing.exists():
                return JsonResponse({'error': 'You already uploaded this file.'}, status=409)

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

        # Preserve extension and avoid unsafe names
        safe_name = f"{secrets.token_urlsafe(12)}.{original_name.split('.')[-1].lower()}"
        encrypted_file.name = safe_name

        # Create file object with both fields if they exist
        file_data = {
            'user': request.user,
            'file': encrypted_file,
            'original_name': original_name,
            'size': len(encrypted_data),
            'sha256': file_sha256,
            'encryption_meta': json.dumps(chunk_keys_nonces_tags)
        }
        
        # Add deleted field if it exists in model
        if hasattr(File, 'deleted'):
            file_data['deleted'] = False
            
        file_obj = File.objects.create(**file_data)

        FileLog.objects.create(user=request.user, file=file_obj, action='UPLOAD')

        return JsonResponse({
            'id': file_obj.id,
            'name': file_obj.original_name,
            'size': file_obj.size,
            'uploaded_at': file_obj.uploaded_at.isoformat()
        })

    except Exception as e:
        logger.error(f"Upload failed: {str(e)}")
        return JsonResponse({'error': f'Upload failed: {str(e)}'}, status=500)


@login_required
def list_files(request):
    # Show only non-deleted files
    files_query = File.objects.filter(user=request.user)
    
    # Handle both deleted (boolean) and deleted_at (timestamp)
    if hasattr(File, 'deleted'):
        files_query = files_query.filter(deleted=False)
    else:
        files_query = files_query.filter(deleted_at__isnull=True)
    
    files = files_query.values('id', 'original_name', 'size', 'uploaded_at')
    
    file_list = [
        {
            'id': f['id'],
            'filename': f['original_name'],
            'size': f['size'],
            'uploaded_at': f['uploaded_at'].isoformat()
        }
        for f in files
    ]
    return JsonResponse(file_list, safe=False)


@login_required
@require_http_methods(["POST"])
def delete_file(request, file_id):
    # Get file that's not deleted
    try:
        file_obj = File.objects.get(id=file_id, user=request.user)
        
        # Check if already deleted
        if hasattr(file_obj, 'deleted') and file_obj.deleted:
            return JsonResponse({'error': 'File already deleted'}, status=400)
        elif hasattr(file_obj, 'deleted_at') and file_obj.deleted_at:
            return JsonResponse({'error': 'File already deleted'}, status=400)
    except File.DoesNotExist:
        return JsonResponse({'error': 'File not found'}, status=404)

    try:
        # Soft delete: set both fields if they exist
        if hasattr(file_obj, 'deleted'):
            file_obj.deleted = True
        if hasattr(file_obj, 'deleted_at'):
            file_obj.deleted_at = timezone.now()
        
        file_obj.save()

        # Create or update trash entry
        trash, created = Trash.objects.update_or_create(
            file=file_obj,
            defaults={'deleted_at': timezone.now()}
        )
        
        FileLog.objects.create(user=request.user, file=file_obj, action='DELETE')

        return JsonResponse({'status': 'deleted', 'id': file_obj.id})

    except Exception as e:
        logger.error(f"Delete failed: {str(e)}")
        return JsonResponse({'error': 'Failed to delete file.'}, status=500)


@login_required
def trash_list(request):
    if request.method != 'GET':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    # Show only deleted files
    trashed_query = File.objects.filter(user=request.user)
    
    # Handle both deleted (boolean) and deleted_at (timestamp)
    if hasattr(File, 'deleted'):
        trashed_query = trashed_query.filter(deleted=True)
    else:
        trashed_query = trashed_query.filter(deleted_at__isnull=False)
    
    trashed_files = trashed_query.select_related('trash')

    data = []
    for f in trashed_files:
        # Get deletion date
        deletion_date = None
        if hasattr(f, 'deleted_at') and f.deleted_at:
            deletion_date = f.deleted_at
        elif hasattr(f, 'trash') and f.trash.deleted_at:
            deletion_date = f.trash.deleted_at
        
        # Calculate days remaining (30 days from deletion)
        days_remaining = 30
        permanent_delete_date = None
        
        if deletion_date:
            permanent_delete_date = deletion_date + timedelta(days=30)
            days_remaining = max(0, (permanent_delete_date - timezone.now()).days)

        data.append({
            'id': f.id,
            'original_name': f.original_name,
            'size': f.size,
            'deleted_at': deletion_date.isoformat() if deletion_date else None,
            'days_remaining': days_remaining,
            'permanent_delete_date': permanent_delete_date.isoformat() if permanent_delete_date else None
        })

    return JsonResponse({'files': data})


@login_required
@csrf_exempt
@require_http_methods(["POST"])
def restore_file(request, file_id):
    try:
        file = File.objects.get(id=file_id, user=request.user)
        
        # Check if file is actually deleted
        is_deleted = False
        if hasattr(file, 'deleted') and file.deleted:
            is_deleted = True
        elif hasattr(file, 'deleted_at') and file.deleted_at:
            is_deleted = True
            
        if not is_deleted:
            return JsonResponse({'error': 'File is not in trash'}, status=400)
            
    except File.DoesNotExist:
        return JsonResponse({'error': 'File not found'}, status=404)

    # Perform restore
    if hasattr(file, 'deleted'):
        file.deleted = False
    if hasattr(file, 'deleted_at'):
        file.deleted_at = None
    
    file.save()
    
    # Remove from trash table
    Trash.objects.filter(file=file).delete()

    # Log the restoration
    FileLog.objects.create(user=request.user, file=file, action='RESTORE')

    return JsonResponse({
        'success': True,
        'message': 'File restored successfully',
        'file_id': file.id
    })


@login_required
def dashboard(request):
    shared_links = SharedLink.objects.filter(
        owner=request.user
    ).select_related('file')

    return render(request, 'dashboard.html', {
        'shared_links': shared_links
    })