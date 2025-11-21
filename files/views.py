# DropVault/files/views.py
import os
import hashlib
import secrets
import base64
import json
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
from .models import File, Trash, FileLog
from .bloomfilter import BloomFilter
from django.views.decorators.csrf import csrf_exempt

# Constants
ALLOWED_EXTENSIONS = {'.pdf', '.jpg', '.jpeg', '.png', '.docx', '.txt', '.mp4'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
CHUNK_SIZE = 4 * 1024 * 1024       # 4 MB

# Global Bloom filter (singleton — fine for dev; consider Redis/caching in prod)
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

        # Compute file-level SHA-256 (hash of concatenated chunk hashes)
        file_hasher = hashlib.sha256()
        for h in chunk_hashes:
            file_hasher.update(h.encode('utf-8'))
        file_sha256 = file_hasher.hexdigest()

        # Deduplication: check if identical file already exists for this user
        if _bloom.contains(file_sha256):
            if File.objects.filter(sha256=file_sha256, user=request.user, deleted=False).exists():
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

        file_obj = File.objects.create(
            user=request.user,
            file=encrypted_file,
            original_name=original_name,
            size=len(encrypted_data),
            sha256=file_sha256,
            encryption_meta=json.dumps(chunk_keys_nonces_tags)
        )

        FileLog.objects.create(user=request.user, file=file_obj, action='UPLOAD')

        return JsonResponse({
            'id': file_obj.id,
            'name': file_obj.original_name,
            'size': file_obj.size,
            'uploaded_at': file_obj.uploaded_at.isoformat()
        })

    except Exception as e:
        # Log error in real app
        return JsonResponse({'error': 'Upload failed. Please try again.'}, status=500)


@login_required
def list_files(request):
    files = File.objects.filter(
        user=request.user,
        deleted=False
    ).values('id', 'original_name', 'size', 'uploaded_at')  # ← keep this
    # Convert to list of dicts with 'filename' key for JS
    file_list = [
        {
            'id': f['id'],
            'filename': f['original_name'],  # ← JS uses 'filename'
            'size': f['size'],
            'uploaded_at': f['uploaded_at'].isoformat()
        }
        for f in files
    ]
    return JsonResponse(file_list, safe=False)

@login_required
@require_http_methods(["POST"])
def delete_file(request, file_id):
    file_obj = get_object_or_404(File, id=file_id, user=request.user, deleted=False)

    try:
        # Soft delete: mark & move to trash
        file_obj.deleted = True
        file_obj.save(update_fields=['deleted'])

        Trash.objects.get_or_create(file=file_obj)  # Avoid duplicate if re-deleted
        FileLog.objects.create(user=request.user, file=file_obj, action='DELETE')

        return JsonResponse({'status': 'deleted', 'id': file_obj.id})

    except Exception:
        return JsonResponse({'error': 'Failed to delete file.'}, status=500)


@login_required
def trash_list(request):
    trashed = File.objects.filter(
        user=request.user,
        deleted=True
    ).values('id', 'original_name', 'size', 'uploaded_at')
    return JsonResponse(list(trashed), safe=False)

@login_required
def dashboard(request):
    shared_links = SharedLink.objects.filter(
        owner=request.user
    ).select_related('file')

    return render(request, 'dashboard.html', {
        'shared_links': shared_links
    })