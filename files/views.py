import os
import hashlib
import secrets
import base64
from django.shortcuts import get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.conf import settings
from django.core.files.base import ContentFile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from .models import File, Trash, FileLog
from .bloomfilter import BloomFilter

# Validation constants
ALLOWED_EXTENSIONS = {'.pdf', '.jpg', '.jpeg', '.png', '.docx', '.txt', '.mp4'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
CHUNK_SIZE = 4 * 1024 * 1024  # 4 MB per chunk (Dropbox-style)

_bloom = BloomFilter(m=1_000_000, k=5)

def validate_file(file):
    ext = os.path.splitext(file.name)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False, "Invalid file type"
    if file.size > MAX_FILE_SIZE:
        return False, "File too large (max 50MB)"
    return True, ""

def _encrypt_chunk(plaintext_chunk):
    """Encrypt a single chunk with AES-256-GCM. Returns (ciphertext, nonce, tag)."""
    nonce = secrets.token_bytes(12)  # GCM nonce = 96 bits
    key = secrets.token_bytes(32)    # AES-256 key

    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(plaintext_chunk) + encryptor.finalize()
    tag = encryptor.tag

    return ciphertext, key, nonce, tag


def create_file_chunks_with_hash(django_file, chunk_size=4 * 1024 * 1024):
    """
    Reads a Django UploadedFile in chunks and returns:
    - list of raw byte chunks
    - list of SHA-256 hexdigests for each chunk
    """
    chunks = []
    hashes = []
    
    django_file.seek(0)
    while True:
        chunk = django_file.read(chunk_size)
        if not chunk:
            break
        chunks.append(chunk)
        chunk_hash = hashlib.sha256(chunk).hexdigest()
        hashes.append(chunk_hash)
    
    return chunks, hashes

@login_required
@require_http_methods(["POST"])
def upload_file(request):
    file = request.FILES.get('file')
    if not file:
        return JsonResponse({'error': 'No file provided'}, status=400)
    
    valid, msg = validate_file(file)
    if not valid:
        return JsonResponse({'error': msg}, status=400)

    # ➤ Use the clean helper function
    chunks, chunk_hashes = create_file_chunks_with_hash(file, chunk_size=CHUNK_SIZE)

    # Compute file-level hash (hash of all chunk hashes)
    file_hasher = hashlib.sha256()
    for h in chunk_hashes:
        file_hasher.update(h.encode())
    file_sha256 = file_hasher.hexdigest()

    # Bloom filter check (same as before)
    if _bloom.contains(file_sha256):
        if File.objects.filter(sha256=file_sha256, user=request.user).exists():
            return JsonResponse({'error': 'File already uploaded.'}, status=400)
    _bloom.add(file_sha256)

    # Encrypt each chunk
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

    # Save file (same as before)
    encrypted_file = ContentFile(encrypted_data)
    encrypted_file.name = file.name

    import json
    encryption_meta = json.dumps(chunk_keys_nonces_tags)

    file_obj = File.objects.create(
        user=request.user,
        file=encrypted_file,
        original_name=file.name,
        size=len(encrypted_data),
        sha256=file_sha256,
        encryption_meta=encryption_meta
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