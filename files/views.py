# files/views.py
import logging
import sys
import os
import hashlib
import secrets
import json
import traceback
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



# At the top of files/views.py, add:
from rest_framework.authtoken.models import Token
from django.contrib.sessions.models import Session
from django.contrib.auth import get_user_model

User = get_user_model()

def authenticate_request(request):
    """Authenticate request using token or session"""
    if request.user.is_authenticated:
        return request.user
    
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if auth_header.startswith('Token '):
        token_key = auth_header.split(' ')[1]
        try:
            token = Token.objects.get(key=token_key)
            return token.user
        except Token.DoesNotExist:
            pass
    
    session_id = request.META.get('HTTP_X_SESSION_ID', '')
    if session_id:
        try:
            session = Session.objects.get(session_key=session_id)
            session_data = session.get_decoded()
            user_id = session_data.get('_auth_user_id')
            if user_id:
                return User.objects.get(pk=user_id)
        except:
            pass
    
    return None

# ═══════════════════════════════════════════════════════════
# 🔧 LOGGING - Force flush to console
# ═══════════════════════════════════════════════════════════
def log_info(msg):
    print(f"[INFO] {msg}", file=sys.stdout, flush=True)
    sys.stdout.flush()

def log_error(msg):
    print(f"[ERROR] {msg}", file=sys.stdout, flush=True)
    sys.stdout.flush()


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
    if not file:
        return False, "No file provided"
    ext = os.path.splitext(file.name)[1].lower()
    if ext and ext not in ALLOWED_EXTENSIONS:
        return False, f"File type '{ext}' not allowed"
    if file.size > MAX_FILE_SIZE:
        return False, "File too large (max 50MB)"
    return True, ""


def get_file_hash(file):
    hasher = hashlib.sha256()
    file.seek(0)
    for chunk in file.chunks():
        hasher.update(chunk)
    file.seek(0)
    return hasher.hexdigest()


# ═══════════════════════════════════════════════════════════
# 🔐 JSON Response Helpers
# ═══════════════════════════════════════════════════════════
def json_response(data, status=200):
    """Always return proper JSON with correct headers"""
    response = JsonResponse(data, status=status)
    response['Content-Type'] = 'application/json'
    response['X-Content-Type-Options'] = 'nosniff'
    return response


def auth_error_response():
    """Standard auth error response"""
    return json_response({
        'error': 'Authentication required',
        'message': 'Please login to continue',
        'login_required': True
    }, status=401)


# ═══════════════════════════════════════════════════════════
# 📤 UPLOAD FILE
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def upload_file(request):
    """Upload a file - handles POST and OPTIONS"""
    
    # Handle OPTIONS preflight
    if request.method == "OPTIONS":
        response = json_response({'status': 'ok'})
        response["Access-Control-Allow-Origin"] = "*"
        response["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        response["Access-Control-Allow-Headers"] = "Content-Type, X-CSRFToken"
        return response
    
    if request.method != "POST":
        return json_response({'error': 'Method not allowed'}, status=405)
    
    log_info("=" * 60)
    log_info("📤 UPLOAD REQUEST RECEIVED")
    log_info(f"📤 Method: {request.method}")
    log_info(f"📤 User: {request.user}")
    log_info(f"📤 Is Authenticated: {request.user.is_authenticated}")
    log_info(f"📤 Session Key: {request.session.session_key}")
    log_info(f"📤 Content-Type: {request.content_type}")
    log_info(f"📤 FILES keys: {list(request.FILES.keys())}")
    log_info("=" * 60)
    
    try:
        # Check authentication
        if not request.user.is_authenticated:
            log_error("📤 ❌ NOT AUTHENTICATED!")
            return auth_error_response()
        
        log_info(f"📤 ✅ User authenticated: {request.user.email}")
        
        # Check for file
        if 'file' not in request.FILES:
            log_error("📤 ❌ No file in request")
            return json_response({
                'error': 'No file provided',
                'message': 'Please select a file to upload'
            }, status=400)
        
        file = request.FILES['file']
        log_info(f"📤 File: {file.name} ({file.size} bytes)")
        
        # Validate
        valid, error_msg = validate_file(file)
        if not valid:
            log_error(f"📤 ❌ Validation failed: {error_msg}")
            return json_response({'error': error_msg}, status=400)
        
        # Get hash
        file_hash = get_file_hash(file)
        log_info(f"📤 Hash: {file_hash[:16]}...")
        
        # Check duplicate
        if File.objects.filter(user=request.user, sha256=file_hash, deleted=False).exists():
            log_info("📤 ⚠️ Duplicate detected")
            return json_response({
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
        
        log_info(f"📤 ✅ SUCCESS! File ID: {file_obj.id}")
        
        # Log action (ignore errors)
        try:
            FileLog.objects.create(user=request.user, file=file_obj, action='UPLOAD')
        except:
            pass
        
        return json_response({
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
        log_error(f"📤 ❌ EXCEPTION: {str(e)}")
        log_error(traceback.format_exc())
        return json_response({
            'error': 'Upload failed',
            'message': str(e)
        }, status=500)


# ═══════════════════════════════════════════════════════════
# 📂 LIST FILES
# ═══════════════════════════════════════════════════════════

@csrf_exempt
def list_files(request):
    """List user's active files"""
    if request.method == "OPTIONS":
        return json_response({'status': 'ok'})
    
    user = authenticate_request(request)
    
    log_info(f"📂 LIST FILES - User: {user}")
    
    if not user:
        return auth_error_response()
    
    files = File.objects.filter(
        user=user,
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
    
    response = JsonResponse(file_list, safe=False)
    response['Content-Type'] = 'application/json'
    return response


# ═══════════════════════════════════════════════════════════
# 🗑️ DELETE FILE
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def delete_file(request, file_id):
    """Move file to trash"""
    
    if request.method == "OPTIONS":
        return json_response({'status': 'ok'})
    
    log_info(f"🗑️ DELETE - File: {file_id}, Auth: {request.user.is_authenticated}")
    
    try:
        if not request.user.is_authenticated:
            return auth_error_response()
        
        file_obj = File.objects.get(id=file_id, user=request.user)
        
        if file_obj.deleted:
            return json_response({'error': 'Already in trash'}, status=400)
        
        file_obj.deleted = True
        file_obj.deleted_at = timezone.now()
        file_obj.save(update_fields=['deleted', 'deleted_at'])
        
        Trash.objects.update_or_create(
            file=file_obj,
            defaults={'deleted_at': timezone.now()}
        )
        
        log_info(f"🗑️ ✅ Moved to trash: {file_obj.original_name}")
        
        return json_response({
            'status': 'success',
            'message': 'File moved to trash'
        })
        
    except File.DoesNotExist:
        return json_response({'error': 'File not found'}, status=404)
    except Exception as e:
        log_error(f"🗑️ Error: {e}")
        return json_response({'error': str(e)}, status=500)


# ═══════════════════════════════════════════════════════════
# 🗑️ TRASH LIST
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def trash_list(request):
    """List files in trash"""
    
    if request.method == "OPTIONS":
        return json_response({'status': 'ok'})
    
    log_info(f"🗑️ TRASH - Auth: {request.user.is_authenticated}")
    
    try:
        if not request.user.is_authenticated:
            return auth_error_response()
        
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
                'size': f.size,
                'deleted_at': deleted_at.isoformat(),
                'days_remaining': days_remaining
            })
        
        log_info(f"🗑️ Returning {len(data)} items")
        
        response = JsonResponse(data, safe=False)
        response['Content-Type'] = 'application/json'
        return response
        
    except Exception as e:
        log_error(f"🗑️ Error: {e}")
        return JsonResponse([], safe=False)


# ═══════════════════════════════════════════════════════════
# ♻️ RESTORE FILE
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def restore_file(request, file_id):
    """Restore file from trash"""
    
    if request.method == "OPTIONS":
        return json_response({'status': 'ok'})
    
    log_info(f"♻️ RESTORE - File: {file_id}")
    
    try:
        if not request.user.is_authenticated:
            return auth_error_response()
        
        file_obj = File.objects.get(id=file_id, user=request.user)
        
        if not file_obj.deleted:
            return json_response({'error': 'File not in trash'}, status=400)
        
        file_obj.deleted = False
        file_obj.deleted_at = None
        file_obj.save(update_fields=['deleted', 'deleted_at'])
        
        Trash.objects.filter(file=file_obj).delete()
        
        log_info(f"♻️ ✅ Restored: {file_obj.original_name}")
        
        return json_response({
            'status': 'success',
            'success': True,
            'message': 'File restored'
        })
        
    except File.DoesNotExist:
        return json_response({'error': 'File not found'}, status=404)
    except Exception as e:
        log_error(f"♻️ Error: {e}")
        return json_response({'error': str(e)}, status=500)


# ═══════════════════════════════════════════════════════════
# 🔍 DEBUG
# ═══════════════════════════════════════════════════════════
@csrf_exempt
def debug_files(request):
    if not request.user.is_authenticated:
        return json_response({'error': 'Not authenticated'}, status=401)
    
    files = File.objects.filter(user=request.user)
    return json_response({
        'user': request.user.email,
        'total': files.count(),
        'active': files.filter(deleted=False).count(),
        'deleted': files.filter(deleted=True).count()
    })


# ═══════════════════════════════════════════════════════════
# 📊 DASHBOARD
# ═══════════════════════════════════════════════════════════
@login_required
def dashboard(request):
    log_info(f"📊 DASHBOARD - User: {request.user.email}")
    
    # Ensure CSRF token is set
    get_token(request)
    
    files = File.objects.filter(user=request.user, deleted=False).order_by('-uploaded_at')
    shared_links = SharedLink.objects.filter(owner=request.user).select_related('file')
    
    return render(request, 'dashboard.html', {
        'files': files,
        'shared_links': shared_links
    })