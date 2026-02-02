# files/views.py
import logging
import sys
import os
import re
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
from django.db.models import Sum
from .models import File

from .models import File, Trash, FileLog, SharedLink
import requests as http_requests
import requests
from django.http import HttpResponse
import uuid

from rest_framework.authtoken.models import Token
from django.contrib.sessions.models import Session
from django.contrib.auth import get_user_model

User = get_user_model()

logger = logging.getLogger(__name__)

def log_info(msg):
    """Log info message"""
    logger.info(msg)
    print(f"[INFO] {msg}", file=sys.stdout, flush=True)
    sys.stdout.flush()

def log_error(msg):
    """Log error message"""
    logger.error(msg)
    print(f"[ERROR] {msg}", file=sys.stderr, flush=True)
    sys.stderr.flush()


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


ALLOWED_EXTENSIONS = {
    # Images
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.ico',
    '.svg', '.eps', '.ai', '.heic', '.heif', '.tiff', '.tif',
    # Documents
    '.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt',
    '.pages', '.tex', '.wpd', '.wps',
    # Spreadsheets
    '.xls', '.xlsx', '.csv', '.ods', '.xlsm', '.xlsb',
    # Presentations
    '.ppt', '.pptx', '.odp', '.key',
    # Videos
    '.mp4', '.mov', '.avi', '.webm', '.mkv', '.flv', '.wmv', 
    '.m4v', '.3gp', '.mpg', '.mpeg', '.m2v', '.ogv',
    # Audio
    '.mp3', '.wav', '.flac', '.aac', '.ogg', '.m4a', '.wma',
    '.opus', '.oga', '.mid', '.midi',
    # Archives
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',
    '.tgz', '.tbz2', '.cab', '.dmg', '.iso',
    # Code
    '.html', '.css', '.js', '.json', '.xml', '.sql',
    '.py', '.java', '.cpp', '.c', '.h', '.cs', '.php',
    '.rb', '.go', '.rs', '.swift', '.kt', '.ts', '.jsx', '.tsx',
    # Development
    '.vsix', '.deb', '.rpm', '.apk', '.exe', '.msi', '.app',
    '.sh', '.bat', '.cmd', '.ps1',
    # Data
    '.db', '.sqlite', '.mdb', '.accdb',
    # Design
    '.psd', '.ai', '.sketch', '.fig', '.xd',
    # Other
    '.epub', '.mobi', '.azw', '.azw3', '.djvu',
    '.md', '.markdown', '.log', '.yml', '.yaml', '.toml', '.ini', '.cfg',
}

MAX_FILE_SIZE = 500 * 1024 * 1024  # 500 MB


def sanitize_filename(filename):
    """Remove special characters and spaces from filename"""
    name, ext = os.path.splitext(filename)
    # Replace spaces and special chars
    name = re.sub(r'[^\w\-]', '_', name)
    # Remove consecutive underscores
    name = re.sub(r'_+', '_', name)
    # Limit length
    name = name[:100]
    return f"{name}{ext}"


def validate_file(file):
    """Validate file type and size"""
    if not file:
        return False, "No file provided"
    
    ext = os.path.splitext(file.name)[1].lower()
    
    if ext and ext not in ALLOWED_EXTENSIONS:
        return False, f"File type '{ext}' not allowed"
    
    if file.size > MAX_FILE_SIZE:
        return False, f"File too large (max 100MB)"
    
    return True, ""


def get_file_hash(file):
    hasher = hashlib.sha256()
    file.seek(0)
    for chunk in file.chunks():
        hasher.update(chunk)
    file.seek(0)
    return hasher.hexdigest()


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


@csrf_exempt
def upload_file(request):
    """Upload a file to Cloudinary - FIXED with higher limits"""
    
    if request.method == "OPTIONS":
        response = json_response({'status': 'ok'})
        response["Access-Control-Allow-Origin"] = "*"
        response["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        response["Access-Control-Allow-Headers"] = "Content-Type, X-CSRFToken, Authorization"
        return response
    
    if request.method != "POST":
        return json_response({'error': 'Method not allowed'}, status=405)
    
    log_info("=" * 60)
    log_info("📤 UPLOAD REQUEST")
    log_info("=" * 60)
    
    try:
        user = authenticate_request(request)
        if not user:
            log_error("📤 Authentication failed")
            return auth_error_response()
        
        log_info(f"📤 User: {user.email} (ID: {user.id})")
        
        if 'file' not in request.FILES:
            log_error("📤 No file in request.FILES")
            return json_response({'error': 'No file provided'}, status=400)
        
        file = request.FILES['file']
        log_info(f"📤 File: {file.name} ({file.size} bytes, {file.content_type})")
        
        # ✅ FIX: Get file extension properly
        file_ext = os.path.splitext(file.name)[1].lower()
        ext = file_ext.lstrip('.') if file_ext else ''
        
        log_info(f"📤 Extension: .{ext}")
        
        # ✅ FIX: Increase size limits based on file type
        video_exts = ['mp4', 'mov', 'avi', 'webm', 'mkv', 'flv', 'wmv', 'm4v', '3gp']
        image_exts = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'ico', 'svg', 'heic', 'heif']
        
        # ✅ Size limits (Cloudinary free tier supports up to 100MB for videos)
        # For Render free tier with 512MB RAM, we need to be conservative
        if ext in video_exts:
            # ✅ Allow up to 500MB for videos (will stream upload)
            max_size = 500 * 1024 * 1024  # 500MB
            size_label = "500MB"
        elif ext in image_exts:
            max_size = 100 * 1024 * 1024  # 100MB for images
            size_label = "100MB"
        else:
            # Other files (documents, archives, etc.)
            max_size = 200 * 1024 * 1024  # 200MB
            size_label = "200MB"
        
        # Check size
        if file.size > max_size:
            file_size_mb = file.size / (1024*1024)
            log_error(f"📤 File too large: {file_size_mb:.1f}MB > {size_label}")
            return json_response({
                'error': 'File too large',
                'message': f'This file type must be under {size_label}. Your file is {file_size_mb:.1f}MB',
                'max_size': size_label,
                'your_size': f'{file_size_mb:.1f}MB'
            }, status=400)
        
        # ✅ FIX: More lenient file type validation
        # Check if extension is in allowed list
        if file_ext and file_ext not in ALLOWED_EXTENSIONS:
            # ✅ Allow it anyway but log warning (for flexibility)
            log_info(f"📤 ⚠️ Extension {file_ext} not in whitelist, but allowing upload")
            # You can uncomment this to strictly enforce:
            # return json_response({
            #     'error': f'File type {file_ext} not allowed',
            #     'allowed_types': 'Images, Videos, Documents, Archives'
            # }, status=400)
        
        # Get hash
        try:
            file_hash = get_file_hash(file)
            log_info(f"📤 File hash: {file_hash[:16]}...")
        except Exception as hash_err:
            log_error(f"📤 Hash error: {hash_err}")
            return json_response({'error': 'Failed to process file'}, status=500)
        
        # Check duplicate
        duplicate = File.objects.filter(user=user, sha256=file_hash, deleted=False).first()
        if duplicate:
            log_info(f"📤 Duplicate file detected: {duplicate.id}")
            return json_response({
                'error': 'Duplicate file',
                'message': 'You already uploaded this file',
            }, status=409)
        
        # Get Cloudinary config
        cloud_name = os.environ.get('CLOUDINARY_CLOUD_NAME')
        api_key = os.environ.get('CLOUDINARY_API_KEY')
        api_secret = os.environ.get('CLOUDINARY_API_SECRET')
        
        if not (cloud_name and api_key and api_secret):
            log_error("📤 Cloudinary not configured")
            return json_response({'error': 'Storage not configured'}, status=500)
        
        log_info(f"📤 Cloudinary: ✅ Configured")
        
        # ✅ Upload to Cloudinary with chunking for large files
        try:
            import cloudinary
            import cloudinary.uploader
            
            cloudinary.config(
                cloud_name=cloud_name,
                api_key=api_key,
                api_secret=api_secret,
                secure=True
            )
            
            # Generate unique filename
            unique_name = f"{uuid.uuid4().hex}"
            
            # ✅ FIX: Better resource type detection
            if ext in image_exts:
                resource_type = 'image'
            elif ext in video_exts:
                resource_type = 'video'
            else:
                # Everything else goes to 'raw'
                resource_type = 'raw'
            
            log_info(f"📤 Resource type: {resource_type}")
            
            # ✅ Upload options with chunking for large files
            upload_options = {
                'folder': f"user_{user.id}",
                'public_id': unique_name,
                'resource_type': resource_type,
                'type': 'upload',
                'access_mode': 'public',
                'timeout': 600,  # 10 minutes
            }
            
            # ✅ Enable chunking for files > 20MB
            if file.size > 20 * 1024 * 1024:
                upload_options['chunk_size'] = 6000000  # 6MB chunks
                log_info(f"📤 Large file detected, using chunked upload (6MB chunks)")
            
            # Add format for raw files
            if resource_type == 'raw' and ext:
                upload_options['format'] = ext
            
            log_info(f"📤 Uploading to Cloudinary...")
            log_info(f"📤 File size: {file.size / (1024*1024):.1f}MB")
            
            # Reset file pointer
            file.seek(0)
            
            # ✅ Upload with progress logging
            upload_result = cloudinary.uploader.upload(file, **upload_options)
            
            cloudinary_public_id = upload_result.get('public_id')
            cloudinary_url = upload_result.get('secure_url')
            actual_resource_type = upload_result.get('resource_type', resource_type)
            
            log_info(f"📤 ✅ Cloudinary upload successful")
            log_info(f"📤    Public ID: {cloudinary_public_id}")
            log_info(f"📤    URL: {cloudinary_url}")
            
        except Exception as cloud_err:
            log_error(f"📤 ❌ Cloudinary error: {cloud_err}")
            log_error(traceback.format_exc())
            
            # Better error message
            error_msg = str(cloud_err)
            if 'timeout' in error_msg.lower():
                error_msg = 'Upload timeout - file may be too large or connection too slow'
            elif 'unauthorized' in error_msg.lower():
                error_msg = 'Storage authentication failed - please try again'
            
            return json_response({
                'error': 'Upload to cloud storage failed',
                'message': error_msg,
                'details': str(cloud_err)
            }, status=500)
        
        # Save to database
        try:
            log_info(f"📤 Saving to database...")
            
            # Check if field exists
            from django.db import connection
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name='files_file' AND column_name='cloudinary_resource_type';
                """)
                has_field = cursor.fetchone() is not None
            
            if has_field:
                file_obj = File.objects.create(
                    user=user,
                    original_name=file.name,
                    size=file.size,
                    sha256=file_hash,
                    deleted=False,
                    cloudinary_url=cloudinary_url,
                    cloudinary_public_id=cloudinary_public_id,
                    cloudinary_resource_type=actual_resource_type
                )
            else:
                file_obj = File.objects.create(
                    user=user,
                    original_name=file.name,
                    size=file.size,
                    sha256=file_hash,
                    deleted=False,
                    cloudinary_url=cloudinary_url,
                    cloudinary_public_id=cloudinary_public_id,
                    cloudinary_resource_type=actual_resource_type
                )
            
            log_info(f"📤 ✅ Database save successful! File ID: {file_obj.id}")
            log_info(f"📤    Resource Type: {actual_resource_type}")


        except Exception as db_err:
            log_error(f"📤 ❌ Database error: {db_err}")
            log_error(traceback.format_exc())
            
            # Clean up Cloudinary
            try:
                cloudinary.uploader.destroy(cloudinary_public_id, resource_type=actual_resource_type)
                log_info(f"📤 Cleaned up Cloudinary file")
            except:
                pass
            
            return json_response({
                'error': 'Failed to save file',
                'message': str(db_err)
            }, status=500)
        
        # Create log and notification
        try:
            FileLog.objects.create(user=user, file=file_obj, action='UPLOAD')
        except Exception as file_log_err:
            log_error(f"📤 File log error (ignored): {file_log_err}")
        
        try:
            create_user_notification(
                user=user,
                notification_type='FILE_UPLOAD',
                title='File Uploaded',
                message=f'"{file_obj.original_name}" uploaded successfully',
                file_name=file_obj.original_name,
                file_id=file_obj.id
            )
        except Exception as notif_err:
            log_error(f"📤 Notification error (ignored): {notif_err}")
        
        log_info(f"📤 ✅ UPLOAD COMPLETE - File ID: {file_obj.id}")
        log_info("=" * 60)
        
        return json_response({
            'status': 'success',
            'message': 'File uploaded successfully',
            'file': {
                'id': file_obj.id,
                'filename': file_obj.original_name,
                'size': file_obj.size,
                'uploaded_at': file_obj.uploaded_at.isoformat(),
                'cloudinary_url': cloudinary_url,
                'storage': 'cloudinary'
            }
        }, status=201)
        
    except Exception as main_err:
        log_error(f"📤 ❌ UPLOAD ERROR: {main_err}")
        log_error(traceback.format_exc())
        return json_response({
            'error': 'Upload failed',
            'message': str(main_err)
        }, status=500)

def format_file_size(size_bytes):
    """Convert bytes to human-readable format"""
    if size_bytes == 0:
        return "0 B"
    
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    unit_index = 0
    size = float(size_bytes)
    
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1
    
    return f"{size:.2f} {units[unit_index]}"


def get_resource_type_from_filename(filename):
    """Determine Cloudinary resource type from filename"""
    ext = filename.split('.')[-1].lower() if '.' in filename else ''
    
    image_exts = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg', 'ico']
    video_exts = ['mp4', 'mov', 'avi', 'webm', 'mkv', 'flv', 'wmv']
    
    if ext in image_exts:
        return 'image'
    elif ext in video_exts:
        return 'video'
    else:
        return 'raw'


@csrf_exempt
def download_file(request, file_id):
    """Download user's own file"""
    
    if request.method == "OPTIONS":
        return json_response({'status': 'ok'})
    
    log_info(f"📥 DOWNLOAD - File ID: {file_id}")
    
    try:
        user = authenticate_request(request)
        if not user:
            return auth_error_response()
        
        try:
            file_obj = File.objects.get(id=file_id, user=user, deleted=False)
        except File.DoesNotExist:
            return JsonResponse({'error': 'File not found'}, status=404)
        
        log_info(f"📥 File: {file_obj.original_name}")
        log_info(f"📥 Stored URL: {file_obj.cloudinary_url}")
        log_info(f"📥 Public ID: {file_obj.cloudinary_public_id}")
        
        # ✅ Get the stored Cloudinary URL directly
        download_url = file_obj.cloudinary_url
        
        if not download_url:
            log_error("📥 No cloudinary_url stored")
            return JsonResponse({'error': 'File not available'}, status=404)
        
        # ✅ For PDFs/raw files, try to generate signed URL
        ext = file_obj.original_name.split('.')[-1].lower() if '.' in file_obj.original_name else ''
        is_raw_file = ext in ['pdf', 'doc', 'docx', 'txt', 'xls', 'xlsx', 'ppt', 'pptx', 'zip', 'rar']
        
        if is_raw_file and file_obj.cloudinary_public_id:
            log_info(f"📥 Raw file detected, generating signed URL...")
            
            try:
                import cloudinary
                import cloudinary.utils
                
                cloud_name = os.environ.get('CLOUDINARY_CLOUD_NAME')
                api_key = os.environ.get('CLOUDINARY_API_KEY')
                api_secret = os.environ.get('CLOUDINARY_API_SECRET')
                
                cloudinary.config(
                    cloud_name=cloud_name,
                    api_key=api_key,
                    api_secret=api_secret,
                    secure=True
                )
                
                # ✅ Try different resource types
                for res_type in ['raw', 'image', 'auto']:
                    try:
                        signed_url, _ = cloudinary.utils.cloudinary_url(
                            file_obj.cloudinary_public_id,
                            resource_type=res_type,
                            type='upload',
                            secure=True,
                            sign_url=True,
                            attachment=True  # Forces download
                        )
                        
                        log_info(f"📥 Trying signed URL ({res_type}): {signed_url}")
                        
                        # Test if URL works
                        import requests as http_requests
                        test_response = http_requests.head(signed_url, timeout=5)
                        
                        if test_response.status_code == 200:
                            download_url = signed_url
                            log_info(f"📥 ✅ Signed URL works with resource_type={res_type}")
                            break
                        else:
                            log_info(f"📥 Signed URL returned {test_response.status_code}")
                            
                    except Exception as e:
                        log_info(f"📥 Signed URL failed for {res_type}: {e}")
                        continue
                        
            except Exception as e:
                log_error(f"📥 Could not generate signed URL: {e}")
                # Fall back to stored URL
                download_url = file_obj.cloudinary_url
        
        log_info(f"📥 Final URL: {download_url}")
        
        # Fetch and stream
        if download_url and download_url.startswith('http'):
            try:
                import requests as http_requests
                
                # Add headers that might help with Cloudinary access
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
                
                response = http_requests.get(download_url, stream=True, timeout=60, headers=headers)
                
                log_info(f"📥 Response Status: {response.status_code}")
                
                if response.status_code == 401:
                    log_error(f"📥 401 Unauthorized - URL may have expired or access denied")
                    
                    # ✅ Last resort: try the original stored URL
                    if download_url != file_obj.cloudinary_url:
                        log_info(f"📥 Trying original stored URL...")
                        response = http_requests.get(file_obj.cloudinary_url, stream=True, timeout=60, headers=headers)
                        log_info(f"📥 Original URL Response: {response.status_code}")
                
                if response.status_code != 200:
                    log_error(f"📥 Failed with status: {response.status_code}")
                    return JsonResponse({
                        'error': 'File temporarily unavailable',
                        'details': f'HTTP {response.status_code}',
                        'suggestion': 'Please re-upload this file'
                    }, status=503)
                
                content_type = response.headers.get('Content-Type', 'application/octet-stream')
                
                from django.http import HttpResponse
                django_response = HttpResponse(
                    response.iter_content(chunk_size=8192),
                    content_type=content_type
                )
                django_response['Content-Disposition'] = f'attachment; filename="{file_obj.original_name}"'
                
                if 'Content-Length' in response.headers:
                    django_response['Content-Length'] = response.headers['Content-Length']
                
                log_info(f"📥 ✅ Download started: {file_obj.original_name}")
                
                try:
                    FileLog.objects.create(user=user, file=file_obj, action='DOWNLOAD')
                except:
                    pass
                
                return django_response
                
            except Exception as e:
                log_error(f"📥 Download error: {e}")
                log_error(traceback.format_exc())
                return JsonResponse({'error': str(e)}, status=500)
        else:
            return JsonResponse({
                'error': 'File URL not available',
                'solution': 'Please re-upload this file'
            }, status=404)
                    
    except Exception as e:
        log_error(f"📥 Error: {e}")
        log_error(traceback.format_exc())
        return JsonResponse({'error': str(e)}, status=500)    

@csrf_exempt
def list_files(request):
    """List user's active files with shared links"""
    if request.method == "OPTIONS":
        return json_response({'status': 'ok'})
    
    user = authenticate_request(request)
    
    log_info(f"📂 LIST FILES - User: {user}")
    
    if not user:
        return auth_error_response()
    
    # Get user's files
    files = File.objects.filter(
        user=user,
        deleted=False
    ).order_by('-uploaded_at')
    
    # Get shared links
    shared_links = SharedLink.objects.filter(
        owner=user,
        is_active=True
    ).select_related('file')
    
    # Format file list
    file_list = []
    for f in files:
        file_list.append({
            'id': f.id,
            'filename': f.original_name,
            'original_name': f.original_name,
            'size': format_file_size(f.size),  # ✅ Formatted string
            'size_bytes': f.size,  # ✅ Also include raw bytes
            'uploaded_at': f.uploaded_at.isoformat()
        })
    
    # Format shared links
    shared_list = []
    for link in shared_links:
        if not link.is_expired():
            shared_list.append({
                'id': link.id,
                'file_id': link.file.id,
                'filename': link.file.original_name,
                'slug': link.slug,
                'share_url': f"{request.build_absolute_uri('/').rstrip('/')}/s/{link.slug}/",
                'download_count': link.download_count,
                'max_downloads': link.max_downloads,
                'view_count': link.view_count,
                'created_at': link.created_at.isoformat(),
                'expires_at': link.expires_at.isoformat() if link.expires_at else None,
            })
    
    log_info(f"📂 Returning {len(file_list)} files, {len(shared_list)} shared links")
    
    #Return correct structure
    response = JsonResponse({
        'your_files': file_list,
        'shared_files': shared_list
    })
    response['Content-Type'] = 'application/json'
    return response


@csrf_exempt
def get_shared_files(request):
    """Get all active shared links for the user"""
    if request.method == "OPTIONS":
        return json_response({'status': 'ok'})
    
    user = authenticate_request(request)
    
    log_info(f"🔗 GET SHARED - User: {user}")
    
    if not user:
        return auth_error_response()
    
    shared_links = SharedLink.objects.filter(
        owner=user,
        is_active=True
    ).select_related('file').order_by('-created_at')
    
    shared_list = []
    for link in shared_links:
        if not link.is_expired():
            site_url = request.build_absolute_uri('/').rstrip('/')
            shared_list.append({
                'id': link.id,
                'file_id': link.file.id,
                'filename': link.file.original_name,
                'file_size': format_file_size(link.file.size),
                'slug': link.slug,
                'share_url': f"{site_url}/s/{link.slug}/",
                'download_count': link.download_count,
                'max_downloads': link.max_downloads,
                'view_count': link.view_count,
                'created_at': link.created_at.isoformat(),
                'expires_at': link.expires_at.isoformat() if link.expires_at else None,
                'downloads_remaining': link.max_downloads - link.download_count,
            })
    
    log_info(f"🔗 Returning {len(shared_list)} shared links")
    
    response = JsonResponse(shared_list, safe=False)
    response['Content-Type'] = 'application/json'
    return response


def get_resource_type_from_filename(filename):
    """Determine Cloudinary resource type from filename"""
    ext = filename.split('.')[-1].lower() if '.' in filename else ''
    
    image_exts = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg', 'ico']
    video_exts = ['mp4', 'mov', 'avi', 'webm', 'mkv', 'flv', 'wmv']
    
    if ext in image_exts:
        return 'image'
    elif ext in video_exts:
        return 'video'
    else:
        return 'raw'


@csrf_exempt
def download_shared_file(request, slug):
    """Download a shared file"""
    log_info(f"📥 DOWNLOAD SHARED - Slug: {slug}")
    
    try:
        link = SharedLink.objects.select_related('file').get(slug=slug, is_active=True)
        
        if link.is_expired():
            link.is_active = False
            link.save()
            return JsonResponse({'error': 'This link has expired'}, status=410)
        
        file_obj = link.file
        
        if file_obj.deleted:
            return JsonResponse({'error': 'File is no longer available'}, status=404)
        
        if link.download_count >= link.max_downloads:
            return JsonResponse({'error': 'Download limit reached'}, status=403)
        
        log_info(f"📥 File: {file_obj.original_name}")
        log_info(f"📥 Public ID: {file_obj.cloudinary_public_id}")
        
        # Determine resource type
        resource_type = get_resource_type_from_filename(file_obj.original_name)
        log_info(f"📥 Resource Type: {resource_type}")
        
        # Get download URL
        download_url = None
        
        # For RAW files, generate signed URL
        if resource_type == 'raw' and file_obj.cloudinary_public_id:
            try:
                import cloudinary
                import cloudinary.utils
                
                cloud_name = os.environ.get('CLOUDINARY_CLOUD_NAME')
                api_key = os.environ.get('CLOUDINARY_API_KEY')
                api_secret = os.environ.get('CLOUDINARY_API_SECRET')
                
                cloudinary.config(
                    cloud_name=cloud_name,
                    api_key=api_key,
                    api_secret=api_secret,
                    secure=True
                )
                
                download_url, _ = cloudinary.utils.cloudinary_url(
                    file_obj.cloudinary_public_id,
                    resource_type='raw',
                    type='upload',
                    secure=True,
                    sign_url=True
                )
                log_info(f"📥 Signed URL: {download_url}")
                
            except Exception as e:
                log_error(f"📥 Signed URL error: {e}")
                download_url = file_obj.cloudinary_url
        else:
            download_url = file_obj.cloudinary_url
        
        if not download_url:
            return JsonResponse({'error': 'File not available'}, status=404)
        
        log_info(f"📥 Download URL: {download_url}")
        
        # Fetch and stream
        if download_url.startswith('http'):
            try:
                response = requests.get(download_url, stream=True, timeout=60)
                
                log_info(f"📥 Response: {response.status_code}")
                
                if response.status_code != 200:
                    return JsonResponse({
                        'error': 'File temporarily unavailable',
                        'details': f'HTTP {response.status_code}'
                    }, status=503)
                
                # Increment download count
                link.download_count += 1
                link.save(update_fields=['download_count'])
                
                content_type = response.headers.get('Content-Type', 'application/octet-stream')
                
                django_response = HttpResponse(
                    response.iter_content(chunk_size=8192),
                    content_type=content_type
                )
                django_response['Content-Disposition'] = f'attachment; filename="{file_obj.original_name}"'
                
                log_info(f"📥 ✅ Download started: {file_obj.original_name}")
                return django_response
                
            except Exception as e:
                log_error(f"📥 Error: {e}")
                return JsonResponse({'error': str(e)}, status=500)
        else:
            return JsonResponse({
                'error': 'File no longer available'
            }, status=404)
        
    except SharedLink.DoesNotExist:
        return JsonResponse({'error': 'Invalid or expired share link'}, status=404)
    except Exception as e:
        log_error(f"📥 Error: {e}")
        return JsonResponse({'error': str(e)}, status=500)

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
        
        file_name = file_obj.original_name  # Save before update
        
        file_obj.deleted = True
        file_obj.deleted_at = timezone.now()
        file_obj.save(update_fields=['deleted', 'deleted_at'])
        
        Trash.objects.update_or_create(
            file=file_obj,
            defaults={'deleted_at': timezone.now()}
        )
        
        log_info(f"🗑️ ✅ Moved to trash: {file_obj.original_name}")
        
        # ✅ CREATE NOTIFICATION
        create_user_notification(
            user=request.user,
            notification_type='FILE_DELETED',
            title='File Moved to Trash',
            message=f'"{file_name}" has been moved to trash.',
            file_name=file_name,
            file_id=file_obj.id
        )
        
        return json_response({
            'status': 'success',
            'message': 'File moved to trash'
        })
        
    except File.DoesNotExist:
        return json_response({'error': 'File not found'}, status=404)
    except Exception as e:
        log_error(f"🗑️ Error: {e}")
        return json_response({'error': str(e)}, status=500)


@csrf_exempt
def trash_list(request):
    """List files in trash"""
    
    if request.method == "OPTIONS":
        return json_response({'status': 'ok'})
    
    user = authenticate_request(request)
    
    log_info(f"🗑️ TRASH LIST - User: {user}, Auth: {user is not None}")
    
    if not user:
        return auth_error_response()
    
    try:
        files = File.objects.filter(
            user=user,
            deleted=True
        ).order_by('-deleted_at')
        
        file_list = []
        total_size = 0
        
        for f in files:
            deleted_at = f.deleted_at or timezone.now()
            days_remaining = max(0, 30 - (timezone.now() - deleted_at).days)
            
            file_list.append({
                'id': f.id,
                'filename': f.original_name,
                'size': format_file_size(f.size),  # ✅ Formatted string
                'size_bytes': f.size,  # ✅ Also raw bytes for calculations
                'deleted_at': deleted_at.isoformat(),
                'days_remaining': days_remaining
            })
            
            total_size += f.size
        
        log_info(f"🗑️ Returning {len(file_list)} trashed files")
        
        # ✅ FIXED: Return object with 'files' property
        response = JsonResponse({
            'files': file_list,
            'total_count': len(file_list),
            'total_size': total_size,
            'total_size_formatted': format_file_size(total_size)
        })
        response['Content-Type'] = 'application/json'
        return response
        
    except Exception as e:
        log_error(f"🗑️ Error: {e}")
        log_error(traceback.format_exc())
        return JsonResponse({
            'files': [],
            'total_count': 0,
            'total_size': 0
        })


@csrf_exempt
def permanent_delete(request, file_id):
    """Permanently delete a file from trash"""
    
    if request.method == "OPTIONS":
        return json_response({'status': 'ok'})
    
    if request.method != "DELETE":
        return json_response({'error': 'Method not allowed'}, status=405)
    
    user = authenticate_request(request)
    
    log_info(f"🗑️ PERMANENT DELETE - File: {file_id}, User: {user}")
    
    if not user:
        return auth_error_response()
    
    try:
        file_obj = File.objects.get(id=file_id, user=user, deleted=True)
        
        filename = file_obj.original_name
        
        # Delete file from storage (if exists)
        try:
            if file_obj.file:
                file_obj.file.delete()
        except Exception as e:
            log_error(f"File storage deletion error (ignored): {e}")
        
        # Delete from database
        file_obj.delete()
        
        # Clean up trash record
        Trash.objects.filter(file_id=file_id).delete()
        
        log_info(f"🗑️ ✅ Permanently deleted: {filename}")
        
        return json_response({
            'status': 'success',
            'success': True,
            'message': f'File permanently deleted'
        })
        
    except File.DoesNotExist:
        return json_response({'error': 'File not found in trash'}, status=404)
    except Exception as e:
        log_error(f"🗑️ Permanent delete error: {e}")
        log_error(traceback.format_exc())
        return json_response({'error': str(e)}, status=500)



@csrf_exempt
def empty_trash(request):
    """Permanently delete all files in trash"""
    
    if request.method == "OPTIONS":
        return json_response({'status': 'ok'})
    
    if request.method != "DELETE" and request.method != "POST":
        return json_response({'error': 'Method not allowed'}, status=405)
    
    user = authenticate_request(request)
    
    log_info(f"🗑️ EMPTY TRASH - User: {user}")
    
    if not user:
        return auth_error_response()
    
    try:
        trashed_files = File.objects.filter(user=user, deleted=True)
        count = trashed_files.count()
        
        # Delete files from storage
        for file_obj in trashed_files:
            try:
                if file_obj.file:
                    file_obj.file.delete()
            except Exception as e:
                log_error(f"File storage deletion error (ignored): {e}")
        
        # Delete from database
        trashed_files.delete()
        
        # Clean up trash records
        Trash.objects.filter(file__user=user).delete()
        
        log_info(f"🗑️ ✅ Emptied trash: {count} files deleted")
        
        return json_response({
            'status': 'success',
            'success': True,
            'message': f'{count} files permanently deleted',
            'deleted_count': count
        })
        
    except Exception as e:
        log_error(f"🗑️ Empty trash error: {e}")
        log_error(traceback.format_exc())
        return json_response({'error': str(e)}, status=500)


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
        
        file_name = file_obj.original_name
        
        file_obj.deleted = False
        file_obj.deleted_at = None
        file_obj.save(update_fields=['deleted', 'deleted_at'])
        
        Trash.objects.filter(file=file_obj).delete()
        
        log_info(f"♻️ ✅ Restored: {file_obj.original_name}")
        
        # ✅ CREATE NOTIFICATION
        create_user_notification(
            user=request.user,
            notification_type='FILE_RESTORED',
            title='File Restored',
            message=f'"{file_name}" has been restored from trash.',
            file_name=file_name,
            file_id=file_obj.id
        )
        
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



def create_user_notification(user, notification_type, title, message, file_name=None, file_id=None):
    """Helper to create notifications for user actions"""
    try:
        from accounts.models import Notification
        Notification.objects.create(
            user=user,
            notification_type=notification_type,
            title=title,
            message=message,
            file_name=file_name,
            file_id=file_id
        )
        log_info(f"🔔 Notification created: {notification_type} - {title}")
    except Exception as e:
        log_error(f"🔔 Failed to create notification: {e}")
        


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


@csrf_exempt
def debug_file_info(request, file_id):
    """Debug endpoint to check file storage location"""
    user = authenticate_request(request)
    
    if not user:
        return json_response({'error': 'Not authenticated'}, status=401)
    
    try:
        file_obj = File.objects.get(id=file_id, user=user)
        
        # Get the actual download URL
        download_url = file_obj.cloudinary_url
        url_source = 'cloudinary_url field'
        
        if not download_url and file_obj.file:
            try:
                download_url = file_obj.file.url
                url_source = 'file.url field'
            except:
                pass
        
        # Determine URL type
        url_type = None
        if download_url:
            if 'cloudinary' in download_url or 'res.cloudinary.com' in download_url:
                url_type = 'cloudinary'
            elif download_url.startswith('http'):
                url_type = 'remote'
            else:
                url_type = 'local'
        
        return json_response({
            'file': {
                'id': file_obj.id,
                'name': file_obj.original_name,
                'size': file_obj.size,
                'uploaded_at': file_obj.uploaded_at.isoformat(),
                'deleted': file_obj.deleted,
            },
            'storage': {
                'cloudinary_url': file_obj.cloudinary_url,
                'cloudinary_public_id': file_obj.cloudinary_public_id,
                'file_field_url': file_obj.file.url if file_obj.file else None,
                'download_url': download_url,
                'url_source': url_source,
                'url_type': url_type,
                'is_cloudinary': url_type == 'cloudinary',
                'can_download': url_type in ['cloudinary', 'remote'],
            },
            'message': 'File is downloadable' if url_type == 'cloudinary' else 'File may not be available'
        })
        
    except File.DoesNotExist:
        return json_response({'error': 'File not found'}, status=404)
    

@csrf_exempt
def debug_storage_config(request):
    """Check if Cloudinary is properly configured"""
    from django.core.files.storage import default_storage
    
    # Get actual storage backend
    storage_backend = default_storage
    
    # For Django 4.2+, get the actual backend
    actual_backend = storage_backend
    if hasattr(storage_backend, '_wrapped'):
        actual_backend = storage_backend._wrapped
    if hasattr(storage_backend, 'backend'):
        actual_backend = storage_backend.backend
    
    storage_class = type(actual_backend).__name__
    storage_module = type(actual_backend).__module__
    
    # Check STORAGES setting
    storages_setting = getattr(settings, 'STORAGES', None)
    
    # Check environment variables
    cloud_name = os.environ.get('CLOUDINARY_CLOUD_NAME', '')
    api_key = os.environ.get('CLOUDINARY_API_KEY', '')
    api_secret = os.environ.get('CLOUDINARY_API_SECRET', '')
    
    # Check settings
    cloudinary_storage = getattr(settings, 'CLOUDINARY_STORAGE', {})
    default_file_storage = getattr(settings, 'DEFAULT_FILE_STORAGE', 'NOT SET')
    
    # Determine if cloudinary is actually being used
    is_cloudinary = (
        'cloudinary' in storage_class.lower() or 
        'cloudinary' in storage_module.lower() or
        (storages_setting and 'cloudinary' in str(storages_setting.get('default', {})).lower())
    )
    
    return json_response({
        'environment_variables': {
            'CLOUDINARY_CLOUD_NAME': cloud_name if cloud_name else 'NOT SET ❌',
            'CLOUDINARY_API_KEY': 'SET ✅' if api_key else 'NOT SET ❌',
            'CLOUDINARY_API_SECRET': 'SET ✅' if api_secret else 'NOT SET ❌',
            'all_set': bool(cloud_name and api_key and api_secret)
        },
        'django_settings': {
            'DEFAULT_FILE_STORAGE': default_file_storage,
            'STORAGES': storages_setting,
            'CLOUDINARY_STORAGE': {
                'CLOUD_NAME': cloudinary_storage.get('CLOUD_NAME', 'NOT SET'),
                'API_KEY': 'SET' if cloudinary_storage.get('API_KEY') else 'NOT SET',
                'API_SECRET': 'SET' if cloudinary_storage.get('API_SECRET') else 'NOT SET',
            }
        },
        'actual_storage_being_used': {
            'class': storage_class,
            'module': storage_module,
            'raw_type': str(type(actual_backend)),
            'is_cloudinary': is_cloudinary
        },
        'diagnosis': 'WORKING ✅' if is_cloudinary else 'NOT WORKING ❌ - Files going to local storage!'
    })

@csrf_exempt
def test_cloudinary_upload(request):
    """Test if Cloudinary upload actually works"""
    import cloudinary
    import cloudinary.uploader
    from io import BytesIO
    
    user = authenticate_request(request)
    if not user:
        return json_response({'error': 'Not authenticated'}, status=401)
    
    try:
        # Configure cloudinary directly
        cloudinary.config(
            cloud_name=os.environ.get('CLOUDINARY_CLOUD_NAME'),
            api_key=os.environ.get('CLOUDINARY_API_KEY'),
            api_secret=os.environ.get('CLOUDINARY_API_SECRET')
        )
        
        # Create a simple test file
        test_content = b"This is a test file to verify Cloudinary upload works."
        test_file = BytesIO(test_content)
        
        # Try uploading to Cloudinary directly
        result = cloudinary.uploader.upload(
            test_file,
            folder="test",
            resource_type="raw",
            public_id=f"test_upload_{user.id}"
        )
        
        return json_response({
            'status': 'SUCCESS ✅',
            'message': 'Cloudinary upload works!',
            'cloudinary_url': result.get('secure_url'),
            'public_id': result.get('public_id'),
            'result': result
        })
        
    except Exception as e:
        log_error(f"Cloudinary test upload failed: {e}")
        return json_response({
            'status': 'FAILED ❌',
            'error': str(e),
            'message': 'Cloudinary upload failed. Check your credentials.',
            'debug': {
                'cloud_name': os.environ.get('CLOUDINARY_CLOUD_NAME', 'NOT SET'),
                'api_key_set': bool(os.environ.get('CLOUDINARY_API_KEY')),
                'api_secret_set': bool(os.environ.get('CLOUDINARY_API_SECRET')),
            }
        }, status=500)
    
@csrf_exempt
def test_cloudinary_pdf(request):
    """Test PDF upload and download from Cloudinary"""
    user = authenticate_request(request)
    if not user:
        return json_response({'error': 'Not authenticated'}, status=401)
    
    import cloudinary
    import cloudinary.uploader
    import cloudinary.utils
    from io import BytesIO
    
    cloud_name = os.environ.get('CLOUDINARY_CLOUD_NAME')
    api_key = os.environ.get('CLOUDINARY_API_KEY')
    api_secret = os.environ.get('CLOUDINARY_API_SECRET')
    
    cloudinary.config(
        cloud_name=cloud_name,
        api_key=api_key,
        api_secret=api_secret,
        secure=True
    )
    
    # Create a simple test PDF-like content
    test_content = b"%PDF-1.4 test content"
    test_file = BytesIO(test_content)
    
    results = {}
    
    # Test 1: Upload as 'raw'
    try:
        result1 = cloudinary.uploader.upload(
            test_file,
            folder="test",
            public_id=f"test_pdf_{user.id}_raw",
            resource_type='raw',
            type='upload',
            access_mode='public'
        )
        results['raw_upload'] = {
            'status': 'success',
            'url': result1.get('secure_url'),
            'public_id': result1.get('public_id')
        }
    except Exception as e:
        results['raw_upload'] = {'status': 'failed', 'error': str(e)}
    
    # Test 2: Upload as 'auto'
    test_file.seek(0)
    try:
        result2 = cloudinary.uploader.upload(
            test_file,
            folder="test",
            public_id=f"test_pdf_{user.id}_auto",
            resource_type='auto',
            type='upload',
            access_mode='public'
        )
        results['auto_upload'] = {
            'status': 'success',
            'url': result2.get('secure_url'),
            'public_id': result2.get('public_id')
        }
    except Exception as e:
        results['auto_upload'] = {'status': 'failed', 'error': str(e)}
    
    # Test 3: Check if URLs are accessible
    import requests as http_requests
    
    for key in ['raw_upload', 'auto_upload']:
        if results.get(key, {}).get('url'):
            url = results[key]['url']
            try:
                resp = http_requests.head(url, timeout=5)
                results[key]['accessible'] = resp.status_code == 200
                results[key]['access_status'] = resp.status_code
            except Exception as e:
                results[key]['accessible'] = False
                results[key]['access_error'] = str(e)
    
    # Test 4: Generate signed URL
    if results.get('raw_upload', {}).get('public_id'):
        try:
            signed_url, _ = cloudinary.utils.cloudinary_url(
                results['raw_upload']['public_id'],
                resource_type='raw',
                type='upload',
                secure=True,
                sign_url=True
            )
            results['signed_url'] = signed_url
            
            # Test signed URL
            resp = http_requests.head(signed_url, timeout=5)
            results['signed_url_accessible'] = resp.status_code == 200
            results['signed_url_status'] = resp.status_code
        except Exception as e:
            results['signed_url_error'] = str(e)
    
    return json_response(results)


def update_user_storage(user):
    """Recalculate user's total storage used"""
    total_size = File.objects.filter(
        user=user,
        deleted=False
    ).aggregate(total=Sum('size'))['total'] or 0
    
    user.storage_used = total_size
    user.save(update_fields=['storage_used'])
    return total_size
