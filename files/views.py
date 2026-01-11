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
import requests as http_requests
import requests
from django.http import HttpResponse
import uuid



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

#LOGGING - Force flush to console

def log_info(msg):
    print(f"[INFO] {msg}", file=sys.stdout, flush=True)
    sys.stdout.flush()

def log_error(msg):
    print(f"[ERROR] {msg}", file=sys.stdout, flush=True)
    sys.stdout.flush()


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
    """Upload a file to Cloudinary"""
    
    if request.method == "OPTIONS":
        response = json_response({'status': 'ok'})
        response["Access-Control-Allow-Origin"] = "*"
        response["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        response["Access-Control-Allow-Headers"] = "Content-Type, X-CSRFToken, Authorization"
        return response
    
    if request.method != "POST":
        return json_response({'error': 'Method not allowed'}, status=405)
    
    log_info("=" * 60)
    log_info("📤 UPLOAD REQUEST RECEIVED")
    log_info("=" * 60)
    
    try:
        # Check authentication
        user = authenticate_request(request)
        if not user:
            log_error("📤 ❌ NOT AUTHENTICATED!")
            return auth_error_response()
        
        log_info(f"📤 ✅ User authenticated: {user.email}")
        
        # Check for file
        if 'file' not in request.FILES:
            return json_response({
                'error': 'No file provided',
                'message': 'Please select a file to upload'
            }, status=400)
        
        file = request.FILES['file']
        log_info(f"📤 File: {file.name} ({file.size} bytes)")
        
        # Validate
        valid, error_msg = validate_file(file)
        if not valid:
            return json_response({'error': error_msg}, status=400)
        
        # Get hash
        file_hash = get_file_hash(file)
        
        # Check duplicate
        if File.objects.filter(user=user, sha256=file_hash, deleted=False).exists():
            return json_response({
                'error': 'Duplicate file',
                'message': 'You already uploaded this file'
            }, status=409)
        
        # ═══════════════════════════════════════════════════════════
        # UPLOAD TO CLOUDINARY
        # ═══════════════════════════════════════════════════════════
        cloud_name = os.environ.get('CLOUDINARY_CLOUD_NAME')
        api_key = os.environ.get('CLOUDINARY_API_KEY')
        api_secret = os.environ.get('CLOUDINARY_API_SECRET')
        
        if not (cloud_name and api_key and api_secret):
            return json_response({
                'error': 'Storage not configured'
            }, status=500)
        
        try:
            import cloudinary
            import cloudinary.uploader
            import cloudinary.utils
            
            cloudinary.config(
                cloud_name=cloud_name,
                api_key=api_key,
                api_secret=api_secret,
                secure=True
            )
            
            # Generate unique filename
            unique_name = f"{uuid.uuid4().hex}"
            
            # Determine resource type based on content
            content_type = file.content_type or ''
            ext = file.name.split('.')[-1].lower() if '.' in file.name else ''
            
            if content_type.startswith('image/') or ext in ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp']:
                resource_type = 'image'
            elif content_type.startswith('video/') or ext in ['mp4', 'mov', 'avi', 'webm']:
                resource_type = 'video'
            else:
                resource_type = 'raw'
            
            log_info(f"📤 Content-Type: {content_type}, Extension: {ext}, Resource Type: {resource_type}")
            
            # Upload to Cloudinary
            file.seek(0)
            upload_result = cloudinary.uploader.upload(
                file,
                folder=f"user_{user.id}",
                public_id=unique_name,
                resource_type=resource_type,
                type='upload'
            )
            
            cloudinary_public_id = upload_result.get('public_id')
            actual_resource_type = upload_result.get('resource_type', resource_type)
            
            log_info(f"📤 Upload result - Public ID: {cloudinary_public_id}, Resource Type: {actual_resource_type}")
            
            # ✅ Generate appropriate URL
            if actual_resource_type == 'raw':
                # For raw files (PDFs, docs), generate signed URL
                cloudinary_url, options = cloudinary.utils.cloudinary_url(
                    cloudinary_public_id,
                    resource_type='raw',
                    type='upload',
                    secure=True,
                    sign_url=True
                )
                log_info(f"📤 Generated SIGNED URL for raw file")
            else:
                # For images/videos, use regular URL
                cloudinary_url = upload_result.get('secure_url')
            
            log_info(f"📤 ✅ Final URL: {cloudinary_url}")
            
        except Exception as e:
            log_error(f"📤 ❌ Cloudinary error: {e}")
            log_error(traceback.format_exc())
            return json_response({
                'error': 'Upload failed',
                'message': str(e)
            }, status=500)
        
        # ═══════════════════════════════════════════════════════════
        # CREATE FILE RECORD
        # ═══════════════════════════════════════════════════════════
        file_obj = File.objects.create(
            user=user,
            original_name=file.name,
            size=file.size,
            sha256=file_hash,
            deleted=False,
            cloudinary_url=cloudinary_url,
            cloudinary_public_id=cloudinary_public_id,
            cloudinary_resource_type=actual_resource_type  # Store resource type
        )
        
        log_info(f"📤 ✅ File saved! ID: {file_obj.id}")
        
        # Log & Notify
        try:
            FileLog.objects.create(user=user, file=file_obj, action='UPLOAD')
            create_user_notification(
                user=user,
                notification_type='FILE_UPLOAD',
                title='File Uploaded Successfully',
                message=f'"{file_obj.original_name}" has been uploaded.',
                file_name=file_obj.original_name,
                file_id=file_obj.id
            )
        except:
            pass
        
        return json_response({
            'status': 'success',
            'message': 'File uploaded successfully',
            'file': {
                'id': file_obj.id,
                'filename': file_obj.original_name,
                'size': file_obj.size,
                'uploaded_at': file_obj.uploaded_at.isoformat(),
                'cloudinary_url': cloudinary_url,
                'storage': 'cloudinary',
                'resource_type': actual_resource_type
            }
        }, status=201)
        
    except Exception as e:
        log_error(f"📤 ❌ EXCEPTION: {e}")
        log_error(traceback.format_exc())
        return json_response({
            'error': 'Upload failed',
            'message': str(e)
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


@csrf_exempt
def download_file(request, file_id):
    """Download user's own file"""
    
    if request.method == "OPTIONS":
        return json_response({'status': 'ok'})
    
    log_info(f"📥 DOWNLOAD FILE - ID: {file_id}")
    
    try:
        user = authenticate_request(request)
        if not user:
            return auth_error_response()
        
        try:
            file_obj = File.objects.get(id=file_id, user=user, deleted=False)
        except File.DoesNotExist:
            return JsonResponse({'error': 'File not found'}, status=404)
        
        log_info(f"📥 File: {file_obj.original_name}")
        
        # Get download URL
        download_url = file_obj.cloudinary_url
        
        # ✅ For raw files, regenerate signed URL (in case it expired)
        if file_obj.cloudinary_public_id and file_obj.cloudinary_resource_type == 'raw':
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
                log_info(f"📥 Generated fresh signed URL")
            except Exception as e:
                log_error(f"📥 Could not generate signed URL: {e}")
        
        log_info(f"📥 Download URL: {download_url}")
        
        if not download_url:
            return JsonResponse({'error': 'File not available'}, status=404)
        
        # Fetch from Cloudinary
        if download_url.startswith('http'):
            try:
                import requests as http_requests
                
                response = http_requests.get(download_url, stream=True, timeout=60)
                
                log_info(f"📥 Cloudinary response: {response.status_code}")
                
                if response.status_code != 200:
                    log_error(f"📥 Failed: HTTP {response.status_code}")
                    log_error(f"📥 Response: {response.text[:500]}")
                    return JsonResponse({
                        'error': 'File temporarily unavailable',
                        'details': f'HTTP {response.status_code}'
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
                log_error(f"📥 Error: {e}")
                return JsonResponse({'error': str(e)}, status=500)
        else:
            return JsonResponse({
                'error': 'File no longer available',
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
        
        # ✅ Use cloudinary_url field
        download_url = file_obj.cloudinary_url
        
        if not download_url and file_obj.file:
            try:
                download_url = file_obj.file.url
            except:
                pass
        
        log_info(f"📥 Download URL: {download_url}")
        
        if not download_url:
            return JsonResponse({'error': 'File not available'}, status=404)
        
        # Download from Cloudinary
        if download_url.startswith('http'):
            try:
                response = requests.get(download_url, stream=True, timeout=60)
                
                if response.status_code != 200:
                    return JsonResponse({
                        'error': 'File temporarily unavailable'
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
                'error': 'File no longer available',
                'solution': 'Please re-upload this file'
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
    