# dropvault/urls.py
from django.contrib import admin
from django.urls import path, include
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.conf.urls.static import static
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from accounts import views as accounts_views
from files import views as file_views
from files import sharingviews


@csrf_exempt
def health_check(request):
    """Health check endpoint"""
    return JsonResponse({
        'status': 'ok',
        'message': 'DropVault Backend is running',
        'version': '1.0.0'
    })


urlpatterns = [
    # ═══════════════════════════════════════════════════════════
    # 🏥 HEALTH CHECK
    # ═══════════════════════════════════════════════════════════
    path('health/', health_check, name='health_check'),
    path('api/health/', health_check, name='api_health_check'),
    
    # ═══════════════════════════════════════════════════════════
    # 🔧 ADMIN
    # ═══════════════════════════════════════════════════════════
    path('admin/', admin.site.urls),
    
    # ═══════════════════════════════════════════════════════════
    # 🏠 WEB PAGES (HTML)
    # ═══════════════════════════════════════════════════════════
    path('', accounts_views.home, name='home'),
    path('dashboard/', login_required(file_views.dashboard), name='dashboard'),
    
    # ═══════════════════════════════════════════════════════════
    # 🔐 AUTH APIs (REACT FRONTEND)
    # ═══════════════════════════════════════════════════════════
    path('api/auth/login/', accounts_views.api_login, name='api_auth_login'),
    path('api/auth/register/', accounts_views.api_signup, name='api_auth_register'),
    path('api/auth/logout/', accounts_views.api_logout, name='api_auth_logout'),
    path('api/auth/profile/', accounts_views.api_user_profile, name='api_auth_profile'),
    path('api/auth/google/', accounts_views.api_google_login, name='api_google_login'),
    path('api/auth/check/', accounts_views.api_check_auth, name='api_auth_check'),
    
    # Legacy endpoints (backward compatibility)
    path('api/signup/', accounts_views.api_signup, name='api_signup'),
    path('api/login/', accounts_views.api_login, name='api_login'),
    path('api/logout/', accounts_views.api_logout, name='api_logout'),
    path('api/verify-email/', accounts_views.api_verify_email, name='api_verify_email'),
    
    # ═══════════════════════════════════════════════════════════
    # 📊 DASHBOARD APIs
    # ═══════════════════════════════════════════════════════════
    path('api/dashboard/stats/', accounts_views.api_dashboard, name='api_dashboard_stats'),
    path('api/dashboard/', accounts_views.api_dashboard, name='api_dashboard'),
    
    # ═══════════════════════════════════════════════════════════
    # 👤 USER & SETTINGS APIs
    # ═══════════════════════════════════════════════════════════
    path('api/settings/profile/', accounts_views.api_update_profile, name='api_settings_profile'),
    path('api/settings/password/', accounts_views.api_change_password, name='api_settings_password'),
    path('api/settings/preferences/', accounts_views.api_preferences, name='api_settings_preferences'),
    
    # Legacy endpoints
    path('api/user/', accounts_views.api_user_profile, name='api_user_profile'),
    path('api/user/profile/', accounts_views.api_update_profile, name='api_update_profile'),
    path('api/user/password/', accounts_views.api_change_password, name='api_change_password'),
    path('api/user/preferences/', accounts_views.api_preferences, name='api_preferences'),
    
    # ═══════════════════════════════════════════════════════════
    # 📁 FILE APIs
    # ═══════════════════════════════════════════════════════════
    path('api/files/', file_views.list_files, name='api_files_list'),
    path('api/files/upload/', file_views.upload_file, name='api_files_upload'),
    path('api/files/trash/', file_views.trash_list, name='api_files_trash'),
    path('api/files/<int:file_id>/', file_views.delete_file, name='api_files_delete'),
    path('api/files/<int:file_id>/restore/', file_views.restore_file, name='api_files_restore'),
    path('api/files/<int:file_id>/share/', sharingviews.create_share_link, name='api_files_share'),
    # ❌ REMOVED: path('api/files/shared/', file_views.shared_files, name='api_files_shared'),
    
    # Legacy endpoints
    path('api/upload/', file_views.upload_file, name='api_upload'),
    path('api/list/', file_views.list_files, name='api_list'),
    path('api/delete/<int:file_id>/', file_views.delete_file, name='api_delete'),
    path('api/trash/', file_views.trash_list, name='api_trash'),
    path('api/restore/<int:file_id>/', file_views.restore_file, name='api_restore'),
    path('api/debug/files/', file_views.debug_files, name='api_debug_files'),
    
    # ═══════════════════════════════════════════════════════════
    # 🔗 SHARING APIs
    # ═══════════════════════════════════════════════════════════
    path('api/share/<int:file_id>/', sharingviews.create_share_link, name='api_share'),
    path('api/share/<int:file_id>/email/', sharingviews.share_via_email, name='api_share_email'),
    
    # ═══════════════════════════════════════════════════════════
    # 📄 FILE WEB ROUTES (HTML)
    # ═══════════════════════════════════════════════════════════
    path('files/', include('files.urls')),
    
    # ═══════════════════════════════════════════════════════════
    # 👤 ACCOUNT WEB ROUTES (HTML)
    # ═══════════════════════════════════════════════════════════
    path('accounts/', include('accounts.urls')),
    
    # ═══════════════════════════════════════════════════════════
    # 🔗 PUBLIC SHARED FILES
    # ═══════════════════════════════════════════════════════════
    path('s/<slug:slug>/', sharingviews.shared_file_view, name='shared_file'),
    path('s/<slug:slug>/download/', sharingviews.download_shared_file, name='shared_file_download'),
]

# Static/Media files
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)