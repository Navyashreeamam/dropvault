# dropvault/urls.py
from django.contrib import admin
from django.urls import path, include
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.conf.urls.static import static
from django.http import JsonResponse
from accounts import views as accounts_views
from files import views as file_views
from files import sharingviews


# ═══════════════════════════════════════════════════════════
# 🏥 HEALTH CHECK
# ═══════════════════════════════════════════════════════════
def health_check(request):
    return JsonResponse({'status': 'ok', 'message': 'DropVault is running'})


urlpatterns = [
    # ===== HEALTH CHECK (MUST BE FIRST) =====
    path('health/', health_check, name='health_check'),
    
    # ===== ADMIN =====
    path('admin/', admin.site.urls),
    
    # ===== HOME & DASHBOARD =====
    path('', accounts_views.home, name='home'),
    path('dashboard/', login_required(file_views.dashboard), name='dashboard'),
    
    # ===== AUTH APIs =====
    path('api/signup/', accounts_views.api_signup, name='api_signup'),
    path('api/login/', accounts_views.api_login, name='api_login'),
    path('api/verify-email/', accounts_views.api_verify_email, name='api_verify_email'),
    
    # ===== FILE APIs (/api/ prefix) =====
    path('api/upload/', file_views.upload_file, name='api_upload'),
    path('api/list/', file_views.list_files, name='api_list'),
    path('api/delete/<int:file_id>/', file_views.delete_file, name='api_delete'),
    path('api/trash/', file_views.trash_list, name='api_trash'),
    path('api/restore/<int:file_id>/', file_views.restore_file, name='api_restore'),
    
    # ===== FILE APIs (/files/ prefix - alternate) =====
    path('files/upload/', file_views.upload_file, name='files_upload'),
    path('files/list/', file_views.list_files, name='files_list'),
    path('files/delete/<int:file_id>/', file_views.delete_file, name='files_delete'),
    path('files/trash/', file_views.trash_list, name='files_trash'),
    path('files/restore/<int:file_id>/', file_views.restore_file, name='files_restore'),
    
    # ===== SHARING APIs =====
    path('api/share/<int:file_id>/', sharingviews.create_share_link, name='api_share'),
    path('api/share/<int:file_id>/email/', sharingviews.share_via_email, name='api_share_email'),
    path('files/share/<int:file_id>/', sharingviews.create_share_link, name='files_share'),
    path('files/share/<int:file_id>/email/', sharingviews.share_via_email, name='files_share_email'),
    
    # ===== WEB PAGES =====
    path('accounts/', include('accounts.urls')),
    
    # ===== PUBLIC SHARED FILES =====
    path('s/<slug:slug>/', sharingviews.shared_file_view, name='shared_file'),
    path('s/<slug:slug>/download/', sharingviews.shared_file_view, {'action': 'download'}, name='shared_file_download'),
]

# Static/Media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)