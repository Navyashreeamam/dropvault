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


def health_check(request):
    return JsonResponse({'status': 'ok', 'message': 'DropVault is running'})


urlpatterns = [
    # Health Check
    path('health/', health_check, name='health_check'),
    
    # Admin
    path('admin/', admin.site.urls),
    
    # Home & Dashboard
    path('', accounts_views.home, name='home'),
    path('dashboard/', login_required(file_views.dashboard), name='dashboard'),
    
    # Auth APIs
    path('api/signup/', accounts_views.api_signup, name='api_signup'),
    path('api/login/', accounts_views.api_login, name='api_login'),
    path('api/verify-email/', accounts_views.api_verify_email, name='api_verify_email'),
    
    # File APIs (/api/ prefix)
    path('api/upload/', file_views.upload_file, name='api_upload'),
    path('api/list/', file_views.list_files, name='api_list'),
    path('api/delete/<int:file_id>/', file_views.delete_file, name='api_delete'),
    path('api/trash/', file_views.trash_list, name='api_trash'),
    path('api/restore/<int:file_id>/', file_views.restore_file, name='api_restore'),
    
    # File URLs (include files app)
    path('files/', include('files.urls')),
    
    # Sharing APIs
    path('api/share/<int:file_id>/', sharingviews.create_share_link, name='api_share'),
    path('api/share/<int:file_id>/email/', sharingviews.share_via_email, name='api_share_email'),
    
    # Account pages
    path('accounts/', include('accounts.urls')),
    
    # Public Shared Files
    path('s/<slug:slug>/', sharingviews.shared_file_view, name='shared_file'),
    path('s/<slug:slug>/download/', sharingviews.download_shared_file, name='shared_file_download'),
]

# Static/Media files
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)