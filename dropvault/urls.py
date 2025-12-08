# dropvault/urls.py
from django.contrib import admin
from django.urls import path, include
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.conf.urls.static import static
from accounts import views as accounts_views
from files import views as file_views
from files import sharingviews

urlpatterns = [
    # Admin
    path('admin/', admin.site.urls),
    
    # ===== HOME & DASHBOARD =====
    path('', accounts_views.home, name='home'),
    path('dashboard/', login_required(file_views.dashboard), name='dashboard'),
    
    # ===== AUTH APIs (Direct - No prefix) =====
    path('api/signup/', accounts_views.api_signup, name='api_signup'),
    path('api/login/', accounts_views.api_login, name='api_login'),
    path('api/verify-email/', accounts_views.api_verify_email, name='api_verify_email'),
    
    # ===== FILE APIs =====
    path('api/upload/', file_views.upload_file, name='upload_file'),
    path('api/list/', file_views.list_files, name='list_files'),
    path('api/delete/<int:file_id>/', file_views.delete_file, name='delete_file'),
    path('api/trash/', file_views.trash_list, name='trash_list'),
    path('api/restore/<int:file_id>/', file_views.restore_file, name='restore_file'),
    
    # ===== SHARING APIs =====
    path('api/share/<int:file_id>/', sharingviews.create_share_link, name='create_share_link'),
    path('api/share/<int:file_id>/email/', sharingviews.share_via_email, name='share_via_email'),
    
    # ===== WEB PAGES (HTML) =====
    path('accounts/', include('accounts.urls')),
    
    # ===== PUBLIC SHARED FILES =====
    path('s/<slug:slug>/', sharingviews.shared_file_view, name='shared_file'),
    path('s/<slug:slug>/download/', sharingviews.shared_file_view, {'action': 'download'}, name='shared_file_download'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)