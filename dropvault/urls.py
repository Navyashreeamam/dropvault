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
    
    # Web Pages
    path('', accounts_views.home, name='home'),
    path('dashboard/', login_required(file_views.dashboard), name='dashboard'),
    
    # AUTH APIs
    path('api/signup/', accounts_views.api_signup, name='api_signup'),
    path('api/login/', accounts_views.api_login, name='api_login'),
    path('api/logout/', accounts_views.api_logout, name='api_logout'),
    path('api/verify-email/', accounts_views.api_verify_email, name='api_verify_email'),
    path('api/auth/check/', accounts_views.api_check_auth, name='api_check_auth'),
    path('api/auth/google/', accounts_views.api_google_login, name='api_google_login'),
    path('api/set-password/', accounts_views.api_set_password, name='api_set_password'),
    path('api/forgot-password/', accounts_views.api_forgot_password, name='api_forgot_password'),
    path('api/reset-password/', accounts_views.api_reset_password, name='api_reset_password'),
    path('api/verify-reset-token/', accounts_views.api_verify_reset_token, name='api_verify_reset_token'),

    path('api/debug-user/', accounts_views.api_debug_user, name='api_debug_user'),
    path('api/check-password-status/', accounts_views.api_check_user_password_status, name='api_check_password_status'),
    path('api/request-password-reset/', accounts_views.api_request_password_reset, name='api_request_password_reset'),
    path('api/reset-password/', accounts_views.api_reset_password, name='api_reset_password'),
    
    # USER APIs
    path('api/user/', accounts_views.api_user_profile, name='api_user_profile'),
    path('api/dashboard/', accounts_views.api_dashboard, name='api_dashboard'),
    path('api/user/profile/', accounts_views.api_update_profile, name='api_update_profile'),
    path('api/user/password/', accounts_views.api_change_password, name='api_change_password'),
    path('api/user/preferences/', accounts_views.api_preferences, name='api_preferences'),
    path('api/user/storage/', accounts_views.api_user_storage, name='api_user_storage'),

    

    # NOTIFICATION APIs - NEW
    path('api/notifications/', accounts_views.api_notifications, name='api_notifications'),
    path('api/notifications/<int:notification_id>/read/', accounts_views.api_notification_read, name='api_notification_read'),
    path('api/notifications/read-all/', accounts_views.api_notifications_read_all, name='api_notifications_read_all'),
    path('api/notifications/<int:notification_id>/delete/', accounts_views.api_notification_delete, name='api_notification_delete'),

    # FILE APIs
    path('api/upload/', file_views.upload_file, name='api_upload'),
    path('api/list/', file_views.list_files, name='api_list'),
    path('api/files/', file_views.list_files, name='api_files'),
    path('api/delete/<int:file_id>/', file_views.delete_file, name='api_delete'),
    path('api/trash/', file_views.trash_list, name='api_trash'),
    path('api/restore/<int:file_id>/', file_views.restore_file, name='api_restore'),
    path('api/files/<int:file_id>/download/', file_views.download_file, name='api_download_file'),
    path('api/download/<int:file_id>/', file_views.download_file, name='api_download'),
    path('api/files/<int:file_id>/info/', file_views.debug_file_info, name='api_file_info'),
    path('api/debug/storage/', file_views.debug_storage_config, name='debug_storage'),

    path('api/trash/permanent/<int:file_id>/', file_views.permanent_delete, name='api_permanent_delete'),
    path('api/trash/empty/', file_views.empty_trash, name='api_empty_trash'),

    # SHARING APIs
    path('api/share/<int:file_id>/', sharingviews.create_share_link, name='api_share'),
    path('api/share/<int:file_id>/email/', sharingviews.share_via_email, name='api_share_email'),
    path('api/shared/', file_views.get_shared_files, name='api_shared_files'),

    # Web routes
    path('files/', include('files.urls')),
    path('accounts/', include('accounts.urls')),
    
    # Public shared files
    path('s/<slug:slug>/', sharingviews.shared_file_view, name='shared_file'),
    path('s/<slug:slug>/download/', sharingviews.download_shared_file, name='shared_file_download'),

    path('api/test-cloudinary/', file_views.test_cloudinary_upload, name='test_cloudinary'),
    path('api/test-cloudinary-pdf/', file_views.test_cloudinary_pdf, name='test_cloudinary_pdf'),

]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)