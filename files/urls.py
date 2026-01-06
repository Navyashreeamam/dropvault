# files/urls.py
from django.urls import path
from . import views, sharingviews

urlpatterns = [
    # File Management
    path('upload/', views.upload_file, name='upload_file'),
    path('list/', views.list_files, name='list_files'),
    path('delete/<int:file_id>/', views.delete_file, name='delete_file'),
    path('trash/', views.trash_list, name='trash_list'),
    path('restore/<int:file_id>/', views.restore_file, name='restore_file'),
    
    path('shared/', views.get_shared_files, name='get_shared_files'),

    # Debug
    path('debug/files/', views.debug_files, name='debug_files'),
    
    # Add this for testing email config
    path('api/test-email-config/', sharingviews.test_email_config, name='test_email_config'),
    
    path('debug/shared/<slug:slug>/', sharingviews.debug_shared_file, name='debug_shared_file'),
    # Sharing
    path('share/<int:file_id>/', sharingviews.create_share_link, name='create_share_link'),
    path('share/<int:file_id>/email/', sharingviews.share_via_email, name='share_via_email'),
]