# dropvault/files/urls.py
from django.urls import path
from . import views, sharingviews

urlpatterns = [
    # --- Existing (keep) ---
    path('upload/', views.upload_file, name='upload_file'),
    path('list/', views.list_files, name='list_files'),
    path('delete/<int:file_id>/', views.delete_file, name='delete_file'),
    path('trash/', views.trash_list, name='trash_list'),
    
    # --- Sharing (keep) ---
    path('share/<int:file_id>/', sharingviews.create_share_link, name='create_share_link'),
    path('share/<int:file_id>/email/', sharingviews.share_via_email, name='share_via_email'),

    # --- 🔥 NEW: Public sharing endpoints ---
    path('s/<slug:slug>/download/', sharingviews.SharedFileView.as_view(), {'action': 'download'}, name='shared_file_download'),
    path('s/<slug:slug>/download/', sharingviews.download_shared_file, name='download_shared_file'),
]