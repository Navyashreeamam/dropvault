# dropvault/files/urls.py
from django.urls import path
from . import views, sharingviews
from .sharingviews import access_shared_file_by_slug


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
    path('s/<slug:slug>/', sharingviews.shared_file_view, name='shared_file'),
    path('s/<slug:slug>/download/', sharingviews.shared_file_view, {'action': 'download'}, name='shared_file_download'),
    
    path('s/<str:slug>/', sharingviews.access_shared_file_by_slug, name='access_shared_file_by_slug'),
]