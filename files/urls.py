# files/urls.py — API ONLY (flat)
from django.urls import path
from . import views, sharingviews

urlpatterns = [
    # ✅ Flat API paths — NO 'api/' prefix
    path('upload/', views.upload_file, name='upload_file'),
    path('list/', views.list_files, name='list_files'),
    path('delete/<int:file_id>/', views.delete_file, name='delete_file'),
    path('trash/', views.trash_list, name='trash_list'),
    path('restore/<int:file_id>/', views.restore_file, name='restore_file'),
    
    # Sharing
    path('share/<int:file_id>/', sharingviews.create_share_link, name='create_share_link'),
    path('share/<int:file_id>/email/', sharingviews.share_via_email, name='share_via_email'),
]