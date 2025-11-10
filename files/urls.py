# dropvault/files/urls.py
from django.urls import path
from . import views, sharingviews

urlpatterns = [
    path('upload/', views.upload_file, name='upload_file'),          # → POST /files/upload/
    path('list/', views.list_files, name='list_files'),              # → GET /files/list/
    path('delete/<int:file_id>/', views.delete_file, name='delete_file'),
    path('trash/', views.trash_list, name='trash_list'),

    # Sharing
    path('share/<int:file_id>/', sharingviews.create_share_link, name='create_share_link'),
    path('share/<int:file_id>/email/', sharingviews.share_via_email, name='share_via_email'),
]