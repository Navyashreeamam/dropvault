# DropVault/files/urls.py
from django.urls import path
from . import views
from . import sharingviews

urlpatterns = [
    # File operations
    path('upload/', views.upload_file, name='upload_file'),
    path('list/', views.list_files, name='list_files'),
    path('delete/<int:file_id>/', views.delete_file, name='delete_file'),
    path('trash/', views.trash_list, name='trash_list'),

    # Sharing features
    path('share/<int:file_id>/', sharingviews.create_share_link, name='create_share_link'),
    path('s/<str:slug>/', sharingviews.access_shared_file, name='access_shared_file'),
    path('s/<str:slug>/download/', sharingviews.download_shared_file, name='download_shared_file'),
]