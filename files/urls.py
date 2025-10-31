from django.urls import path
from . import views
from . import sharingviews

urlpatterns = [
    # Existing file operations
    path('upload/', views.upload_file, name='upload_file'),
    path('list/', views.list_files, name='list_files'),
    path('delete/<int:file_id>/', views.delete_file, name='delete_file'),
    path('trash/', views.trash_list, name='trash_list'),
    
        # NEW: Sharing features
    path('share/<int:file_id>/', sharingviews.create_share_link, name='create_share_link'),
]