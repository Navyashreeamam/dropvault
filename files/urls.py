from django.urls import path
from . import views

urlpatterns = [
    path('upload/', views.upload_file, name='upload_file'),
    path('list/', views.list_files, name='list_files'),
    path('delete/<int:file_id>/', views.delete_file, name='delete_file'),
    path('trash/', views.trash_list, name='trash_list'),
]