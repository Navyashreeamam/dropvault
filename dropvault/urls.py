# dropvault/urls.py
from django.contrib import admin
from django.urls import path, include
from django.views.generic import TemplateView
from files import sharingviews

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include('allauth.urls')),
    path('accounts/', include('accounts.urls')),
    path('files/', include('files.urls')),
    path('', TemplateView.as_view(template_name='home.html'), name='home'),  # ← name='home'
    
        # ✅ ADD THESE AT THE END (top-level, no prefix)
    path('s/<str:slug>/', sharingviews.access_shared_file, name='shared_file'),
    path('s/<str:slug>/download/', sharingviews.download_shared_file, name='download_shared_file'),
]