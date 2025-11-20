# dropvault/urls.py
from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect
from django.contrib.auth.decorators import login_required
from accounts import views as accounts_views
from files import views as file_views
from files import sharingviews

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include('allauth.urls')),
    path('accounts/', include('accounts.urls')),
    path('files/', include('files.urls')),
    path('s/<slug:slug>/', sharingviews.SharedFileView.as_view(), name='shared_file'),
    path('s/<slug:slug>/download/', sharingviews.SharedFileView.as_view(), {'action': 'download'}, name='shared_file_download'),
    path('', accounts_views.home, name='home'),
    path('dashboard/', login_required(file_views.dashboard), name='dashboard'),
]