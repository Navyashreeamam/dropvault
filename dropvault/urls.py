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
    
    # Allauth (must come BEFORE custom accounts/ to allow override of /login, /signup if needed)
    path('accounts/', include('allauth.urls')),
    
    # Custom account views (will override allauth for /login, /signup, etc. if same name)
    path('accounts/', include('accounts.urls')),
    
    # File APIs & operations
    path('files/', include('files.urls')),

    # 🔗 Shared file public access (slug-based) — moved under /s/ (standard)
    path('s/<str:slug>/', sharingviews.access_shared_file, name='shared_file'),
    path('s/<str:slug>/download/', sharingviews.download_shared_file, name='download_shared_file'),

    # ✅ Homepage: use your view, not TemplateView
    path('', accounts_views.home, name='home'),
    
    # Dashboard (optional — can be removed; covered by /)
    path('dashboard/', login_required(file_views.dashboard), name='dashboard'),
]