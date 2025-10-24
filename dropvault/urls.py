# dropvaluet/urls.py
from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView  # ← ADD THIS

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include('accounts.urls')),
    path('files/', include('files.urls')),
    path('', RedirectView.as_view(url='/accounts/')),  # ← ROOT ROUTE
]