# accounts/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),        # ← handles /accounts/
    path('signup/', views.signup, name='signup'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('verify-email/', views.verify_email, name='verify_email'),
]