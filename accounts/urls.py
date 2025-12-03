# accounts/urls.py
from django.urls import path
from . import views

urlpatterns = [
    # ===== Web Views (HTML) =====
    path('', views.home, name='home'),
    path('home/', views.home, name='home_alt'),
    path('signup/', views.signup_view, name='signup'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    
    # Email verification
    path('verify-email/<str:token>/', views.verify_email, name='verify_email'),
    path('verify-prompt/', views.verify_email_prompt, name='verify_email_prompt'),
    
    # MFA
    path('setup-mfa/', views.setup_mfa, name='setup_mfa'),
    path('otp-verify/', views.otp_verify, name='otp_verify'),
    path('disable-mfa/', views.disable_mfa, name='disable_mfa'),
    
    # Utility
    path('test-email/', views.test_email, name='test_email'),
    path('upload-test/', views.upload_test, name='upload_test'),

    # ===== API Views (JSON) =====
    path('api/signup/', views.api_signup, name='api_signup'),
    path('api/login/', views.api_login, name='api_login'),
    path('api/verify-email/', views.api_verify_email, name='api_verify_email'),
]