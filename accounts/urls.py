# accounts/urls.py
from django.urls import path
from . import views

# These will be prefixed with /accounts/ from main urls
# Only WEB PAGES here - APIs are in main urls.py
urlpatterns = [
    # Auth Pages (HTML)
    path('signup/', views.signup_view, name='signup'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    
    # Email Verification
    path('verify-email/<str:token>/', views.verify_email, name='verify_email'),
    path('verify-prompt/', views.verify_email_prompt, name='verify_email_prompt'),
    
    # MFA
    path('setup-mfa/', views.setup_mfa, name='setup_mfa'),
    path('otp-verify/', views.otp_verify, name='otp_verify'),
    path('disable-mfa/', views.disable_mfa, name='disable_mfa'),
    
    # Testing
    path('test-email/', views.test_email, name='test_email'),
    path('upload-test/', views.upload_test, name='upload_test'),
]