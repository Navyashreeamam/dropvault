from django.urls import include, path
from django.contrib.auth.decorators import login_required
from django.views.generic import RedirectView
from . import views
from files import views as file_views

urlpatterns = [
    # Home/Redirects
    path('', views.home, name='home'),
    path('home/', views.home, name='home'),
    
    # Auth
    path('signup/', views.signup, name='signup'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    
    # Dashboard & Utils
    path('dashboard/', file_views.dashboard, name='dashboard'),
    path('test-email/', login_required(views.test_email), name='test_email'),  # Restricted
    path('upload-test/', login_required(views.upload_test), name='upload_test'),
    
    # Email Verification
    path('verify-email/<str:token>/', views.verify_email, name='verify_email'),
    path('verify-prompt/', login_required(views.verify_email_prompt), name='verify_email_prompt'),
    
    # MFA/OTP
    path('setup-mfa/', login_required(views.setup_mfa), name='setup_mfa'),
    path('otp-verify/', login_required(views.otp_verify), name='otp_verify'),
    path('disable-mfa/', login_required(views.disable_mfa), name='disable_mfa'),
    
    # API Endpoints (for testing)
    path('api/', include([
        path('signup/', views.signup, name='api_signup'),
        path('login/', views.api_login, name='api_login'),
        path('verify-email/', views.api_verify_email, name='api_verify_email'),
    ])),
]