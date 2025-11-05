from django.urls import include, path
from django.contrib.auth.decorators import login_required
from django.views.generic import RedirectView
from . import views

urlpatterns = [
    path('', login_required(RedirectView.as_view(pattern_name='dashboard')), name='accounts_home'),
    path('signup/', views.signup, name='signup'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', login_required(views.dashboard), name='dashboard'),
    path('verify-email/', views.verify_email, name='verify_email'),
    path('verify-prompt/', views.verify_email_prompt, name='verify_email_prompt'),
    path('test-email/', views.test_email, name='test_email'),
    path('setup-mfa/', views.setup_mfa, name='setup_mfa'),
]