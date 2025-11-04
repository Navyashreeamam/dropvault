from django.contrib import admin
from django.contrib.auth.models import User
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import UserProfile, LoginAttempt

# Inline to show UserProfile inside User admin
class UserProfileInline(admin.StackedInline):
    model = UserProfile
    can_delete = False
    verbose_name_plural = 'Profile'

# Extend the default UserAdmin
class UserAdmin(BaseUserAdmin):
    inlines = (UserProfileInline,)

# Re-register User with the new admin
admin.site.unregister(User)
admin.site.register(User, UserAdmin)

# Register LoginAttempt
@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ['email', 'ip_address', 'success', 'timestamp']
    list_filter = ['success', 'timestamp']
    search_fields = ['email', 'ip_address']
    readonly_fields = ['email', 'ip_address', 'success', 'timestamp']
    ordering = ['-timestamp']