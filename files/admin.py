# DropVault/files/admin.py
from django.contrib import admin
from .models import SharedLink

@admin.register(SharedLink)
class SharedLinkAdmin(admin.ModelAdmin):
    list_display = [
        'slug', 'file', 'owner', 'view_count', 'download_count',
        'first_accessed_at', 'expires_at', 'is_active', 'created_at'
    ]
    list_filter = ['is_active', 'created_at']
    search_fields = ['slug', 'file__original_name', 'owner__email']
    readonly_fields = ['token', 'created_at', 'first_accessed_at', 'expires_at']