from django.contrib import admin
from .models import File, Trash, FileLog, SharedLink


@admin.register(File)
class FileAdmin(admin.ModelAdmin):
    list_display = ['id', 'original_name', 'user', 'size', 'uploaded_at', 'deleted', 'sha256', 'is_shared']
    list_filter = ['deleted', 'uploaded_at', 'user']  # ← REMOVED 'is_shared' here
    search_fields = ['original_name', 'user__email', 'sha256']
    readonly_fields = ['sha256', 'uploaded_at']

    def is_shared(self, obj):
        return SharedLink.objects.filter(file=obj, is_active=True).exists()
    is_shared.boolean = True
    is_shared.short_description = 'Shared'


@admin.register(Trash)
class TrashAdmin(admin.ModelAdmin):
    list_display = ['file', 'deleted_at']
    readonly_fields = ['file', 'deleted_at']


@admin.register(FileLog)
class FileLogAdmin(admin.ModelAdmin):
    list_display = ['user', 'file', 'action', 'timestamp']
    list_filter = ['action', 'timestamp', 'user']
    readonly_fields = ['user', 'file', 'action', 'timestamp']
    ordering = ['-timestamp']


@admin.register(SharedLink)
class SharedLinkAdmin(admin.ModelAdmin):
    list_display = [
        'slug', 'file', 'owner', 'view_count', 'download_count',
        'first_accessed_at', 'expires_at', 'is_active', 'created_at'
    ]
    list_filter = ['is_active', 'created_at', 'owner']
    search_fields = ['slug', 'file__original_name', 'owner__email']
    readonly_fields = ['token', 'created_at', 'first_accessed_at', 'expires_at']