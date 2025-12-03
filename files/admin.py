# files/admin.py
from django.contrib import admin
from django.utils.html import format_html
from django.utils import timezone
from .models import File, FileLog, SharedLink, Trash


@admin.register(File)
class FileAdmin(admin.ModelAdmin):
    list_display = ['original_name', 'user', 'size_display', 'uploaded_at', 'status_display', 'actions_display']
    list_filter = ['uploaded_at', 'user']
    search_fields = ['original_name', 'user__email', 'sha256']
    readonly_fields = ['sha256', 'uploaded_at', 'size_display', 'file_link']
    date_hierarchy = 'uploaded_at'
    
    fieldsets = (
        ('File Information', {
            'fields': ('original_name', 'file', 'file_link', 'size_display', 'sha256')
        }),
        ('Ownership', {
            'fields': ('user',)
        }),
        ('Timestamps', {
            'fields': ('uploaded_at', 'deleted_at'),
        }),
        ('Metadata', {
            'fields': ('encryption_meta',),
            'classes': ('collapse',)
        }),
    )

    def size_display(self, obj):
        """Display file size in human-readable format"""
        size = obj.size
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"
    size_display.short_description = 'Size'

    def status_display(self, obj):
        """Display file status (active/trashed)"""
        if obj.deleted_at:
            return format_html('<span style="color: red;">🗑️ Trashed</span>')
        return format_html('<span style="color: green;">✅ Active</span>')
    status_display.short_description = 'Status'

    def actions_display(self, obj):
        """Display quick action buttons"""
        if obj.deleted_at:
            return format_html(
                '<a class="button" href="/admin/files/file/{}/restore/">Restore</a>',
                obj.pk
            )
        return format_html(
            '<a class="button" href="/admin/files/file/{}/soft-delete/">Move to Trash</a>',
            obj.pk
        )
    actions_display.short_description = 'Actions'

    def file_link(self, obj):
        """Display clickable file link"""
        if obj.file:
            return format_html('<a href="{}" target="_blank">Download</a>', obj.file.url)
        return '-'
    file_link.short_description = 'File Link'

    def get_queryset(self, request):
        """Show all files (including trashed) in admin"""
        return File.all_objects.all()


@admin.register(FileLog)
class FileLogAdmin(admin.ModelAdmin):
    list_display = ['user', 'file', 'action', 'timestamp', 'ip_address']
    list_filter = ['action', 'timestamp']
    search_fields = ['user__email', 'file__original_name', 'ip_address']
    readonly_fields = ['user', 'file', 'action', 'timestamp', 'ip_address']
    date_hierarchy = 'timestamp'

    def has_add_permission(self, request):
        """Logs should not be manually created"""
        return False

    def has_delete_permission(self, request, obj=None):
        """Logs should not be deleted"""
        return False


@admin.register(SharedLink)
class SharedLinkAdmin(admin.ModelAdmin):
    list_display = ['file', 'owner', 'slug', 'status_display', 'download_count', 'max_downloads', 'created_at', 'expires_at']
    list_filter = ['is_active', 'is_email_only', 'created_at']
    search_fields = ['file__original_name', 'owner__email', 'slug', 'token']
    readonly_fields = ['slug', 'token', 'view_count', 'download_count', 'first_accessed_at', 'created_at']
    date_hierarchy = 'created_at'
    
    fieldsets = (
        ('Link Information', {
            'fields': ('file', 'owner', 'slug', 'token')
        }),
        ('Access Control', {
            'fields': ('is_active', 'is_email_only', 'max_downloads', 'expires_at')
        }),
        ('Statistics', {
            'fields': ('view_count', 'download_count', 'first_accessed_at', 'created_at')
        }),
    )

    def status_display(self, obj):
        """Display link status"""
        if obj.is_expired():
            return format_html('<span style="color: red;">🔴 Expired</span>')
        return format_html('<span style="color: green;">🟢 Active</span>')
    status_display.short_description = 'Status'


@admin.register(Trash)
class TrashAdmin(admin.ModelAdmin):
    list_display = ['file', 'deleted_at']
    list_filter = ['deleted_at']
    search_fields = ['file__original_name']
    readonly_fields = ['file', 'deleted_at']
    date_hierarchy = 'deleted_at'

    def has_add_permission(self, request):
        """Trash entries should be created automatically"""
        return False