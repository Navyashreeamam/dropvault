# dropvault/files/serializers.py

from rest_framework import serializers
from .models import File, SharedLink


class SharedLinkSerializer(serializers.ModelSerializer):
    file_name = serializers.CharField(source='file.original_name', read_only=True)
    file_size = serializers.IntegerField(source='file.size', read_only=True)
    link = serializers.SerializerMethodField()
    expires_at = serializers.DateTimeField(read_only=True)

    class Meta:
        model = SharedLink
        fields = [
            'slug', 'file_name', 'file_size',
            'max_downloads', 'view_count', 'download_count',
            'expires_at', 'link'
        ]

    def get_link(self, obj):
        request = self.context.get('request')
        if request:
            return request.build_absolute_uri(f"/s/{obj.slug}/")
        return f"/s/{obj.slug}/"