from django.db import models
from django.contrib.auth.models import User
import uuid
import os

def user_upload_path(instance, filename):
    """Store as: media/user_<id>/<uuid>.<ext>"""
    ext = filename.split('.')[-1].lower()
    safe_name = f"{uuid.uuid4().hex}.{ext}"
    return os.path.join(f"user_{instance.user.id}", safe_name)

class File(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, db_index=True)
    file = models.FileField(upload_to=user_upload_path)
    original_name = models.CharField(max_length=255)
    size = models.PositiveBigIntegerField()
    uploaded_at = models.DateTimeField(auto_now_add=True)
    deleted = models.BooleanField(default=False, db_index=True)
    sha256 = models.CharField(max_length=64, db_index=True)

    class Meta:
        indexes = [
            models.Index(fields=['user', 'deleted']),
        ]

class Trash(models.Model):
    file = models.OneToOneField(File, on_delete=models.CASCADE)
    deleted_at = models.DateTimeField(auto_now_add=True)

class FileLog(models.Model):
    ACTIONS = [('UPLOAD', 'Upload'), ('DELETE', 'Delete'), ('RESTORE', 'Restore')]
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file = models.ForeignKey(File, on_delete=models.CASCADE)
    action = models.CharField(max_length=10, choices=ACTIONS)
    timestamp = models.DateTimeField(auto_now_add=True)