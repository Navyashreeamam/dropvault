# files/storage.py
"""
Custom Cloudinary storage backend that uploads files directly to Cloudinary
without using django-cloudinary-storage package
"""
import cloudinary
import cloudinary.uploader
from django.core.files.storage import Storage
from django.conf import settings
from django.utils.decoding import force_str
from urllib.parse import urljoin


class CloudinaryStorage(Storage):
    """Custom Cloudinary storage backend"""
    
    def __init__(self):
        self.cloud_name = settings.CLOUDINARY_CLOUD_NAME
        self.api_key = settings.CLOUDINARY_API_KEY
        self.api_secret = settings.CLOUDINARY_API_SECRET
    
    def _save(self, name, content):
        """Save file to Cloudinary"""
        try:
            # Upload to Cloudinary
            result = cloudinary.uploader.upload(
                content,
                folder='dropvault',
                use_filename=True,
                unique_filename=True,
                resource_type='auto'
            )
            
            # Return the public_id (we'll use this as the name)
            return result.get('public_id', name)
        except Exception as e:
            print(f"Cloudinary upload error: {e}")
            raise
    
    def _open(self, name, mode='rb'):
        """
        Retrieve file from Cloudinary.
        For download, we'll use the URL directly.
        """
        # Return None since we'll use URLs for retrieval
        return None
    
    def url(self, name):
        """Generate Cloudinary URL for the file"""
        try:
            # Generate secure URL
            url = cloudinary.utils.cloudinary_url(
                name,
                secure=True,
                resource_type='auto'
            )[0]
            return url
        except Exception as e:
            print(f"Error generating Cloudinary URL: {e}")
            return None
    
    def exists(self, name):
        """Check if file exists in Cloudinary"""
        try:
            cloudinary.api.resource(name)
            return True
        except:
            return False
    
    def delete(self, name):
        """Delete file from Cloudinary"""
        try:
            cloudinary.uploader.destroy(name)
        except Exception as e:
            print(f"Error deleting from Cloudinary: {e}")
    
    def size(self, name):
        """Get file size from Cloudinary"""
        try:
            resource = cloudinary.api.resource(name)
            return resource.get('bytes', 0)
        except:
            return 0