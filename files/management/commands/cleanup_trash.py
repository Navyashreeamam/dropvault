# files/management/commands/cleanup_trash.py
from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from files.models import File
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Delete files that have been in trash for more than 30 days'

    def handle(self, *args, **options):
        cutoff_date = timezone.now() - timedelta(days=30)
        old_files = File.objects.filter(
            deleted=True,
            deleted_at__lt=cutoff_date
        )
        
        count = 0
        for file in old_files:
            try:
                # Delete physical file
                if file.file:
                    file.file.delete(save=False)
                # Delete database record
                file.delete()
                count += 1
            except Exception as e:
                logger.error(f"Failed to delete file {file.id}: {e}")
        
        self.stdout.write(
            self.style.SUCCESS(f'Successfully deleted {count} old files')
        )