# core/management/commands/clean_trash.py
from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from files.models import Trash, File


class Command(BaseCommand):
    help = 'Permanently delete files in trash older than 30 days'

    def handle(self, *args, **options):
        cutoff = timezone.now() - timedelta(days=30)
        old_trash = Trash.objects.filter(deleted_at__lt=cutoff)
        count = old_trash.count()

        # Delete File entries + cascade to Trash (via on_delete=CASCADE)
        file_ids = old_trash.values_list('file_id', flat=True)
        File.objects.filter(id__in=file_ids).delete()  # CASCADE deletes Trash too

        self.stdout.write(
            self.style.SUCCESS(f'Purged {count} files from trash (older than 30 days).')
        )