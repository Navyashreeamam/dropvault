from django.core.management.base import BaseCommand
from django.contrib.sites.models import Site
from django.conf import settings
import os


class Command(BaseCommand):
    help = 'Setup Django Site for production'

    def handle(self, *args, **options):
        # Get domain from environment
        railway_domain = os.environ.get('RAILWAY_STATIC_URL', '').replace('https://', '').replace('http://', '')
        
        if not railway_domain:
            railway_domain = 'dropvault-web-production.up.railway.app'
        
        site_id = getattr(settings, 'SITE_ID', 1)
        
        site, created = Site.objects.get_or_create(
            pk=site_id,
            defaults={
                'domain': railway_domain,
                'name': 'DropVault'
            }
        )
        
        if not created:
            site.domain = railway_domain
            site.name = 'DropVault'
            site.save()
            self.stdout.write(self.style.SUCCESS(f'✓ Updated site: {railway_domain}'))
        else:
            self.stdout.write(self.style.SUCCESS(f'✓ Created site: {railway_domain}'))