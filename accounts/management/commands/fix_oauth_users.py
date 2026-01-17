# accounts/management/commands/fix_oauth_users.py
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
import secrets


class Command(BaseCommand):
    help = 'Fix OAuth users who have no password by setting a random password'

    def handle(self, *args, **kwargs):
        # Find all users without usable passwords
        users_to_fix = []
        
        for user in User.objects.all():
            if not user.has_usable_password():
                users_to_fix.append(user)
        
        if not users_to_fix:
            self.stdout.write(
                self.style.SUCCESS('✅ All users already have passwords!')
            )
            return
        
        self.stdout.write(f'Found {len(users_to_fix)} users without passwords:')
        
        for user in users_to_fix:
            # Set random password
            random_password = secrets.token_urlsafe(16)
            user.set_password(random_password)
            user.save()
            
            self.stdout.write(
                self.style.SUCCESS(f'✅ Fixed user: {user.email} (username: {user.username})')
            )
        
        self.stdout.write('')
        self.stdout.write(
            self.style.SUCCESS(f'✅ Successfully fixed {len(users_to_fix)} users!')
        )
        self.stdout.write('')
        self.stdout.write('📝 Note: Users can now login with Google, then set their own password in Settings.')