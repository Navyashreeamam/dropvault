# accounts/management/commands/set_password.py
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User


class Command(BaseCommand):
    help = 'Set password for a user'

    def add_arguments(self, parser):
        parser.add_argument('email', type=str, help='User email')
        parser.add_argument('password', type=str, help='New password')

    def handle(self, *args, **kwargs):
        email = kwargs['email']
        password = kwargs['password']
        
        try:
            user = User.objects.get(email=email)
            user.set_password(password)
            user.save()
            
            self.stdout.write(
                self.style.SUCCESS(f'✅ Password set for user: {user.email}')
            )
            self.stdout.write(f'   Username: {user.username}')
            self.stdout.write(f'   Has usable password: {user.has_usable_password()}')
            
        except User.DoesNotExist:
            self.stdout.write(
                self.style.ERROR(f'❌ User not found: {email}')
            )