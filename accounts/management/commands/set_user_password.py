# accounts/management/commands/set_user_password.py
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User


class Command(BaseCommand):
    help = 'Set password for a user (useful for OAuth users)'

    def add_arguments(self, parser):
        parser.add_argument('email', type=str, help='User email address')
        parser.add_argument('password', type=str, help='New password')

    def handle(self, *args, **kwargs):
        email = kwargs['email']
        password = kwargs['password']
        
        try:
            user = User.objects.get(email=email)
            
            self.stdout.write(f"Found user: {user.username} ({user.email})")
            self.stdout.write(f"Current password status: {user.has_usable_password()}")
            
            # Set password
            user.set_password(password)
            user.save()
            
            self.stdout.write(
                self.style.SUCCESS(f'✅ Password successfully set for: {user.email}')
            )
            self.stdout.write(f'   Username: {user.username}')
            self.stdout.write(f'   Has usable password: {user.has_usable_password()}')
            self.stdout.write(f'   User can now login with email + password')
            
        except User.DoesNotExist:
            self.stdout.write(
                self.style.ERROR(f'❌ User not found with email: {email}')
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'❌ Error: {str(e)}')
            )