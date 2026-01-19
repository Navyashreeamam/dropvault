# accounts/management/commands/fix_user_passwords.py

from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password

User = get_user_model()


class Command(BaseCommand):
    help = 'Fix or check user passwords'

    def add_arguments(self, parser):
        parser.add_argument('--email', type=str, help='Specific user email')
        parser.add_argument('--password', type=str, help='New password to set')
        parser.add_argument('--list', action='store_true', help='List all users')
        parser.add_argument('--check', action='store_true', help='Check password status')

    def handle(self, *args, **options):
        if options['list']:
            self.list_users()
        elif options['email'] and options['password']:
            self.set_password(options['email'], options['password'])
        elif options['check']:
            self.check_all_users()
        else:
            self.stdout.write("Usage:")
            self.stdout.write("  --list                    List all users")
            self.stdout.write("  --check                   Check all users' password status")
            self.stdout.write("  --email X --password Y    Set password for user")

    def list_users(self):
        users = User.objects.all().order_by('id')
        self.stdout.write(f"\n{'ID':<5} {'Email':<40} {'Has Password':<15} {'Active':<8}")
        self.stdout.write("=" * 70)
        for user in users:
            self.stdout.write(
                f"{user.id:<5} {user.email:<40} {str(user.has_usable_password()):<15} {str(user.is_active):<8}"
            )

    def check_all_users(self):
        users = User.objects.all()
        self.stdout.write(f"\nTotal users: {users.count()}")
        
        no_password = users.filter(password__startswith='!').count()
        self.stdout.write(f"Users without usable password: {no_password}")
        
        for user in users:
            status = "✅" if user.has_usable_password() else "❌ NO PASSWORD"
            self.stdout.write(f"  {user.email}: {status}")

    def set_password(self, email, password):
        try:
            user = User.objects.get(email=email.lower())
            old_status = user.has_usable_password()
            
            user.set_password(password)
            user.save()
            
            # Verify
            verified = check_password(password, user.password)
            
            self.stdout.write(self.style.SUCCESS(
                f"\n✅ Password set for {email}"
                f"\n   Old had_password: {old_status}"
                f"\n   New verified: {verified}"
            ))
        except User.DoesNotExist:
            self.stdout.write(self.style.ERROR(f"❌ User not found: {email}"))