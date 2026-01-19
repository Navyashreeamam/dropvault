# accounts/migrations/0003_fix_corrupted_passwords.py
"""
Fix corrupted passwords from old signup code.

Users affected: Those created before the fix who used api_signup
Issue: Passwords were double-hashed and cannot be verified
Solution: Mark these users to require password reset on next login
"""

from django.db import migrations
from django.contrib.auth.hashers import is_password_usable


def detect_and_fix_corrupted_passwords(apps, schema_editor):
    """
    Detect users with potentially corrupted passwords and mark them.
    
    Detection method:
    - Users with pbkdf2 hashes that have unusually long hash components
    - This indicates the hash was created from an already-hashed value
    """
    User = apps.get_model('auth', 'User')
    
    print("\n" + "=" * 70)
    print("🔧 FIXING CORRUPTED PASSWORDS")
    print("=" * 70)
    
    total_users = User.objects.count()
    corrupted_count = 0
    oauth_count = 0
    valid_count = 0
    
    for user in User.objects.all():
        password = user.password
        
        # Skip OAuth users (no password)
        if password == '!' or not password:
            oauth_count += 1
            continue
        
        # Check if password hash structure looks corrupted
        if password.startswith('pbkdf2_'):
            parts = password.split('$')
            
            # Normal hash: pbkdf2_sha256$iterations$salt$hash
            # Corrupted hash: hash part is unusually long (>60 chars)
            if len(parts) >= 4:
                hash_part = parts[-1]
                
                # Normal Django hash is ~44 chars, double-hashed is much longer
                if len(hash_part) > 60:
                    print(f"⚠️  Found corrupted password: {user.email}")
                    print(f"   Hash length: {len(hash_part)} (normal is ~44)")
                    
                    # Mark password as unusable (forces password reset)
                    user.set_unusable_password()
                    user.save(update_fields=['password'])
                    
                    corrupted_count += 1
                    print(f"   ✅ Marked for password reset")
                else:
                    valid_count += 1
            else:
                # Invalid structure - mark as unusable
                user.set_unusable_password()
                user.save(update_fields=['password'])
                corrupted_count += 1
        else:
            # Unknown format - mark as unusable
            user.set_unusable_password()
            user.save(update_fields=['password'])
            corrupted_count += 1
    
    print("\n" + "=" * 70)
    print(f"✅ Migration complete")
    print(f"   Total users: {total_users}")
    print(f"   Valid passwords: {valid_count}")
    print(f"   OAuth-only: {oauth_count}")
    print(f"   Corrupted (fixed): {corrupted_count}")
    print("=" * 70 + "\n")


def reverse_migration(apps, schema_editor):
    # Cannot reverse - passwords are already corrupted
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_alter_notification_options_alter_userprofile_options_and_more'),
    ]

    operations = [
        migrations.RunPython(
            detect_and_fix_corrupted_passwords,
            reverse_migration
        ),
    ]