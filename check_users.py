# check_users.py
"""
Check which users have corrupted passwords from old signup code
"""

import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dropvault.settings')
django.setup()

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password, is_password_usable

User = get_user_model()

print("=" * 70)
print("🔍 CHECKING USER PASSWORD STATUS")
print("=" * 70)

users = User.objects.all().order_by('id')

print(f"\nTotal users: {users.count()}\n")

for user in users:
    print(f"User ID: {user.id}")
    print(f"Email: {user.email}")
    print(f"Username: {user.username}")
    print(f"Has usable password: {user.has_usable_password()}")
    print(f"Password hash: {user.password[:60]}...")
    
    # Check if it's a valid Django hash
    if user.password.startswith('pbkdf2_'):
        # Check if it looks double-hashed (hash of a hash)
        # Valid hashes have specific structure: pbkdf2_sha256$iterations$salt$hash
        parts = user.password.split('$')
        if len(parts) >= 4:
            print(f"Hash structure: VALID ({len(parts)} parts)")
            
            # Try to detect double-hashing
            # A double-hashed password will have a very long hash part
            hash_part = parts[-1]
            if len(hash_part) > 60:
                print(f"⚠️  WARNING: Hash part is unusually long ({len(hash_part)} chars)")
                print(f"   This might be a double-hashed password!")
                print(f"   🔧 ACTION REQUIRED: Reset this user's password")
            else:
                print(f"✅ Hash looks normal ({len(hash_part)} chars)")
        else:
            print(f"❌ INVALID hash structure ({len(parts)} parts)")
    elif user.password == '!':
        print("ℹ️  OAuth-only account (no password set)")
    else:
        print(f"❓ Unknown password format")
    
    print("-" * 70)

print("\n" + "=" * 70)
print("📊 SUMMARY")
print("=" * 70)

total = users.count()
with_password = users.exclude(password='!').count()
oauth_only = users.filter(password='!').count()

print(f"Total users: {total}")
print(f"With password: {with_password}")
print(f"OAuth-only: {oauth_only}")

print("\n💡 Users created BEFORE the fix may have corrupted passwords")
print("   They need to reset their password to login with email+password")