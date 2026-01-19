# fix_user_passwords.py
"""
Fix users with corrupted passwords by resetting them
"""

import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dropvault.settings')
django.setup()

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password

User = get_user_model()

print("=" * 70)
print("🔧 PASSWORD RESET UTILITY")
print("=" * 70)

def reset_user_password(email, new_password):
    """Reset a user's password correctly"""
    try:
        user = User.objects.get(email=email)
        print(f"\n📧 User: {user.email} (ID: {user.id})")
        print(f"   Current hash: {user.password[:50]}...")
        
        # Set new password CORRECTLY
        user.set_password(new_password)
        user.save()
        
        print(f"   ✅ New password set!")
        print(f"   New hash: {user.password[:50]}...")
        
        # Verify it works
        from django.contrib.auth.hashers import check_password
        verification = check_password(new_password, user.password)
        
        if verification:
            print(f"   ✅ Password verification: PASSED")
            print(f"\n   New login credentials:")
            print(f"   Email: {user.email}")
            print(f"   Password: {new_password}")
            return True
        else:
            print(f"   ❌ Password verification: FAILED")
            return False
            
    except User.DoesNotExist:
        print(f"❌ User not found: {email}")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

# Interactive mode
print("\nThis script will reset passwords for users with corrupted passwords")
print("from the old signup code.\n")

while True:
    print("\n" + "=" * 70)
    email = input("Enter user email (or 'quit' to exit): ").strip().lower()
    
    if email == 'quit':
        break
    
    if not email or '@' not in email:
        print("❌ Invalid email")
        continue
    
    try:
        user = User.objects.get(email=email)
        print(f"\n✅ Found user: {user.email}")
        print(f"   ID: {user.id}")
        print(f"   Username: {user.username}")
        print(f"   Name: {user.first_name} {user.last_name}")
        print(f"   Has password: {user.has_usable_password()}")
        
        confirm = input(f"\nReset password for this user? (yes/no): ").strip().lower()
        
        if confirm == 'yes':
            new_password = input("Enter new password (min 8 chars): ").strip()
            
            if len(new_password) < 8:
                print("❌ Password must be at least 8 characters")
                continue
            
            confirm_password = input("Confirm new password: ").strip()
            
            if new_password != confirm_password:
                print("❌ Passwords don't match")
                continue
            
            success = reset_user_password(email, new_password)
            
            if success:
                print("\n✅ SUCCESS! User can now login with:")
                print(f"   Email: {email}")
                print(f"   Password: {new_password}")
        else:
            print("❌ Cancelled")
            
    except User.DoesNotExist:
        print(f"❌ No user found with email: {email}")

print("\n" + "=" * 70)
print("✅ Password reset utility finished")
print("=" * 70)