# test_auth.py
"""
Test authentication system
Run: python test_auth.py
"""

import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dropvault.settings')
django.setup()

from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.hashers import check_password

User = get_user_model()

def test_signup_and_login():
    print("=" * 70)
    print("🧪 TESTING AUTHENTICATION SYSTEM")
    print("=" * 70)
    
    # Test credentials
    test_email = "authtest@example.com"
    test_password = "TestPassword123"
    
    # Clean up old test user
    print("\n🧹 Cleaning up old test user...")
    User.objects.filter(email=test_email).delete()
    
    print("\n1️⃣ Creating user with create_user()...")
    try:
        user = User.objects.create_user(
            username='authtest',
            email=test_email,
            password=test_password,  # Raw password
            first_name='Auth',
            last_name='Test'
        )
        print(f"   ✅ User created: {user.email}")
        print(f"   Username: {user.username}")
        print(f"   Has usable password: {user.has_usable_password()}")
        print(f"   Password hash starts with: {user.password[:30]}...")
    except Exception as e:
        print(f"   ❌ User creation failed: {e}")
        return False
    
    print("\n2️⃣ Testing password verification (check_password)...")
    password_check = check_password(test_password, user.password)
    print(f"   Password: '{test_password}'")
    print(f"   Hash: {user.password[:50]}...")
    print(f"   ✅ Password check result: {password_check}")
    
    if not password_check:
        print("   ❌ PASSWORD CHECK FAILED!")
        print("   This means the password was not hashed correctly")
        return False
    
    print("\n3️⃣ Testing Django authenticate()...")
    auth_user = authenticate(username=user.username, password=test_password)
    print(f"   Username: {user.username}")
    print(f"   Password: {test_password}")
    print(f"   Authenticate result: {auth_user is not None}")
    
    if auth_user:
        print(f"   ✅ Authenticated as: {auth_user.email}")
    else:
        print("   ❌ AUTHENTICATION FAILED!")
        print("   Password check passed but authenticate failed")
        print("   This might be a backend configuration issue")
        return False
    
    print("\n4️⃣ Testing wrong password...")
    wrong_auth = authenticate(username=user.username, password='WrongPassword123')
    if wrong_auth is None:
        print("   ✅ Correctly rejected wrong password")
    else:
        print("   ❌ SECURITY ISSUE: Wrong password was accepted!")
        return False
    
    print("\n5️⃣ Testing email-based login (like your API does)...")
    try:
        found_user = User.objects.get(email=test_email)
        print(f"   ✅ Found user by email: {found_user.email}")
        
        email_password_check = check_password(test_password, found_user.password)
        print(f"   Password verification: {email_password_check}")
        
        if email_password_check:
            email_auth = authenticate(username=found_user.username, password=test_password)
            if email_auth:
                print(f"   ✅ Email-based login works!")
            else:
                print(f"   ❌ Email login: Password correct but authenticate failed")
                return False
        else:
            print(f"   ❌ Email login: Password verification failed")
            return False
            
    except User.DoesNotExist:
        print(f"   ❌ User not found by email")
        return False
    
    print("\n" + "=" * 70)
    print("✅ ALL TESTS PASSED!")
    print("=" * 70)
    print("\n💡 Your authentication system is working correctly!")
    print(f"   Test user created: {test_email}")
    print(f"   Password: {test_password}")
    print("\n🔧 You can now test the API:")
    print(f"   Signup: POST /api/signup/ with email={test_email}")
    print(f"   Login:  POST /api/login/ with email={test_email}")
    return True

if __name__ == "__main__":
    success = test_signup_and_login()
    if not success:
        print("\n" + "=" * 70)
        print("❌ TESTS FAILED - Check the errors above")
        print("=" * 70)