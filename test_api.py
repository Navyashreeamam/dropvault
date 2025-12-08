# test_api.py
import requests
import os
import json

BASE_URL = "http://127.0.0.1:8000"

# Colors for output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"

def print_result(name, response):
    status = response.status_code
    if 200 <= status < 300:
        print(f"{GREEN}✅ {name}: {status}{RESET}")
    elif status == 401:
        print(f"{YELLOW}🔒 {name}: {status} (Auth Required){RESET}")
    else:
        print(f"{RED}❌ {name}: {status}{RESET}")
    
    try:
        print(f"   Response: {json.dumps(response.json(), indent=2)[:300]}")
    except:
        print(f"   Response: {response.text[:200]}")
    print()

# Store data between tests
test_data = {}

print(f"\n{BLUE}{'='*60}")
print("🧪 DROPVAULT API TEST SUITE")
print(f"{'='*60}{RESET}\n")

# ============ 1. SIGNUP ============
print(f"{YELLOW}📝 TEST 1: SIGNUP{RESET}")
print(f"   URL: POST {BASE_URL}/api/signup/")
response = requests.post(
    f"{BASE_URL}/api/signup/",
    json={
        "username": "apitest_user",
        "email": "apitest@example.com",
        "password": "Test@12345",
        "confirm_password": "Test@12345"
    },
    headers={"Content-Type": "application/json"}
)
print_result("Signup", response)

# ============ 2. LOGIN ============
print(f"{YELLOW}🔐 TEST 2: LOGIN{RESET}")
print(f"   URL: POST {BASE_URL}/api/login/")
response = requests.post(
    f"{BASE_URL}/api/login/",
    json={
        "username": "apitest_user",
        "password": "Test@12345"
    },
    headers={"Content-Type": "application/json"}
)
print_result("Login", response)

# Save token
try:
    data = response.json()
    # Try different token field names
    test_data["token"] = data.get("token") or data.get("key") or data.get("access") or data.get("auth_token")
    if test_data["token"]:
        print(f"   {GREEN}📌 Token saved: {test_data['token'][:30]}...{RESET}")
    else:
        print(f"   {YELLOW}⚠️ No token in response. Keys: {list(data.keys())}{RESET}")
except Exception as e:
    print(f"{RED}   ⚠️ Could not parse response: {e}{RESET}")
    test_data["token"] = None

# Auth header
headers = {"Content-Type": "application/json"}
if test_data.get("token"):
    headers["Authorization"] = f"Token {test_data['token']}"

# ============ 3. UPLOAD FILE ============
print(f"\n{YELLOW}📤 TEST 3: FILE UPLOAD{RESET}")
print(f"   URL: POST {BASE_URL}/api/upload/")

# Create a test file
test_file_content = "This is a test file for DropVault API testing! Created at: " + str(__import__('datetime').datetime.now())
with open("test_upload.txt", "w") as f:
    f.write(test_file_content)

upload_headers = {}
if test_data.get("token"):
    upload_headers["Authorization"] = f"Token {test_data['token']}"

with open("test_upload.txt", "rb") as f:
    response = requests.post(
        f"{BASE_URL}/api/upload/",
        headers=upload_headers,
        files={"file": ("test_upload.txt", f, "text/plain")}
    )
print_result("Upload", response)

# Save file ID
try:
    file_data = response.json()
    test_data["file_id"] = file_data.get("id") or file_data.get("file_id") or file_data.get("file", {}).get("id")
    if test_data["file_id"]:
        print(f"   {GREEN}📌 File ID: {test_data['file_id']}{RESET}")
except:
    test_data["file_id"] = 1

# ============ 4. LIST FILES ============
print(f"\n{YELLOW}📂 TEST 4: LIST FILES{RESET}")
print(f"   URL: GET {BASE_URL}/api/list/")
response = requests.get(
    f"{BASE_URL}/api/list/",
    headers=headers
)
print_result("List Files", response)

# ============ 5. CREATE SHARE LINK ============
print(f"\n{YELLOW}🔗 TEST 5: CREATE SHARE LINK{RESET}")
file_id = test_data.get("file_id", 1)
print(f"   URL: POST {BASE_URL}/api/share/{file_id}/")
response = requests.post(
    f"{BASE_URL}/api/share/{file_id}/",
    headers=headers,
    json={"expires_in_days": 7}
)
print_result("Create Share", response)

# Save share slug
try:
    share_data = response.json()
    test_data["share_slug"] = share_data.get("slug") or share_data.get("share_slug")
    test_data["share_url"] = share_data.get("share_url") or share_data.get("url")
    if test_data.get("share_url"):
        print(f"   {GREEN}📌 Share URL: {test_data['share_url']}{RESET}")
except:
    pass

# ============ 6. SHARE VIA EMAIL ============
print(f"\n{YELLOW}📧 TEST 6: SHARE VIA EMAIL{RESET}")
print(f"   URL: POST {BASE_URL}/api/share/{file_id}/email/")
response = requests.post(
    f"{BASE_URL}/api/share/{file_id}/email/",
    headers=headers,
    json={
        "recipient_email": "friend@example.com",
        "message": "Check this file!"
    }
)
print_result("Share Email", response)

# ============ 7. ACCESS SHARED FILE ============
if test_data.get("share_slug"):
    print(f"\n{YELLOW}🌐 TEST 7: ACCESS SHARED FILE{RESET}")
    print(f"   URL: GET {BASE_URL}/s/{test_data['share_slug']}/")
    response = requests.get(f"{BASE_URL}/s/{test_data['share_slug']}/")
    print_result("Access Share", response)
else:
    print(f"\n{YELLOW}🌐 TEST 7: ACCESS SHARED FILE - SKIPPED (no share slug){RESET}")

# ============ 8. DELETE FILE (SOFT DELETE) ============
print(f"\n{YELLOW}🗑️ TEST 8: DELETE FILE{RESET}")
print(f"   URL: DELETE {BASE_URL}/api/delete/{file_id}/")
response = requests.delete(
    f"{BASE_URL}/api/delete/{file_id}/",
    headers=headers
)
print_result("Delete", response)

# ============ 9. VIEW TRASH ============
print(f"\n{YELLOW}🗑️ TEST 9: VIEW TRASH{RESET}")
print(f"   URL: GET {BASE_URL}/api/trash/")
response = requests.get(
    f"{BASE_URL}/api/trash/",
    headers=headers
)
print_result("Trash List", response)

# ============ 10. RESTORE FILE ============
print(f"\n{YELLOW}♻️ TEST 10: RESTORE FILE{RESET}")
print(f"   URL: POST {BASE_URL}/api/restore/{file_id}/")
response = requests.post(
    f"{BASE_URL}/api/restore/{file_id}/",
    headers=headers
)
print_result("Restore", response)

# ============ CLEANUP ============
try:
    os.remove("test_upload.txt")
except:
    pass

# ============ SUMMARY ============
print(f"\n{BLUE}{'='*60}")
print("📊 TEST SUMMARY")
print(f"{'='*60}{RESET}")
print(f"""
{GREEN}API ENDPOINTS TESTED:{RESET}

AUTH:
  POST  /api/signup/           - User registration
  POST  /api/login/            - User login (get token)
  
FILES:
  POST  /api/upload/           - Upload file
  GET   /api/list/             - List user files
  DEL   /api/delete/<id>/      - Soft delete file
  GET   /api/trash/            - View deleted files
  POST  /api/restore/<id>/     - Restore deleted file
  
SHARING:
  POST  /api/share/<id>/       - Create share link
  POST  /api/share/<id>/email/ - Share via email
  GET   /s/<slug>/             - Access shared file

{YELLOW}WEB PAGES (HTML):{RESET}
  GET   /                      - Home
  GET   /dashboard/            - Dashboard
  GET   /accounts/signup/      - Signup form
  GET   /accounts/login/       - Login form
  GET   /accounts/logout/      - Logout
""")
print(f"{GREEN}✅ Testing Complete!{RESET}\n")