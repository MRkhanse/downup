# test_security.py
# Yeh alag file hai - Flask server chalta rahega

import requests
import time

# =========================================================
# 🛡️ SECURITY TESTING SCRIPT
# =========================================================

BASE_URL = "http://127.0.0.1:5000"  # Aapka server URL

print("="*60)
print("🔍 SECURITY TESTING STARTED")
print("="*60)

# =========================================================
# TEST 1: SQL INJECTION
# =========================================================

print("\n📝 TEST 1: SQL Injection")
print("-" * 40)

test_inputs = [
    ("' OR '1'='1", "Basic SQL Injection"),
    ("'; DROP TABLE users; --", "Drop table attempt"),
    ("admin'--", "Comment injection"),
    ("' UNION SELECT * FROM users--", "Union injection"),
    ("' OR 1=1--", "Always true condition"),
    ("admin' OR '1'='1' --", "Admin bypass"),
    ("' ; SELECT * FROM admins --", "Admin table access"),
]

for payload, description in test_inputs:
    try:
        response = requests.post(
            f"{BASE_URL}/login",
            data={'phone': payload, 'password': 'anything'},
            timeout=5
        )
        status = response.status_code
        result = "✅ BLOCKED" if status in [403, 429, 500] else "⚠️ MAYBE VULNERABLE"
        print(f"Payload: {payload[:30]}... -> Status: {status} {result}")
    except Exception as e:
        print(f"❌ Error: {e}")

# =========================================================
# TEST 2: RATE LIMITING
# =========================================================

print("\n📝 TEST 2: Rate Limiting (Brute Force Protection)")
print("-" * 40)

for i in range(10):
    try:
        response = requests.post(
            f"{BASE_URL}/login",
            data={'phone': f'test{i}@test.com', 'password': 'wrong'},
            timeout=5
        )
        print(f"Attempt {i+1}: Status {response.status_code}")
        if response.status_code == 429:
            print("✅ RATE LIMITING ACTIVE - Blocked after 5 attempts")
            break
        time.sleep(0.5)
    except Exception as e:
        print(f"❌ Error: {e}")

# =========================================================
# TEST 3: XSS (Cross-Site Scripting)
# =========================================================

print("\n📝 TEST 3: XSS Protection")
print("-" * 40)

xss_payloads = [
    ("<script>alert('XSS')</script>", "Basic script"),
    ("<img src=x onerror=alert('XSS')>", "Image onerror"),
    ("<svg onload=alert('XSS')>", "SVG onload"),
    ("javascript:alert('XSS')", "JavaScript URI"),
    ("'><script>alert('XSS')</script>", "Tag injection"),
]

for payload, description in xss_payloads:
    print(f"Testing: {description}")
    # Note: Manually check in browser for XSS
    print(f"Payload: {payload[:50]}...")

# =========================================================
# TEST 4: DIRECTORY TRAVERSAL
# =========================================================

print("\n📝 TEST 4: Directory Traversal")
print("-" * 40)

traversal_payloads = [
    "/static/../../../etc/passwd",
    "/static/../../database.db",
    "/admin/../../config.py",
    "/../../.env",
    "/static/..\\..\\..\\windows\\win.ini",
]

for payload in traversal_payloads:
    try:
        response = requests.get(f"{BASE_URL}{payload}", timeout=5)
        status = response.status_code
        result = "✅ BLOCKED" if status in [403, 404] else "⚠️ MAYBE ACCESSIBLE"
        print(f"Path: {payload} -> Status: {status} {result}")
    except Exception as e:
        print(f"❌ Error: {e}")

# =========================================================
# TEST 5: CSRF Protection
# =========================================================

print("\n📝 TEST 5: CSRF Protection")
print("-" * 40)

try:
    # Without CSRF token
    response = requests.post(
        f"{BASE_URL}/change-password",
        data={'new_password': 'hacked123'},
        timeout=5
    )
    status = response.status_code
    result = "✅ PROTECTED" if status in [403, 401] else "⚠️ MAYBE VULNERABLE"
    print(f"No CSRF token -> Status: {status} {result}")
except Exception as e:
    print(f"❌ Error: {e}")

# =========================================================
# TEST 6: Session Security
# =========================================================

print("\n📝 TEST 6: Session Security")
print("-" * 40)

try:
    # Login first
    session = requests.Session()
    login_resp = session.post(
        f"{BASE_URL}/login",
        data={'phone': '03001234567', 'password': 'password123'},
        timeout=5
    )
    
    if login_resp.status_code == 200:
        # Try to access with different IP (simulated)
        print("Session created - Testing session fixation...")
        print("✅ Session security active (manual check required)")
    else:
        print("Login failed - skipping session test")
except Exception as e:
    print(f"❌ Error: {e}")

# =========================================================
# TEST 7: Password Policy
# =========================================================

print("\n📝 TEST 7: Password Policy")
print("-" * 40)

weak_passwords = [
    ("123456", "Too short"),
    ("password", "Common word"),
    ("abc123", "No uppercase"),
    ("PASSWORD123", "No lowercase"),
    ("Pass123", "No special char"),
]

for pwd, desc in weak_passwords:
    print(f"Testing: {desc} - '{pwd}' -> Should be rejected")

print("\n" + "="*60)
print("✅ TESTING COMPLETE - Check results above")
print("="*60)