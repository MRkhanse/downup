"""
test_sessions.py
Test multiple user sessions to check for session mixing issues
"""

import requests
import time
import json

# Base URL
BASE_URL = "http://127.0.0.1:5000"

# Test users (update with your actual users)
TEST_USERS = [
    {
        "name": "User One",
        "phone": "03123456789",  # Change to actual registered phone
        "password": "password123"
    },
    {
        "name": "User Two", 
        "phone": "03223456789",  # Change to actual registered phone
        "password": "password123"
    },
    {
        "name": "User Three",
        "phone": "03323456789",  # Change to actual registered phone
        "password": "password123"
    }
]

def test_user_session(user_data, session_num):
    """Test a single user session"""
    print(f"\n{'='*60}")
    print(f"Testing Session {session_num}: {user_data['name']}")
    print(f"{'='*60}")
    
    # Create a new session for this user
    session = requests.Session()
    
    try:
        # Step 1: Login
        print(f"1. Logging in as {user_data['phone']}...")
        login_response = session.post(
            f"{BASE_URL}/login",
            data={
                "phone": user_data["phone"],
                "password": user_data["password"]
            },
            allow_redirects=False
        )
        
        if login_response.status_code != 302:  # Expecting redirect
            print(f"   ❌ Login failed: Status {login_response.status_code}")
            print(f"   Response: {login_response.text[:200]}")
            return False
        
        print(f"   ✅ Login successful (redirected)")
        
        # Step 2: Get user dashboard
        print(f"2. Accessing dashboard...")
        time.sleep(1)  # Small delay
        
        dashboard_response = session.get(f"{BASE_URL}/user-dashboard")
        
        if dashboard_response.status_code == 200:
            print(f"   ✅ Dashboard loaded successfully")
            
            # Check if correct user data is shown
            if user_data["name"].lower() in dashboard_response.text.lower():
                print(f"   ✅ Correct user name found in dashboard")
            else:
                print(f"   ⚠️ User name not found in dashboard")
                
            # Check session info
            print(f"3. Checking session info...")
            session_response = session.get(f"{BASE_URL}/session-info")
            if session_response.status_code == 200:
                print(f"   ✅ Session info available")
            else:
                print(f"   ⚠️ No session info route")
                
        elif dashboard_response.status_code == 302:
            print(f"   ⚠️ Redirected (might need deposit/approval)")
        else:
            print(f"   ❌ Dashboard failed: Status {dashboard_response.status_code}")
            
        # Step 3: Get debug status
        print(f"4. Getting debug status...")
        debug_response = session.get(f"{BASE_URL}/debug-status")
        if debug_response.status_code == 200:
            print(f"   ✅ Debug info available")
            # Extract user ID from debug page
            import re
            user_id_match = re.search(r'User ID: (\d+)', debug_response.text)
            if user_id_match:
                user_id = user_id_match.group(1)
                print(f"   👤 User ID from debug: {user_id}")
        else:
            print(f"   ⚠️ Debug page not available")
            
        # Step 4: Check session cookies
        print(f"5. Session cookies:")
        for cookie in session.cookies:
            print(f"   🍪 {cookie.name}: {cookie.value[:20]}...")
            
        return True
        
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
        return False

def test_multiple_sessions_parallel():
    """Test multiple sessions in parallel (simulating multiple tabs)"""
    print(f"\n{'#'*60}")
    print("TESTING MULTIPLE SESSIONS IN PARALLEL")
    print(f"{'#'*60}")
    
    results = []
    
    # Test each user
    for i, user in enumerate(TEST_USERS, 1):
        result = test_user_session(user, i)
        results.append((user["name"], result))
        
        # Small delay between users
        if i < len(TEST_USERS):
            time.sleep(2)
    
    # Summary
    print(f"\n{'#'*60}")
    print("TEST SUMMARY")
    print(f"{'#'*60}")
    
    for user_name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{user_name}: {status}")
    
    # Test session mixing
    print(f"\n{'#'*60}")
    print("CHECKING FOR SESSION MIXING")
    print(f"{'#'*60}")
    
    # Create fresh sessions for all users
    all_sessions = []
    for user in TEST_USERS:
        s = requests.Session()
        s.post(f"{BASE_URL}/login", data=user)
        all_sessions.append((user["name"], s))
    
    # Now check if sessions are isolated
    print("Accessing dashboard with all sessions...")
    for user_name, sess in all_sessions:
        response = sess.get(f"{BASE_URL}/debug-status")
        if response.status_code == 200:
            print(f"{user_name}: Can access debug page")
        else:
            print(f"{user_name}: Cannot access debug page")

def test_session_isolation():
    """Specifically test session isolation"""
    print(f"\n{'#'*60}")
    print("SESSION ISOLATION TEST")
    print(f"{'#'*60}")
    
    # Create two independent sessions
    session1 = requests.Session()
    session2 = requests.Session()
    
    # Login different users to each session
    if len(TEST_USERS) >= 2:
        user1 = TEST_USERS[0]
        user2 = TEST_USERS[1]
        
        print(f"Session 1 logging in as: {user1['name']}")
        session1.post(f"{BASE_URL}/login", data=user1)
        
        print(f"Session 2 logging in as: {user2['name']}")
        session2.post(f"{BASE_URL}/login", data=user2)
        
        # Get session info from both
        print(f"\nChecking session isolation:")
        
        info1 = session1.get(f"{BASE_URL}/session-info").text if session1.get(f"{BASE_URL}/session-info").status_code == 200 else "No session info"
        info2 = session2.get(f"{BASE_URL}/session-info").text if session2.get(f"{BASE_URL}/session-info").status_code == 200 else "No session info"
        
        # Extract user IDs if possible
        import re
        user1_id = re.search(r'User ID: (\d+)', info1)
        user2_id = re.search(r'User ID: (\d+)', info2)
        
        if user1_id and user2_id:
            if user1_id.group(1) != user2_id.group(1):
                print("✅ Sessions are properly isolated (different User IDs)")
            else:
                print("❌ SESSIONS ARE MIXED! Same User ID in both sessions")
        else:
            print("⚠️ Could not verify session isolation")

def cleanup_test_users():
    """Clean up test users from database (admin function)"""
    print(f"\n{'#'*60}")
    print("CLEANING UP TEST USERS")
    print(f"{'#'*60}")
    
    # This would require admin login
    admin_session = requests.Session()
    
    # Admin login (update with your admin credentials)
    admin_creds = {
        "username": "admin",
        "password": "admin123"
    }
    
    print("Logging in as admin...")
    login_resp = admin_session.post(f"{BASE_URL}/admin/login", data=admin_creds)
    
    if login_resp.status_code == 302:
        print("✅ Admin login successful")
        
        # Get users page
        users_resp = admin_session.get(f"{BASE_URL}/admin/users")
        if users_resp.status_code == 200:
            print("✅ Accessed users page")
            # Here you would parse and delete test users
            # Implementation depends on your admin panel
    else:
        print("❌ Admin login failed")

if __name__ == "__main__":
    print("="*70)
    print("UPSIDE PLATFORM - SESSION TESTING TOOL")
    print("="*70)
    print("\nBefore running:")
    print("1. Make sure Flask server is running on http://127.0.0.1:5000")
    print("2. Update TEST_USERS with actual registered users")
    print("3. Ensure users have completed registration and approval")
    print("\n" + "="*70)
    
    try:
        # Test basic connectivity
        print("\nTesting server connectivity...")
        try:
            response = requests.get(BASE_URL, timeout=5)
            print(f"✅ Server is responding (Status: {response.status_code})")
        except:
            print(f"❌ Cannot connect to {BASE_URL}")
            print("Make sure Flask server is running!")
            exit(1)
        
        # Run tests
        choice = input("\nSelect test:\n1. Test single session\n2. Test multiple sessions\n3. Test session isolation\n4. Run all tests\nChoice (1-4): ").strip()
        
        if choice == "1":
            if TEST_USERS:
                test_user_session(TEST_USERS[0], 1)
        elif choice == "2":
            test_multiple_sessions_parallel()
        elif choice == "3":
            test_session_isolation()
        elif choice == "4":
            test_user_session(TEST_USERS[0], 1)
            test_multiple_sessions_parallel()
            test_session_isolation()
        else:
            print("Invalid choice")
            
        print(f"\n{'='*70}")
        print("TEST COMPLETE")
        print(f"{'='*70}")
        
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
    except Exception as e:
        print(f"\n❌ Error during testing: {str(e)}")