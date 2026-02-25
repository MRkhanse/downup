# =========================================================
# UPSIDE MVP - OPTIMIZED ADMIN PANEL
# =========================================================
from flask import Flask, render_template, request, redirect, session, flash, jsonify, url_for, abort  # ✅ ADDED abort
from flask import Flask, render_template, request, redirect, session, flash, jsonify, url_for
import sqlite3, re, os, json
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps 
from datetime import datetime, timedelta
import requests
from bs4 import BeautifulSoup
import requests
from urllib.parse import urlparse
import re
# UPSIDE MVP - OPTIMIZED ADMIN PANEL
# =========================================================
# =========================================================
# 🔐 SECURITY IMPORTS
# =========================================================

import secrets
import hashlib
import time
from collections import defaultdict
import hmac
import bleach
import ipaddress

# =========================================================
# ✅ CREATE FLASK APP
# =========================================================
app = Flask(__name__)
app.secret_key = "super-secret-key-2024-upside"

# =========================================================
# 🔥 RATE LIMITING PROTECTION
# =========================================================

# Rate limiter storage
rate_limits = defaultdict(list)

def check_rate_limit(key, max_attempts=5, window=300):
    """Check rate limit"""
    now = time.time()
    
    # Clean old attempts
    rate_limits[key] = [t for t in rate_limits[key] if now - t < window]
    
    if len(rate_limits[key]) >= max_attempts:
        return False
    
    rate_limits[key].append(now)
    return True

def rate_limit(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = request.remote_addr
        key = f"{ip}:{request.path}"
        
        if not check_rate_limit(key):
            flash("Too many attempts. Try again later.", "error")
            return redirect(request.referrer or "/")
        
        return f(*args, **kwargs)
    return decorated

# =========================================================
# 🔥 CSRF PROTECTION
# =========================================================

def generate_csrf_token():
    """Generate CSRF token"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf_token(token):
    """Validate CSRF token"""
    return 'csrf_token' in session and hmac.compare_digest(
        session['csrf_token'], token
    )

def csrf_protect(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == "POST":
            token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
            if not token or not validate_csrf_token(token):
                abort(403, "Invalid CSRF token")
        return f(*args, **kwargs)
    return decorated

# Add CSRF token to all templates
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf_token)

# =========================================================
# 🔥 XSS PROTECTION
# =========================================================

def sanitize_input(data):
    """Remove XSS from input"""
    if isinstance(data, str):
        # Remove all HTML tags
        return bleach.clean(data, tags=[], attributes={}, strip=True)
    elif isinstance(data, dict):
        return {k: sanitize_input(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_input(item) for item in data]
    return data

@app.before_request
def sanitize_all_inputs():
    """Sanitize all incoming data"""
    if request.method == "POST":
        # Sanitize form data
        if hasattr(request, 'form') and request.form:
            # Create a mutable copy
            form_data = request.form.to_dict()
            for key in form_data:
                form_data[key] = sanitize_input(form_data[key])
            request.form = form_data
        
        # Sanitize JSON data
        if request.is_json:
            request.json = sanitize_input(request.get_json())

# =========================================================
# 🔥 PASSWORD POLICY
# =========================================================

def validate_password(password):
    """Check password strength"""
    errors = []
    
    if len(password) < 8:
        errors.append("Password must be at least 8 characters")
    
    if not any(c.isupper() for c in password):
        errors.append("Password must contain uppercase letter")
    
    if not any(c.islower() for c in password):
        errors.append("Password must contain lowercase letter")
    
    if not any(c.isdigit() for c in password):
        errors.append("Password must contain number")
    
    if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
        errors.append("Password must contain special character")
    
    return errors

# =========================================================
# 🔥 SECURE SESSION MANAGEMENT
# =========================================================

def create_secure_session(user_id, role='user'):
    """Create secure session"""
    session.permanent = True
    app.permanent_session_lifetime = timedelta(hours=2)
    
    session['user_id'] = user_id
    session['role'] = role
    session['ip'] = request.remote_addr
    session['user_agent'] = request.user_agent.string
    session['login_time'] = time.time()
    session['session_id'] = secrets.token_hex(16)

def validate_session():
    """Check if session is valid"""
    if 'user_id' not in session:
        return False
    
    # Check IP
    if session.get('ip') != request.remote_addr:
        print(f"⚠️ IP mismatch - possible hijack")
        session.clear()
        return False
    
    # Check User-Agent
    if session.get('user_agent') != request.user_agent.string:
        print(f"⚠️ User-Agent mismatch - possible hijack")
        session.clear()
        return False
    
    # Check session age
    login_time = session.get('login_time', 0)
    if time.time() - login_time > 7200:  # 2 hours
        session.clear()
        flash("Session expired", "error")
        return False
    
    return True

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not validate_session():
            flash("Please login first", "error")
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin"):
            flash("Admin access required", "error")
            return redirect("/admin/login")
        
        if not validate_session():
            session.clear()
            return redirect("/admin/login")
        
        return f(*args, **kwargs)
    return decorated

# =========================================================
# 🔥 IP SECURITY
# =========================================================

class IPSecurity:
    """IP-based security"""
    
    BLACKLIST = set()  # Blocked IPs
    WHITELIST = {'127.0.0.1', '::1'}  # Allowed IPs
    
    @classmethod
    def check_ip(cls, ip):
        """Check if IP is allowed"""
        if ip in cls.BLACKLIST:
            return False
        
        # Admin routes ke liye whitelist (optional)
        if request.path.startswith('/admin') and ip not in cls.WHITELIST:
            # Comment this out if you want admin accessible from all IPs
            # return False
            pass
        
        return True

@app.before_request
def ip_security_check():
    """Check IP before any request"""
    ip = request.remote_addr
    
    if not IPSecurity.check_ip(ip):
        abort(403, "Access denied from your location")

# =========================================================
# 🔥 HONEYPOT TRAPS
# =========================================================

class Honeypot:
    """Hackers ko trap karo"""
    
    @staticmethod
    def add_honeypot():
        """Add hidden honeypot field to forms"""
        return '<input type="text" name="honeypot" value="" style="position:absolute; left:-9999px; top:-9999px;" tabindex="-1" autocomplete="off">'
    
    @staticmethod
    def check_honeypot():
        """Check if honeypot was triggered"""
        if request.form.get('honeypot'):
            # Bot detected!
            ip = request.remote_addr
            print(f"🚨 HONEYPOT TRIGGERED by {ip}")
            
            # Block IP
            IPSecurity.BLACKLIST.add(ip)
            
            abort(403, "Bot detected")

@app.before_request
def check_honeypot():
    """Check honeypot on POST requests"""
    if request.method == 'POST' and 'honeypot' in request.form:
        Honeypot.check_honeypot()

# =========================================================
# 🔥 AUDIT LOGGING
# =========================================================

class AuditLogger:
    """Sab kuch log karo"""
    
    @staticmethod
    def log(action, user_id=None, details=None):
        """Log all important actions"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'ip': request.remote_addr,
            'user_agent': request.user_agent.string,
            'path': request.path,
            'method': request.method,
            'user_id': user_id or session.get('user_id'),
            'action': action,
            'details': details
        }
        
        # Log to file
        try:
            with open('audit.log', 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except:
            pass
        
        # Print important actions
        if action in ['LOGIN_FAILED', 'UNAUTHORIZED_ACCESS']:
            print(f"🚨 {action}: {details} from {request.remote_addr}")

# =========================================================
# 🔥 SECURE DECORATOR (Combines all protections)
# =========================================================

def super_secure(f):
    """ULTIMATE security decorator"""
    @wraps(f)
    @rate_limit
    def decorated(*args, **kwargs):
        # IP check
        if not IPSecurity.check_ip(request.remote_addr):
            AuditLogger.log('BLOCKED_IP', details={'ip': request.remote_addr})
            abort(403)
        
        # Session check (if login required)
        if hasattr(f, '__name__') and f.__name__ not in ['login', 'register']:
            if not validate_session():
                return redirect("/login")
        
        # Log access
        AuditLogger.log('PAGE_ACCESS', details={'path': request.path})
        
        return f(*args, **kwargs)
    return decorated

# =========================================================
# 🔥 FIX FOR PYLANCE ERROR (pyotp is optional)
# =========================================================

# pyotp is optional - if you want 2FA, install it:
# pip install pyotp

try:
    import pyotp
    TWO_FA_AVAILABLE = True
except ImportError:
    TWO_FA_AVAILABLE = False
    # Define dummy functions so code doesn't break
    class pyotp:
        @staticmethod
        def random_base32():
            return secrets.token_hex(16)
        class TOTP:
            def __init__(self, secret):
                self.secret = secret
            def verify(self, code):
                return False

# =========================================================
# ✅ CONTEXT PROCESSORS
# =========================================================

@app.context_processor
def inject_now():
    return {'now': datetime.now()}

@app.template_filter('calculate_percent')
def calculate_percent(completed, total):
    if total and total > 0:
        return (completed / total) * 100
    return 0


# ... your existing get_db(), init_db(), and all routes ...
# =========================================================
# DATABASE SETUP - OPTIMIZED
# =========================================================

def get_db():
    """Get database connection with proper error handling"""
    try:
        conn = sqlite3.connect(
            "database.db", 
            timeout=30,
            check_same_thread=False
        )
        conn.row_factory = sqlite3.Row
        # Enable WAL mode for better concurrency
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn
    except Exception as e:
        print(f"❌ Database connection error: {e}")
        raise

def init_db():
    """Initialize database tables"""
    db = get_db()
    try:
        # Users table
        # In your init_db() function
        db.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        selected_package TEXT,
        package_amount INTEGER DEFAULT 0,
        daily_reward INTEGER DEFAULT 0,
        deposit_status TEXT DEFAULT 'pending',
        is_active INTEGER DEFAULT 0,
        balance INTEGER DEFAULT 0,           
        earning_balance INTEGER DEFAULT 0,    
        deposit_tx_id TEXT,
        deposit_screenshot TEXT,
        rejection_reason TEXT,
        show_rejection INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
""")
        
        # Deposit requests table
        db.execute("""
            CREATE TABLE IF NOT EXISTS deposit_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                name TEXT,
                phone TEXT,
                selected_package TEXT,
                package_amount INTEGER,
                daily_reward INTEGER,
                deposit_tx_id TEXT,
                status TEXT DEFAULT 'pending',
                admin_notes TEXT,
                rejected_at DATETIME,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        
        
        # Admins table
        db.execute("""
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)
        
        # WITHDRAWALS TABLE - ADD THIS
        db.execute("""
            CREATE TABLE IF NOT EXISTS withdrawals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                user_name TEXT NOT NULL,
                user_phone TEXT NOT NULL,
                amount INTEGER NOT NULL,
                processing_fee INTEGER DEFAULT 0,
                net_amount INTEGER NOT NULL,
                method TEXT NOT NULL,
                account_number TEXT NOT NULL,
                account_name TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                admin_notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                processed_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        # =========================================================
# ADD BALANCE TRANSACTIONS TABLE TO init_db()
# =========================================================

        # Balance transactions audit log
        db.execute("""
            CREATE TABLE IF NOT EXISTS balance_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                user_name TEXT NOT NULL,
                previous_balance INTEGER NOT NULL,
                amount INTEGER NOT NULL,
                new_balance INTEGER NOT NULL,
                transaction_type TEXT NOT NULL, -- 'credit' or 'debit'
                reason TEXT NOT NULL,
                admin_username TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        # User sessions table for rejection tracking
        db.execute("""
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_type TEXT NOT NULL,
                session_data TEXT,
                expires_at DATETIME NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
      
        
        # Available ads for all users
        db.execute("""
        CREATE TABLE IF NOT EXISTS available_ads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ad_name TEXT NOT NULL,
            ad_description TEXT,
            ad_url TEXT,
            duration_seconds INTEGER DEFAULT 30,
            reward_amount INTEGER DEFAULT 100,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
                   
    """)
        
        # User ad watching progress
        db.execute("""
        CREATE TABLE IF NOT EXISTS user_ad_progress (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            ad_id INTEGER NOT NULL,
            watched_date DATE NOT NULL,
            is_completed INTEGER DEFAULT 0,
            completed_at TIMESTAMP,
            reward_credited INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
        
        # Admin notifications for completed ads
        db.execute("""
    CREATE TABLE IF NOT EXISTS ad_completion_notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        user_name TEXT NOT NULL,
        user_phone TEXT NOT NULL,
        user_balance INTEGER DEFAULT 0,
        ad_id INTEGER NOT NULL,
        ad_name TEXT NOT NULL,
        reward_amount INTEGER DEFAULT 0,
        watched_seconds INTEGER DEFAULT 0,
        date_completed DATE NOT NULL,
        is_processed INTEGER DEFAULT 0,
        processed_by_admin TEXT,
        processed_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
""")
        
        # Add some sample ads
        existing_ads = db.execute("SELECT COUNT(*) as count FROM available_ads").fetchone()["count"]
        if existing_ads == 0:
            sample_ads = [
                ("Product Demo", "Watch product demonstration", "https://example.com/ad1", 30, 100),
                ("Brand Promotion", "Brand awareness video", "https://example.com/ad2", 30, 100),
                ("Service Ad", "Service promotion video", "https://example.com/ad3", 30, 100),
                ("Special Offer", "Limited time offer", "https://example.com/ad4", 30, 100),
                ("New Product", "New product launch", "https://example.com/ad5", 30, 100),
            ]
            for ad in sample_ads:
                db.execute(
                    "INSERT INTO available_ads (ad_name, ad_description, ad_url, duration_seconds, reward_amount) VALUES (?, ?, ?, ?, ?)",
                    ad
                )
        
# USDT Address Table (Admin controlled)
        db.execute("""
            CREATE TABLE IF NOT EXISTS admin_usdt_address (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address TEXT NOT NULL,
                network TEXT DEFAULT 'TRC20',
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Insert default USDT address if none exists
        existing = db.execute("SELECT COUNT(*) as count FROM admin_usdt_address").fetchone()["count"]
        if existing == 0:
            db.execute(
                "INSERT INTO admin_usdt_address (address, network) VALUES (?, ?)",
                ("TY76gVBsH9hK9P5J8n7mLQpTqN4EckRqj2", "TRC20")
            )
        
        # 🆕 Deposit Address History (for audit)
        db.execute("""
            CREATE TABLE IF NOT EXISTS deposit_address_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                deposit_tx_id TEXT NOT NULL,
                usdt_address TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
         # Password Reset Requests Table
        db.execute("""
            CREATE TABLE IF NOT EXISTS password_reset_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                user_name TEXT NOT NULL,
                user_phone TEXT NOT NULL,
                status TEXT DEFAULT 'pending', -- pending, approved, rejected
                new_password TEXT, -- Temporary field for admin to set password
                admin_notes TEXT,
                requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                processed_at TIMESTAMP,
                processed_by TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        # Password History (for security)
        db.execute("""
            CREATE TABLE IF NOT EXISTS password_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                password_hash TEXT NOT NULL,
                changed_by TEXT DEFAULT 'user',
                changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        db.execute("""
    CREATE TABLE IF NOT EXISTS support_tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        user_name TEXT NOT NULL,
        user_phone TEXT NOT NULL,
        subject TEXT NOT NULL,
        message TEXT NOT NULL,
        status TEXT DEFAULT 'open',
        admin_response TEXT,
        responded_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        closed_at TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
""")
        


        db.commit()
       

        # Default admin (admin/admin123)
        try:
            existing = db.execute("SELECT * FROM admins WHERE username='admin'").fetchone()
            if not existing:
                db.execute(
                    "INSERT INTO admins (username, password) VALUES (?, ?)",
                    ("admin", generate_password_hash("admin123"))
                )
        except:
            pass  # Table might not exist yet
        
        db.commit()
        print("✅ Database initialized successfully")
    except Exception as e:
        print(f"❌ Database init error: {e}")
        db.rollback()
        raise
    finally:
        db.close()

init_db()
# Add these columns to users table in init_db()
def init_db():
    db = get_db()
    try:
        # Add new columns if they don't exist
        columns = db.execute("PRAGMA table_info(users)").fetchall()
        column_names = [col[1] for col in columns]
        
        if 'package_amount' not in column_names:
            db.execute("ALTER TABLE users ADD COLUMN package_amount INTEGER DEFAULT 0")
        
        if 'package_lock_until' not in column_names:
            db.execute("ALTER TABLE users ADD COLUMN package_lock_until DATE")
        
        if 'withdrawable_balance' not in column_names:
            db.execute("ALTER TABLE users ADD COLUMN withdrawable_balance INTEGER DEFAULT 0")
        
        if 'locked_balance' not in column_names:
            db.execute("ALTER TABLE users ADD COLUMN locked_balance INTEGER DEFAULT 0")
        
        db.commit()
        print("✅ Database schema updated")
    except Exception as e:
        print(f"❌ Error updating schema: {e}")
    finally:
        db.close()


# =========================================================
# DECORATORS - OPTIMIZED
# =========================================================

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login first", "error")
            return redirect("/login")
        
        # Check if user still exists in database
        user = get_user(session["user_id"])
        if not user:
            # User was deleted, clear session
            session.clear()
            flash("Your account has been deleted", "error")
            return redirect("/login")
            
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin"):
            flash("Admin access required", "error")
            return redirect("/admin/login")
        return f(*args, **kwargs)
    return decorated

# =========================================================
# HELPERS - OPTIMIZED
# =========================================================
# 📁 app.py - Helper functions section me yeh ADD karein

def get_active_usdt_address():
    """Get current active USDT address from database"""
    db = get_db()
    try:
        address = db.execute("""
            SELECT address FROM admin_usdt_address 
            WHERE is_active = 1 
            ORDER BY created_at DESC 
            LIMIT 1
        """).fetchone()
        
        if address:
            return address["address"]
        else:
            # Fallback address
            return "TY76gVBsH9hK9P5J8n7mLQpTqN4EckRqj2"
    except Exception as e:
        print(f"Error getting USDT address: {e}")
        return "TY76gVBsH9hK9P5J8n7mLQpTqN4EckRqj2"
    finally:
        db.close()

def record_deposit_address(user_id, tx_id, usdt_address):
    """Record which address user sent deposit to"""
    db = get_db()
    try:
        db.execute("""
            INSERT INTO deposit_address_history 
            (user_id, deposit_tx_id, usdt_address)
            VALUES (?, ?, ?)
        """, (user_id, tx_id, usdt_address))
        db.commit()
    except Exception as e:
        print(f"Error recording deposit address: {e}")
    finally:
        db.close()

def get_user(user_id):
    """Get user by ID with error handling - FIXED"""
    if not user_id:
        return None
    
    db = get_db()
    try:
        user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if user:
            return dict(user)  # Convert Row to dict
        else:
            print(f"⚠️ User {user_id} not found in database")
            return None
    except Exception as e:
        print(f"❌ Error getting user {user_id}: {e}")
        return None
    finally:
        db.close()

def assign_ads_to_user(user_id):
    """Assign 5 ads to user - FIXED: Missing db.close()"""
    db = get_db()
    try:
        user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if user:
            reward_per_ad = user['daily_reward'] // 5 if user['daily_reward'] > 0 else 100
            for i in range(1, 6):
                db.execute(
                    "INSERT INTO user_ads (user_id, ad_name, reward_amount) VALUES (?, ?, ?)",
                    (user_id, f"Ad #{i}", reward_per_ad)
                )
            db.commit()
    except Exception as e:
        print(f"❌ Error assigning ads: {e}")
    finally:
        db.close()

# =========================================================
# USER ROUTES - OPTIMIZED
# =========================================================

@app.route("/")
def landing():
    return render_template("home.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        # Validation
        if not name:
            flash("Name required", "error")
            return redirect("/register")
        if not re.match(r"^03\d{9}$", phone):
            flash("Invalid phone number format (03XXXXXXXXX)", "error")
            return redirect("/register")
        if len(password) < 6:
            flash("Password must be at least 6 characters", "error")
            return redirect("/register")
        if password != confirm:
            flash("Passwords do not match", "error")
            return redirect("/register")

        try:
            db = get_db()
            db.execute(
                "INSERT INTO users (name, phone, password) VALUES (?,?,?)",
                (name, phone, generate_password_hash(password))
            )
            db.commit()
            user = db.execute("SELECT id FROM users WHERE phone=?", (phone,)).fetchone()
            session["user_id"] = user["id"]
            session["user_name"] = name
            flash("Registration successful!", "success")
            return redirect("/select-package")
        except sqlite3.IntegrityError:
            flash("Phone number already registered", "error")
            return redirect("/register")
        except Exception as e:
            flash(f"Registration error: {str(e)}", "error")
            return redirect("/register")
        finally:
            db.close()
    
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        
        if not phone or not password:
            flash("Phone and password required", "error")
            return redirect("/login")
        
        db = get_db()
        try:
            user = db.execute("SELECT * FROM users WHERE phone=?", (phone,)).fetchone()
            
            if not user or not check_password_hash(user["password"], password):
                flash("Invalid credentials", "error")
                return redirect("/login")
            
            # Set session
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            
            # Check if user needs to see rejection page
            if user["show_rejection"] == 1 and user["deposit_status"] == "rejected":
                return redirect("/deposit-rejected")
            
            # Redirect based on status - FIXED: changed /rejected to /deposit-rejected
            if not user["selected_package"]:
                return redirect("/select-package")
            elif user["deposit_status"] == "submitted" and user["is_active"] != 1:
                return redirect("/waiting-approval")
            elif user["deposit_status"] == "rejected":  # FIXED LINE
                return redirect("/deposit-rejected")  # Changed from /rejected
            elif user["deposit_status"] == "approved" and user["is_active"] == 1:
                return redirect("/user-dashboard")
            elif user["selected_package"] and not user["deposit_status"]:
                return redirect("/deposit")
            else:
                return redirect("/deposit")
                
        except Exception as e:
            flash(f"Login error: {str(e)}", "error")
            return redirect("/login")
        finally:
            db.close()
    
    return render_template("signin.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully", "info")
    return redirect("/login")

@app.route("/select-package", methods=["GET","POST"])
@login_required
def select_package():
    user = get_user(session["user_id"])
    if not user:
        flash("User not found", "error")
        return redirect("/login")
    
    if request.method == "POST":
        package_key = request.form.get("package")
        packages = {
            "1_lac": {"amount": 100000, "reward": 500},
            "3_lac": {"amount": 300000, "reward": 1500},
            "5_lac": {"amount": 500000, "reward": 2500},
            "10_lac": {"amount": 1000000, "reward": 5000},
        }
        
        if package_key in packages:
            db = get_db()
            try:
                db.execute("""
                    UPDATE users SET
                    selected_package=?, package_amount=?, daily_reward=?
                    WHERE id=?
                """, (package_key, packages[package_key]["amount"], packages[package_key]["reward"], user["id"]))
                db.commit()
                return redirect("/deposit")
            except Exception as e:
                flash(f"Error selecting package: {str(e)}", "error")
                return redirect("/select-package")
            finally:
                db.close()
        else:
            flash("Invalid package selected", "error")
            return redirect("/select-package")
    
    return render_template("package.html", user=user)



# =========================================================
# ADMIN USDT ADDRESS ROUTES - NEW SECTION
# =========================================================

@app.route("/admin/usdt-address")
@admin_required
def admin_usdt_address():
    """Admin page to manage USDT address"""
    db = get_db()
    try:
        # Get current active address
        current_address = db.execute("""
            SELECT * FROM admin_usdt_address 
            WHERE is_active = 1 
            ORDER BY created_at DESC 
            LIMIT 1
        """).fetchone()
        
        # 🆕 GET ALL REQUIRED COUNTS FOR SIDEBAR
        # Get pending deposit requests count
        pending_requests = db.execute("""
            SELECT COUNT(*) as count FROM deposit_requests 
            WHERE status = 'pending'
        """).fetchone()
        pending_requests_count = pending_requests['count'] if pending_requests else 0
        
        # Get pending withdrawals count
        withdrawals_count = db.execute("""
            SELECT COUNT(*) as count FROM withdrawals 
            WHERE status = 'pending'
        """).fetchone()
        withdrawals_count = withdrawals_count['count'] if withdrawals_count else 0
        
        # Get pending ads notifications count
        notifications_count = db.execute("""
            SELECT COUNT(*) as count FROM ad_completion_notifications 
            WHERE is_processed = 0
        """).fetchone()
        notifications_count = notifications_count['count'] if notifications_count else 0
        
        # Get pending password resets count
        pending_resets_count = db.execute("""
            SELECT COUNT(*) as count FROM password_reset_requests 
            WHERE status = 'pending'
        """).fetchone()
        pending_resets_count = pending_resets_count['count'] if pending_resets_count else 0
        
        # Get total users count for sidebar
        total_users = db.execute("SELECT COUNT(*) as count FROM users").fetchone()
        total_users = total_users['count'] if total_users else 0
        
        return render_template("admin/usdt_address.html", 
                             current_address=current_address,
                             pending_requests=pending_requests_count,
                             withdrawals_count=withdrawals_count,
                             notifications_count=notifications_count,
                             pending_resets_count=pending_resets_count,
                             total_users=total_users)
        
    except Exception as e:
        print(f"Error loading USDT address: {e}")
        flash("Error loading USDT address", "error")
        return render_template("admin/usdt_address.html", 
                             current_address=None,
                             pending_requests=0,
                             withdrawals_count=0,
                             notifications_count=0,
                             pending_resets_count=0,
                             total_users=0)
    finally:
        db.close()
@app.route("/admin/usdt-address/update", methods=["POST"])
@admin_required
def update_usdt_address():
    """Update USDT address (admin only)"""
    new_address = request.form.get("address", "").strip()
    network = request.form.get("network", "TRC20").strip()
    
    # Basic validation
    if not new_address or len(new_address) < 20:
        flash("Please enter a valid USDT address", "error")
        return redirect("/admin/usdt-address")
    
    db = get_db()
    try:
        # Deactivate all previous addresses
        db.execute("UPDATE admin_usdt_address SET is_active = 0")
        
        # Insert new address
        db.execute("""
            INSERT INTO admin_usdt_address (address, network, is_active)
            VALUES (?, ?, 1)
        """, (new_address, network))
        
        db.commit()
        flash("✅ USDT address updated successfully!", "success")
        
    except Exception as e:
        db.rollback()
        flash(f"Error updating address: {str(e)}", "error")
    finally:
        db.close()
    
    return redirect("/admin/usdt-address")
# 📁 app.py - UPDATE deposit() route COMPLETELY

@app.route("/deposit")
@login_required
def deposit():
    user = get_user(session["user_id"])
    if not user:
        flash("User not found", "error")
        return redirect("/login")
    
    if not user["selected_package"]:
        return redirect("/select-package")
    
    # 🛠️ DEBUG: Print to console
    print(f"\n🔍 [deposit] User: {user['name']}")
    
    db = None
    try:
        db = get_db()
        
        # Get current active address
        address_row = db.execute("""
            SELECT address FROM admin_usdt_address 
            WHERE is_active = 1 
            ORDER BY created_at DESC 
            LIMIT 1
        """).fetchone()
        
        if address_row:
            usdt_address = address_row["address"]
            print(f"✅ [deposit] DB Address found: {usdt_address[:20]}...")
        else:
            usdt_address = "TY76gVBsH9hK9P5J8n7mLQpTqN4EckRqj2"
            print(f"⚠️ [deposit] No address in DB, using default")
            
        # 🛠️ DEBUG: Show in browser also
        debug_info = {
            "db_address": usdt_address,
            "user_id": user["id"],
            "user_name": user["name"]
        }
        print(f"📦 [deposit] Sending to template: {debug_info}")
        
        return render_template("payment.html", 
                             user=user, 
                             usdt_address=usdt_address,
                             debug_info=debug_info)  # Optional debug
        
    except Exception as e:
        print(f"❌ [deposit] Error: {e}")
        usdt_address = "TY76gVBsH9hK9P5J8n7mLQpTqN4EckRqj2"
        return render_template("payment.html", 
                             user=user, 
                             usdt_address=usdt_address)
    finally:
        if db:
            db.close()
# 📁 app.py - YOUR EXISTING submit_deposit() function me yeh ADD karein

@app.route("/submit-deposit", methods=["POST"])
@login_required
def submit_deposit():
    user = get_user(session["user_id"])
    if not user:
        flash("User not found", "error")
        return redirect("/login")
    
    tx_id = request.form.get("tx_id", "").strip()
    screenshot = request.files.get("screenshot")
    
    if not tx_id:
        flash("Transaction ID required", "error")
        return redirect("/deposit")
    
    if not screenshot or screenshot.filename == '':
        flash("Screenshot required", "error")
        return redirect("/deposit")
    
    # Save screenshot
    try:
        filename = f"{user['id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{screenshot.filename}"
        filepath = os.path.join("static/uploads", filename)
        os.makedirs("static/uploads", exist_ok=True)
        screenshot.save(filepath)
    except Exception as e:
        flash(f"Error saving screenshot: {str(e)}", "error")
        return redirect("/deposit")
    
    db = get_db()
    try:
        # 🆕 Get the USDT address user saw when depositing
        current_usdt_address = get_active_usdt_address()
        
        # Update user
        db.execute("""
            UPDATE users
            SET deposit_status='submitted',
                deposit_tx_id=?,
                deposit_screenshot=?
            WHERE id=?
        """, (tx_id, filename, user["id"]))
        
        # Create deposit request
        db.execute("""
            INSERT INTO deposit_requests 
            (user_id, name, phone, selected_package, package_amount, daily_reward, deposit_tx_id, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
        """, (
            user["id"], user["name"], user["phone"], 
            user["selected_package"], user["package_amount"], user["daily_reward"],
            tx_id
        ))
        
        # 🆕 Record which address user sent to (for audit)
        db.execute("""
            INSERT INTO deposit_address_history 
            (user_id, deposit_tx_id, usdt_address)
            VALUES (?, ?, ?)
        """, (user["id"], tx_id, current_usdt_address))
        
        db.commit()
        flash("Deposit submitted! Waiting for approval.", "success")
        return redirect("/waiting-approval")
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
        return redirect("/deposit")
    finally:
        db.close()
@app.route("/waiting-approval")
@login_required
def waiting_approval():
    user = get_user(session["user_id"])
    if not user:
        flash("User not found", "error")
        return redirect("/login")
    
    # FIXED: Check if rejected first
    if user["deposit_status"] == "rejected":
        return redirect("/deposit-rejected")
    
    # Check if already approved
    if user["deposit_status"] == "approved" and user["is_active"] == 1:
        return redirect("/user-dashboard")
    
    if user["deposit_status"] != "submitted":
        return redirect("/deposit")
    
    return render_template("pending.html", user=user)



@app.route("/deposit-rejected")
@login_required
def deposit_rejected():
    """Show deposit rejection page to user"""
    user = get_user(session["user_id"])
    if not user:
        flash("User not found", "error")
        return redirect("/login")
    
    # Check if user is actually rejected
    if user["deposit_status"] != "rejected":
        # If not rejected, redirect based on status
        if user["deposit_status"] == "submitted":
            return redirect("/waiting-approval")
        elif user["deposit_status"] == "approved":
            return redirect("/user-dashboard")
        else:
            return redirect("/deposit")
    
    # User is rejected, show rejection page
    # Reset the show_rejection flag
    db = get_db()
    try:
        db.execute("UPDATE users SET show_rejection = 0 WHERE id = ?", (user["id"],))
        db.commit()
    except Exception as e:
        print(f"Error updating user: {e}")
    finally:
        db.close()
    
    return render_template("deposit_rejected.html", user=user)



# =========================================================
# USER DASHBOARD ROUTES - FIXED
# =========================================================

@app.route("/user-dashboard")
@login_required
def user_dashboard():
    """User dashboard - SIMPLE & ERROR-FREE"""
    user = get_user(session["user_id"])
    
    if user["is_active"] != 1:
        return redirect("/waiting-approval")
    
    try:
        db = get_db()
        
        print(f"\n🔍 [user_dashboard] User: {user['name']} (ID: {user['id']})")
        
        # 1. Get ads - SIMPLE QUERY
        ads_result = db.execute("""
            SELECT id, ad_name, ad_description, reward_amount 
            FROM available_ads 
            WHERE is_active = 1
            LIMIT 5
        """).fetchall()
        
        # Convert to list of dicts
        ads_list = []
        for row in ads_result:
            ads_list.append(dict(row))
        
        print(f"✅ Found {len(ads_list)} ads")
        
        # If no ads, create defaults
        if not ads_list:
            print("⚠️ No ads, creating defaults...")
            default_ads = [
                ("Ad #1", "Watch to earn rewards", 100),
                ("Ad #2", "Watch to earn rewards", 100),
                ("Ad #3", "Watch to earn rewards", 100),
                ("Ad #4", "Watch to earn rewards", 100),
                ("Ad #5", "Watch to earn rewards", 100),
            ]
            
            for name, desc, reward in default_ads:
                db.execute("""
                    INSERT INTO available_ads (ad_name, ad_description, reward_amount, is_active)
                    VALUES (?, ?, ?, 1)
                """, (name, desc, reward))
            
            db.commit()
            
            # Fetch again
            ads_result = db.execute("SELECT * FROM available_ads WHERE is_active = 1 LIMIT 5").fetchall()
            ads_list = [dict(row) for row in ads_result]
        
        # 2. Get completed ads - SIMPLE & SAFE
        completed_ids = set()
        completed_count = 0
        todays_earnings = 0
        
        try:
            today = datetime.now().strftime('%Y-%m-%d')
            
            # Try with watched_date
            try:
                completed_result = db.execute("""
                    SELECT ad_id FROM user_ad_progress 
                    WHERE user_id = ? AND watched_date = ? AND is_completed = 1
                """, (user['id'], today)).fetchall()
            except:
                # If watched_date doesn't exist, try date
                completed_result = db.execute("""
                    SELECT ad_id FROM user_ad_progress 
                    WHERE user_id = ? AND date = ? AND is_completed = 1
                """, (user['id'], today)).fetchall()
            
            completed_ids = {row['ad_id'] for row in completed_result}
            completed_count = len(completed_ids)
            
            # Calculate earnings
            for ad in ads_list:
                if ad['id'] in completed_ids:
                    todays_earnings += ad.get('reward_amount', 0)
                    
        except Exception as e:
            print(f"⚠️ Progress check error (non-critical): {e}")
        
        # 3. Add completion status
        final_ads = []
        for ad in ads_list:
            ad_copy = ad.copy()
            ad_copy['is_completed'] = 1 if ad['id'] in completed_ids else 0
            final_ads.append(ad_copy)
        
        # 4. Calculate progress
        total_ads = len(final_ads)
        progress_percent = 0
        if total_ads > 0:
            progress_percent = (completed_count / total_ads) * 100
        
        # Progress bar color
        bar_color = "bg-blue-500"
        if progress_percent == 100:
            bar_color = "bg-green-500"
        elif progress_percent >= 50:
            bar_color = "bg-yellow-500"
        
        all_completed = (completed_count == total_ads) if total_ads > 0 else False
        
        print(f"""
        📊 SUMMARY:
        - Ads: {total_ads}
        - Completed: {completed_count}
        - Earnings: {todays_earnings}
        - Progress: {progress_percent}%
        """)
        
        db.close()
        
        return render_template("user/user_dashboard.html", 
                             user=user,
                             ads=final_ads,
                             completed_ads=completed_count,
                             total_ads=total_ads,
                             todays_earnings=todays_earnings,
                             progress_percent=progress_percent,
                             bar_color=bar_color,
                             progress={
                                 "completed_ads": completed_count,
                                 "total_ads": total_ads,
                                 "all_completed": all_completed
                             })
        
    except Exception as e:
        print(f"❌ [user_dashboard] CRITICAL ERROR: {e}")
        
        # Emergency fallback
        sample_ads = [
            {"id": 1, "ad_name": "Ad #1", "ad_description": "Watch to earn", "reward_amount": 100, "is_completed": 0},
            {"id": 2, "ad_name": "Ad #2", "ad_description": "Watch to earn", "reward_amount": 100, "is_completed": 0},
            {"id": 3, "ad_name": "Ad #3", "ad_description": "Watch to earn", "reward_amount": 100, "is_completed": 0},
            {"id": 4, "ad_name": "Ad #4", "ad_description": "Watch to earn", "reward_amount": 100, "is_completed": 0},
            {"id": 5, "ad_name": "Ad #5", "ad_description": "Watch to earn", "reward_amount": 100, "is_completed": 0},
        ]
        
        return render_template("user/user_dashboard.html", 
                             user=user,
                             ads=sample_ads,
                             completed_ads=0,
                             total_ads=5,
                             todays_earnings=0,
                             progress_percent=0,
                             bar_color="bg-blue-500",
                             progress={
                                 "completed_ads": 0,
                                 "total_ads": 5,
                                 "all_completed": False
                             })

                             
                             
@app.route("/user/mark-ad-complete/<int:ad_id>")
@login_required
def mark_ad_complete(ad_id):
    """Mark ad as completed - WITH ERROR HANDLING"""
    
    user_id = session["user_id"]
    today = datetime.now().strftime('%Y-%m-%d')
    
    db = get_db()
    try:
        # Check which date column exists
        columns = db.execute("PRAGMA table_info(user_ad_progress)").fetchall()
        column_names = [col[1] for col in columns]
        
        if 'watched_date' in column_names:
            date_column = 'watched_date'
        elif 'date' in column_names:
            date_column = 'date'
        else:
            # Add the column
            db.execute("ALTER TABLE user_ad_progress ADD COLUMN watched_date DATE")
            date_column = 'watched_date'
        
        # Check how many ads already completed today
        completed_count = db.execute(f"""
            SELECT COUNT(*) as count FROM user_ad_progress 
            WHERE user_id = ? AND {date_column} = ? AND is_completed = 1
        """, (user_id, today)).fetchone()['count']
        
        # Don't allow more than 5 ads per day
        if completed_count >= 5:
            flash("Daily limit reached (5 ads)", "error")
            db.close()
            return redirect("/user-dashboard")
        
        # Check if this specific ad already completed
        existing = db.execute(f"""
            SELECT id FROM user_ad_progress 
            WHERE user_id = ? AND ad_id = ? AND {date_column} = ? AND is_completed = 1
        """, (user_id, ad_id, today)).fetchone()
        
        if existing:
            flash("You've already completed this ad today", "info")
            db.close()
            return redirect("/user-dashboard")
        
        # Mark this ad as completed
        db.execute(f"""
            INSERT INTO user_ad_progress (user_id, ad_id, {date_column}, is_completed, completed_at)
            VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP)
        """, (user_id, ad_id, today))
        
        db.commit()
        
        # Check if this was the 5th ad (after increment)
        new_count = completed_count + 1
        
        if new_count == 5:
            # Get user info
            user = db.execute("SELECT name, phone, daily_reward FROM users WHERE id = ?", (user_id,)).fetchone()
            
            if user:
                # Check if notification already exists for today
                existing_notif = db.execute("""
                    SELECT id FROM ad_completion_notifications 
                    WHERE user_id = ? AND date_completed = ?
                """, (user_id, today)).fetchone()
                
                if not existing_notif:
                    try:
                        db.execute("""
                            INSERT INTO ad_completion_notifications 
                            (user_id, user_name, user_phone, ad_id, ad_name, reward_amount, date_completed)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        """, (
                            user_id, 
                            user['name'], 
                            user['phone'], 
                            0,  # Special ID for batch
                            'Daily 5 Ads Completed', 
                            user['daily_reward'], 
                            today
                        ))
                        db.commit()
                        print(f"✅ [BATCH] User {user['name']} completed all 5 ads. Reward: {user['daily_reward']} PKR")
                    except Exception as e:
                        print(f"⚠️ Notification error: {e}")
        
        flash("Ad completed! Keep watching to earn daily reward.", "success")
        
    except Exception as e:
        print(f"❌ Error in mark_ad_complete: {e}")
        flash("Error completing ad", "error")
    finally:
        db.close()
    
    return redirect("/user-dashboard")


@app.route("/emergency-fix")
def emergency_fix():
    """Emergency fix for notification system"""
    import sqlite3
    from datetime import datetime
    
    try:
        conn = sqlite3.connect('app.db')
        cursor = conn.cursor()
        
        print("="*50)
        print("🔍 DATABASE DIAGNOSIS")
        print("="*50)
        
        # 1. Check all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        print("📊 ALL TABLES:")
        for table in tables:
            print(f"   - {table[0]}")
        
        # 2. Check ad_completion_notifications table
        print("\n🔔 NOTIFICATIONS TABLE:")
        if ('ad_completion_notifications',) in tables:
            # Check columns
            cursor.execute("PRAGMA table_info(ad_completion_notifications)")
            columns = cursor.fetchall()
            print("   Columns:")
            for col in columns:
                print(f"     {col[1]} ({col[2]})")
            
            # Check data
            cursor.execute("SELECT COUNT(*) FROM ad_completion_notifications")
            count = cursor.fetchone()[0]
            print(f"   Total rows: {count}")
            
            cursor.execute("SELECT * FROM ad_completion_notifications LIMIT 5")
            rows = cursor.fetchall()
            print(f"   Sample data:")
            for row in rows:
                print(f"     {row}")
        else:
            print("   ❌ Table does not exist!")
            
        # 3. Check available_ads table
        print("\n📺 AVAILABLE ADS TABLE:")
        if ('available_ads',) in tables:
            cursor.execute("SELECT id, ad_name, reward_amount FROM available_ads")
            ads = cursor.fetchall()
            print("   Current ads:")
            for ad in ads:
                print(f"     ID: {ad[0]}, Name: {ad[1]}, Reward: {ad[2]}")
        
        # 4. Check users table
        print("\n👥 USERS TABLE:")
        if ('users',) in tables:
            cursor.execute("SELECT id, name, phone FROM users LIMIT 3")
            users = cursor.fetchall()
            print("   Sample users:")
            for user in users:
                print(f"     ID: {user[0]}, Name: {user[1]}, Phone: {user[2]}")
        
        conn.close()
        
        return """
        <h1>Emergency Diagnosis Complete</h1>
        <p>Check your console/terminal for database details.</p>
        <a href="/admin/ads">Go to Admin</a>
        """
        
    except Exception as e:
        return f"Error: {str(e)}"
@app.route("/admin/debug-notifications")
@admin_required
def debug_notifications():
    """Debug route to check notification issues"""
    
    db = get_db()
    
    # Get all notifications
    all_notifs = db.execute("""
        SELECT n.*, u.balance as user_current_balance
        FROM ad_completion_notifications n
        LEFT JOIN users u ON n.user_id = u.id
        ORDER BY n.id DESC
    """).fetchall()
    
    # Get table structure
    columns = db.execute("PRAGMA table_info(ad_completion_notifications)").fetchall()
    
    # Count by status
    pending_count = db.execute("SELECT COUNT(*) FROM ad_completion_notifications WHERE is_processed = 0").fetchone()[0]
    processed_count = db.execute("SELECT COUNT(*) FROM ad_completion_notifications WHERE is_processed = 1").fetchone()[0]
    
    db.close()
    
    return render_template("admin/debug_notifications.html",
                         all_notifs=all_notifs,
                         columns=columns,
                         pending_count=pending_count,
                         processed_count=processed_count)


# =========================================================
# ADMIN ADS MANAGEMENT ROUTES - FIXED
# =========================================================

@app.route("/admin/ads")
@admin_required
def manage_ads():
    """COMPLETELY FIXED admin ads management"""
    
    print(f"\n🔔 [manage_ads] Loading ads page...")
    
    db = None
    try:
        db = get_db()
        
        # ===== 1. GET ADS =====
        ads = []
        try:
            # Simple query first to test
            ads = db.execute("SELECT * FROM available_ads ORDER BY id DESC").fetchall()
            print(f"📊 Found {len(ads)} ads in database")
            
            # Print each ad for debugging
            for ad in ads:
                print(f"   - ID: {ad['id']}, Name: {ad['ad_name']}, Active: {ad['is_active']}")
                
        except Exception as e:
            print(f"⚠️ Ads query error: {e}")
            ads = []
        
        # ===== 2. GET NOTIFICATIONS =====
        notifications = []
        try:
            # Simple query for notifications
            notifications = db.execute("""
                SELECT * FROM ad_completion_notifications 
                WHERE is_processed = 0 
                ORDER BY id DESC
            """).fetchall()
            print(f"📊 Found {len(notifications)} pending notifications")
            
        except Exception as e:
            print(f"⚠️ Notifications query error: {e}")
            notifications = []
        
        # ===== 3. GET SIDEBAR STATS =====
        total_users = 0
        pending_requests = []
        withdrawals_count = 0
        withdrawals_amount = 0
        pending_resets_count = 0
        
        try:
            # Total users
            result = db.execute("SELECT COUNT(*) as count FROM users").fetchone()
            total_users = result['count'] if result else 0
            
            # Pending requests
            pending_requests = db.execute("""
                SELECT * FROM deposit_requests WHERE status = 'pending'
            """).fetchall()
            
            # Withdrawals
            w_stats = db.execute("""
                SELECT COUNT(*) as count, COALESCE(SUM(amount), 0) as total 
                FROM withdrawals
            """).fetchone()
            if w_stats:
                withdrawals_count = w_stats['count'] or 0
                withdrawals_amount = w_stats['total'] or 0
            
            # Password resets
            reset = db.execute("""
                SELECT COUNT(*) as count FROM password_reset_requests WHERE status = 'pending'
            """).fetchone()
            pending_resets_count = reset['count'] if reset else 0
            
        except Exception as e:
            print(f"⚠️ Stats error: {e}")
        
        print(f"\n📤 SENDING TO TEMPLATE:")
        print(f"   - ads: {len(ads)}")
        print(f"   - notifications: {len(notifications)}")
        print(f"   - total_users: {total_users}")
        
        return render_template("admin/ads.html",
                             ads=ads,
                             notifications=notifications,
                             pending_requests=pending_requests,
                             withdrawals_count=withdrawals_count,
                             withdrawals_amount=withdrawals_amount,
                             total_users=total_users,
                             pending_resets_count=pending_resets_count,
                             notifications_count=len(notifications))
        
    except Exception as e:
        print(f"❌ [manage_ads] CRITICAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        
        # Safe fallback
        return render_template("admin/ads.html",
                             ads=[],
                             notifications=[],
                             pending_requests=[],
                             withdrawals_count=0,
                             withdrawals_amount=0,
                             total_users=0,
                             pending_resets_count=0,
                             notifications_count=0)
    
    finally:
        if db:
            db.close()


@app.route("/admin/ads/add", methods=["GET", "POST"])
@admin_required
def add_new_ad():
    """Add new real ad - COMPLETE FIXED VERSION"""
    if request.method == "POST":
        ad_name = request.form.get("ad_name", "").strip()
        ad_type = request.form.get("ad_type", "youtube").strip()
        ad_url = request.form.get("ad_url", "").strip()
        embed_code = request.form.get("embed_code", "").strip()
        ad_description = request.form.get("ad_description", "").strip()
        
        # Duration ko safely convert karo
        duration_str = request.form.get("duration", "30")
        try:
            duration = int(duration_str)
        except:
            duration = 30
            
        if not ad_name:
            flash("Ad name is required", "error")
            return redirect("/admin/ads/add")
        
        # Extract video ID for YouTube/Vimeo
        video_id = None
        if ad_type == 'youtube' and ad_url:
            import re
            youtube_regex = r'(?:youtube\.com\/(?:[^\/]+\/.+\/|(?:v|e(?:mbed)?)\/|.*[?&]v=)|youtu\.be\/)([^"&?\/\s]{11})'
            match = re.search(youtube_regex, ad_url)
            if match:
                video_id = match.group(1)
        elif ad_type == 'vimeo' and ad_url:
            import re
            vimeo_regex = r'(?:vimeo\.com\/|player\.vimeo\.com\/video\/)([0-9]+)'
            match = re.search(vimeo_regex, ad_url)
            if match:
                video_id = match.group(1)
        
        # Handle thumbnail upload
        thumbnail = request.files.get('thumbnail')
        thumbnail_path = None
        if thumbnail and thumbnail.filename:
            import os, time
            safe_filename = ''.join(c for c in thumbnail.filename if c.isalnum() or c in '._-')
            filename = f"thumb_{int(time.time())}_{safe_filename}"
            filepath = os.path.join("static/thumbnails", filename)
            os.makedirs("static/thumbnails", exist_ok=True)
            thumbnail.save(filepath)
            thumbnail_path = f"/static/thumbnails/{filename}"
        
        db = get_db()
        try:
            db.execute("""
                INSERT INTO available_ads 
                (ad_name, ad_description, ad_type, ad_url, embed_code, video_id, 
                 thumbnail_url, duration_seconds, reward_amount, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 1)
            """, (
                ad_name, 
                ad_description,
                ad_type,
                ad_url,
                embed_code,
                video_id,
                thumbnail_path,
                duration
            ))
            db.commit()
            flash(f"✅ Ad '{ad_name}' created successfully!", "success")
        except Exception as e:
            print(f"Error adding ad: {e}")
            flash(f"Error adding ad: {str(e)}", "error")
        finally:
            db.close()
        
        return redirect("/admin/ads")
    
    # ===== GET REQUEST - SHOW FORM WITH STATS =====
    db = get_db()
    try:
        # ✅ FIX 1: Count queries - har query ko alag se handle karo
        pending_result = db.execute("SELECT COUNT(*) as count FROM deposit_requests WHERE status='pending'").fetchone()
        pending_requests_count = pending_result['count'] if pending_result else 0
        
        withdrawals_result = db.execute("SELECT COUNT(*) as count FROM withdrawals WHERE status='pending'").fetchone()
        withdrawals_count = withdrawals_result['count'] if withdrawals_result else 0
        
        # ✅ FIX 2: Get notifications as LIST (not count)
        notifications = db.execute("SELECT * FROM ad_completion_notifications WHERE is_processed=0").fetchall()
        notifications_count = len(notifications)  # ✅ len() on list is safe
        
        resets_result = db.execute("SELECT COUNT(*) as count FROM password_reset_requests WHERE status='pending'").fetchone()
        pending_resets_count = resets_result['count'] if resets_result else 0
        
        users_result = db.execute("SELECT COUNT(*) as count FROM users").fetchone()
        total_users = users_result['count'] if users_result else 0
        
        print(f"📊 Stats: pending={pending_requests_count}, withdrawals={withdrawals_count}, notifications={notifications_count}, resets={pending_resets_count}, users={total_users}")
        
    except Exception as e:
        print(f"❌ Error getting stats: {e}")
        # Default values on error
        pending_requests_count = 0
        withdrawals_count = 0
        notifications = []
        notifications_count = 0
        pending_resets_count = 0
        total_users = 0
    finally:
        db.close()
    
    # ✅ FIX 3: Template ko sahi variables pass karo
    return render_template("admin/add_ad.html",
                         pending_requests=pending_requests_count,      # ✅ integer
                         withdrawals_count=withdrawals_count,          # ✅ integer
                         notifications=notifications,                   # ✅ list
                         notifications_count=notifications_count,       # ✅ integer
                         pending_resets_count=pending_resets_count,     # ✅ integer
                         total_users=total_users)                       # ✅ integer







@app.route("/user/watch-ad/<int:ad_id>")
@login_required
def watch_ad(ad_id):
    """Watch ad page - FIXED"""
    user = get_user(session["user_id"])
    
    if user["is_active"] != 1:
        return redirect("/waiting-approval")
    
    try:
        db = get_db()
        
        # Get ad details
        ad = db.execute("SELECT * FROM available_ads WHERE id=?", (ad_id,)).fetchone()
        
        if not ad:
            flash("Ad not found", "error")
            db.close()
            return redirect("/user-dashboard")
        
        # Check if table 'user_ad_progress' exists
        try:
            # Check if already watched today
            from datetime import datetime
            today = datetime.now().strftime('%Y-%m-%d')
            
            already_watched = db.execute("""
                SELECT * FROM user_ad_progress 
                WHERE user_id = ? AND ad_id = ? AND watched_date = ? AND is_completed = 1
            """, (user['id'], ad_id, today)).fetchone()
            
            if already_watched:
                flash("You have already watched this ad today", "info")
                db.close()
                return redirect("/user-dashboard")
        except Exception as e:
            print(f"Note: Checking ad progress: {e}")
            # Table might not exist yet, that's okay
        
        db.close()
        
        # Convert Row to dict for template
        ad_dict = dict(ad) if ad else {}
        
        return render_template("user/watch_ad.html", 
                             user=user, 
                             ad=ad_dict,
                             ad_id=ad_id)
        
    except Exception as e:
        print(f"Error in watch_ad: {e}")
        flash("Error loading ad", "error")
        return redirect("/user-dashboard")




@app.route("/admin/ads/edit/<int:ad_id>", methods=["GET", "POST"])
@admin_required
def edit_existing_ad(ad_id):  # Renamed from edit_ad
    """Edit ad - FIXED"""
    try:
        db = get_db()
        
        if request.method == "POST":
            ad_name = request.form.get("ad_name", "").strip()
            ad_description = request.form.get("ad_description", "").strip()
            ad_url = request.form.get("ad_url", "").strip()
            duration = request.form.get("duration", type=int, default=30)
            reward = request.form.get("reward", type=int, default=100)
            is_active = request.form.get("is_active", type=int, default=1)
            
            db.execute("""
                UPDATE available_ads 
                SET ad_name=?, ad_description=?, ad_url=?, 
                    duration_seconds=?, reward_amount=?, is_active=?
                WHERE id=?
            """, (ad_name, ad_description, ad_url, duration, reward, is_active, ad_id))
            db.commit()
            
            flash("Ad updated successfully", "success")
            return redirect("/admin/ads")
        
        ad = db.execute("SELECT * FROM available_ads WHERE id=?", (ad_id,)).fetchone()
        
        if not ad:
            flash("Ad not found", "error")
            return redirect("/admin/ads")
        
        return render_template("admin/edit_ad.html", ad=ad)
        
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
        return redirect("/admin/ads")
    finally:
        if 'db' in locals():
            db.close()

@app.route("/admin/ads/delete/<int:ad_id>")
@admin_required
def delete_existing_ad(ad_id):  # Renamed from delete_ad
    """Delete ad - FIXED"""
    try:
        db = get_db()
        db.execute("DELETE FROM available_ads WHERE id=?", (ad_id,))
        db.commit()
        flash("Ad deleted successfully", "success")
    except Exception as e:
        flash(f"Error deleting ad: {str(e)}", "error")
    finally:
        db.close()
    
    return redirect("/admin/ads")
@app.route("/admin/debug-column")
@admin_required
def debug_column():
    """Check if withdrawable_balance column exists"""
    
    db = get_db()
    try:
        # Check users table columns
        columns = db.execute("PRAGMA table_info(users)").fetchall()
        col_names = [col[1] for col in columns]
        
        result = "<h1>🔍 Column Check</h1>"
        result += "<h2>Users Table Columns:</h2><ul>"
        for col in col_names:
            result += f"<li>{col}</li>"
        result += "</ul>"
        
        if 'withdrawable_balance' in col_names:
            result += "<p style='color:green'>✅ withdrawable_balance EXISTS</p>"
            
            # Check actual data
            users = db.execute("SELECT id, name, withdrawable_balance, balance FROM users").fetchall()
            result += "<h2>User Data:</h2><table border='1'>"
            result += "<tr><th>ID</th><th>Name</th><th>withdrawable_balance</th><th>balance</th></tr>"
            for user in users:
                result += f"<tr>"
                result += f"<td>{user['id']}</td>"
                result += f"<td>{user['name']}</td>"
                result += f"<td>{user['withdrawable_balance']}</td>"
                result += f"<td>{user['balance']}</td>"
                result += f"</tr>"
            result += "</table>"
        else:
            result += "<p style='color:red'>❌ withdrawable_balance MISSING</p>"
            
        return result
        
    except Exception as e:
        return f"<h1>Error: {e}</h1>"
    finally:
        db.close()
@app.route("/admin/add-missing-column")
def add_missing_column():
    """Add withdrawable_balance column to users table"""
    
    db = get_db()
    result = "<h1>🔧 Adding Missing Column</h1>"
    
    try:
        # Check current columns
        columns = db.execute("PRAGMA table_info(users)").fetchall()
        col_names = [col[1] for col in columns]
        
        result += "<h2>Current Columns:</h2><ul>"
        for col in col_names:
            result += f"<li>{col}</li>"
        result += "</ul>"
        
        # ADD THE MISSING COLUMN
        if 'withdrawable_balance' not in col_names:
            db.execute("ALTER TABLE users ADD COLUMN withdrawable_balance INTEGER DEFAULT 0")
            result += "<p style='color:green; font-weight:bold'>✅ withdrawable_balance COLUMN ADDED SUCCESSFULLY!</p>"
        else:
            result += "<p style='color:orange'>⚠️ withdrawable_balance already exists</p>"
        
        # Also add other useful columns
        if 'locked_balance' not in col_names:
            db.execute("ALTER TABLE users ADD COLUMN locked_balance INTEGER DEFAULT 0")
            result += "<p style='color:green'>✅ locked_balance column added</p>"
        
        if 'package_lock_until' not in col_names:
            db.execute("ALTER TABLE users ADD COLUMN package_lock_until DATE")
            result += "<p style='color:green'>✅ package_lock_until column added</p>"
        
        db.commit()
        
        # Show updated columns
        columns = db.execute("PRAGMA table_info(users)").fetchall()
        col_names = [col[1] for col in columns]
        result += "<h2>Updated Columns:</h2><ul>"
        for col in col_names:
            result += f"<li>{col}</li>"
        result += "</ul>"
        
        result += "<p><a href='/admin/ads'>Go to Ads</a> | <a href='/admin/users'>Go to Users</a></p>"
        
        return result
        
    except Exception as e:
        return f"<h1>❌ Error: {e}</h1>"
    finally:
        db.close()
@app.route("/admin/init-user-balances")
@admin_required
def init_user_balances():
    """Initialize withdrawable_balance for all users"""
    
    db = get_db()
    try:
        # Copy balance to withdrawable_balance for all users
        db.execute("""
            UPDATE users 
            SET withdrawable_balance = balance 
            WHERE withdrawable_balance IS NULL OR withdrawable_balance = 0
        """)
        db.commit()
        
        return "✅ All user balances initialized! <a href='/admin/users'>Go to Users</a>"
        
    except Exception as e:
        return f"❌ Error: {e}"
    finally:
        db.close()     
                
@app.route("/admin/notification/approve/<int:notification_id>")
@admin_required
def approve_ad_completion(notification_id):
    """Approve ad completion - NOW WORKING"""
    
    try:
        db = get_db()
        
        # Get notification
        notification = db.execute("""
            SELECT * FROM ad_completion_notifications 
            WHERE id=? AND is_processed=0
        """, (notification_id,)).fetchone()
        
        if not notification:
            flash("Notification not found", "error")
            return redirect("/admin/ads")
        
        # ✅ NOW withdrawable_balance EXISTS!
        db.execute("""
            UPDATE users 
            SET withdrawable_balance = withdrawable_balance + ?
            WHERE id = ?
        """, (notification["reward_amount"], notification["user_id"]))
        
        # Mark as processed
        db.execute("""
            UPDATE ad_completion_notifications 
            SET is_processed = 1,
                processed_by_admin = ?,
                processed_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (session.get("admin_username", "admin"), notification_id))
        
        db.commit()
        
        flash(f"✅ Reward {notification['reward_amount']} PKR added to {notification['user_name']}'s withdrawable balance", "success")
        
    except Exception as e:
        print(f"Error: {e}")
        flash(f"Error: {str(e)}", "error")
    finally:
        if 'db' in locals():
            db.close()
    
    return redirect("/admin/ads")

@app.route("/admin/fix-complete-database")
@admin_required
def fix_complete_database():
    """Add ALL missing columns to ALL tables"""
    
    db = get_db()
    result = "<h1>🔧 COMPLETE DATABASE FIX</h1>"
    
    try:
        # ===== 1. USERS TABLE =====
        result += "<h2>📊 Users Table</h2>"
        columns = db.execute("PRAGMA table_info(users)").fetchall()
        col_names = [col[1] for col in columns]
        
        result += f"<p>Current columns: {', '.join(col_names)}</p>"
        
        users_columns = [
            ('withdrawable_balance', 'INTEGER DEFAULT 0'),
            ('locked_balance', 'INTEGER DEFAULT 0'),
            ('package_lock_until', 'DATE'),
            ('total_earned', 'INTEGER DEFAULT 0'),
            ('total_withdrawn', 'INTEGER DEFAULT 0'),
            ('email', 'TEXT'),
            ('updated_at', 'TIMESTAMP'),
            ('last_login', 'TIMESTAMP')
        ]
        
        for col_name, col_type in users_columns:
            if col_name not in col_names:
                db.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_type}")
                result += f"<p style='color:green'>✅ Added {col_name} to users</p>"
        
        # Initialize withdrawable_balance from balance
        if 'withdrawable_balance' in [c[0] for c in users_columns] or 'withdrawable_balance' in col_names:
            db.execute("UPDATE users SET withdrawable_balance = balance WHERE withdrawable_balance IS NULL OR withdrawable_balance = 0")
            result += "<p>✅ Initialized withdrawable_balance from balance</p>"
        
        # ===== 2. DEPOSIT_REQUESTS TABLE =====
        result += "<h2>📊 Deposit Requests Table</h2>"
        columns = db.execute("PRAGMA table_info(deposit_requests)").fetchall()
        col_names = [col[1] for col in columns]
        
        deposit_columns = [
            ('usdt_address', 'TEXT'),
            ('usdt_amount', 'REAL'),
            ('approved_at', 'TIMESTAMP'),
            ('approved_by', 'TEXT'),
            ('package_type', 'TEXT')
        ]
        
        for col_name, col_type in deposit_columns:
            if col_name not in col_names:
                db.execute(f"ALTER TABLE deposit_requests ADD COLUMN {col_name} {col_type}")
                result += f"<p style='color:green'>✅ Added {col_name} to deposit_requests</p>"
        
        # ===== 3. WITHDRAWALS TABLE =====
        result += "<h2>📊 Withdrawals Table</h2>"
        columns = db.execute("PRAGMA table_info(withdrawals)").fetchall()
        col_names = [col[1] for col in columns]
        
        withdrawal_columns = [
            ('withdrawable_amount', 'INTEGER DEFAULT 0'),
            ('usdt_address', 'TEXT'),
            ('usdt_amount', 'REAL'),
            ('txn_id', 'TEXT'),
            ('processed_by', 'TEXT'),
            ('processed_at', 'TIMESTAMP'),
            ('remarks', 'TEXT')
        ]
        
        for col_name, col_type in withdrawal_columns:
            if col_name not in col_names:
                db.execute(f"ALTER TABLE withdrawals ADD COLUMN {col_name} {col_type}")
                result += f"<p style='color:green'>✅ Added {col_name} to withdrawals</p>"
        
        # ===== 4. AD_COMPLETION_NOTIFICATIONS TABLE =====
        result += "<h2>📊 Ad Completion Notifications Table</h2>"
        columns = db.execute("PRAGMA table_info(ad_completion_notifications)").fetchall()
        col_names = [col[1] for col in columns]
        
        notification_columns = [
            ('ad_id', 'INTEGER'),
            ('reward_amount', 'INTEGER DEFAULT 0'),
            ('date_completed', 'DATE'),
            ('is_processed', 'INTEGER DEFAULT 0'),
            ('processed_by_admin', 'TEXT'),
            ('processed_at', 'TIMESTAMP')
        ]
        
        for col_name, col_type in notification_columns:
            if col_name not in col_names:
                db.execute(f"ALTER TABLE ad_completion_notifications ADD COLUMN {col_name} {col_type}")
                result += f"<p style='color:green'>✅ Added {col_name} to ad_completion_notifications</p>"
        
        # ===== 5. USER_AD_PROGRESS TABLE =====
        result += "<h2>📊 User Ad Progress Table</h2>"
        columns = db.execute("PRAGMA table_info(user_ad_progress)").fetchall()
        col_names = [col[1] for col in columns]
        
        progress_columns = [
            ('reward_credited', 'INTEGER DEFAULT 0'),
            ('watched_date', 'DATE'),
            ('completed_at', 'TIMESTAMP'),
            ('ad_name', 'TEXT')
        ]
        
        for col_name, col_type in progress_columns:
            if col_name not in col_names:
                db.execute(f"ALTER TABLE user_ad_progress ADD COLUMN {col_name} {col_type}")
                result += f"<p style='color:green'>✅ Added {col_name} to user_ad_progress</p>"
        
        # ===== 6. BALANCE_TRANSACTIONS TABLE =====
        result += "<h2>📊 Balance Transactions Table</h2>"
        columns = db.execute("PRAGMA table_info(balance_transactions)").fetchall()
        col_names = [col[1] for col in columns]
        
        transaction_columns = [
            ('balance_type', 'TEXT DEFAULT \'withdrawable\''),
            ('previous_withdrawable', 'INTEGER DEFAULT 0'),
            ('new_withdrawable', 'INTEGER DEFAULT 0'),
            ('previous_locked', 'INTEGER DEFAULT 0'),
            ('new_locked', 'INTEGER DEFAULT 0')
        ]
        
        for col_name, col_type in transaction_columns:
            if col_name not in col_names:
                db.execute(f"ALTER TABLE balance_transactions ADD COLUMN {col_name} {col_type}")
                result += f"<p style='color:green'>✅ Added {col_name} to balance_transactions</p>"
        
        # ===== 7. PASSWORD_RESET_REQUESTS TABLE =====
        result += "<h2>📊 Password Reset Requests Table</h2>"
        columns = db.execute("PRAGMA table_info(password_reset_requests)").fetchall()
        col_names = [col[1] for col in columns]
        
        reset_columns = [
            ('user_id', 'INTEGER'),
            ('user_name', 'TEXT'),
            ('user_phone', 'TEXT'),
            ('new_password', 'TEXT'),
            ('admin_notes', 'TEXT'),
            ('processed_by', 'TEXT'),
            ('processed_at', 'TIMESTAMP')
        ]
        
        for col_name, col_type in reset_columns:
            if col_name not in col_names:
                db.execute(f"ALTER TABLE password_reset_requests ADD COLUMN {col_name} {col_type}")
                result += f"<p style='color:green'>✅ Added {col_name} to password_reset_requests</p>"
        
        # ===== 8. SUPPORT_TICKETS TABLE =====
        result += "<h2>📊 Support Tickets Table</h2>"
        columns = db.execute("PRAGMA table_info(support_tickets)").fetchall()
        col_names = [col[1] for col in columns]
        
        ticket_columns = [
            ('user_id', 'INTEGER'),
            ('user_name', 'TEXT'),
            ('user_phone', 'TEXT'),
            ('subject', 'TEXT'),
            ('message', 'TEXT'),
            ('admin_response', 'TEXT'),
            ('status', 'TEXT DEFAULT \'open\''),
            ('resolved_by', 'TEXT'),
            ('closed_at', 'TIMESTAMP'),
            ('updated_at', 'TIMESTAMP')
        ]
        
        for col_name, col_type in ticket_columns:
            if col_name not in col_names:
                db.execute(f"ALTER TABLE support_tickets ADD COLUMN {col_name} {col_type}")
                result += f"<p style='color:green'>✅ Added {col_name} to support_tickets</p>"
        
        db.commit()
        
        result += "<h2 style='color:green'>✅ ALL MISSING COLUMNS ADDED SUCCESSFULLY!</h2>"
        result += "<p><a href='/admin/dashboard'>Go to Dashboard</a> | <a href='/admin/check-all-tables'>Check All Tables</a></p>"
        
        return result
        
    except Exception as e:
        return f"<h1>❌ Error: {e}</h1>"
    finally:
        db.close()


@app.route("/admin/notification/reject/<int:notification_id>")
@admin_required
def reject_ad_completion(notification_id):  # Renamed from reject_ad_notification
    """Reject ad completion - FIXED"""
    
    try:
        db = get_db()
        
        db.execute("""
            UPDATE ad_completion_notifications 
            SET is_processed = 1,
                processed_by_admin = ?,
                processed_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (session["admin_username"], notification_id))
        
        db.commit()
        flash("Notification marked as processed (no reward)", "info")
        
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
    finally:
        if 'db' in locals():
            db.close()
    
    return redirect("/admin/ads")

# =========================================================
# SIMPLIFIED USER ADS PAGE (Optional)
# =========================================================

@app.route("/user/ads-page")
@login_required
def user_ads_page():  # Renamed from user_ads
    """Simple user ads page - FIXED"""
    user = get_user(session["user_id"])
    
    if user["is_active"] != 1:
        flash("Please activate your account first", "error")
        return redirect("/user-dashboard")
    
    return render_template("user/ads_simple.html", user=user)

@app.route("/user/watch-ad-page/<int:ad_id>")
@login_required
def watch_ad_page(ad_id):  # Renamed from watch_ad
    """Simple watch ad page - FIXED"""
    user = get_user(session["user_id"])
    
    # For now, just return a simple page
    return render_template("user/watch_ad_simple.html", user=user, ad_id=ad_id)


# =========================================================
# ADMIN ROUTES - OPTIMIZED
# =========================================================

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if session.get("admin"):
        return redirect("/admin/dashboard")
    
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        if not username or not password:
            flash("Username and password required", "error")
            return redirect("/admin/login")
        
        db = get_db()
        try:
            admin = db.execute("SELECT * FROM admins WHERE username=?", (username,)).fetchone()
            
            if admin and check_password_hash(admin["password"], password):
                session["admin"] = True
                session["admin_username"] = username
                flash("Admin login successful", "success")
                return redirect("/admin/dashboard")
            else:
                flash("Invalid credentials", "error")
                return redirect("/admin/login")
        except Exception as e:
            flash(f"Login error: {str(e)}", "error")
            return redirect("/admin/login")
        finally:
            db.close()
    
    return render_template("admin/login.html")

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    session.pop("admin_username", None)
    flash("Admin logged out", "info")
    return redirect("/admin/login")


@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    """Admin main dashboard - shows pending requests"""
    db = get_db()
    try:
        # Get pending deposit requests
        pending_deposits = db.execute("""
            SELECT dr.*, u.deposit_screenshot 
            FROM deposit_requests dr
            LEFT JOIN users u ON dr.user_id = u.id
            WHERE dr.status = 'pending'
            ORDER BY dr.created_at DESC
        """).fetchall()
        
        # Get withdrawal requests
        pending_withdrawals = db.execute("""
            SELECT * FROM withdrawals 
            ORDER BY created_at DESC
        """).fetchall()
        
        # 🆕 GET PENDING PASSWORD RESET COUNT
        try:
            pending_resets = db.execute("""
                SELECT COUNT(*) as count 
                FROM password_reset_requests 
                WHERE status = 'pending'
            """).fetchone()
            pending_resets_count = pending_resets['count'] if pending_resets else 0
        except Exception as e:
            print(f"⚠️ Password reset table error: {e}")
            pending_resets_count = 0
        
        # Get pending ads notifications count
        try:
            notifications_count = db.execute("""
                SELECT COUNT(*) as count 
                FROM ad_completion_notifications 
                WHERE is_processed = 0
            """).fetchone()["count"]
        except:
            notifications_count = 0
        
        # 🔥 FIXED: Get open support tickets count
        try:
            open_tickets = db.execute("""
                SELECT COUNT(*) as count 
                FROM support_tickets 
                WHERE status = 'open'
            """).fetchone()
            open_tickets_count = open_tickets['count'] if open_tickets else 0
        except Exception as e:
            print(f"⚠️ Support tickets table error: {e}")
            open_tickets_count = 0
        
        # Get stats
        total_users = db.execute("SELECT COUNT(*) as count FROM users").fetchone()["count"]
        active_users = db.execute("SELECT COUNT(*) as count FROM users WHERE is_active = 1").fetchone()["count"]
        
        # Withdrawal stats
        withdrawal_stats = db.execute("""
            SELECT COUNT(*) as count, COALESCE(SUM(amount), 0) as total 
            FROM withdrawals
        """).fetchone()
        
        withdrawals_count = withdrawal_stats['count'] if withdrawal_stats else 0
        withdrawals_amount = withdrawal_stats['total'] if withdrawal_stats else 0
        
        return render_template("admin/dashboard.html",
                             pending_requests=pending_deposits,
                             pending_withdrawals=pending_withdrawals,
                             total_users=total_users,
                             active_users=active_users,
                             withdrawals_count=withdrawals_count,
                             withdrawals_amount=withdrawals_amount,
                             notifications_count=notifications_count,
                             pending_resets_count=pending_resets_count,
                             open_tickets_count=open_tickets_count)  # ✅ YEH ADD KARO
        
    except Exception as e:
        print(f"Database error: {e}")
        return render_template("admin/dashboard.html",
                             pending_requests=[],
                             pending_withdrawals=[],
                             total_users=0,
                             active_users=0,
                             withdrawals_count=0,
                             withdrawals_amount=0,
                             notifications_count=0,
                             pending_resets_count=0,
                             open_tickets_count=0)  # ✅ YEH BHI ADD KARO
    finally:
        db.close()
             
@app.route("/admin/approve/<int:request_id>")
@admin_required
def approve_request(request_id):
    """Approve deposit - TEST VERSION (2 MINUTES LOCK)"""
    
    db = get_db()
    try:
        # Get request
        request_data = db.execute("SELECT * FROM deposit_requests WHERE id=?", (request_id,)).fetchone()
        
        if not request_data:
            flash("Request not found", "error")
            return redirect("/admin/dashboard")
        
        user_id = request_data["user_id"]
        package_amount = request_data["package_amount"]
        
        # ✅ TEST LOCK - 2 MINUTES ONLY
        from datetime import datetime, timedelta
        lock_until = (datetime.now() + timedelta(days=5)).strftime('%Y-%m-%d %H:%M:%S')
        
        print(f"⏰ Lock set until: {lock_until}")
        print(f"⏰ Current time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # ✅ UPDATE USER WITH PACKAGE LOCK DATE
        db.execute("""
            UPDATE users 
            SET package_amount = ?,
                locked_balance = ?,
                package_lock_until = ?,
                deposit_status = 'approved',
                is_active = 1
            WHERE id = ?
        """, (package_amount, package_amount, lock_until, user_id))
        
        db.execute("UPDATE deposit_requests SET status='approved' WHERE id=?", (request_id,))
        db.commit()
        
        flash(f"✅ Package approved! TEST MODE - Unlocks in 2 minutes at {lock_until[11:19]}", "success")
        
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
    finally:
        db.close()
    
    return redirect("/admin/dashboard")
@app.route("/admin/reject/<int:request_id>", methods=["GET", "POST"])
@admin_required
def reject_request(request_id):
    """Reject a deposit request - UPDATED to show rejection page to user"""
    
    if request.method == "POST":
        reason = request.form.get("reason", "No reason provided")
        
        db = None
        try:
            db = get_db()
            
            # Get request details
            request_data = db.execute("SELECT * FROM deposit_requests WHERE id=?", (request_id,)).fetchone()
            if not request_data:
                flash("Request not found", "error")
                return redirect("/admin/dashboard")
            
            user_id = request_data["user_id"]
            
            # Update deposit request
            db.execute("""
                UPDATE deposit_requests 
                SET status = 'rejected',
                    admin_notes = ?,
                    rejected_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (reason, request_id))
            
            # Update user status
            db.execute("""
                UPDATE users 
                SET deposit_status = 'rejected',
                    is_active = 0,
                    rejection_reason = ?,
                    show_rejection = 1
                WHERE id = ?
            """, (reason, user_id))
            
            # Store session data for user to see rejection page
            session_data = {
                'request_id': request_id,
                'reason': reason,
                'admin_notes': reason,
                'user_name': request_data['name'],
                'user_phone': request_data['phone'],
                'selected_package': request_data['selected_package'],
                'package_amount': request_data['package_amount'],
                'deposit_tx_id': request_data['deposit_tx_id'],
                'rejected_at': datetime.now().isoformat()
            }
            
            db.execute("""
                INSERT INTO user_sessions 
                (user_id, session_type, session_data, expires_at)
                VALUES (?, ?, ?, datetime('now', '+24 hours'))
            """, (user_id, 'deposit_rejected', json.dumps(session_data)))
            
            db.commit()
            flash(f"Request rejected for user {request_data['name']}. User will see rejection page on next login.", "success")
            
        except Exception as e:
            if db:
                db.rollback()
            flash(f"Error: {str(e)}", "error")
        finally:
            if db:
                db.close()
        
        return redirect("/admin/dashboard")
    
    # GET - show rejection form
    db = get_db()
    try:
        request_data = db.execute("SELECT * FROM deposit_requests WHERE id=?", (request_id,)).fetchone()
        if not request_data:
            flash("Request not found", "error")
            return redirect("/admin/dashboard")
        
        return render_template("admin/reject_form.html", 
                             request_data=request_data, 
                             request_id=request_id)
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
        return redirect("/admin/dashboard")
    finally:
        db.close()

@app.route("/admin/users")
@admin_required
def admin_users():
    """Show all users"""
    db = get_db()
    try:
        users = db.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
        return render_template("admin/users.html", users=users)
    except Exception as e:
        flash(f"Error loading users: {str(e)}", "error")
        return render_template("admin/users.html", users=[])
    finally:
        db.close()

@app.route("/admin/user/delete/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    """Delete user with safe table checks"""
    
    reason = request.form.get("reason", "No reason provided")
    
    db = None
    try:
        db = get_db()
        
        # Get user info
        user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not user:
            flash("User not found", "error")
            return redirect("/admin/users")
        
        # Get all tables in database
        tables = db.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table'
        """).fetchall()
        table_names = [t['name'] for t in tables]
        
        print(f"📋 Available tables: {table_names}")
        
        # Tables that might have user_id column
        possible_tables = [
            'users',
            'deposit_requests', 
            'user_sessions',
            'withdrawals',
            'balance_transactions',
            'user_ad_progress',
            'ad_completion_notifications',
            'deposit_address_history',
            'password_reset_requests',
            'support_tickets'
        ]
        
        # Delete from tables that exist
        for table in possible_tables:
            if table in table_names:
                try:
                    db.execute(f"DELETE FROM {table} WHERE user_id=?", (user_id,))
                    print(f"✅ Deleted from {table}")
                except Exception as e:
                    print(f"⚠️ Error deleting from {table}: {e}")
        
        # Also try to delete by id from users table (already done above)
        # Ensure users table is deleted last
        db.execute("DELETE FROM users WHERE id=?", (user_id,))
        
        db.commit()
        flash(f"User '{user['name']}' has been deleted.", "success")
        
    except Exception as e:
        if db:
            db.rollback()
        flash(f"Error deleting user: {str(e)}", "error")
    finally:
        if db:
            db.close()
        return redirect("/admin/users")
@app.route("/admin/password-resets")
@admin_required
def admin_password_resets():
    """View all password reset requests"""
    db = get_db()
    try:
        # Pending requests
        pending_requests = db.execute("""
            SELECT * FROM password_reset_requests 
            WHERE status = 'pending'
            ORDER BY requested_at DESC
        """).fetchall()
        
        # Processed requests (last 10)
        processed_requests = db.execute("""
            SELECT * FROM password_reset_requests 
            WHERE status != 'pending'
            ORDER BY processed_at DESC
            LIMIT 10
        """).fetchall()
        
        return render_template("admin/password_resets.html",
                             pending_requests=pending_requests,
                             processed_requests=processed_requests)
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
        return redirect("/admin/dashboard")
    finally:
        db.close()

@app.route("/admin/password-reset/approve/<int:request_id>", methods=["GET", "POST"])
@admin_required
def approve_password_reset(request_id):
    """Approve and set new password"""
    
    if request.method == "POST":
        new_password = request.form.get("new_password", "").strip()
        
        if not new_password or len(new_password) < 6:
            flash("Password must be at least 6 characters", "error")
            return redirect(f"/admin/password-reset/approve/{request_id}")
        
        db = get_db()
        try:
            # Get request
            reset_req = db.execute("""
                SELECT * FROM password_reset_requests 
                WHERE id = ? AND status = 'pending'
            """, (request_id,)).fetchone()
            
            if not reset_req:
                flash("Request not found", "error")
                return redirect("/admin/password-resets")
            
            # Update user password
            db.execute("""
                UPDATE users SET password = ? 
                WHERE id = ?
            """, (generate_password_hash(new_password), reset_req["user_id"]))
            
            # Update request
            db.execute("""
                UPDATE password_reset_requests 
                SET status = 'approved',
                    new_password = ?,
                    processed_at = CURRENT_TIMESTAMP,
                    processed_by = ?
                WHERE id = ?
            """, (new_password, session.get("admin_username"), request_id))
            
            db.commit()
            
            flash(f"✅ Password set for {reset_req['user_name']}. New password: {new_password}", "success")
            
        except Exception as e:
            flash(f"Error: {str(e)}", "error")
        finally:
            db.close()
        
        return redirect("/admin/password-resets")
    
    # GET - Show form
    db = get_db()
    try:
        reset_req = db.execute("""
            SELECT * FROM password_reset_requests 
            WHERE id = ?
        """, (request_id,)).fetchone()
        
        if not reset_req:
            flash("Request not found", "error")
            return redirect("/admin/password-resets")
        
        return render_template("admin/set_password.html", request=reset_req)
    finally:
        db.close()

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """User submits password reset request"""
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        phone = request.form.get("phone", "").strip()
        
        if not name or not phone:
            flash("Name and phone required", "error")
            return redirect("/forgot-password")
        
        db = get_db()
        try:
            # Find user
            user = db.execute("""
                SELECT id, name, phone FROM users 
                WHERE phone = ? AND name LIKE ?
            """, (phone, f"%{name}%")).fetchone()
            
            if not user:
                flash("No account found with these details", "error")
                return redirect("/forgot-password")
            
            # Check pending request
            existing = db.execute("""
                SELECT id FROM password_reset_requests 
                WHERE user_id = ? AND status = 'pending'
            """, (user["id"],)).fetchone()
            
            if existing:
                flash("A request is already pending", "info")
                return redirect("/login")
            
            # Create request
            db.execute("""
                INSERT INTO password_reset_requests 
                (user_id, user_name, user_phone, status)
                VALUES (?, ?, ?, 'pending')
            """, (user["id"], user["name"], user["phone"]))
            
            db.commit()
            flash("✅ Reset request sent to admin!", "success")
            
        except Exception as e:
            flash(f"Error: {str(e)}", "error")
        finally:
            db.close()
        
        return redirect("/login")
    
    return render_template("forgot_password.html")
    


@app.route("/admin/user/toggle/<int:user_id>")
@admin_required
def toggle_user_status(user_id):
    """Toggle user active status"""
    db = get_db()
    try:
        user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not user:
            flash("User not found", "error")
            return redirect("/admin/users")
        
        new_status = 0 if user["is_active"] == 1 else 1
        db.execute("UPDATE users SET is_active = ? WHERE id = ?", (new_status, user_id))
        db.commit()
        
        status_text = "activated" if new_status == 1 else "deactivated"
        flash(f"User {user['name']} {status_text}", "success")
        
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
    finally:
        db.close()
    
    return redirect("/admin/users")


# =========================================================
# USER SEARCH AND BALANCE MANAGEMENT
# =========================================================

@app.route("/admin/search-user", methods=["GET", "POST"])
@admin_required
def search_user():
    """Search users by name, phone, or ID"""
    if request.method == "POST":
        search_term = request.form.get("search", "").strip()
        
        if not search_term:
            flash("Please enter search term", "error")
            return redirect("/admin/users")
        
        db = get_db()
        try:
            # Search in users table
            users = db.execute("""
                SELECT * FROM users 
                WHERE name LIKE ? 
                   OR phone LIKE ? 
                   OR id = ?
                ORDER BY created_at DESC
            """, (f"%{search_term}%", f"%{search_term}%", search_term if search_term.isdigit() else 0)).fetchall()
            
            if not users:
                flash(f"No users found for '{search_term}'", "warning")
                return redirect("/admin/users")
            
            return render_template("admin/users.html", 
                                 users=users, 
                                 search_term=search_term)
            
        except Exception as e:
            flash(f"Search error: {str(e)}", "error")
            return redirect("/admin/users")
        finally:
            db.close()
    
    return redirect("/admin/users")

@app.route("/admin/user/update-balance/<int:user_id>", methods=["GET", "POST"])
@admin_required
def update_user_balance(user_id):
    """Update user balance - COMPLETELY FIXED VERSION"""
    
    db = get_db()
    
    # GET USER
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    
    if not user:
        flash("User not found", "error")
        return redirect("/admin/users")
    
    # ===== HANDLE POST REQUEST (UPDATE BALANCE) =====
    if request.method == "POST":
        # Get form data
        action = request.form.get("action", "").strip()          # 'add' or 'subtract'
        amount_str = request.form.get("amount", "").strip()
        reason = request.form.get("reason", "").strip()
        balance_type = request.form.get("balance_type", "earnings").strip()  # 'earnings' or 'package'
        
        print(f"🔍 POST DATA: action={action}, amount={amount_str}, type={balance_type}, reason={reason}")
        
        # VALIDATION
        if not amount_str or not amount_str.isdigit():
            flash("Please enter a valid amount", "error")
            return redirect(f"/admin/user/update-balance/{user_id}")
        
        amount = int(amount_str)
        
        if amount <= 0:
            flash("Amount must be greater than 0", "error")
            return redirect(f"/admin/user/update-balance/{user_id}")
        
        if not reason:
            flash("Please provide a reason", "error")
            return redirect(f"/admin/user/update-balance/{user_id}")
        
        # CHECK LOCK STATUS FOR PACKAGE
        from datetime import datetime
        today = datetime.now().strftime('%Y-%m-%d')
        lock_until = user['package_lock_until'] if user['package_lock_until'] else None
        is_locked = lock_until and lock_until > today
        is_unlocked = lock_until and lock_until <= today
        
        
        try:
            # DETERMINE WHICH BALANCE TO UPDATE
            if balance_type == "earnings":
                column = "withdrawable_balance"
                current_balance = user["withdrawable_balance"] or 0
                balance_name = "Earnings"
            else:
                column = "package_amount"
                current_balance = user["package_amount"] or 0
                balance_name = "Package"
            
            print(f"📊 Current {balance_name}: {current_balance}")
            
            # CALCULATE NEW BALANCE
            if action == "add":
                new_balance = current_balance + amount
                transaction_type = "credit"
                action_text = "added to"
            else:  # subtract
                if amount > current_balance:
                    flash(f"Cannot deduct {amount} PKR. Current {balance_name} balance: {current_balance} PKR", "error")
                    return redirect(f"/admin/user/update-balance/{user_id}")
                new_balance = current_balance - amount
                transaction_type = "debit"
                action_text = "deducted from"
            
            print(f"✅ New {balance_name}: {new_balance}")
            
            # 🔥 FIX: UPDATE DATABASE - THIS IS THE CRITICAL PART
            result = db.execute(f"UPDATE users SET {column} = ? WHERE id = ?", (new_balance, user_id))
            db.commit()
            
            print(f"✅ Database updated: {result.rowcount} rows affected")
            
            # LOG TRANSACTION
            try:
                db.execute("""
                    INSERT INTO balance_transactions 
                    (user_id, user_name, previous_balance, amount, new_balance, 
                     transaction_type, reason, balance_type, admin_username)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    user_id, user["name"], current_balance, amount, new_balance,
                    transaction_type, reason, balance_type, session.get("admin_username", "admin")
                ))
                db.commit()
                print("✅ Transaction logged")
            except Exception as e:
                print(f"⚠️ Transaction log error (non-critical): {e}")
            
            flash(f"✅ {amount} PKR {action_text} {balance_name}. New balance: {new_balance} PKR", "success")
            
        except Exception as e:
            db.rollback()
            print(f"❌ ERROR: {e}")
            flash(f"Error updating balance: {str(e)}", "error")
        finally:
            db.close()
        
        return redirect(f"/admin/user/update-balance/{user_id}")
    
    # ===== GET REQUEST - SHOW FORM =====
    
    # Calculate lock status
    from datetime import datetime
    today = datetime.now().strftime('%Y-%m-%d')
    lock_until = user['package_lock_until'] if user['package_lock_until'] else None
    is_locked = lock_until and lock_until > today
    is_unlocked = lock_until and lock_until <= today
    
    # Get transaction history
    transactions = []
    try:
        transactions = db.execute("""
            SELECT * FROM balance_transactions 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT 20
        """, (user_id,)).fetchall()
        print(f"📋 Found {len(transactions)} transactions")
    except Exception as e:
        print(f"⚠️ Transaction fetch error: {e}")
        transactions = []
    
    db.close()
    
    return render_template("admin/update_balance.html",
                         user=user,
                         transactions=transactions,
                         is_locked=is_locked,
                         is_unlocked=is_unlocked,
                         lock_until=lock_until,
                         now=datetime.now())

@app.route("/admin/fix-transactions-table")
@admin_required
def fix_transactions_table():
    """Add balance_type column to balance_transactions table"""
    
    db = get_db()
    try:
        # Check if table exists
        table_check = db.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='balance_transactions'
        """).fetchone()
        
        if not table_check:
            # Create table with all columns
            db.execute("""
                CREATE TABLE balance_transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    user_name TEXT NOT NULL,
                    previous_balance INTEGER NOT NULL,
                    amount INTEGER NOT NULL,
                    new_balance INTEGER NOT NULL,
                    transaction_type TEXT NOT NULL,
                    balance_type TEXT NOT NULL DEFAULT 'earnings',
                    reason TEXT NOT NULL,
                    admin_username TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            return "✅ Table created successfully with balance_type column!"
        
        # Check existing columns
        columns = db.execute("PRAGMA table_info(balance_transactions)").fetchall()
        column_names = [col[1] for col in columns]
        
        result = "<h1>🔧 Fixing balance_transactions table</h1>"
        result += f"<p>Current columns: {', '.join(column_names)}</p>"
        
        # Add missing column
        if 'balance_type' not in column_names:
            db.execute("ALTER TABLE balance_transactions ADD COLUMN balance_type TEXT DEFAULT 'earnings'")
            result += "<p>✅ Added balance_type column</p>"
        else:
            result += "<p>✅ balance_type column already exists</p>"
        
        db.commit()
        result += "<p><a href='/admin/dashboard'>Back to Dashboard</a></p>"
        return result
        
    except Exception as e:
        return f"<h1>❌ Error: {e}</h1>"
    finally:
        db.close()
# =========================================================
# WITHDRAWAL ROUTES - SIMPLE VERSION
# =========================================================
from datetime import datetime

@app.route("/withdraw")
@login_required
def withdraw_page():
    """Withdraw funds page - FIXED lock status calculation"""
    user = get_user(session["user_id"])
    if not user:
        flash("User not found", "error")
        return redirect("/login")
    
    # Check if user is active
    if user["is_active"] != 1 or user["deposit_status"] != "approved":
        flash("Please activate your account first", "error")
        return redirect("/user-dashboard")
    
    # 🔥 FIX: Calculate lock status CORRECTLY
    from datetime import datetime
    
    today = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    lock_until = user.get('package_lock_until')
    
    print(f"🔍 DEBUG - Today: {today}")
    print(f"🔍 DEBUG - Lock until: {lock_until}")
    
    is_locked = False
    is_unlocked = False
    
    if lock_until:
        if lock_until > today:
            is_locked = True
            print(f"🔒 Package is LOCKED until {lock_until}")
        else:
            is_unlocked = True
            print(f"🔓 Package is UNLOCKED (current time > {lock_until})")
    
    return render_template("user/withdraw.html", 
                         user=user,
                         is_unlocked=is_unlocked,
                         is_locked=is_locked,
                         lock_until=lock_until)

@app.route("/submit-withdraw", methods=["POST"])
@login_required
def submit_withdraw():
    """Submit withdrawal request - REQUEST ONLY, NO AUTO PAYMENT"""
    
    db = None
    try:
        db = get_db()
        
        # First, ensure column exists
        try:
            db.execute("SELECT withdraw_type FROM withdrawals LIMIT 1").fetchone()
        except:
            db.execute("ALTER TABLE withdrawals ADD COLUMN withdraw_type TEXT DEFAULT 'earnings'")
            db.commit()
        
        # Get user data
        user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        if not user:
            flash("User not found", "error")
            return redirect("/login")
        
        user_dict = dict(user)
        
        # Check if user is active
        if user_dict["is_active"] != 1 or user_dict["deposit_status"] != "approved":
            flash("Please activate your account first", "error")
            return redirect("/user-dashboard")
        
        # Get withdraw_type
        withdraw_type = request.form.get("withdraw_type", "").strip()
        if withdraw_type not in ['earnings', 'package']:
            withdraw_type = 'earnings'
        
        print(f"🔍 Withdraw type: {withdraw_type}")
        
        # Get form data
        amount = request.form.get("amount", "").strip()
        method = request.form.get("method", "").strip()
        
        # Get account details based on method
        if method == "usdt":
            account_number = request.form.get("account_number", "").strip()
            account_name = request.form.get("account_name", "").strip()
        elif method == "jazzcash":
            account_number = request.form.get("jazzcash_number", "").strip()
            account_name = request.form.get("jazzcash_name", "").strip()
        elif method == "easypaisa":
            account_number = request.form.get("easypaisa_number", "").strip()
            account_name = request.form.get("easypaisa_name", "").strip()
        else:
            account_number = request.form.get("account_number", "").strip()
            account_name = request.form.get("account_name", "").strip()
        
        # Validation
        if not amount or not method or not account_number or not account_name:
            flash("All fields are required", "error")
            return redirect("/withdraw")
        
        try:
            amount = int(amount)
        except ValueError:
            flash("Invalid amount", "error")
            return redirect("/withdraw")
        
        if amount < 1000:
            flash("Minimum withdrawal is 1,000 PKR", "error")
            return redirect("/withdraw")
        
        # 🔥 FIX: Calculate lock status CORRECTLY here too
        from datetime import datetime
        today = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        lock_until = user_dict.get('package_lock_until')
        
        print(f"🔍 SUBMIT - Today: {today}")
        print(f"🔍 SUBMIT - Lock until: {lock_until}")
        
        is_locked = False
        is_unlocked = False
        
        if lock_until:
            if lock_until > today:
                is_locked = True
                print(f"🔒 Package is LOCKED")
            else:
                is_unlocked = True
                print(f"🔓 Package is UNLOCKED")
        
        # Determine balance based on type
        if withdraw_type == "package":
            if is_locked:  # Use is_locked flag
                flash("❌ Package amount is still locked. Cannot withdraw yet.", "error")
                return redirect("/withdraw")
            available_balance = user_dict.get("package_amount", 0)
            balance_name = "Package"
        else:
            available_balance = user_dict.get("withdrawable_balance", 0)
            balance_name = "Earnings"
        
        if amount > available_balance:
            flash(f"Insufficient {balance_name} balance. Available: {available_balance:,} PKR", "error")
            return redirect("/withdraw")
        
        # Calculate processing fee (2%)
        processing_fee = int(amount * 0.02)
        net_amount = amount - processing_fee
        
        # ✅ FIX: REQUEST ONLY - Insert withdrawal request without deducting balance
        db.execute("""
            INSERT INTO withdrawals 
            (user_id, user_name, user_phone, amount, processing_fee, net_amount, 
             method, account_number, account_name, status, withdraw_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
        """, (
            user_dict["id"], user_dict["name"], user_dict["phone"], 
            amount, processing_fee, net_amount,
            method, account_number, account_name,
            withdraw_type
        ))
        
        # ✅ FIX: DO NOT DEDUCT BALANCE HERE - Admin will deduct when approving
        # The balance remains untouched until admin approves
        
        db.commit()
        
        # Admin notification
        print("\n" + "="*60)
        print(f"📢 ADMIN NOTIFICATION: NEW WITHDRAWAL REQUEST")
        print("="*60)
        print(f"👤 User: {user_dict['name']} ({user_dict['phone']})")
        print(f"💰 Amount: {amount:,} PKR (from {balance_name})")
        print(f"💵 Net Amount: {net_amount:,} PKR (after 2% fee)")
        print(f"🏦 Method: {method}")
        print(f"📱 Account: {account_name} - {account_number}")
        print(f"⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60 + "\n")
        
        flash(f"✅ {balance_name} withdrawal request of {amount:,} PKR submitted! Admin will process within 24 hours.", "success")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        if db:
            db.rollback()
        flash(f"Error submitting request: {str(e)}", "error")
        return redirect("/withdraw")
    finally:
        if db:
            db.close()
    
    return redirect("/user-dashboard")


@app.route("/admin/fix-all-withdrawals")
@admin_required
def fix_all_withdrawals():
    """Completely fix all withdrawals"""
    
    db = get_db()
    result = "<h1>🔧 Complete Withdrawals Fix</h1>"
    
    try:
        # 1. Check/add column
        columns = db.execute("PRAGMA table_info(withdrawals)").fetchall()
        column_names = [col[1] for col in columns]
        
        if 'withdraw_type' not in column_names:
            db.execute("ALTER TABLE withdrawals ADD COLUMN withdraw_type TEXT DEFAULT 'earnings'")
            result += "<p>✅ Added withdraw_type column</p>"
        
        # 2. For existing records, try to determine type
        # Get all withdrawals without type
        to_fix = db.execute("SELECT * FROM withdrawals WHERE withdraw_type IS NULL OR withdraw_type = ''").fetchall()
        result += f"<p>Found {len(to_fix)} withdrawals to fix</p>"
        
        fixed = 0
        for w in to_fix:
            # Get user's balances at that time (approximate)
            user = db.execute("SELECT package_amount FROM users WHERE id = ?", (w['user_id'],)).fetchone()
            
            if user and user['package_amount'] and w['amount'] > user['package_amount'] * 0.5:
                # Large amount likely package withdrawal
                db.execute("UPDATE withdrawals SET withdraw_type = 'package' WHERE id = ?", (w['id'],))
            else:
                # Default to earnings
                db.execute("UPDATE withdrawals SET withdraw_type = 'earnings' WHERE id = ?", (w['id'],))
            fixed += 1
        
        db.commit()
        result += f"<p>✅ Fixed {fixed} withdrawals</p>"
        
    except Exception as e:
        result += f"<p>❌ Error: {e}</p>"
    finally:
        db.close()
    
    return result

    
        # =========================================================
# WITHDRAWAL DELETE ROUTE
# =========================================================

@app.route("/admin/withdraw/delete/<int:withdraw_id>")
@admin_required
def delete_withdrawal(withdraw_id):
    """Delete a withdrawal request"""
    db = get_db()
    try:
        # Get withdrawal details first
        withdrawal = db.execute("SELECT * FROM withdrawals WHERE id = ?", (withdraw_id,)).fetchone()
        if not withdrawal:
            flash("Withdrawal request not found", "error")
            return redirect("/admin/dashboard")
        
        # Delete the withdrawal record
        db.execute("DELETE FROM withdrawals WHERE id = ?", (withdraw_id,))
        db.commit()
        
        flash(f"✅ Withdrawal request #{withdraw_id} from {withdrawal['user_name']} has been deleted", "success")
        
    except Exception as e:
        db.rollback()
        flash(f"Error deleting withdrawal: {str(e)}", "error")
    finally:
        db.close()
    
    return redirect("/admin/dashboard")

@app.route("/admin/transaction/delete/<int:transaction_id>", methods=["GET"])  # ✅ Add GET
@admin_required
def delete_transaction(transaction_id):
    """Delete transaction"""
    db = get_db()
    try:
        db.execute("DELETE FROM balance_transactions WHERE id = ?", (transaction_id,))
        db.commit()
        flash("✅ Transaction deleted", "success")
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
    finally:
        db.close()
    return redirect(request.referrer or "/admin/dashboard")
# =========================================================
# SCREENSHOT VIEW ROUTE - ADDED
# =========================================================

@app.route("/admin/view-screenshot/<filename>")
@admin_required
def view_screenshot(filename):
    """View uploaded screenshot"""
    # Security check - prevent directory traversal
    if '..' in filename or '/' in filename or not filename:
        flash("Invalid filename", "error")
        return redirect("/admin/dashboard")
    
    filepath = os.path.join("static/uploads", filename)
    
    # Check if file exists
    if not os.path.exists(filepath):
        flash("Screenshot not found", "error")
        return redirect("/admin/dashboard")
    
    return render_template("admin/view_screenshot.html", filename=filename)

  # =========================================================
# USER PROFILE ROUTES
# =========================================================

@app.route("/profile")
@login_required
def profile():
    """User profile page -显示用户信息"""
    user = get_user(session["user_id"])
    
    if not user:
        flash("User not found", "error")
        return redirect("/login")
    
    db = get_db()
    try:
        # Get recent activities (last 5 transactions)
        recent_activities = []
        
        # Get recent deposits
        deposits = db.execute("""
            SELECT 'deposit' as type, created_at, package_amount as amount, status 
            FROM deposit_requests 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT 3
        """, (user["id"],)).fetchall()
        
        # Get recent withdrawals
        withdrawals = db.execute("""
            SELECT 'withdrawal' as type, created_at, amount, status 
            FROM withdrawals 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT 3
        """, (user["id"],)).fetchall()
        
        # Get recent ad completions
        ads = db.execute("""
            SELECT 'ad' as type, created_at, reward_amount as amount, 'completed' as status 
            FROM user_ad_progress 
            WHERE user_id = ? AND is_completed = 1
            ORDER BY created_at DESC 
            LIMIT 3
        """, (user["id"],)).fetchall()
        
        # Combine and sort all activities
        all_activities = list(deposits) + list(withdrawals) + list(ads)
        all_activities.sort(key=lambda x: x['created_at'], reverse=True)
        
        # Format for template
        from datetime import datetime
        now = datetime.now()
        
        for act in all_activities[:5]:  # Limit to 5 most recent
            time_diff = now - datetime.strptime(act['created_at'], '%Y-%m-%d %H:%M:%S')
            
            if time_diff.days > 0:
                time_str = f"{time_diff.days} day{'s' if time_diff.days > 1 else ''} ago"
            elif time_diff.seconds // 3600 > 0:
                hours = time_diff.seconds // 3600
                time_str = f"{hours} hour{'s' if hours > 1 else ''} ago"
            elif time_diff.seconds // 60 > 0:
                minutes = time_diff.seconds // 60
                time_str = f"{minutes} minute{'s' if minutes > 1 else ''} ago"
            else:
                time_str = "Just now"
            
            # Set icon and color based on type
            if act['type'] == 'deposit':
                icon = 'arrow-down'
                color = 'green'
                amount_color = 'green'
                description = f"Deposit of {act['amount']} PKR"
                if act['status'] == 'approved':
                    description += " (Approved)"
                elif act['status'] == 'pending':
                    description += " (Pending)"
            elif act['type'] == 'withdrawal':
                icon = 'arrow-up'
                color = 'red'
                amount_color = 'red'
                description = f"Withdrawal of {act['amount']} PKR"
                if act['status'] == 'approved':
                    description += " (Completed)"
                elif act['status'] == 'pending':
                    description += " (Pending)"
            else:  # ad completion
                icon = 'play'
                color = 'blue'
                amount_color = 'green'
                description = f"Ad reward: +{act['amount']} PKR"
            
            recent_activities.append({
                'icon': icon,
                'color': color,
                'amount_color': amount_color,
                'description': description,
                'time': time_str,
                'amount': f"+{act['amount']} PKR" if act['type'] != 'withdrawal' else f"-{act['amount']} PKR"
            })
        
        # Calculate total earned (sum of all approved ad rewards)
        total_earned = db.execute("""
            SELECT COALESCE(SUM(up.reward_amount), 0) as total
            FROM user_ad_progress up
            WHERE up.user_id = ? AND up.reward_credited = 1
        """, (user["id"],)).fetchone()["total"]
        
        # Calculate total withdrawn (sum of all approved withdrawals)
        total_withdrawn = db.execute("""
            SELECT COALESCE(SUM(amount), 0) as total
            FROM withdrawals 
            WHERE user_id = ? AND status = 'approved'
        """, (user["id"],)).fetchone()["total"]
        
        # Add these to user dict
        user_dict = dict(user)
        user_dict['total_earned'] = total_earned
        user_dict['total_withdrawn'] = total_withdrawn
        user_dict['email'] = user_dict.get('email', '')  # Add email if exists
        
        db.close()
        
        return render_template("user/profile.html", 
                             user=user_dict,
                             recent_activities=recent_activities)
    
    except Exception as e:
        print(f"❌ Profile error: {e}")
        import traceback
        traceback.print_exc()
        
        # Return with basic user data if error
        user_dict = dict(user)
        user_dict['total_earned'] = 0
        user_dict['total_withdrawn'] = 0
        user_dict['email'] = ''
        
        return render_template("user/profile.html", 
                             user=user_dict,
                             recent_activities=[])


@app.route("/update-profile", methods=["POST"])
@login_required
def update_profile():
    """Update user profile information"""
    user_id = session["user_id"]
    
    name = request.form.get("name", "").strip()
    phone = request.form.get("phone", "").strip()
    email = request.form.get("email", "").strip()
    
    # Validation
    if not name:
        flash("Name is required", "error")
        return redirect("/profile")
    
    if not phone or not re.match(r"^03\d{9}$", phone):
        flash("Invalid phone number format (03XXXXXXXXX)", "error")
        return redirect("/profile")
    
    if email and not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        flash("Invalid email format", "error")
        return redirect("/profile")
    
    db = get_db()
    try:
        # Check if phone already exists for another user
        existing = db.execute("""
            SELECT id FROM users 
            WHERE phone = ? AND id != ?
        """, (phone, user_id)).fetchone()
        
        if existing:
            flash("Phone number already registered to another account", "error")
            return redirect("/profile")
        
        # Update user profile
        db.execute("""
            UPDATE users 
            SET name = ?, phone = ?, email = ?
            WHERE id = ?
        """, (name, phone, email if email else None, user_id))
        
        db.commit()
        
        # Update session name
        session["user_name"] = name
        
        flash("✅ Profile updated successfully!", "success")
        
    except Exception as e:
        print(f"❌ Update profile error: {e}")
        flash(f"Error updating profile: {str(e)}", "error")
    finally:
        db.close()
    
    return redirect("/profile")


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    """Change user password"""
    user = get_user(session["user_id"])
    
    if not user:
        flash("User not found", "error")
        return redirect("/login")
    
    if request.method == "POST":
        current = request.form.get("current_password", "").strip()
        new = request.form.get("new_password", "").strip()
        confirm = request.form.get("confirm_password", "").strip()
        
        # Validation
        if not current or not new or not confirm:
            flash("All fields are required", "error")
            return redirect("/change-password")
        
        # Verify current password
        if not check_password_hash(user["password"], current):
            flash("Current password is incorrect", "error")
            return redirect("/change-password")
        
        if len(new) < 6:
            flash("New password must be at least 6 characters", "error")
            return redirect("/change-password")
        
        if new != confirm:
            flash("New passwords do not match", "error")
            return redirect("/change-password")
        
        if new == current:
            flash("New password must be different from current", "error")
            return redirect("/change-password")
        
        db = get_db()
        try:
            # Update password
            db.execute("""
                UPDATE users 
                SET password = ?
                WHERE id = ?
            """, (generate_password_hash(new), user["id"]))
            
            db.commit()
            flash("✅ Password changed successfully! Please login again.", "success")
            
            # Logout user
            session.clear()
            return redirect("/login")
            
        except Exception as e:
            print(f"❌ Change password error: {e}")
            flash(f"Error changing password: {str(e)}", "error")
            return redirect("/change-password")
        finally:
            db.close()
    
    return render_template("user/change_password.html", user=user)


@app.route("/delete-account", methods=["POST"])
@login_required
def delete_account():
    """Delete user account (self-deletion)"""
    user_id = session["user_id"]
    
    # Get password confirmation from form
    password = request.form.get("password", "").strip()
    
    if not password:
        flash("Password is required to delete account", "error")
        return redirect("/profile")
    
    db = get_db()
    try:
        # Verify user exists and password is correct
        user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        
        if not user:
            flash("User not found", "error")
            return redirect("/login")
        
        if not check_password_hash(user["password"], password):
            flash("Incorrect password", "error")
            return redirect("/profile")
        
        # Start transaction
        db.execute("BEGIN TRANSACTION")
        
        # Delete user data from all tables
        tables = [
            "user_ad_progress",
            "ad_completion_notifications",
            "deposit_requests",
            "withdrawals",
            "balance_transactions",
            "deposit_address_history",
            "user_sessions",
            "user_ads"  # if exists
        ]
        
        for table in tables:
            try:
                db.execute(f"DELETE FROM {table} WHERE user_id = ?", (user_id,))
            except Exception as e:
                print(f"Note: Could not delete from {table}: {e}")
        
        # Finally delete the user
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        
        db.commit()
        
        # Clear session
        session.clear()
        
        flash("✅ Your account has been permanently deleted.", "info")
        return redirect("/register")
        
    except Exception as e:
        db.rollback()
        print(f"❌ Delete account error: {e}")
        flash(f"Error deleting account: {str(e)}", "error")
        return redirect("/profile")
    finally:
        db.close()



# =========================================================
# SUPPORT ROUTES - FIXED
# =========================================================

@app.route("/support")
@login_required
def support_page():
    """Support center page"""
    user = get_user(session["user_id"])
    
    if not user:
        flash("User not found", "error")
        return redirect("/login")
    
    # Get user's recent tickets
    db = get_db()
    try:
        tickets = db.execute("""
            SELECT * FROM support_tickets 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT 5
        """, (user["id"],)).fetchall()
        
        db.close()
        return render_template("user/support.html", 
                             user=user,
                             tickets=tickets)
    except Exception as e:
        print(f"❌ Support page error: {e}")
        if db:
            db.close()
        return render_template("user/support.html", 
                             user=user,
                             tickets=[])


@app.route("/submit-support-ticket", methods=["POST"])
@login_required
def submit_support_ticket():
    """Submit a new support ticket"""
    user_id = session["user_id"]
    
    subject = request.form.get("subject", "").strip()
    message = request.form.get("message", "").strip()
    
    if not subject or not message:
        flash("Please fill all fields", "error")
        return redirect("/support")
    
    db = get_db()
    try:
        # Get user details
        user = db.execute("SELECT name, phone FROM users WHERE id = ?", (user_id,)).fetchone()
        
        if not user:
            flash("User not found", "error")
            return redirect("/login")
        
        # 🔥 FIXED: Insert and get ID
        cursor = db.execute("""
            INSERT INTO support_tickets 
            (user_id, user_name, user_phone, subject, message, status)
            VALUES (?, ?, ?, ?, ?, 'open')
        """, (user_id, user["name"], user["phone"], subject, message))
        
        db.commit()
        ticket_id = cursor.lastrowid  # ✅ YEH KAM KAREGA
        
        # Optional: Send email/notification to admin
        print(f"\n📧 New Support Ticket #{ticket_id} from {user['name']}")
        
        flash("✅ Support ticket submitted successfully! We'll respond within 2 hours.", "success")
        
    except Exception as e:
        print(f"❌ Ticket submission error: {e}")
        flash(f"Error submitting ticket: {str(e)}", "error")
    finally:
        db.close()
    
    return redirect("/support")


# =========================================================
# ADMIN SUPPORT ROUTES
# =========================================================

@app.route("/admin/support-tickets")
@admin_required
def admin_support_tickets():
    """Admin view of all support tickets"""
    db = get_db()
    try:
        # Get open tickets
        open_tickets = db.execute("""
            SELECT * FROM support_tickets 
            WHERE status = 'open' 
            ORDER BY created_at DESC
        """).fetchall()
        
        # Get in-progress tickets
        in_progress_tickets = db.execute("""
            SELECT * FROM support_tickets 
            WHERE status = 'in_progress' 
            ORDER BY updated_at DESC
        """).fetchall()
        
        # Get closed tickets (last 20)
        closed_tickets = db.execute("""
            SELECT * FROM support_tickets 
            WHERE status = 'closed' 
            ORDER BY closed_at DESC 
            LIMIT 20
        """).fetchall()
        
        db.close()
        
        return render_template("admin/support_tickets.html",
                             open_tickets=open_tickets,
                             in_progress_tickets=in_progress_tickets,
                             closed_tickets=closed_tickets)
    except Exception as e:
        print(f"❌ Admin support error: {e}")
        if db:
            db.close()
        flash(f"Error loading tickets: {str(e)}", "error")
        return redirect("/admin/dashboard")


@app.route("/admin/support-ticket/<int:ticket_id>", methods=["GET", "POST"])
@admin_required
def admin_view_ticket(ticket_id):
    """View and respond to a support ticket"""
    
    if request.method == "POST":
        response = request.form.get("response", "").strip()
        status = request.form.get("status", "in_progress")
        
        if not response:
            flash("Response cannot be empty", "error")
            return redirect(f"/admin/support-ticket/{ticket_id}")
        
        db = get_db()
        try:
            # Update ticket
            if status == "closed":
                db.execute("""
                    UPDATE support_tickets 
                    SET admin_response = ?,
                        status = ?,
                        responded_by = ?,
                        updated_at = CURRENT_TIMESTAMP,
                        closed_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (response, status, session.get("admin_username"), ticket_id))
            else:
                db.execute("""
                    UPDATE support_tickets 
                    SET admin_response = ?,
                        status = ?,
                        responded_by = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (response, status, session.get("admin_username"), ticket_id))
            
            db.commit()
            flash("✅ Response sent to user", "success")
            
        except Exception as e:
            print(f"❌ Ticket response error: {e}")
            flash(f"Error: {str(e)}", "error")
        finally:
            db.close()
        
        return redirect("/admin/support-tickets")
    
    # GET - show ticket details
    db = get_db()
    try:
        ticket = db.execute("""
            SELECT * FROM support_tickets WHERE id = ?
        """, (ticket_id,)).fetchone()
        
        if not ticket:
            flash("Ticket not found", "error")
            return redirect("/admin/support-tickets")
        
        db.close()
        return render_template("admin/view_ticket.html", ticket=ticket)
    except Exception as e:
        print(f"❌ Error loading ticket: {e}")
        if db:
            db.close()
        flash(f"Error: {str(e)}", "error")
        return redirect("/admin/support-tickets")


@app.route("/admin/support-ticket/close/<int:ticket_id>")
@admin_required
def admin_close_ticket(ticket_id):
    """Close a support ticket"""
    db = get_db()
    try:
        db.execute("""
            UPDATE support_tickets 
            SET status = 'closed',
                closed_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (ticket_id,))
        db.commit()
        flash("✅ Ticket closed", "success")
    except Exception as e:
        print(f"❌ Error closing ticket: {e}")
        flash(f"Error: {str(e)}", "error")
    finally:
        db.close()
    
    return redirect("/admin/support-tickets")
@app.route("/admin/support-ticket/delete/<int:ticket_id>")
@admin_required
def delete_support_ticket(ticket_id):
    """Delete a support ticket permanently"""
    
    db = get_db()
    try:
        # Get ticket details for logging
        ticket = db.execute("SELECT * FROM support_tickets WHERE id = ?", (ticket_id,)).fetchone()
        
        if not ticket:
            flash("Ticket not found", "error")
            return redirect("/admin/support-tickets")
        
        # Delete the ticket
        db.execute("DELETE FROM support_tickets WHERE id = ?", (ticket_id,))
        db.commit()
        
        # Log the deletion
        print(f"✅ Admin {session.get('admin_username')} deleted ticket #{ticket_id}")
        
        flash(f"Ticket #{ticket_id} has been permanently deleted", "success")
        
    except Exception as e:
        print(f"❌ Error deleting ticket: {e}")
        flash(f"Error deleting ticket: {str(e)}", "error")
    finally:
        db.close()
    
    return redirect("/admin/support-tickets")

from werkzeug.security import generate_password_hash, check_password_hash

@app.route("/admin/change-password", methods=["GET", "POST"])
@admin_required
def change_admin_password():
    """Change admin password"""
    
    if request.method == "POST":
        current_password = request.form.get("current_password", "").strip()
        new_password = request.form.get("new_password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()
        
        # Validation
        if not current_password or not new_password or not confirm_password:
            flash("All fields are required", "error")
            return redirect("/admin/change-password")
        
        if len(new_password) < 6:
            flash("New password must be at least 6 characters", "error")
            return redirect("/admin/change-password")
        
        if new_password != confirm_password:
            flash("New passwords do not match", "error")
            return redirect("/admin/change-password")
        
        db = get_db()
        try:
            # Get admin details
            admin = db.execute(
                "SELECT * FROM admins WHERE username = ?", 
                (session.get("admin_username"),)
            ).fetchone()
            
            if not admin:
                flash("Admin not found", "error")
                return redirect("/admin/logout")
            
            # Verify current password
            if not check_password_hash(admin["password"], current_password):
                flash("Current password is incorrect", "error")
                return redirect("/admin/change-password")
            
            # Update password
            hashed_password = generate_password_hash(new_password)
            db.execute(
                "UPDATE admins SET password = ? WHERE username = ?",
                (hashed_password, session.get("admin_username"))
            )
            db.commit()
            
            flash("✅ Password changed successfully! Please login with new password.", "success")
            
            # Logout admin to login with new password
            session.pop("admin", None)
            session.pop("admin_username", None)
            return redirect("/admin/login")
            
        except Exception as e:
            flash(f"Error: {str(e)}", "error")
            return redirect("/admin/change-password")
        finally:
            db.close()
    
    return render_template("admin/change_admin_password.html")

@app.route("/admin/reset-password", methods=["GET", "POST"])
def admin_reset_password():
    """Admin password reset (forgot password)"""
    
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        phone = request.form.get("phone", "").strip()  # Optional security question
        
        db = get_db()
        try:
            # Check if admin exists
            admin = db.execute(
                "SELECT * FROM admins WHERE username = ?", 
                (username,)
            ).fetchone()
            
            if not admin:
                flash("Admin not found", "error")
                return redirect("/admin/reset-password")
            
            # Generate a temporary password
            import random
            import string
            temp_password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
            
            # Update password
            hashed_password = generate_password_hash(temp_password)
            db.execute(
                "UPDATE admins SET password = ? WHERE username = ?",
                (hashed_password, username)
            )
            db.commit()
            
            # In production, send this via email/SMS
            flash(f"✅ Temporary password: {temp_password}", "success")
            flash("Please login and change your password immediately", "info")
            
            return redirect("/admin/login")
            
        except Exception as e:
            flash(f"Error: {str(e)}", "error")
            return redirect("/admin/reset-password")
        finally:
            db.close()
    
    return render_template("admin/reset_admin_password.html")


@app.route("/security-test")
def security_test():
    """Run security tests and show results"""
    
    import requests
    from threading import Thread
    import time
    
    results = []
    
    # Test 1: SQL Injection
    results.append("<h3>📝 SQL Injection Test</h3>")
    payloads = ["' OR '1'='1", "'; DROP TABLE users; --"]
    
    for payload in payloads:
        # This is just simulation - actual test would need to POST
        results.append(f"Testing: {payload} -> Should be blocked")
    
    # Test 2: Rate Limiting
    results.append("<h3>📝 Rate Limiting Test</h3>")
    results.append("Try 5+ failed logins - Should get 429 error")
    
    return "<br>".join(results) 


    
# =========================================================
# CHANGE PASSWORD PAGE TEMPLATE
# =========================================================
# Create templates/user/change_password.html      
# =========================================================
# STATIC ROUTES
# =========================================================

@app.route("/contact")
@login_required
def contact():
    return render_template("contact.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/privacy")
def privacy():
    return render_template("privacy.html")

@app.route("/terms")
def terms():
    return render_template("terms.html")


# === DISCLAIMER PAGE ROUTE ===
@app.route("/disclaimer")
def disclaimer():
    """Display disclaimer page"""
    return render_template("disclaimer.html")


    # OR this:
# app.py mein yeh add karo



@app.route("/packages")  # ya "/package"
def packages_page():
    """Public packages page"""
    # Get user from session if logged in
    user = None
    if 'user_id' in session:
        user = get_user(session['user_id'])
    
    return render_template("package.html", user=user)
# =========================================================
# ERROR HANDLERS
# =========================================================

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# =========================================================
# RUN APP
# =========================================================

if __name__ == "__main__":
    # Create necessary folders
    os.makedirs("static/uploads", exist_ok=True)
    os.makedirs("templates/admin", exist_ok=True)
    os.makedirs("templates/user", exist_ok=True)
    
    print("="*60)
    print("🚀 Upside Platform Starting...")
    print(f"📁 Uploads folder: {os.path.abspath('static/uploads')}")
    print("🌐 Server running at: http://127.0.0.1:5000")
    print("🔑 Admin login: admin / admin123")
    print("="*60)
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True
    )


# http://127.0.0.1:5000/admin/dashboard