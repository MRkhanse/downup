# secure_decorators.py - FIXED VERSION
from flask import session, redirect, abort, request, flash
from functools import wraps
import time

# =========================================================
# SECURITY DECORATORS
# =========================================================

def login_required_secure(f):
    """Secure login required decorator with timeout"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login first", "error")
            return redirect("/login")  # ✅ Direct redirect, no router
        
        # Check session age (2 hours)
        login_time = session.get('login_time', 0)
        if time.time() - login_time > 7200:
            session.clear()
            flash("Session expired. Please login again.", "error")
            return redirect("/login")
        
        return f(*args, **kwargs)
    return decorated

def admin_required_secure(f):
    """Secure admin required decorator"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin"):
            flash("Admin access required", "error")
            return redirect("/admin/login")
        
        # Check session age (1 hour for admin)
        admin_time = session.get('admin_time', 0)
        if time.time() - admin_time > 3600:
            session.clear()
            flash("Admin session expired", "error")
            return redirect("/admin/login")
        
        return f(*args, **kwargs)
    return decorated

def rate_limit(max_attempts=5, window=300):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip = request.remote_addr
            now = time.time()
            
            # Simple in-memory rate limiting
            if not hasattr(request, 'rate_limits'):
                request.rate_limits = {}
            
            if not hasattr(request, 'rate_limits_data'):
                request.rate_limits_data = {}
            
            # Clean old attempts
            request.rate_limits_data = {k: v for k, v in request.rate_limits_data.items() 
                                       if now - v[0] < window}
            
            # Check current attempts
            attempts = request.rate_limits_data.get(ip, [])
            if len(attempts) >= max_attempts:
                flash("Too many attempts. Please try again later.", "error")
                return redirect(request.referrer or "/")
            
            # Add attempt
            request.rate_limits_data[ip] = attempts + [(now, request.path)]
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def prevent_direct_access(f):
    """Prevent direct URL access"""
    @wraps(f)
    def decorated(*args, **kwargs):
        referrer = request.referrer
        if not referrer or request.host not in referrer:
            abort(404)  # Return 404 to hide existence
        return f(*args, **kwargs)
    return decorated