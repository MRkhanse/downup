# urls.py - ALL URLS CENTRALIZED
import secrets
import os
import hashlib
import time
from datetime import datetime, timedelta

class SecureURLs:
    """Complete URL management system"""
    
    def __init__(self):
        # Load secret from environment
        self.secret_key = os.getenv('URL_SECRET_KEY', secrets.token_urlsafe(16))
        self.rotation_day = int(os.getenv('URL_ROTATION_DAY', 1))
        
        # Generate daily hash for rotation
        self._generate_daily_hash()
        
        # ===== PUBLIC PAGES (Normal URLs) =====
        self.HOME = "/"
        self.LOGIN = "/login"
        self.REGISTER = "/register"
        self.FORGOT_PASSWORD = "/forgot-password"
        self.PACKAGES = "/packages"
        self.ABOUT = "/about"
        self.CONTACT = "/contact"
        self.TERMS = "/terms"
        self.PRIVACY = "/privacy"
        self.DISCLAIMERS = "/disclaimers"
        
        # ===== USER PAGES (Secure URLs) =====
        self.USER_DASHBOARD = self._secure_path("user-dashboard")
        self.USER_WITHDRAW = self._secure_path("withdraw")
        self.USER_DEPOSIT = self._secure_path("deposit")
        self.USER_PROFILE = self._secure_path("profile")
        self.USER_SUPPORT = self._secure_path("support")
        self.USER_CHANGE_PASSWORD = self._secure_path("change-password")
        self.USER_WATCH_AD = self._secure_path("watch-ad")
        self.USER_DEPOSIT_REJECTED = self._secure_path("deposit-rejected")
        
        # ===== ADMIN PAGES (Secure URLs) =====
        self.ADMIN_DASHBOARD = self._secure_path("admin-dashboard")
        self.ADMIN_USERS = self._secure_path("admin-users")
        self.ADMIN_USER_DETAIL = self._secure_path("admin-user-detail")
        self.ADMIN_ADS = self._secure_path("admin-ads")
        self.ADMIN_ADD_AD = self._secure_path("admin-add-ad")
        self.ADMIN_EDIT_AD = self._secure_path("admin-edit-ad")
        self.ADMIN_APPROVED = self._secure_path("admin-approved")
        self.ADMIN_REJECTED = self._secure_path("admin-rejected")
        self.ADMIN_REJECT_FORM = self._secure_path("admin-reject-form")
        self.ADMIN_DEPOSITS_PENDING = self._secure_path("admin-deposits-pending")
        self.ADMIN_WITHDRAWALS = self._secure_path("admin-withdrawals")
        self.ADMIN_PASSWORD_RESETS = self._secure_path("admin-password-resets")
        self.ADMIN_SET_PASSWORD = self._secure_path("admin-set-password")
        self.ADMIN_USDT_ADDRESS = self._secure_path("admin-usdt-address")
        self.ADMIN_UPDATE_BALANCE = self._secure_path("admin-update-balance")
        self.ADMIN_VIEW_SCREENSHOT = self._secure_path("admin-view-screenshot")
        self.ADMIN_VIEW_TICKET = self._secure_path("admin-view-ticket")
        self.ADMIN_SUPPORT_TICKETS = self._secure_path("admin-support-tickets")
        self.ADMIN_STATISTICS = self._secure_path("admin-statistics")
        self.ADMIN_CHANGE_PASSWORD = self._secure_path("admin-change-password")
        self.ADMIN_DEBUG_NOTIFICATION = self._secure_path("admin-debug-notification")
        
        # ===== ULTRA SECURE PAGES =====
        self.ADMIN_SETTINGS = self._ultra_secure_path("settings")
        self.ADMIN_LOGS = self._ultra_secure_path("logs")
        self.ADMIN_BACKUP = self._ultra_secure_path("backup")
    
    def _generate_daily_hash(self):
        """Generate daily changing hash for rotation"""
        today = datetime.now().strftime('%Y-%m-%d')
        hash_input = f"{self.secret_key}-{today}-{self.rotation_day}"
        self.daily_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:12]
    
    def _secure_path(self, name):
        """Generate secure path with daily rotation"""
        # Format: /{daily_hash}/{random_id}/{name}
        random_id = secrets.token_hex(6)
        return f"/{self.daily_hash}/{random_id}/{name}"
    
    def _ultra_secure_path(self, name):
        """Ultra secure path with double hashing"""
        first = hashlib.sha256(f"{name}{secrets.token_hex(8)}".encode()).hexdigest()[:16]
        second = secrets.token_hex(12)
        return f"/{first}/{second}/{name}"
    
    def rotate_urls(self):
        """Force URL rotation"""
        self._generate_daily_hash()
        # Reinitialize all URLs
        self.__init__()

# Initialize URLs
urls = SecureURLs()