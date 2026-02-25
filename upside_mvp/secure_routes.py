# secure_routes.py
from flask import session, redirect, abort, request, url_for
from functools import wraps
import time

import urls

class SecureRouter:
    """Route management and helpers"""
    
    def __init__(self, urls):
        self.urls = urls
        self.url_map = self._create_url_map()
    
    def _create_url_map(self):
        """Create complete URL mapping"""
        return {
            # Public pages
            'home': self.urls.HOME,
            'login': self.urls.LOGIN,
            'register': self.urls.REGISTER,
            'forgot_password': self.urls.FORGOT_PASSWORD,
            'packages': self.urls.PACKAGES,
            'about': self.urls.ABOUT,
            'contact': self.urls.CONTACT,
            'terms': self.urls.TERMS,
            'privacy': self.urls.PRIVACY,
            'disclaimers': self.urls.DISCLAIMERS,
            
            # User pages
            'user_dashboard': self.urls.USER_DASHBOARD,
            'user_withdraw': self.urls.USER_WITHDRAW,
            'user_deposit': self.urls.USER_DEPOSIT,
            'user_profile': self.urls.USER_PROFILE,
            'user_support': self.urls.USER_SUPPORT,
            'user_change_password': self.urls.USER_CHANGE_PASSWORD,
            'user_watch_ad': self.urls.USER_WATCH_AD,
            'user_deposit_rejected': self.urls.USER_DEPOSIT_REJECTED,
            
            # Admin pages
            'admin_dashboard': self.urls.ADMIN_DASHBOARD,
            'admin_users': self.urls.ADMIN_USERS,
            'admin_user_detail': self.urls.ADMIN_USER_DETAIL,
            'admin_ads': self.urls.ADMIN_ADS,
            'admin_add_ad': self.urls.ADMIN_ADD_AD,
            'admin_edit_ad': self.urls.ADMIN_EDIT_AD,
            'admin_approved': self.urls.ADMIN_APPROVED,
            'admin_rejected': self.urls.ADMIN_REJECTED,
            'admin_reject_form': self.urls.ADMIN_REJECT_FORM,
            'admin_deposits_pending': self.urls.ADMIN_DEPOSITS_PENDING,
            'admin_withdrawals': self.urls.ADMIN_WITHDRAWALS,
            'admin_password_resets': self.urls.ADMIN_PASSWORD_RESETS,
            'admin_set_password': self.urls.ADMIN_SET_PASSWORD,
            'admin_usdt_address': self.urls.ADMIN_USDT_ADDRESS,
            'admin_update_balance': self.urls.ADMIN_UPDATE_BALANCE,
            'admin_view_screenshot': self.urls.ADMIN_VIEW_SCREENSHOT,
            'admin_view_ticket': self.urls.ADMIN_VIEW_TICKET,
            'admin_support_tickets': self.urls.ADMIN_SUPPORT_TICKETS,
            'admin_statistics': self.urls.ADMIN_STATISTICS,
            'admin_change_password': self.urls.ADMIN_CHANGE_PASSWORD,
            'admin_debug_notification': self.urls.ADMIN_DEBUG_NOTIFICATION,
            
            # Ultra secure
            'admin_settings': self.urls.ADMIN_SETTINGS,
            'admin_logs': self.urls.ADMIN_LOGS,
            'admin_backup': self.urls.ADMIN_BACKUP,
        }
    
    def get_url(self, page_name):
        """Get URL for page"""
        return self.url_map.get(page_name, '/')
    
    def redirect_to(self, page_name):
        """Redirect to secure page"""
        return redirect(self.get_url(page_name))

router = SecureRouter(urls)