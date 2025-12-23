"""
Session Manager - Handle authentication and session state
Easy for LLM to manage login sessions
"""

import json
import pickle
import os
from typing import Dict, Optional, List, Any
from dataclasses import dataclass, field
from datetime import datetime
from .http_client import HTTPClient, Response


@dataclass
class AuthCredentials:
    """Store authentication credentials"""
    username: str = ""
    password: str = ""
    token: str = ""
    api_key: str = ""
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class SessionState:
    """Track session state"""
    is_authenticated: bool = False
    auth_type: str = ""  # form, basic, bearer, api_key, cookie
    login_url: str = ""
    logout_url: str = ""
    user_info: Dict[str, Any] = field(default_factory=dict)
    csrf_token: str = ""
    session_cookie: str = ""


class SessionManager:
    """
    Manage authentication sessions for web apps
    
    Usage for LLM:
    - manager.login_form(url, username, password) - Login via form
    - manager.login_basic(url, username, password) - HTTP Basic Auth
    - manager.login_bearer(token) - Set Bearer token
    - manager.check_auth() - Check if still authenticated
    - manager.logout() - Logout and clear session
    """
    
    def __init__(self, client: Optional[HTTPClient] = None):
        self.client = client or HTTPClient()
        self.credentials = AuthCredentials()
        self.state = SessionState()
        self.auth_indicators = {
            "logged_in": [
                "logout", "sign out", "log out", "dashboard", "my account",
                "profile", "welcome", "settings", "preferences"
            ],
            "logged_out": [
                "login", "sign in", "log in", "register", "forgot password",
                "create account", "unauthorized", "access denied"
            ]
        }
    
    def login_form(self, login_url: str, username: str, password: str,
                   username_field: str = "username", 
                   password_field: str = "password",
                   extra_fields: Optional[Dict] = None,
                   csrf_field: Optional[str] = None) -> Dict[str, Any]:
        """
        Login via HTML form submission
        
        Args:
            login_url: URL of login form
            username: Username to login with
            password: Password to login with
            username_field: Name of username input field
            password_field: Name of password input field
            extra_fields: Additional form fields
            csrf_field: Name of CSRF token field (will auto-fetch if provided)
        
        Returns:
            Dict with success status and details
        """
        result = {
            "success": False,
            "message": "",
            "response": None,
            "cookies": {}
        }
        
        # First, get the login page (to get CSRF token and cookies)
        get_resp = self.client.get(login_url)
        
        # Extract CSRF token if needed
        csrf_token = ""
        if csrf_field:
            import re
            patterns = [
                rf'name=["\']?{csrf_field}["\']?\s+value=["\']([^"\']+)["\']',
                rf'value=["\']([^"\']+)["\'].*name=["\']?{csrf_field}["\']?',
                rf'{csrf_field}["\']?\s*:\s*["\']([^"\']+)["\']'
            ]
            for pattern in patterns:
                match = re.search(pattern, get_resp.body, re.IGNORECASE)
                if match:
                    csrf_token = match.group(1)
                    break
        
        # Build form data
        form_data = {
            username_field: username,
            password_field: password
        }
        
        if csrf_token and csrf_field:
            form_data[csrf_field] = csrf_token
            self.state.csrf_token = csrf_token
        
        if extra_fields:
            form_data.update(extra_fields)
        
        # Submit login form
        login_resp = self.client.post(login_url, data=form_data)
        result["response"] = login_resp.to_dict()
        result["cookies"] = self.client.get_cookies()
        
        # Check if login successful
        if self._check_login_success(login_resp):
            self.state.is_authenticated = True
            self.state.auth_type = "form"
            self.state.login_url = login_url
            self.credentials.username = username
            self.credentials.password = password
            result["success"] = True
            result["message"] = "Login successful"
        else:
            result["message"] = "Login failed - check credentials or login indicators"
        
        return result

    def login_basic(self, url: str, username: str, password: str) -> Dict[str, Any]:
        """Login using HTTP Basic Authentication"""
        self.client.set_auth(username, password)
        resp = self.client.get(url)
        
        result = {
            "success": resp.status_code == 200,
            "message": "",
            "response": resp.to_dict()
        }
        
        if resp.status_code == 200:
            self.state.is_authenticated = True
            self.state.auth_type = "basic"
            self.credentials.username = username
            self.credentials.password = password
            result["message"] = "Basic auth successful"
        elif resp.status_code == 401:
            result["message"] = "Authentication failed - invalid credentials"
        else:
            result["message"] = f"Unexpected status: {resp.status_code}"
        
        return result

    def login_bearer(self, token: str, test_url: Optional[str] = None) -> Dict[str, Any]:
        """Set Bearer token authentication"""
        self.client.set_bearer_token(token)
        self.credentials.token = token
        self.state.auth_type = "bearer"
        
        result = {
            "success": True,
            "message": "Bearer token set",
            "token_preview": token[:20] + "..." if len(token) > 20 else token
        }
        
        # Test token if URL provided
        if test_url:
            resp = self.client.get(test_url)
            result["test_response"] = resp.to_dict()
            if resp.status_code == 401:
                result["success"] = False
                result["message"] = "Token appears invalid"
            elif resp.status_code == 200:
                self.state.is_authenticated = True
                result["message"] = "Bearer token valid and set"
        
        return result

    def login_api_key(self, api_key: str, header_name: str = "X-API-Key",
                      test_url: Optional[str] = None) -> Dict[str, Any]:
        """Set API key authentication"""
        self.client.set_header(header_name, api_key)
        self.credentials.api_key = api_key
        self.state.auth_type = "api_key"
        
        result = {
            "success": True,
            "message": f"API key set in {header_name} header"
        }
        
        if test_url:
            resp = self.client.get(test_url)
            result["test_response"] = resp.to_dict()
            if resp.status_code in [401, 403]:
                result["success"] = False
                result["message"] = "API key appears invalid"
            else:
                self.state.is_authenticated = True
        
        return result

    def login_cookie(self, cookies: Dict[str, str], 
                     test_url: Optional[str] = None) -> Dict[str, Any]:
        """Set session cookies directly"""
        for name, value in cookies.items():
            self.client.set_cookie(name, value)
        
        self.credentials.cookies = cookies
        self.state.auth_type = "cookie"
        
        result = {
            "success": True,
            "message": "Cookies set",
            "cookies": cookies
        }
        
        if test_url:
            resp = self.client.get(test_url)
            result["test_response"] = resp.to_dict()
            if self._check_login_success(resp):
                self.state.is_authenticated = True
                result["message"] = "Session cookies valid"
            else:
                result["success"] = False
                result["message"] = "Session appears invalid"
        
        return result

    def _check_login_success(self, response: Response) -> bool:
        """Check if login was successful based on response"""
        body_lower = response.body.lower()
        
        # Check for logout indicators (means we're logged in)
        logged_in_score = sum(1 for ind in self.auth_indicators["logged_in"] 
                              if ind in body_lower)
        
        # Check for login indicators (means we're NOT logged in)
        logged_out_score = sum(1 for ind in self.auth_indicators["logged_out"] 
                               if ind in body_lower)
        
        # Check status codes
        if response.status_code in [401, 403]:
            return False
        
        # Check for redirect to dashboard/home
        if response.status_code in [200, 302] and logged_in_score > logged_out_score:
            return True
        
        return logged_in_score > logged_out_score

    def check_auth(self, test_url: Optional[str] = None) -> Dict[str, Any]:
        """Check if current session is still authenticated"""
        if not test_url:
            test_url = self.state.login_url
        
        if not test_url:
            return {
                "authenticated": self.state.is_authenticated,
                "auth_type": self.state.auth_type,
                "message": "No test URL available"
            }
        
        resp = self.client.get(test_url)
        is_auth = self._check_login_success(resp)
        self.state.is_authenticated = is_auth
        
        return {
            "authenticated": is_auth,
            "auth_type": self.state.auth_type,
            "cookies": self.client.get_cookies(),
            "response_status": resp.status_code
        }

    def logout(self, logout_url: Optional[str] = None) -> Dict[str, Any]:
        """Logout and clear session"""
        result = {"success": True, "message": "Session cleared"}
        
        if logout_url or self.state.logout_url:
            url = logout_url or self.state.logout_url
            resp = self.client.get(url)
            result["response"] = resp.to_dict()
        
        # Clear everything
        self.client.clear_cookies()
        self.credentials = AuthCredentials()
        self.state = SessionState()
        
        return result

    def get_session_info(self) -> Dict[str, Any]:
        """Get current session information"""
        return {
            "is_authenticated": self.state.is_authenticated,
            "auth_type": self.state.auth_type,
            "login_url": self.state.login_url,
            "cookies": self.client.get_cookies(),
            "csrf_token": self.state.csrf_token,
            "user_info": self.state.user_info
        }

    def save_session(self, filepath: str):
        """Save session to file for later use"""
        data = {
            "cookies": self.client.get_cookies(),
            "credentials": {
                "username": self.credentials.username,
                "token": self.credentials.token,
                "api_key": self.credentials.api_key,
                "headers": self.credentials.headers
            },
            "state": {
                "is_authenticated": self.state.is_authenticated,
                "auth_type": self.state.auth_type,
                "login_url": self.state.login_url,
                "csrf_token": self.state.csrf_token
            }
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

    def load_session(self, filepath: str) -> bool:
        """Load session from file"""
        if not os.path.exists(filepath):
            return False
        
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        # Restore cookies
        for name, value in data.get("cookies", {}).items():
            self.client.set_cookie(name, value)
        
        # Restore state
        state = data.get("state", {})
        self.state.is_authenticated = state.get("is_authenticated", False)
        self.state.auth_type = state.get("auth_type", "")
        self.state.login_url = state.get("login_url", "")
        self.state.csrf_token = state.get("csrf_token", "")
        
        return True


class MultiAccountManager:
    """Manage multiple accounts for testing"""
    
    def __init__(self):
        self.accounts: Dict[str, SessionManager] = {}
        self.active_account: Optional[str] = None
    
    def add_account(self, name: str, session: SessionManager):
        """Add an account"""
        self.accounts[name] = session
        if not self.active_account:
            self.active_account = name
    
    def switch_account(self, name: str) -> bool:
        """Switch active account"""
        if name in self.accounts:
            self.active_account = name
            return True
        return False
    
    def get_active(self) -> Optional[SessionManager]:
        """Get active session manager"""
        if self.active_account:
            return self.accounts.get(self.active_account)
        return None
    
    def list_accounts(self) -> List[Dict]:
        """List all accounts and their status"""
        return [
            {
                "name": name,
                "authenticated": session.state.is_authenticated,
                "auth_type": session.state.auth_type,
                "active": name == self.active_account
            }
            for name, session in self.accounts.items()
        ]
