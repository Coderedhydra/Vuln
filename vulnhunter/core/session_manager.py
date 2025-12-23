"""
Session Manager for VulnHunter
Handles authentication, session persistence, and credential management
"""

import json
import pickle
import hashlib
from pathlib import Path
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field
from datetime import datetime
from loguru import logger

from .http_client import HTTPClient, HTTPRequest, HTTPResponse


@dataclass
class Credentials:
    """User credentials storage"""
    username: str = ""
    password: str = ""
    email: str = ""
    token: str = ""
    api_key: str = ""
    custom_fields: Dict[str, str] = field(default_factory=dict)


@dataclass
class AuthSession:
    """Authenticated session data"""
    session_id: str
    cookies: Dict[str, str]
    headers: Dict[str, str]
    tokens: Dict[str, str]
    created_at: datetime
    expires_at: Optional[datetime] = None
    is_valid: bool = True
    user_info: Dict[str, Any] = field(default_factory=dict)


class SessionManager:
    """
    Manages authentication sessions and credentials
    Easy interface for LLM to handle auth flows
    """
    
    def __init__(self, http_client: HTTPClient, storage_path: str = ".vulnhunter_sessions"):
        self.http_client = http_client
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(exist_ok=True)
        
        self.current_session: Optional[AuthSession] = None
        self.credentials: Optional[Credentials] = None
        self.auth_endpoints: Dict[str, str] = {}
        
        # Common auth endpoints to detect
        self.common_login_paths = [
            '/login', '/signin', '/auth/login', '/api/login', '/api/auth/login',
            '/user/login', '/account/login', '/session', '/api/session',
            '/oauth/token', '/api/token', '/authenticate', '/api/authenticate'
        ]
        
        self.common_register_paths = [
            '/register', '/signup', '/auth/register', '/api/register',
            '/user/register', '/account/create', '/api/users', '/join'
        ]
        
        self.common_logout_paths = [
            '/logout', '/signout', '/auth/logout', '/api/logout',
            '/session/destroy', '/api/session'
        ]
    
    def set_credentials(self, username: str = "", password: str = "", 
                       email: str = "", token: str = "", **kwargs) -> Credentials:
        """
        Set credentials for authentication
        
        LLM Usage:
            session_mgr.set_credentials(username="test", password="test123")
        """
        self.credentials = Credentials(
            username=username,
            password=password,
            email=email,
            token=token,
            custom_fields=kwargs
        )
        logger.info(f"Credentials set for user: {username or email or 'token-auth'}")
        return self.credentials
    
    def detect_auth_endpoints(self, discovered_urls: List[str]) -> Dict[str, str]:
        """
        Auto-detect authentication endpoints from crawled URLs
        
        Returns dict with login, register, logout URLs if found
        """
        endpoints = {}
        
        for url in discovered_urls:
            url_lower = url.lower()
            
            for path in self.common_login_paths:
                if path in url_lower and 'login' not in endpoints:
                    endpoints['login'] = url
                    break
                    
            for path in self.common_register_paths:
                if path in url_lower and 'register' not in endpoints:
                    endpoints['register'] = url
                    break
                    
            for path in self.common_logout_paths:
                if path in url_lower and 'logout' not in endpoints:
                    endpoints['logout'] = url
                    break
                    
        self.auth_endpoints = endpoints
        logger.info(f"Detected auth endpoints: {endpoints}")
        return endpoints
    
    def login_form(self, login_url: str, username_field: str = "username",
                   password_field: str = "password", extra_fields: Optional[Dict] = None) -> HTTPResponse:
        """
        Perform form-based login
        
        LLM Usage:
            response = session_mgr.login_form(
                login_url="/login",
                username_field="email",
                password_field="passwd"
            )
        """
        if not self.credentials:
            raise ValueError("Credentials not set. Call set_credentials() first.")
        
        form_data = {
            username_field: self.credentials.username or self.credentials.email,
            password_field: self.credentials.password,
        }
        
        if extra_fields:
            form_data.update(extra_fields)
            
        response = self.http_client.post_form(login_url, form_data)
        
        if response.status_code in [200, 302, 303]:
            self._create_session_from_response(response)
            
        return response
    
    def login_json(self, login_url: str, username_field: str = "username",
                   password_field: str = "password", extra_fields: Optional[Dict] = None) -> HTTPResponse:
        """
        Perform JSON API login
        
        LLM Usage:
            response = session_mgr.login_json(
                login_url="/api/auth/login",
                username_field="email",
                password_field="password"
            )
        """
        if not self.credentials:
            raise ValueError("Credentials not set. Call set_credentials() first.")
        
        json_data = {
            username_field: self.credentials.username or self.credentials.email,
            password_field: self.credentials.password,
        }
        
        if extra_fields:
            json_data.update(extra_fields)
            
        response = self.http_client.post_json(login_url, json_data)
        
        if response.status_code == 200 and response.is_json:
            self._create_session_from_response(response)
            # Extract token if present in response
            if response.json_data:
                self._extract_tokens_from_json(response.json_data)
                
        return response
    
    def login_oauth2(self, token_url: str, client_id: str, client_secret: str,
                     grant_type: str = "password", scope: str = "") -> HTTPResponse:
        """
        Perform OAuth2 authentication
        
        LLM Usage:
            response = session_mgr.login_oauth2(
                token_url="/oauth/token",
                client_id="client123",
                client_secret="secret456"
            )
        """
        if not self.credentials:
            raise ValueError("Credentials not set. Call set_credentials() first.")
        
        data = {
            'grant_type': grant_type,
            'client_id': client_id,
            'client_secret': client_secret,
        }
        
        if grant_type == 'password':
            data['username'] = self.credentials.username or self.credentials.email
            data['password'] = self.credentials.password
            
        if scope:
            data['scope'] = scope
            
        response = self.http_client.post_form(token_url, data)
        
        if response.status_code == 200 and response.is_json:
            self._create_session_from_response(response)
            if response.json_data:
                self._extract_tokens_from_json(response.json_data)
                
        return response
    
    def register_account(self, register_url: str, fields: Dict[str, str],
                        use_json: bool = True) -> HTTPResponse:
        """
        Register a new account
        
        LLM Usage:
            response = session_mgr.register_account(
                register_url="/api/register",
                fields={
                    "username": "testuser",
                    "email": "test@test.com",
                    "password": "Test123!",
                    "confirm_password": "Test123!"
                }
            )
        """
        if use_json:
            response = self.http_client.post_json(register_url, fields)
        else:
            response = self.http_client.post_form(register_url, fields)
            
        logger.info(f"Registration attempt: status={response.status_code}")
        return response
    
    def _create_session_from_response(self, response: HTTPResponse):
        """Create auth session from successful login response"""
        session_id = hashlib.sha256(
            f"{datetime.now().isoformat()}-{response.url}".encode()
        ).hexdigest()[:16]
        
        self.current_session = AuthSession(
            session_id=session_id,
            cookies=response.cookies,
            headers={},
            tokens={},
            created_at=datetime.now(),
        )
        
        # Apply cookies to HTTP client
        for name, value in response.cookies.items():
            self.http_client.set_cookie(name, value)
            
        logger.info(f"Session created: {session_id}")
    
    def _extract_tokens_from_json(self, json_data: Dict):
        """Extract auth tokens from JSON response"""
        token_keys = ['token', 'access_token', 'accessToken', 'jwt', 
                      'auth_token', 'authToken', 'bearer', 'session_token']
        
        for key in token_keys:
            if key in json_data:
                token = json_data[key]
                if self.current_session:
                    self.current_session.tokens[key] = token
                # Auto-set authorization header
                self.http_client.set_auth_token(token)
                logger.info(f"Auth token extracted and set: {key}")
                break
                
        # Check for refresh token
        if 'refresh_token' in json_data and self.current_session:
            self.current_session.tokens['refresh_token'] = json_data['refresh_token']
    
    def set_token_auth(self, token: str, header_name: str = "Authorization",
                       prefix: str = "Bearer"):
        """
        Manually set token authentication
        
        LLM Usage:
            session_mgr.set_token_auth("eyJhbGc...")
            # or
            session_mgr.set_token_auth("api_key_123", header_name="X-API-Key", prefix="")
        """
        self.http_client.set_auth_token(token, header_name, prefix)
        
        if self.current_session:
            self.current_session.tokens['manual_token'] = token
        else:
            self.current_session = AuthSession(
                session_id="manual-token-auth",
                cookies={},
                headers={header_name: f"{prefix} {token}" if prefix else token},
                tokens={'manual_token': token},
                created_at=datetime.now(),
            )
            
        logger.info("Token authentication set")
    
    def is_authenticated(self) -> bool:
        """Check if we have an active session"""
        return self.current_session is not None and self.current_session.is_valid
    
    def get_session_info(self) -> Dict[str, Any]:
        """Get current session information for LLM"""
        if not self.current_session:
            return {"authenticated": False}
            
        return {
            "authenticated": True,
            "session_id": self.current_session.session_id,
            "created_at": self.current_session.created_at.isoformat(),
            "cookies": list(self.current_session.cookies.keys()),
            "tokens": list(self.current_session.tokens.keys()),
            "user_info": self.current_session.user_info,
        }
    
    def test_session(self, protected_url: str) -> bool:
        """
        Test if current session is valid by accessing a protected resource
        
        LLM Usage:
            is_valid = session_mgr.test_session("/api/user/profile")
        """
        response = self.http_client.get(protected_url)
        
        # Consider session valid if we don't get auth errors
        is_valid = response.status_code not in [401, 403]
        
        if self.current_session:
            self.current_session.is_valid = is_valid
            
        return is_valid
    
    def logout(self, logout_url: Optional[str] = None) -> HTTPResponse:
        """Perform logout and clear session"""
        response = None
        
        if logout_url:
            response = self.http_client.get(logout_url)
        elif 'logout' in self.auth_endpoints:
            response = self.http_client.get(self.auth_endpoints['logout'])
            
        # Clear session
        self.current_session = None
        
        # Clear cookies from HTTP client (create new session)
        self.http_client.session.cookies.clear()
        
        logger.info("Logged out and session cleared")
        return response
    
    def save_session(self, name: str = "default"):
        """Save current session to disk"""
        if not self.current_session:
            logger.warning("No session to save")
            return
            
        session_file = self.storage_path / f"{name}.session"
        with open(session_file, 'wb') as f:
            pickle.dump(self.current_session, f)
            
        logger.info(f"Session saved to {session_file}")
    
    def load_session(self, name: str = "default") -> bool:
        """Load session from disk"""
        session_file = self.storage_path / f"{name}.session"
        
        if not session_file.exists():
            logger.warning(f"Session file not found: {session_file}")
            return False
            
        with open(session_file, 'rb') as f:
            self.current_session = pickle.load(f)
            
        # Apply cookies and headers to HTTP client
        for name, value in self.current_session.cookies.items():
            self.http_client.set_cookie(name, value)
            
        for name, value in self.current_session.headers.items():
            self.http_client.set_header(name, value)
            
        logger.info(f"Session loaded: {self.current_session.session_id}")
        return True
    
    def get_csrf_token(self, page_url: str, token_name: str = "csrf") -> Optional[str]:
        """
        Extract CSRF token from a page
        
        LLM Usage:
            csrf = session_mgr.get_csrf_token("/login")
            # Then include in form submission
        """
        from bs4 import BeautifulSoup
        
        response = self.http_client.get(page_url)
        
        if not response.is_html:
            return None
            
        soup = BeautifulSoup(response.body, 'html.parser')
        
        # Look for common CSRF token patterns
        patterns = [
            {'name': token_name},
            {'name': 'csrf_token'},
            {'name': '_csrf'},
            {'name': 'csrfmiddlewaretoken'},
            {'name': '_token'},
            {'name': 'authenticity_token'},
        ]
        
        for pattern in patterns:
            token_input = soup.find('input', pattern)
            if token_input and token_input.get('value'):
                return token_input['value']
                
        # Check meta tags
        meta_csrf = soup.find('meta', {'name': 'csrf-token'})
        if meta_csrf and meta_csrf.get('content'):
            return meta_csrf['content']
            
        return None
