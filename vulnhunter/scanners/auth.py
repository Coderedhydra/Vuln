"""
Authentication Scanner - Auth bypass and weakness detection
Easy for LLM to test authentication vulnerabilities
"""

import re
import hashlib
import base64
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

import sys
sys.path.append('..')
from core.http_client import HTTPClient, Response
from core.session import SessionManager


@dataclass
class AuthResult:
    """Authentication test result"""
    vulnerable: bool
    vuln_type: str
    description: str
    evidence: str
    severity: str
    
    def to_dict(self) -> Dict:
        return {
            "vulnerable": self.vulnerable,
            "vuln_type": self.vuln_type,
            "description": self.description,
            "evidence": self.evidence,
            "severity": self.severity
        }


class AuthScanner:
    """
    Authentication vulnerability scanner
    
    Usage for LLM:
    - scanner.test_login_bypass(url) - Test for auth bypass
    - scanner.test_password_policy(url) - Check password requirements
    - scanner.test_session(session) - Test session security
    - scanner.test_brute_force_protection(url) - Test rate limiting
    """
    
    def __init__(self, client: Optional[HTTPClient] = None):
        self.client = client or HTTPClient()
        
        # SQL injection for auth bypass
        self.sqli_bypass = [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR '1'='1'/*",
            "admin'--",
            "admin'/*",
            "' OR 1=1--",
            "' OR 'x'='x",
            "') OR ('1'='1",
            "') OR ('1'='1'--",
            "' OR username LIKE '%admin%",
            "admin' AND '1'='1",
        ]
        
        # Default/weak credentials
        self.default_credentials = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "admin123"),
            ("admin", "12345"),
            ("admin", "123456"),
            ("root", "root"),
            ("root", "toor"),
            ("root", "password"),
            ("administrator", "administrator"),
            ("test", "test"),
            ("user", "user"),
            ("guest", "guest"),
            ("demo", "demo"),
        ]
        
        # Weak passwords to test policy
        self.weak_passwords = [
            "123456",
            "password",
            "12345678",
            "qwerty",
            "abc123",
            "111111",
            "admin",
            "letmein",
            "welcome",
            "1234",
        ]

    def test_login_bypass(self, login_url: str,
                          username_field: str = "username",
                          password_field: str = "password",
                          extra_fields: Optional[Dict] = None) -> List[AuthResult]:
        """
        Test for authentication bypass vulnerabilities
        
        Args:
            login_url: Login form URL
            username_field: Username input name
            password_field: Password input name
            extra_fields: Additional form fields
        """
        results = []
        
        # Test SQL injection bypass
        for payload in self.sqli_bypass:
            form_data = {
                username_field: payload,
                password_field: "anything"
            }
            if extra_fields:
                form_data.update(extra_fields)
            
            response = self.client.post(login_url, data=form_data)
            
            if self._check_auth_success(response):
                results.append(AuthResult(
                    vulnerable=True,
                    vuln_type="sqli_auth_bypass",
                    description="SQL injection authentication bypass",
                    evidence=f"Bypass successful with payload: {payload}",
                    severity="critical"
                ))
        
        # Test default credentials
        for username, password in self.default_credentials:
            form_data = {
                username_field: username,
                password_field: password
            }
            if extra_fields:
                form_data.update(extra_fields)
            
            response = self.client.post(login_url, data=form_data)
            
            if self._check_auth_success(response):
                results.append(AuthResult(
                    vulnerable=True,
                    vuln_type="default_credentials",
                    description=f"Default credentials work: {username}:{password}",
                    evidence=f"Login successful with {username}:{password}",
                    severity="high"
                ))
        
        return results

    def _check_auth_success(self, response: Response) -> bool:
        """Check if authentication was successful"""
        body = response.body.lower()
        
        # Success indicators
        success_indicators = [
            "logout", "sign out", "log out", "dashboard", "welcome",
            "my account", "profile", "settings", "successfully logged"
        ]
        
        # Failure indicators
        failure_indicators = [
            "invalid", "incorrect", "wrong", "failed", "error",
            "try again", "not found", "unauthorized"
        ]
        
        success_score = sum(1 for ind in success_indicators if ind in body)
        failure_score = sum(1 for ind in failure_indicators if ind in body)
        
        # Check for redirect to dashboard
        if response.status_code in [302, 301]:
            location = response.headers.get("location", "").lower()
            if any(ind in location for ind in ["dashboard", "home", "profile", "account"]):
                return True
        
        return success_score > failure_score

    def test_password_policy(self, registration_url: str,
                            password_field: str = "password",
                            confirm_field: str = "password_confirm",
                            extra_fields: Optional[Dict] = None) -> List[AuthResult]:
        """Test password policy strength"""
        results = []
        
        test_passwords = [
            ("1", "Too short"),
            ("123", "Only numbers"),
            ("abc", "Too short, no numbers"),
            ("password", "Common password, no special chars"),
            ("12345678", "Only numbers, no letters"),
            ("abcdefgh", "Only lowercase, no numbers"),
        ]
        
        for password, weakness in test_passwords:
            form_data = {
                password_field: password,
                confirm_field: password
            }
            if extra_fields:
                form_data.update(extra_fields)
            
            response = self.client.post(registration_url, data=form_data)
            
            # Check if password was accepted
            if not self._check_password_rejected(response, password):
                results.append(AuthResult(
                    vulnerable=True,
                    vuln_type="weak_password_policy",
                    description=f"Weak password accepted: {weakness}",
                    evidence=f"Password '{password}' was accepted",
                    severity="medium"
                ))
        
        return results

    def _check_password_rejected(self, response: Response, password: str) -> bool:
        """Check if password was rejected"""
        body = response.body.lower()
        
        rejection_indicators = [
            "too short", "too weak", "must contain", "requirements",
            "at least", "characters", "uppercase", "lowercase",
            "special character", "digit", "number"
        ]
        
        return any(ind in body for ind in rejection_indicators)

    def test_session(self, session_manager: SessionManager) -> List[AuthResult]:
        """
        Test session security
        
        Args:
            session_manager: Authenticated session to test
        """
        results = []
        
        cookies = session_manager.client.get_cookies()
        
        for name, value in cookies.items():
            # Check for session cookie without HttpOnly
            # (This is a limitation - we can see it, so it's accessible to JS)
            if "session" in name.lower() or "sess" in name.lower():
                results.append(AuthResult(
                    vulnerable=True,
                    vuln_type="session_exposed",
                    description="Session cookie accessible to JavaScript",
                    evidence=f"Session cookie '{name}' can be read",
                    severity="medium"
                ))
            
            # Check for predictable session IDs
            if self._is_predictable_session(value):
                results.append(AuthResult(
                    vulnerable=True,
                    vuln_type="predictable_session",
                    description="Session ID appears predictable",
                    evidence=f"Session value: {value[:20]}...",
                    severity="high"
                ))
            
            # Check for short session ID
            if len(value) < 20:
                results.append(AuthResult(
                    vulnerable=True,
                    vuln_type="weak_session_id",
                    description="Session ID is too short",
                    evidence=f"Session length: {len(value)} characters",
                    severity="medium"
                ))
        
        return results

    def _is_predictable_session(self, session_id: str) -> bool:
        """Check if session ID looks predictable"""
        # Check for sequential numbers
        if session_id.isdigit():
            return True
        
        # Check for timestamp-based
        if re.match(r'^\d{10,13}', session_id):
            return True
        
        # Check for incremental patterns
        if re.match(r'^[0-9a-f]+$', session_id.lower()) and len(session_id) < 16:
            return True
        
        return False

    def test_brute_force_protection(self, login_url: str,
                                    username_field: str = "username",
                                    password_field: str = "password",
                                    attempts: int = 10) -> AuthResult:
        """
        Test for brute force protection
        
        Args:
            login_url: Login URL
            username_field: Username field name
            password_field: Password field name
            attempts: Number of attempts to make
        """
        results = []
        blocked = False
        captcha_shown = False
        
        for i in range(attempts):
            form_data = {
                username_field: f"testuser{i}",
                password_field: f"wrongpass{i}"
            }
            
            response = self.client.post(login_url, data=form_data)
            
            # Check for rate limiting
            if response.status_code == 429:
                blocked = True
                break
            
            # Check for CAPTCHA
            if "captcha" in response.body.lower() or "recaptcha" in response.body.lower():
                captcha_shown = True
                break
            
            # Check for lockout message
            if any(msg in response.body.lower() for msg in ["locked", "blocked", "too many"]):
                blocked = True
                break
        
        if not blocked and not captcha_shown:
            return AuthResult(
                vulnerable=True,
                vuln_type="no_brute_force_protection",
                description=f"No protection after {attempts} failed attempts",
                evidence="No rate limiting, CAPTCHA, or account lockout",
                severity="high"
            )
        else:
            return AuthResult(
                vulnerable=False,
                vuln_type="brute_force_protected",
                description="Brute force protection detected",
                evidence=f"{'Rate limited' if blocked else 'CAPTCHA shown'} after multiple attempts",
                severity="info"
            )

    def test_jwt_vulnerabilities(self, token: str) -> List[AuthResult]:
        """
        Test JWT token for vulnerabilities
        
        Args:
            token: JWT token string
        """
        results = []
        
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return results
            
            # Decode header
            header = base64.urlsafe_b64decode(parts[0] + "==").decode()
            header_json = eval(header.replace('true', 'True').replace('false', 'False'))
            
            # Check for none algorithm
            if header_json.get('alg', '').lower() == 'none':
                results.append(AuthResult(
                    vulnerable=True,
                    vuln_type="jwt_none_algorithm",
                    description="JWT uses 'none' algorithm",
                    evidence="Token header: alg=none",
                    severity="critical"
                ))
            
            # Check for weak algorithms
            weak_algs = ['hs256', 'hs384', 'hs512']
            if header_json.get('alg', '').lower() in weak_algs:
                results.append(AuthResult(
                    vulnerable=True,
                    vuln_type="jwt_weak_algorithm",
                    description=f"JWT uses weak algorithm: {header_json.get('alg')}",
                    evidence="Consider using RS256 or ES256",
                    severity="medium"
                ))
            
            # Decode payload
            payload = base64.urlsafe_b64decode(parts[1] + "==").decode()
            payload_json = eval(payload.replace('true', 'True').replace('false', 'False').replace('null', 'None'))
            
            # Check for sensitive data in payload
            sensitive_keys = ['password', 'secret', 'private', 'ssn', 'credit_card']
            for key in payload_json.keys():
                if any(s in key.lower() for s in sensitive_keys):
                    results.append(AuthResult(
                        vulnerable=True,
                        vuln_type="jwt_sensitive_data",
                        description=f"JWT contains sensitive data: {key}",
                        evidence=f"Found sensitive field in payload: {key}",
                        severity="high"
                    ))
            
            # Check for missing expiration
            if 'exp' not in payload_json:
                results.append(AuthResult(
                    vulnerable=True,
                    vuln_type="jwt_no_expiration",
                    description="JWT has no expiration time",
                    evidence="Missing 'exp' claim in payload",
                    severity="medium"
                ))
        
        except Exception as e:
            pass
        
        return results

    def get_summary(self, results: List[AuthResult]) -> Dict[str, Any]:
        """Get summary of auth scan results"""
        vulnerable = [r for r in results if r.vulnerable]
        
        return {
            "total_tests": len(results),
            "vulnerable_count": len(vulnerable),
            "critical": len([r for r in vulnerable if r.severity == "critical"]),
            "high": len([r for r in vulnerable if r.severity == "high"]),
            "medium": len([r for r in vulnerable if r.severity == "medium"]),
            "vuln_types": list(set(r.vuln_type for r in vulnerable)),
            "findings": [r.to_dict() for r in vulnerable]
        }
