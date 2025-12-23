"""
IDOR Scanner - Insecure Direct Object Reference Detection
Easy for LLM to test access control vulnerabilities
"""

import re
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass

import sys
sys.path.append('..')
from core.http_client import HTTPClient, Response
from core.session import SessionManager


@dataclass
class IDORResult:
    """IDOR test result"""
    vulnerable: bool
    resource_type: str  # user, file, document, etc.
    original_id: str
    tested_id: str
    description: str
    evidence: str
    severity: str
    
    def to_dict(self) -> Dict:
        return {
            "vulnerable": self.vulnerable,
            "resource_type": self.resource_type,
            "original_id": self.original_id,
            "tested_id": self.tested_id,
            "description": self.description,
            "evidence": self.evidence,
            "severity": self.severity
        }


class IDORScanner:
    """
    IDOR vulnerability scanner
    
    Usage for LLM:
    - scanner.test_id_parameter(url, param, current_id) - Test ID parameter
    - scanner.test_sequential(url, param, start_id) - Test sequential IDs
    - scanner.test_uuid_prediction(url, param, uuid) - Test UUID patterns
    - scanner.compare_responses(url1, url2) - Compare two resource responses
    """
    
    def __init__(self, client: Optional[HTTPClient] = None):
        self.client = client or HTTPClient()
        
        # Patterns to identify sensitive data in responses
        self.sensitive_patterns = {
            "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "phone": r'\+?1?\d{10,14}',
            "ssn": r'\d{3}-\d{2}-\d{4}',
            "credit_card": r'\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}',
            "address": r'\d+\s+[\w\s]+(?:street|st|avenue|ave|road|rd|boulevard|blvd)',
            "password_hash": r'\$[26a]\$\d+\$[./A-Za-z0-9]{22,}',
        }
        
        # ID transformation functions
        self.id_transforms = {
            "increment": lambda x: str(int(x) + 1),
            "decrement": lambda x: str(int(x) - 1),
            "double": lambda x: str(int(x) * 2),
            "half": lambda x: str(int(x) // 2),
        }

    def test_id_parameter(self, url: str, param: str, current_id: str,
                          method: str = "GET",
                          ids_to_test: Optional[List[str]] = None) -> List[IDORResult]:
        """
        Test ID parameter for IDOR
        
        Args:
            url: Target URL
            param: ID parameter name
            current_id: Current user's ID
            method: HTTP method
            ids_to_test: Specific IDs to test (or generate automatically)
        
        Returns:
            List of IDOR findings
        """
        results = []
        
        # Get baseline response with current ID
        baseline = self.client.inject_payload(url, param, current_id, method)
        baseline_content = self._extract_content_features(baseline)
        
        # Generate test IDs if not provided
        if not ids_to_test:
            ids_to_test = self._generate_test_ids(current_id)
        
        for test_id in ids_to_test:
            if test_id == current_id:
                continue
            
            response = self.client.inject_payload(url, param, test_id, method)
            
            # Analyze response
            analysis = self._analyze_idor(response, baseline, baseline_content, 
                                         current_id, test_id)
            
            if analysis["vulnerable"]:
                results.append(IDORResult(
                    vulnerable=True,
                    resource_type=analysis["resource_type"],
                    original_id=current_id,
                    tested_id=test_id,
                    description=analysis["description"],
                    evidence=analysis["evidence"],
                    severity=analysis["severity"]
                ))
        
        return results

    def _generate_test_ids(self, current_id: str) -> List[str]:
        """Generate IDs to test based on current ID"""
        test_ids = []
        
        # If numeric
        if current_id.isdigit():
            base = int(current_id)
            test_ids.extend([
                str(base + 1),
                str(base - 1),
                str(base + 10),
                str(base - 10),
                "1",
                "0",
                str(base * 2),
            ])
        
        # If UUID-like
        elif len(current_id) == 36 and current_id.count('-') == 4:
            # Try modifying last character
            test_ids.append(current_id[:-1] + ('0' if current_id[-1] != '0' else '1'))
        
        # If hash-like
        elif re.match(r'^[a-f0-9]+$', current_id.lower()):
            # Try common IDs
            test_ids.extend([
                "1" * len(current_id),
                "admin",
                "0" * len(current_id),
            ])
        
        return test_ids

    def _extract_content_features(self, response: Response) -> Dict[str, Any]:
        """Extract features from response for comparison"""
        body = response.body
        
        features = {
            "length": len(body),
            "emails": re.findall(self.sensitive_patterns["email"], body),
            "has_error": any(err in body.lower() for err in ["error", "not found", "unauthorized"]),
            "status": response.status_code,
        }
        
        # Extract potential user identifiers
        for pattern_name, pattern in self.sensitive_patterns.items():
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                features[pattern_name + "_found"] = matches
        
        return features

    def _analyze_idor(self, response: Response, baseline: Response,
                     baseline_features: Dict, current_id: str,
                     tested_id: str) -> Dict[str, Any]:
        """Analyze response for IDOR vulnerability"""
        result = {
            "vulnerable": False,
            "resource_type": "unknown",
            "description": "",
            "evidence": "",
            "severity": "low"
        }
        
        # If we get a valid response (not 403/404)
        if response.status_code in [200, 201]:
            features = self._extract_content_features(response)
            
            # Check if we got different data (IDOR!)
            if not features["has_error"]:
                # Check for different emails
                baseline_emails = set(baseline_features.get("emails", []))
                new_emails = set(features.get("emails", []))
                
                if new_emails and new_emails != baseline_emails:
                    result["vulnerable"] = True
                    result["resource_type"] = "user_data"
                    result["description"] = "Accessed different user's email addresses"
                    result["evidence"] = f"Found emails: {list(new_emails)[:3]}"
                    result["severity"] = "high"
                    return result
                
                # Check if response is significantly different but valid
                length_diff = abs(features["length"] - baseline_features["length"])
                if length_diff > 100 and features["length"] > 50:
                    result["vulnerable"] = True
                    result["resource_type"] = "unknown"
                    result["description"] = "Accessed different resource"
                    result["evidence"] = f"Response differs by {length_diff} bytes"
                    result["severity"] = "medium"
                    return result
                
                # Check for sensitive data patterns
                for pattern_key in self.sensitive_patterns.keys():
                    found_key = pattern_key + "_found"
                    if features.get(found_key) and not baseline_features.get(found_key):
                        result["vulnerable"] = True
                        result["resource_type"] = pattern_key
                        result["description"] = f"Accessed {pattern_key} from different resource"
                        result["evidence"] = f"Found: {features[found_key][:2]}"
                        result["severity"] = "high"
                        return result
        
        return result

    def test_sequential(self, url: str, param: str, start_id: int,
                       count: int = 10, method: str = "GET") -> List[IDORResult]:
        """
        Test sequential IDs
        
        Args:
            url: Target URL
            param: ID parameter
            start_id: Starting ID
            count: Number of IDs to test
            method: HTTP method
        """
        results = []
        valid_responses = []
        
        for i in range(count):
            test_id = str(start_id + i)
            response = self.client.inject_payload(url, param, test_id, method)
            
            if response.status_code == 200:
                features = self._extract_content_features(response)
                valid_responses.append((test_id, response, features))
        
        # Compare responses to find IDOR
        if len(valid_responses) > 1:
            base_id, base_resp, base_features = valid_responses[0]
            
            for test_id, response, features in valid_responses[1:]:
                # Different content = IDOR
                if features.get("emails") != base_features.get("emails"):
                    results.append(IDORResult(
                        vulnerable=True,
                        resource_type="user_data",
                        original_id=base_id,
                        tested_id=test_id,
                        description="Sequential ID enumeration reveals different users",
                        evidence=f"Different emails found at ID {test_id}",
                        severity="high"
                    ))
        
        return results

    def test_with_different_sessions(self, url: str, param: str,
                                     session1: SessionManager,
                                     session2: SessionManager,
                                     resource_id: str) -> IDORResult:
        """
        Test IDOR with two different user sessions
        
        Args:
            url: Resource URL
            param: ID parameter
            session1: First user's session
            session2: Second user's session  
            resource_id: ID of resource owned by session1
        """
        # Access with owner
        owner_response = session1.client.inject_payload(url, param, resource_id)
        
        # Try access with different user
        other_response = session2.client.inject_payload(url, param, resource_id)
        
        if other_response.status_code == 200:
            owner_features = self._extract_content_features(owner_response)
            other_features = self._extract_content_features(other_response)
            
            # If other user can see similar content, it's IDOR
            if not other_features["has_error"]:
                if abs(owner_features["length"] - other_features["length"]) < owner_features["length"] * 0.2:
                    return IDORResult(
                        vulnerable=True,
                        resource_type="cross_user_access",
                        original_id=resource_id,
                        tested_id=resource_id,
                        description="Different user can access resource",
                        evidence="User 2 accessed User 1's resource",
                        severity="critical"
                    )
        
        return IDORResult(
            vulnerable=False,
            resource_type="none",
            original_id=resource_id,
            tested_id=resource_id,
            description="Access properly denied",
            evidence=f"Status code: {other_response.status_code}",
            severity="info"
        )

    def find_id_parameters(self, url: str) -> List[str]:
        """Find potential ID parameters in URL"""
        id_patterns = [
            r'[?&]id=',
            r'[?&]user_id=',
            r'[?&]userId=',
            r'[?&]account_id=',
            r'[?&]order_id=',
            r'[?&]document_id=',
            r'[?&]file_id=',
            r'[?&]item_id=',
            r'/users/(\d+)',
            r'/accounts/(\d+)',
            r'/orders/(\d+)',
            r'/documents/(\d+)',
        ]
        
        found = []
        for pattern in id_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                # Extract parameter name
                match = re.search(r'[?&](\w+)=', pattern)
                if match:
                    found.append(match.group(1))
                else:
                    found.append(pattern)
        
        return found

    def get_summary(self, results: List[IDORResult]) -> Dict[str, Any]:
        """Get summary of IDOR scan results"""
        vulnerable = [r for r in results if r.vulnerable]
        
        return {
            "total_tests": len(results),
            "vulnerable_count": len(vulnerable),
            "critical": len([r for r in vulnerable if r.severity == "critical"]),
            "high": len([r for r in vulnerable if r.severity == "high"]),
            "resource_types": list(set(r.resource_type for r in vulnerable)),
            "vulnerable_ids": [(r.original_id, r.tested_id) for r in vulnerable],
            "findings": [r.to_dict() for r in vulnerable]
        }
