"""
Base Scanner for VulnHunter
Common functionality for all vulnerability scanners
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from loguru import logger

from ..core.http_client import HTTPClient, HTTPRequest, HTTPResponse


@dataclass
class Vulnerability:
    """Represents a discovered vulnerability"""
    id: str
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    category: str  # sqli, xss, idor, ssrf, etc.
    url: str
    parameter: str = ""
    method: str = "GET"
    payload: str = ""
    evidence: str = ""
    request: str = ""
    response: str = ""
    remediation: str = ""
    cvss_score: float = 0.0
    cwe_id: str = ""
    confidence: str = "medium"  # low, medium, high
    discovered_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "payload": self.payload,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cvss_score": self.cvss_score,
            "cwe_id": self.cwe_id,
            "confidence": self.confidence,
            "discovered_at": self.discovered_at.isoformat(),
        }
    
    def to_llm_summary(self) -> str:
        return f"""
[{self.severity.upper()}] {self.title}
URL: {self.url}
Parameter: {self.parameter}
Payload: {self.payload}
Evidence: {self.evidence[:200]}...
CWE: {self.cwe_id}
"""


@dataclass
class ScanResult:
    """Results from a vulnerability scan"""
    scanner_name: str
    target_url: str
    start_time: datetime
    end_time: Optional[datetime] = None
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    requests_made: int = 0
    
    def add_vulnerability(self, vuln: Vulnerability):
        self.vulnerabilities.append(vuln)
        
    def to_llm_summary(self) -> str:
        duration = (self.end_time - self.start_time).total_seconds() if self.end_time else 0
        
        by_severity = {}
        for v in self.vulnerabilities:
            by_severity[v.severity] = by_severity.get(v.severity, 0) + 1
            
        return f"""
=== {self.scanner_name} Scan Results ===
Target: {self.target_url}
Duration: {duration:.1f}s
Requests Made: {self.requests_made}

Vulnerabilities Found: {len(self.vulnerabilities)}
  Critical: {by_severity.get('critical', 0)}
  High: {by_severity.get('high', 0)}
  Medium: {by_severity.get('medium', 0)}
  Low: {by_severity.get('low', 0)}
  Info: {by_severity.get('info', 0)}

Top Findings:
{self._format_top_findings()}
=====================================
"""
    
    def _format_top_findings(self) -> str:
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_vulns = sorted(self.vulnerabilities, key=lambda v: severity_order.get(v.severity, 5))
        
        lines = []
        for v in sorted_vulns[:5]:
            lines.append(f"  [{v.severity.upper()}] {v.title} @ {v.parameter}")
        return "\n".join(lines) if lines else "  (none)"


class BaseScanner(ABC):
    """
    Abstract base class for vulnerability scanners
    """
    
    def __init__(self, http_client: HTTPClient):
        self.http_client = http_client
        self.name = "BaseScanner"
        self.category = "generic"
        self.results: Optional[ScanResult] = None
        
    @abstractmethod
    def scan_url(self, url: str, method: str = "GET", 
                params: Optional[Dict] = None) -> ScanResult:
        """Scan a specific URL for vulnerabilities"""
        pass
    
    @abstractmethod
    def scan_form(self, action: str, method: str, 
                 inputs: List[Dict]) -> ScanResult:
        """Scan a form for vulnerabilities"""
        pass
    
    def _create_vuln_id(self, category: str, url: str, param: str) -> str:
        """Generate unique vulnerability ID"""
        import hashlib
        data = f"{category}:{url}:{param}"
        return hashlib.md5(data.encode()).hexdigest()[:12]
    
    def _detect_error_patterns(self, response: HTTPResponse, 
                               patterns: List[Tuple[str, str]]) -> Optional[str]:
        """
        Check response for error patterns
        Returns the matching pattern description or None
        """
        import re
        body_lower = response.body.lower()
        
        for pattern, description in patterns:
            if re.search(pattern, body_lower, re.IGNORECASE):
                return description
        return None
    
    def _compare_responses(self, baseline: HTTPResponse, 
                          test: HTTPResponse) -> Dict[str, Any]:
        """Compare two responses to detect anomalies"""
        return {
            "status_diff": baseline.status_code != test.status_code,
            "length_diff": abs(len(baseline.body) - len(test.body)),
            "length_ratio": len(test.body) / len(baseline.body) if len(baseline.body) > 0 else 0,
            "time_diff": test.elapsed_time - baseline.elapsed_time,
            "baseline_status": baseline.status_code,
            "test_status": test.status_code,
        }
    
    def _is_significant_change(self, baseline: HTTPResponse, 
                               test: HTTPResponse, threshold: float = 0.2) -> bool:
        """Check if there's a significant change between responses"""
        comparison = self._compare_responses(baseline, test)
        
        if comparison["status_diff"]:
            return True
        if comparison["length_diff"] > 100 and comparison["length_ratio"] > (1 + threshold):
            return True
        if comparison["time_diff"] > 3:  # Significant time increase (possible sleep injection)
            return True
            
        return False
