"""
Report Tools - Generate vulnerability reports
Easy for LLM to create HackerOne-style reports
"""

import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


@dataclass
class VulnerabilityReport:
    """Structured vulnerability report"""
    title: str
    severity: str
    vuln_type: str
    url: str
    parameter: str = ""
    payload: str = ""
    proof_signal: str = ""
    control_test: str = ""
    description: str = ""
    impact: str = ""
    steps_to_reproduce: List[str] = field(default_factory=list)
    proof_of_concept: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    cvss_score: float = 0.0
    cwe_id: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "title": self.title,
            "severity": self.severity,
            "vuln_type": self.vuln_type,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "proof_signal": self.proof_signal,
            "control_test": self.control_test,
            "description": self.description,
            "impact": self.impact,
            "steps_to_reproduce": self.steps_to_reproduce,
            "proof_of_concept": self.proof_of_concept,
            "remediation": self.remediation,
            "references": self.references,
            "cvss_score": self.cvss_score,
            "cwe_id": self.cwe_id
        }

    def to_markdown(self) -> str:
        """Generate markdown report"""
        md = f"""# {self.title}

## Summary
- **Severity:** {self.severity}
- **Type:** {self.vuln_type}
- **URL:** {self.url}
- **Parameter:** {self.parameter}
- **CWE:** {self.cwe_id}
- **CVSS Score:** {self.cvss_score}

## Description
{self.description}

## Steps to Reproduce
"""
        for i, step in enumerate(self.steps_to_reproduce, 1):
            md += f"{i}. {step}\n"
        
        md += f"""
## Payload Used
```
{self.payload}
```

## Proof Signal (required for confirmed findings)
{self.proof_signal or "[Not provided]"}

## Control Test (required for confirmed findings)
{self.control_test or "[Not provided]"}

## Proof of Concept
{self.proof_of_concept}

## Impact
{self.impact}

## Remediation
{self.remediation}

## References
"""
        for ref in self.references:
            md += f"- {ref}\n"
        
        md += f"\n---\n*Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n"
        
        return md


class ReportTools:
    """
    Report generation tools
    
    Usage for LLM:
    - reports.create(findings) - Create report from findings
    - reports.template(vuln_type) - Get report template
    - reports.generate_markdown(report) - Generate markdown
    - reports.calculate_severity(vuln_type, impact) - Calculate severity
    """
    
    def __init__(self):
        # Severity mapping
        self.severity_map = {
            "critical": {"cvss_min": 9.0, "color": "red"},
            "high": {"cvss_min": 7.0, "color": "orange"},
            "medium": {"cvss_min": 4.0, "color": "yellow"},
            "low": {"cvss_min": 0.1, "color": "blue"},
            "info": {"cvss_min": 0.0, "color": "gray"}
        }
        
        # CWE mapping
        self.cwe_map = {
            "xss": "CWE-79",
            "sqli": "CWE-89",
            "ssrf": "CWE-918",
            "lfi": "CWE-22",
            "rce": "CWE-78",
            "idor": "CWE-639",
            "auth_bypass": "CWE-287",
            "csrf": "CWE-352",
            "xxe": "CWE-611",
            "ssti": "CWE-94",
            "open_redirect": "CWE-601"
        }
        
        # Impact templates
        self.impact_templates = {
            "xss": """An attacker can:
- Steal session cookies and hijack user accounts
- Perform actions on behalf of authenticated users
- Redirect users to malicious websites
- Steal sensitive information displayed on the page
- Deface the website""",
            
            "sqli": """An attacker can:
- Extract sensitive data from the database (credentials, PII, financial data)
- Modify or delete database contents
- Bypass authentication mechanisms
- Potentially execute system commands (depending on DB configuration)
- Compromise the entire database server""",
            
            "ssrf": """An attacker can:
- Access internal services not exposed to the internet
- Retrieve cloud metadata (AWS/GCP/Azure credentials)
- Scan internal network infrastructure
- Potentially achieve remote code execution through internal services
- Exfiltrate sensitive internal data""",
            
            "lfi": """An attacker can:
- Read sensitive files from the server (passwords, configs, source code)
- Potentially achieve remote code execution via log poisoning
- Access application source code
- Read system files (/etc/passwd, etc.)
- Expose API keys and credentials""",
            
            "idor": """An attacker can:
- Access other users' data without authorization
- Modify or delete other users' resources
- Escalate privileges by accessing admin resources
- Violate data privacy regulations (GDPR, HIPAA)
- Extract sensitive personal information""",
        }
        
        # Remediation templates
        self.remediation_templates = {
            "xss": """**Immediate Actions:**
1. Implement context-aware output encoding (HTML, JavaScript, URL, CSS)
2. Use a Content Security Policy (CSP) with strict directives
3. Set HTTPOnly and Secure flags on session cookies
4. Validate and sanitize user input on the server-side

**Long-term Solutions:**
- Use auto-escaping template engines
- Implement security headers (X-XSS-Protection, X-Content-Type-Options)
- Regular security code reviews and testing
- Use frameworks with built-in XSS protection""",
            
            "sqli": """**Immediate Actions:**
1. Use parameterized queries (prepared statements) for all database operations
2. Implement input validation with allowlists
3. Apply principle of least privilege to database accounts
4. Disable detailed error messages in production

**Long-term Solutions:**
- Use ORM frameworks that prevent SQL injection
- Implement Web Application Firewall (WAF)
- Regular penetration testing
- Code review focusing on data layer""",
            
            "ssrf": """**Immediate Actions:**
1. Implement strict allowlist for allowed domains/IPs
2. Block requests to internal/private IP ranges
3. Disable unnecessary URL schemes (file://, gopher://, etc.)
4. Validate and sanitize URL inputs

**Long-term Solutions:**
- Use a dedicated service for URL fetching with proper isolation
- Implement network segmentation
- Monitor outbound traffic for anomalies
- Regular security assessments""",
            
            "lfi": """**Immediate Actions:**
1. Use allowlist for allowed file paths
2. Implement proper input validation (reject ../ and similar)
3. Use basename() to extract filename only
4. Chroot or containerize the application

**Long-term Solutions:**
- Avoid including files based on user input
- Use indirect references (IDs mapping to files)
- Implement proper access controls
- Regular security scanning""",
            
            "idor": """**Immediate Actions:**
1. Implement proper authorization checks for all resource access
2. Use indirect reference maps (random tokens instead of sequential IDs)
3. Verify user ownership before allowing access
4. Log and monitor access patterns

**Long-term Solutions:**
- Implement role-based access control (RBAC)
- Use UUIDs instead of sequential IDs
- Regular access control audits
- Automated security testing""",
        }

    def create_report(self, vuln_type: str, url: str, 
                     parameter: str = "", payload: str = "",
                     additional_info: Optional[Dict] = None) -> VulnerabilityReport:
        """
        Create a vulnerability report
        
        Args:
            vuln_type: Type of vulnerability (xss, sqli, etc.)
            url: Affected URL
            parameter: Vulnerable parameter
            payload: Payload used
            additional_info: Additional information
        
        Returns:
            VulnerabilityReport object
        """
        vuln_type_lower = vuln_type.lower()
        
        # Get severity
        severity = self._calculate_severity(vuln_type_lower)
        
        # Generate title
        title = self._generate_title(vuln_type_lower, url, parameter)
        
        # Get CWE
        cwe = self.cwe_map.get(vuln_type_lower, "CWE-Unknown")
        
        # Get impact
        impact = self.impact_templates.get(vuln_type_lower, "Security impact assessment needed.")
        
        # Get remediation
        remediation = self.remediation_templates.get(vuln_type_lower, "Implement security best practices.")
        
        # Generate steps
        steps = self._generate_steps(vuln_type_lower, url, parameter, payload)
        
        # Generate description
        description = self._generate_description(vuln_type_lower, url, parameter)
        
        report = VulnerabilityReport(
            title=title,
            severity=severity,
            vuln_type=vuln_type,
            url=url,
            parameter=parameter,
            payload=payload,
            description=description,
            impact=impact,
            steps_to_reproduce=steps,
            proof_of_concept="[Screenshot or response snippet demonstrating vulnerability]",
            remediation=remediation,
            references=self._get_references(vuln_type_lower),
            cvss_score=self._estimate_cvss(vuln_type_lower),
            cwe_id=cwe
        )
        
        return report

    def _calculate_severity(self, vuln_type: str) -> str:
        """Calculate severity based on vulnerability type"""
        severity_map = {
            "sqli": "critical",
            "rce": "critical",
            "ssrf": "high",
            "xss": "high",
            "lfi": "high",
            "idor": "high",
            "auth_bypass": "critical",
            "xxe": "high",
            "ssti": "critical",
            "csrf": "medium",
            "open_redirect": "low"
        }
        return severity_map.get(vuln_type, "medium")

    def _generate_title(self, vuln_type: str, url: str, parameter: str) -> str:
        """Generate report title"""
        type_names = {
            "xss": "Cross-Site Scripting (XSS)",
            "sqli": "SQL Injection",
            "ssrf": "Server-Side Request Forgery (SSRF)",
            "lfi": "Local File Inclusion (LFI)",
            "rce": "Remote Code Execution (RCE)",
            "idor": "Insecure Direct Object Reference (IDOR)",
            "auth_bypass": "Authentication Bypass",
            "xxe": "XML External Entity (XXE)",
            "ssti": "Server-Side Template Injection (SSTI)",
            "csrf": "Cross-Site Request Forgery (CSRF)"
        }
        
        type_name = type_names.get(vuln_type, vuln_type.upper())
        
        from urllib.parse import urlparse
        parsed = urlparse(url)
        endpoint = parsed.path or "/"
        
        if parameter:
            return f"{type_name} in `{parameter}` parameter on {endpoint}"
        return f"{type_name} vulnerability on {endpoint}"

    def _generate_description(self, vuln_type: str, url: str, parameter: str) -> str:
        """Generate vulnerability description"""
        descriptions = {
            "xss": f"A Cross-Site Scripting (XSS) vulnerability was discovered in the `{parameter}` parameter at `{url}`. User-supplied input is reflected in the response without proper sanitization, allowing an attacker to inject malicious JavaScript code that executes in the victim's browser.",
            
            "sqli": f"A SQL Injection vulnerability was discovered in the `{parameter}` parameter at `{url}`. The application fails to properly sanitize user input before including it in SQL queries, allowing an attacker to manipulate database queries and potentially access or modify sensitive data.",
            
            "ssrf": f"A Server-Side Request Forgery (SSRF) vulnerability was discovered in the `{parameter}` parameter at `{url}`. The application makes HTTP requests to URLs supplied by users without proper validation, allowing an attacker to access internal resources or cloud metadata endpoints.",
            
            "lfi": f"A Local File Inclusion (LFI) vulnerability was discovered in the `{parameter}` parameter at `{url}`. The application includes files based on user input without proper validation, allowing an attacker to read sensitive files from the server.",
            
            "idor": f"An Insecure Direct Object Reference (IDOR) vulnerability was discovered in the `{parameter}` parameter at `{url}`. The application exposes internal object references, allowing users to access resources belonging to other users by manipulating the identifier.",
        }
        
        return descriptions.get(vuln_type, f"A {vuln_type.upper()} vulnerability was discovered at {url}.")

    def _generate_steps(self, vuln_type: str, url: str, 
                       parameter: str, payload: str) -> List[str]:
        """Generate reproduction steps"""
        steps = [
            f"Navigate to: {url}",
            f"Locate the `{parameter}` parameter",
            f"Inject the following payload: `{payload}`",
            "Submit the request",
            "Observe the vulnerability trigger in the response"
        ]
        
        return steps

    def _estimate_cvss(self, vuln_type: str) -> float:
        """Estimate CVSS score based on vulnerability type"""
        cvss_map = {
            "sqli": 9.8,
            "rce": 10.0,
            "ssrf": 8.6,
            "xss": 6.1,
            "lfi": 7.5,
            "idor": 7.5,
            "auth_bypass": 9.8,
            "xxe": 7.5,
            "ssti": 9.8,
            "csrf": 4.3,
            "open_redirect": 3.4
        }
        return cvss_map.get(vuln_type, 5.0)

    def _get_references(self, vuln_type: str) -> List[str]:
        """Get relevant references"""
        references = {
            "xss": [
                "https://owasp.org/www-community/attacks/xss/",
                "https://portswigger.net/web-security/cross-site-scripting",
                "https://cwe.mitre.org/data/definitions/79.html"
            ],
            "sqli": [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://portswigger.net/web-security/sql-injection",
                "https://cwe.mitre.org/data/definitions/89.html"
            ],
            "ssrf": [
                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                "https://portswigger.net/web-security/ssrf",
                "https://cwe.mitre.org/data/definitions/918.html"
            ],
            "lfi": [
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
                "https://portswigger.net/web-security/file-path-traversal",
                "https://cwe.mitre.org/data/definitions/22.html"
            ],
            "idor": [
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
                "https://portswigger.net/web-security/access-control/idor",
                "https://cwe.mitre.org/data/definitions/639.html"
            ]
        }
        return references.get(vuln_type, ["https://owasp.org/www-project-top-ten/"])

    def generate_markdown_report(self, report: VulnerabilityReport) -> str:
        """Generate markdown from report"""
        return report.to_markdown()

    def generate_json_report(self, report: VulnerabilityReport) -> str:
        """Generate JSON from report"""
        return json.dumps(report.to_dict(), indent=2)

    def create_summary_report(self, findings: List[Dict]) -> str:
        """
        Create summary report from multiple findings
        
        Args:
            findings: List of vulnerability findings
        
        Returns:
            Markdown summary report
        """
        if not findings:
            return "# Security Assessment Report\n\nNo vulnerabilities found."
        
        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f.get("severity", "medium").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        # Count by type
        type_counts = {}
        for f in findings:
            t = f.get("type", "unknown")
            type_counts[t] = type_counts.get(t, 0) + 1
        
        md = f"""# Security Assessment Report
*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*

## Executive Summary

This security assessment identified **{len(findings)}** vulnerabilities:

| Severity | Count |
|----------|-------|
| Critical | {severity_counts['critical']} |
| High | {severity_counts['high']} |
| Medium | {severity_counts['medium']} |
| Low | {severity_counts['low']} |

### Vulnerabilities by Type

| Type | Count |
|------|-------|
"""
        for vuln_type, count in type_counts.items():
            md += f"| {vuln_type.upper()} | {count} |\n"
        
        md += "\n## Detailed Findings\n\n"
        
        for i, finding in enumerate(findings, 1):
            md += f"""### {i}. {finding.get('type', 'Unknown').upper()} - {finding.get('severity', 'Medium').upper()}

- **URL:** {finding.get('url', 'N/A')}
- **Parameter:** {finding.get('param', 'N/A')}
- **Payload:** `{finding.get('payload', 'N/A')}`

---

"""
        
        md += """## Recommendations

1. Prioritize fixing Critical and High severity vulnerabilities immediately
2. Implement input validation and output encoding
3. Use security headers (CSP, X-Frame-Options, etc.)
4. Conduct regular security assessments
5. Implement a vulnerability management program

"""
        
        return md

    def get_template(self, vuln_type: str) -> Dict[str, Any]:
        """
        Get report template for a vulnerability type
        
        Args:
            vuln_type: Vulnerability type
        
        Returns:
            Template dict
        """
        return {
            "title_format": f"[{vuln_type.upper()}] Vulnerability in [Parameter/Endpoint]",
            "severity": self._calculate_severity(vuln_type),
            "cwe": self.cwe_map.get(vuln_type, "CWE-Unknown"),
            "impact": self.impact_templates.get(vuln_type, ""),
            "remediation": self.remediation_templates.get(vuln_type, ""),
            "references": self._get_references(vuln_type)
        }
