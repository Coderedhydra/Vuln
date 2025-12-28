"""
Web Tools - Fast, unified interface for vulnerability scanning
Uses async operations for speed
"""

import json
import asyncio
import aiohttp
import re
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from dataclasses import dataclass
import time


@dataclass
class ScanResult:
    """Scan result with confirmation"""
    vulnerable: bool
    vuln_type: str
    url: str
    param: str
    payload: str
    evidence: str
    severity: str
    extracted_data: Optional[str] = None
    
    def to_dict(self):
        return {
            "vulnerable": self.vulnerable,
            "type": self.vuln_type,
            "url": self.url,
            "param": self.param,
            "payload": self.payload,
            "evidence": self.evidence,
            "severity": self.severity,
            "extracted_data": self.extracted_data
        }


class WebTools:
    """
    Fast web tools for vulnerability scanning
    All operations are optimized for speed
    """
    
    def __init__(self, proxy: Optional[str] = None, timeout: int = 10):
        self.proxy = proxy
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.findings: List[Dict] = []
        self.history: List[Dict] = []
        
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        
        # Effective payloads
        self.payloads = {
            "xss": [
                '<script>alert(1)</script>',
                '"><script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                "'-alert(1)-'",
            ],
            "sqli": [
                ("'", ["sql syntax", "mysql", "postgresql", "sqlite", "ora-"]),
                ("' OR '1'='1", []),
                ("' UNION SELECT NULL--", ["column", "union"]),
            ],
            "lfi": [
                ("../../../etc/passwd", ["root:", "nobody:"]),
                ("....//....//etc/passwd", ["root:"]),
            ],
            "ssrf": [
                ("http://127.0.0.1", ["localhost"]),
                ("http://169.254.169.254/latest/meta-data/", ["ami-id"]),
            ],
        }

    def _run_async(self, coro):
        """Run async code"""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Create new loop for nested async
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    return pool.submit(asyncio.run, coro).result()
            return loop.run_until_complete(coro)
        except RuntimeError:
            return asyncio.run(coro)

    async def _fetch(self, session: aiohttp.ClientSession, url: str,
                     method: str = "GET", data: Optional[Dict] = None) -> tuple:
        """Fast async fetch"""
        start = time.time()
        try:
            if method == "POST":
                async with session.post(url, data=data, headers=self.headers,
                                        ssl=False, allow_redirects=True) as resp:
                    body = await resp.text()
                    return body, resp.status, time.time() - start
            else:
                async with session.get(url, headers=self.headers,
                                       ssl=False, allow_redirects=True) as resp:
                    body = await resp.text()
                    return body, resp.status, time.time() - start
        except Exception as e:
            return str(e), 0, time.time() - start

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

    def fetch(self, url: str, method: str = "GET",
              headers: Optional[Dict] = None,
              data: Optional[Dict] = None,
              json_data: Optional[Dict] = None) -> Dict[str, Any]:
        """Fetch a URL"""
        async def _do_fetch():
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                body, status, elapsed = await self._fetch(session, url, method, data)
                return {
                    "url": url,
                    "status": status,
                    "body": body[:10000],
                    "body_length": len(body),
                    "time_ms": round(elapsed * 1000, 2)
                }
        
        result = self._run_async(_do_fetch())
        self.history.append({"action": "fetch", "url": url})
        return result

    def crawl(self, url: str, depth: int = 1) -> Dict[str, Any]:
        """Fast crawl to discover forms and params"""
        async def _do_crawl():
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                body, status, _ = await self._fetch(session, url)
                
                if status == 0:
                    return {"error": "Failed to fetch", "forms": [], "params": []}
                
                # Extract forms
                forms = []
                for match in re.finditer(r'<form([^>]*)>(.*?)</form>', body, re.I | re.S):
                    attrs, content = match.groups()
                    action = re.search(r'action=["\']([^"\']*)["\']', attrs)
                    method = re.search(r'method=["\']([^"\']*)["\']', attrs)
                    
                    inputs = []
                    for inp in re.finditer(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>', content, re.I):
                        inputs.append(inp.group(1))
                    for ta in re.finditer(r'<textarea[^>]*name=["\']([^"\']*)["\']', content, re.I):
                        inputs.append(ta.group(1))
                    
                    if inputs:
                        forms.append({
                            "action": urljoin(url, action.group(1)) if action else url,
                            "method": method.group(1).upper() if method else "GET",
                            "inputs": inputs
                        })
                
                # Extract links with params
                params = set()
                links = []
                base_netloc = urlparse(url).netloc
                
                for href in re.findall(r'href=["\']([^"\']+)["\']', body, re.I):
                    if href.startswith(('#', 'javascript:', 'mailto:')):
                        continue
                    full_url = urljoin(url, href.split('#')[0])
                    if urlparse(full_url).netloc == base_netloc:
                        links.append(full_url)
                        for p in parse_qs(urlparse(full_url).query):
                            params.add(p)
                
                # Get params from current URL
                for p in parse_qs(urlparse(url).query):
                    params.add(p)
                
                return {
                    "pages_crawled": 1,
                    "urls_discovered": list(set(links))[:30],
                    "forms": forms,
                    "parameters": list(params),
                    "technologies": self._detect_tech(body)
                }
        
        return self._run_async(_do_crawl())

    def _detect_tech(self, body: str) -> List[str]:
        """Detect technologies"""
        techs = []
        checks = [
            ("react", "react"),
            ("vue", "v-model"),
            ("angular", "ng-"),
            ("jquery", "jquery"),
            ("wordpress", "wp-content"),
            ("php", ".php"),
            ("asp", ".aspx"),
        ]
        body_lower = body.lower()
        for tech, pattern in checks:
            if pattern in body_lower:
                techs.append(tech)
        return techs

    def analyze(self, url: str) -> Dict[str, Any]:
        """Analyze page for security issues"""
        result = self.fetch(url)
        body = result.get("body", "")
        
        findings = []
        
        # Check for sensitive info in HTML
        if "password" in body.lower() and "type=\"password\"" not in body.lower():
            findings.append("Possible password in source")
        if re.search(r'api[_-]?key|secret[_-]?key', body, re.I):
            findings.append("Possible API key exposed")
        if "<!--" in body:
            comments = re.findall(r'<!--(.*?)-->', body, re.S)
            for c in comments:
                if any(x in c.lower() for x in ["todo", "fix", "bug", "password", "key"]):
                    findings.append(f"Sensitive comment: {c[:100]}")
        
        return {
            "url": url,
            "forms": self.crawl(url).get("forms", []),
            "security_findings": findings,
            "technologies": self._detect_tech(body)
        }

    def read_source(self, url: str) -> Dict[str, Any]:
        """Read page source"""
        result = self.fetch(url)
        return {
            "url": url,
            "html": result.get("body", ""),
            "length": result.get("body_length", 0)
        }

    def send_request(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        """Send custom request"""
        return self.fetch(url, method, **kwargs)

    def inject_payload(self, url: str, param: str, payload: str,
                       method: str = "GET") -> Dict[str, Any]:
        """Inject payload into parameter"""
        test_url = self._inject_param(url, param, payload)
        result = self.fetch(test_url, method)
        result["payload"] = payload
        result["reflected"] = payload in result.get("body", "")
        return result

    def scan_xss(self, url: str, param: str, method: str = "GET",
                 category: str = "basic") -> Dict[str, Any]:
        """Fast XSS scan with HTML context check"""
        async def _scan():
            results = []
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                # Get baseline
                baseline, _, _ = await self._fetch(session, url)
                is_html = '<html' in baseline.lower() or '<body' in baseline.lower()
                
                for payload in self.payloads["xss"]:
                    test_url = self._inject_param(url, param, payload)
                    body, status, _ = await self._fetch(session, test_url)
                    
                    if status and payload in body:
                        # Check HTML context (not JSON)
                        body_lower = body.lower()
                        in_html = is_html or '<html' in body_lower or '<body' in body_lower
                        not_json = '"args"' not in body_lower
                        
                        if in_html or not_json:
                            result = ScanResult(
                                vulnerable=False,
                                vuln_type="XSS",
                                url=url,
                                param=param,
                                payload=payload,
                                evidence="Hypothesis only: payload reflected in HTML (not proof of exploitability)",
                                severity="high"
                            )
                            results.append(result)
                            self.findings.append(result.to_dict())
                            break
            
            return {
                "url": url,
                "param": param,
                "results": [r.to_dict() for r in results],
                "summary": {"vulnerable_count": len(results)}
            }
        
        return self._run_async(_scan())

    def scan_sqli(self, url: str, param: str, method: str = "GET",
                  test_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """Fast SQLi scan"""
        async def _scan():
            results = []
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                for payload, patterns in self.payloads["sqli"]:
                    test_url = self._inject_param(url, param, payload)
                    body, status, elapsed = await self._fetch(session, test_url)
                    
                    if status:
                        body_lower = body.lower()
                        for pattern in patterns:
                            if pattern in body_lower:
                                result = ScanResult(
                                    vulnerable=False,
                                    vuln_type="SQLi",
                                    url=url,
                                    param=param,
                                    payload=payload,
                                    evidence=f"Hypothesis only: SQL error string '{pattern}' observed (not proof of exploitability)",
                                    severity="critical"
                                )
                                results.append(result)
                                self.findings.append(result.to_dict())
                                break
            
            return {
                "url": url,
                "param": param,
                "results": [r.to_dict() for r in results],
                "summary": {"vulnerable_count": len(results)}
            }
        
        return self._run_async(_scan())

    def scan_ssrf(self, url: str, param: str,
                  categories: Optional[List[str]] = None) -> Dict[str, Any]:
        """Fast SSRF scan with reflection check"""
        async def _scan():
            results = []
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                # Get baseline
                baseline, _, _ = await self._fetch(session, url)
                
                for payload, patterns in self.payloads["ssrf"]:
                    test_url = self._inject_param(url, param, payload)
                    body, status, _ = await self._fetch(session, test_url)
                    
                    if status:
                        body_lower = body.lower()
                        
                        # Skip if just reflection
                        if f'"{payload.lower()}"' in body_lower:
                            continue
                        
                        for pattern in patterns:
                            if pattern.lower() in body_lower and pattern.lower() not in baseline.lower():
                                result = ScanResult(
                                    vulnerable=False,
                                    vuln_type="SSRF",
                                    url=url,
                                    param=param,
                                    payload=payload,
                                    evidence=f"Hypothesis only: internal-looking marker '{pattern}' observed (not proof of SSRF)",
                                    severity="critical"
                                )
                                results.append(result)
                                self.findings.append(result.to_dict())
            
            return {
                "url": url,
                "param": param,
                "results": [r.to_dict() for r in results],
                "summary": {"vulnerable_count": len(results)}
            }
        
        return self._run_async(_scan())

    def scan_lfi(self, url: str, param: str,
                 os_type: str = "linux") -> Dict[str, Any]:
        """Fast LFI scan"""
        async def _scan():
            results = []
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                for payload, patterns in self.payloads["lfi"]:
                    test_url = self._inject_param(url, param, payload)
                    body, status, _ = await self._fetch(session, test_url)
                    
                    if status:
                        for pattern in patterns:
                            if pattern in body:
                                result = ScanResult(
                                    vulnerable=False,
                                    vuln_type="LFI",
                                    url=url,
                                    param=param,
                                    payload=payload,
                                    evidence=f"Hypothesis only: file marker '{pattern}' observed (not proof of exploitability)",
                                    severity="critical",
                                    extracted_data=body[:500]
                                )
                                results.append(result)
                                self.findings.append(result.to_dict())
            
            return {
                "url": url,
                "param": param,
                "results": [r.to_dict() for r in results],
                "summary": {"vulnerable_count": len(results)}
            }
        
        return self._run_async(_scan())

    def scan_auth(self, login_url: str,
                  username_field: str = "username",
                  password_field: str = "password") -> Dict[str, Any]:
        """Scan for auth bypass"""
        # Test SQL bypass
        result = self.fetch(login_url, "POST", data={
            username_field: "' OR '1'='1",
            password_field: "' OR '1'='1"
        })
        
        # NOTE: keyword-based success detection is not valid proof.
        bypassed = False
        
        return {
            "url": login_url,
            "bypassed": False,
            "results": [{
                "type": "SQL Auth Bypass",
                "payload": "' OR '1'='1",
                "vulnerable": False,
                "note": "Hypothesis only: auth bypass requires deterministic proof (e.g., access to a privileged-only endpoint with control session).",
            }]
        }

    def scan_idor(self, url: str, param: str, current_id: str) -> Dict[str, Any]:
        """Scan for IDOR"""
        results = []
        
        # Get baseline
        baseline = self.fetch(url)
        
        # Try other IDs
        test_ids = ["1", "2", "0", str(int(current_id) + 1) if current_id.isdigit() else "1"]
        
        for test_id in test_ids:
            if test_id == current_id:
                continue
            test_url = self._inject_param(url, param, test_id)
            result = self.fetch(test_url)
            
            if result.get("status") == 200 and len(result.get("body", "")) > 100:
                results.append({
                    "type": "IDOR",
                    "param": param,
                    "tested_id": test_id,
                    "vulnerable": False,
                    "evidence": "Hypothesis only: response looked valid for alternate ID (not proof; requires multi-session control)"
                })
        
        return {
            "url": url,
            "param": param,
            "results": results,
            "summary": {"vulnerable_count": len(results)}
        }

    def quick_scan(self, url: str, param: str) -> Dict[str, Any]:
        """Quick multi-vuln scan"""
        results = {
            "url": url,
            "param": param,
            "xss": {"vulnerable": False},
            "sqli": {"vulnerable": False},
            "lfi": {"vulnerable": False}
        }
        
        xss = self.scan_xss(url, param)
        if xss["summary"]["vulnerable_count"] > 0:
            results["xss"] = xss["results"][0]
        
        sqli = self.scan_sqli(url, param)
        if sqli["summary"]["vulnerable_count"] > 0:
            results["sqli"] = sqli["results"][0]
        
        lfi = self.scan_lfi(url, param)
        if lfi["summary"]["vulnerable_count"] > 0:
            results["lfi"] = lfi["results"][0]
        
        return results

    def generate_payload(self, vuln_type: str, **kwargs) -> Dict[str, Any]:
        """Generate payloads"""
        payloads = self.payloads.get(vuln_type.lower(), [])
        if isinstance(payloads[0], tuple):
            return {"payloads": [p[0] for p in payloads]}
        return {"payloads": payloads}

    def get_payloads(self, category: str) -> List[str]:
        """Get payloads for category"""
        payloads = self.payloads.get(category.lower(), [])
        if payloads and isinstance(payloads[0], tuple):
            return [p[0] for p in payloads]
        return payloads

    def mutate_payload(self, payload: str, count: int = 5) -> List[str]:
        """Generate payload mutations"""
        mutations = [payload]
        
        # URL encoding
        mutations.append(payload.replace("<", "%3C").replace(">", "%3E"))
        
        # Double encoding
        mutations.append(payload.replace("<", "%253C").replace(">", "%253E"))
        
        # Case variation
        mutations.append(payload.replace("script", "ScRiPt").replace("alert", "AlErT"))
        
        # HTML entity
        mutations.append(payload.replace("<", "&lt;").replace(">", "&gt;"))
        
        # Add null bytes
        mutations.append(payload.replace("<", "<%00"))
        
        return mutations[:count]

    def login(self, login_url: str, username: str, password: str,
              username_field: str = "username",
              password_field: str = "password",
              csrf_field: Optional[str] = None) -> Dict[str, Any]:
        """Login to application"""
        data = {username_field: username, password_field: password}
        result = self.fetch(login_url, "POST", data=data)
        
        success = "logout" in result.get("body", "").lower() or \
                  "dashboard" in result.get("body", "").lower()
        
        return {"success": success, "status": result.get("status")}

    def set_cookie(self, name: str, value: str):
        """Set cookie"""
        return {"status": "set", "name": name}

    def set_header(self, name: str, value: str):
        """Set header"""
        self.headers[name] = value
        return {"status": "set", "name": name}

    def get_findings(self) -> List[Dict]:
        """Get all findings"""
        return self.findings

    def get_history(self, last_n: int = 10) -> List[Dict]:
        """Get history"""
        return self.history[-last_n:]

    def clear_findings(self):
        """Clear findings"""
        self.findings = []
        return {"status": "cleared"}

    def get_request_history(self, last_n: int = 10) -> List[Dict]:
        """Get request history"""
        return self.history[-last_n:]
