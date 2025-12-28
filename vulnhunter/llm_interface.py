"""
VulnHunter - Fast Vulnerability Scanner with AI Analysis
Code does the testing, AI analyzes results
"""

import re
import json
import asyncio
import aiohttp
import time
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from datetime import datetime

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False


class RealWebClient:
    """Real HTTP client for testing"""
    
    def __init__(self, timeout: int = 15):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.request_count = 0
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
    
    def _run_async(self, coro):
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    return pool.submit(asyncio.run, coro).result()
            return loop.run_until_complete(coro)
        except RuntimeError:
            return asyncio.run(coro)
    
    async def _fetch(self, url: str, method: str = "GET", data: Optional[Dict] = None) -> Dict:
        self.request_count += 1
        start = time.time()
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                if method == "POST":
                    async with session.post(url, data=data, headers=self.headers, ssl=False) as resp:
                        body = await resp.text()
                        return {"success": True, "status": resp.status, "body": body, "url": str(resp.url), "elapsed": time.time() - start}
                else:
                    async with session.get(url, headers=self.headers, ssl=False) as resp:
                        body = await resp.text()
                        return {"success": True, "status": resp.status, "body": body, "url": str(resp.url), "elapsed": time.time() - start}
        except Exception as e:
            return {"success": False, "error": str(e), "url": url}
    
    def get(self, url: str) -> Dict:
        return self._run_async(self._fetch(url))
    
    def post(self, url: str, data: Dict) -> Dict:
        return self._run_async(self._fetch(url, "POST", data))


class FastScanner:
    """Fast parallel vulnerability scanner"""
    
    def __init__(self, timeout: int = 10, max_parallel: int = 10):
        self.client = RealWebClient(timeout)
        self.max_parallel = max_parallel
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.findings: List[Dict] = []
        self.tested: List[Dict] = []
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        
        # Payloads for testing
        self.payloads = {
            "xss": [
                "<script>alert(1)</script>",
                '"><img src=x onerror=alert(1)>',
                "<svg onload=alert(1)>",
            ],
            "sqli": [
                "'",
                "' OR '1'='1",
                "' UNION SELECT NULL--",
            ],
            "lfi": [
                "../../../etc/passwd",
                "....//....//etc/passwd",
            ],
            "ssrf": [
                "http://127.0.0.1",
                "http://169.254.169.254/latest/meta-data/",
            ]
        }
    
    def _run_async(self, coro):
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    return pool.submit(asyncio.run, coro).result()
            return loop.run_until_complete(coro)
        except RuntimeError:
            return asyncio.run(coro)
    
    async def _fetch(self, url: str) -> Dict:
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(url, headers=self.headers, ssl=False) as resp:
                    body = await resp.text()
                    return {"success": True, "status": resp.status, "body": body}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _inject_param(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
    
    async def test_payload(self, url: str, param: str, payload: str, vuln_type: str) -> Dict:
        """Test a single payload"""
        test_url = self._inject_param(url, param, payload)
        result = await self._fetch(test_url)
        
        if not result["success"]:
            return {"tested": True, "vulnerable": False}
        
        body = result["body"]
        body_lower = body.lower()
        vulnerable = False
        evidence = ""
        
        if vuln_type == "xss":
            is_html = "<html" in body_lower or "<body" in body_lower
            is_json = body.strip().startswith("{") or body.strip().startswith("[")
            if payload in body and is_html and not is_json:
                vulnerable = True
                evidence = "Payload reflected in HTML"
        
        elif vuln_type == "sqli":
            sql_errors = ["sql syntax", "mysql", "sqlite", "postgresql", "ora-", "unclosed quotation"]
            for err in sql_errors:
                if err in body_lower:
                    vulnerable = True
                    evidence = f"SQL error: {err}"
                    break
        
        elif vuln_type == "lfi":
            if "root:" in body or "[fonts]" in body:
                vulnerable = True
                evidence = "File content found"
        
        elif vuln_type == "ssrf":
            is_json = body.strip().startswith("{") or body.strip().startswith("[")
            if not is_json and ("ami-id" in body_lower or "instance-id" in body_lower):
                vulnerable = True
                evidence = "Internal resource accessed"
        
        return {
            "tested": True,
            "url": url,
            "param": param,
            "payload": payload,
            "vuln_type": vuln_type,
            "vulnerable": vulnerable,
            "evidence": evidence
        }
    
    async def test_parameter(self, url: str, param: str) -> List[Dict]:
        """Test a parameter with all payloads"""
        tasks = []
        for vuln_type, payloads in self.payloads.items():
            for payload in payloads:
                tasks.append(self.test_payload(url, param, payload, vuln_type))
        
        # Run in parallel
        semaphore = asyncio.Semaphore(self.max_parallel)
        
        async def bounded_task(task):
            async with semaphore:
                return await task
        
        results = await asyncio.gather(*[bounded_task(t) for t in tasks])
        
        for r in results:
            self.tested.append(r)
            if r.get("vulnerable"):
                self.findings.append(r)
        
        return results
    
    def extract_forms(self, html: str, base_url: str) -> List[Dict]:
        """Extract forms from HTML"""
        forms = []
        for match in re.finditer(r'<form([^>]*)>(.*?)</form>', html, re.I | re.S):
            attrs, content = match.groups()
            action = re.search(r'action=["\']([^"\']*)["\']', attrs)
            method = re.search(r'method=["\']([^"\']*)["\']', attrs)
            
            inputs = []
            for inp in re.finditer(r'<input[^>]*name=["\']([^"\']*)["\']', content, re.I):
                inputs.append(inp.group(1))
            for ta in re.finditer(r'<textarea[^>]*name=["\']([^"\']*)["\']', content, re.I):
                inputs.append(ta.group(1))
            
            if inputs:
                forms.append({
                    "action": urljoin(base_url, action.group(1)) if action else base_url,
                    "method": method.group(1).upper() if method else "GET",
                    "inputs": inputs
                })
        return forms
    
    def extract_params(self, html: str, url: str) -> set:
        """Extract URL parameters"""
        params = set()
        for p in parse_qs(urlparse(url).query):
            params.add(p)
        for href in re.findall(r'href=["\']([^"\']*\?[^"\']*)["\']', html, re.I):
            for p in parse_qs(urlparse(urljoin(url, href)).query):
                params.add(p)
        return params
    
    def scan(self, url: str) -> Dict:
        """Full scan of URL"""
        result = self._run_async(self._fetch(url))
        
        if not result["success"]:
            return {"error": result.get("error"), "vulnerabilities": []}
        
        html = result["body"]
        forms = self.extract_forms(html, url)
        params = self.extract_params(html, url)
        
        # Test all params
        all_results = []
        for param in list(params)[:10]:
            test_url = url if "?" in url else f"{url}?{param}=test"
            results = self._run_async(self.test_parameter(test_url, param))
            all_results.extend(results)
        
        for form in forms[:5]:
            for inp in form["inputs"][:3]:
                action = form["action"]
                if "?" not in action:
                    action = f"{action}?{inp}=test"
                results = self._run_async(self.test_parameter(action, inp))
                all_results.extend(results)
        
        return {
            "url": url,
            "forms_found": len(forms),
            "params_found": len(params),
            "tests_run": len(all_results),
            "vulnerabilities": self.findings
        }


class VulnHunterLLM:
    """LLM-assisted vulnerability hunter"""
    
    def __init__(self, model: str = "llama3.1:8b"):
        self.model = model
        self.scanner = FastScanner()
        self.target_url = ""
        self.findings = []
    
    def start(self, url: str) -> str:
        """Start scanning a target"""
        self.target_url = url
        
        # Do the scan
        result = self.scanner.scan(url)
        
        if "error" in result:
            return f"Error scanning {url}: {result['error']}"
        
        self.findings = result.get("vulnerabilities", [])
        
        # Get AI analysis
        if OLLAMA_AVAILABLE:
            try:
                analysis = ollama.chat(
                    model=self.model,
                    messages=[{
                        "role": "user",
                        "content": f"""Analyze this vulnerability scan:

Target: {url}
Forms found: {result['forms_found']}
Parameters found: {result['params_found']}
Tests run: {result['tests_run']}

Vulnerabilities found:
{json.dumps(self.findings, indent=2) if self.findings else 'None'}

Summarize the security findings and recommend next steps."""
                    }]
                )
                return analysis['message']['content']
            except Exception as e:
                pass
        
        # Fallback without AI
        if self.findings:
            return f"Found {len(self.findings)} vulnerabilities:\n" + "\n".join(
                f"- {f['vuln_type']}: {f['param']} ({f['evidence']})" for f in self.findings
            )
        return f"Scan complete. Tested {result['tests_run']} payloads. No vulnerabilities found."
    
    def continue_hunt(self, instruction: str = "") -> str:
        """Continue with optional instruction"""
        if OLLAMA_AVAILABLE and instruction:
            try:
                response = ollama.chat(
                    model=self.model,
                    messages=[{
                        "role": "user",
                        "content": f"""Previous findings: {json.dumps(self.findings)}
Target: {self.target_url}

User request: {instruction}

Provide security analysis and recommendations."""
                    }]
                )
                return response['message']['content']
            except:
                pass
        return self.get_report()
    
    def get_findings(self) -> List[Dict]:
        return self.findings
    
    def get_report(self) -> str:
        report = f"# Vulnerability Report\nTarget: {self.target_url}\n\n"
        if self.findings:
            report += f"## Found {len(self.findings)} vulnerabilities\n\n"
            for f in self.findings:
                report += f"- **{f['vuln_type'].upper()}**: {f['param']} - {f['evidence']}\n"
        else:
            report += "No vulnerabilities confirmed.\n"
        return report


def quick_scan(url: str) -> Dict:
    """Quick scan function"""
    scanner = FastScanner()
    return scanner.scan(url)


def manual_scan(url: str, scan_type: str = "all") -> Dict:
    """Manual scan"""
    return quick_scan(url)
