"""
VulnHunter - Autonomous AI Bug Bounty Hunter
NOT a static scanner - An intelligent, adaptive security researcher

The LLM drives ALL decisions:
- Analyzes targets like a human would
- Creates custom payloads based on code review
- Adapts based on responses
- Confirms vulnerabilities through real exploitation
- Never fakes or simulates results
"""

import re
import json
import asyncio
import aiohttp
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from datetime import datetime

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False


class RealWebClient:
    """
    Real HTTP client - NO simulation, NO fake responses
    Every request is real, every response is real
    """
    
    def __init__(self, timeout: int = 15):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.session = None
        self.request_count = 0
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
    
    def _run_async(self, coro):
        """Run async in sync context"""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    return pool.submit(asyncio.run, coro).result()
            return loop.run_until_complete(coro)
        except RuntimeError:
            return asyncio.run(coro)
    
    async def _request(self, method: str, url: str, 
                       headers: Optional[Dict] = None,
                       data: Optional[Dict] = None,
                       params: Optional[Dict] = None) -> Dict:
        """Make a REAL HTTP request"""
        self.request_count += 1
        start = time.time()
        
        req_headers = {**self.headers, **(headers or {})}
        
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.request(
                    method, url,
                    headers=req_headers,
                    data=data,
                    params=params,
                    ssl=False,
                    allow_redirects=True
                ) as resp:
                    body = await resp.text()
                    elapsed = time.time() - start
                    
                    return {
                        "success": True,
                        "url": str(resp.url),
                        "status": resp.status,
                        "headers": dict(resp.headers),
                        "body": body,
                        "body_length": len(body),
                        "elapsed_seconds": round(elapsed, 3),
                        "content_type": resp.headers.get("content-type", ""),
                    }
        except Exception as e:
            return {
                "success": False,
                "url": url,
                "error": str(e),
                "status": 0
            }
    
    def get(self, url: str, headers: Optional[Dict] = None, 
            params: Optional[Dict] = None) -> Dict:
        """GET request"""
        return self._run_async(self._request("GET", url, headers, params=params))
    
    def post(self, url: str, data: Optional[Dict] = None,
             headers: Optional[Dict] = None) -> Dict:
        """POST request"""
        return self._run_async(self._request("POST", url, headers, data))
    
    def request(self, method: str, url: str, **kwargs) -> Dict:
        """Any HTTP method"""
        return self._run_async(self._request(method, url, **kwargs))


class VulnHunterLLM:
    """
    Autonomous AI Bug Bounty Hunter
    
    This is NOT a scanner. This is an intelligent agent that:
    1. Explores targets like a human researcher
    2. Analyzes code and responses to understand the application
    3. Creates custom payloads based on what it observes
    4. Adapts its approach based on results
    5. Confirms vulnerabilities through REAL exploitation
    6. Never simulates or fakes anything
    
    The LLM makes ALL decisions - tools just execute what it decides.
    """
    
    def __init__(self, model: str = "llama3.1:8b"):
        if not OLLAMA_AVAILABLE:
            raise RuntimeError("Ollama required. Install: pip install ollama")
        
        self.model = model
        self.client = RealWebClient()
        self.conversation: List[Dict] = []
        self.findings: List[Dict] = []
        self.target_url = ""
        self.explored_urls: set = set()
        self.discovered_params: set = set()
        self.discovered_forms: List[Dict] = []
        self.observations: List[str] = []
        
        self.system_prompt = self._build_system_prompt()
    
    def _build_system_prompt(self) -> str:
        return """You are an autonomous bug bounty hunter. You work INDEPENDENTLY to find real vulnerabilities.

## YOUR MISSION
Find security vulnerabilities in the target. You must:
1. Explore the target automatically
2. Find ALL forms, parameters, and inputs
3. Test each one for vulnerabilities
4. Confirm and report real findings
5. Keep going until you've tested everything

## YOUR TOOLS

Call tools like this: TOOL: tool_name(param="value")

### Exploration Tools:
- **fetch(url)** - Get a URL, see headers and body
- **read_source(url)** - Read HTML source code  
- **find_forms(url)** - Find all forms and inputs
- **find_links(url)** - Find internal links and parameters

### Testing Tools:
- **inject(url, param, payload)** - Inject payload into URL parameter
- **post_form(url, data)** - Submit form with data like {"user": "test", "pass": "123"}
- **send_request(method, url, headers, data)** - Custom HTTP request

### Reporting:
- **report_finding(type, url, param, payload, evidence, severity)** - Report CONFIRMED vulnerability

## HOW TO HUNT

### Step 1: Discover Attack Surface
TOOL: find_forms(url="TARGET_URL")
TOOL: find_links(url="TARGET_URL")

### Step 2: Analyze Each Input
For each form/parameter found:
- What type of input is it? (search, login, id, file, url)
- What vulnerabilities might apply?

### Step 3: Test With Smart Payloads
Based on context, test:
- **Search/text fields**: XSS payloads
- **ID/numeric fields**: SQLi payloads  
- **File parameters**: LFI payloads
- **URL parameters**: SSRF payloads
- **Login forms**: Auth bypass

### Step 4: Confirm & Report
When a payload works, CONFIRM it:
- XSS: Payload appears unencoded in HTML
- SQLi: Error message OR data extracted
- LFI: File contents visible (root:, [fonts], etc)
- SSRF: Internal resource accessed

Then report:
TOOL: report_finding(type="XSS", url="...", param="q", payload="<script>alert(1)</script>", evidence="Reflected in HTML", severity="high")

## SMART PAYLOADS

### XSS (Cross-Site Scripting)
- `<script>alert(1)</script>`
- `"><img src=x onerror=alert(1)>`
- `'-alert(1)-'`
- `<svg onload=alert(1)>`

### SQLi (SQL Injection)
- `'` (single quote - check for errors)
- `' OR '1'='1`
- `' OR 1=1--`
- `' UNION SELECT NULL,NULL--`
- `1 AND 1=1` vs `1 AND 1=2` (boolean)

### LFI (Local File Inclusion)
- `../../../etc/passwd`
- `....//....//etc/passwd`
- `/etc/passwd`

### SSRF (Server-Side Request Forgery)
- `http://127.0.0.1`
- `http://localhost`
- `http://169.254.169.254/latest/meta-data/`

### Auth Bypass
- Username: `admin' --`
- Password: `' OR '1'='1`

## IMPORTANT RULES

1. **BE AUTONOMOUS** - Don't wait for instructions, keep testing
2. **USE TOOLS** - Every test must use a real tool call
3. **ANALYZE RESPONSES** - Read what comes back carefully
4. **ADAPT** - If something is filtered, try bypass techniques
5. **CONFIRM** - Only report when you have PROOF
6. **BE THOROUGH** - Test EVERY parameter you find

## START IMMEDIATELY

When given a target:
1. First, discover all forms and links
2. Then test each parameter systematically
3. Report any confirmed vulnerabilities
4. Continue until everything is tested

GO!"""

    def _parse_tool_calls(self, text: str) -> List[Dict]:
        """Parse tool calls from LLM response"""
        calls = []
        pattern = r'TOOL:\s*(\w+)\((.*?)\)(?:\s|$)'
        
        for match in re.finditer(pattern, text, re.DOTALL):
            tool_name = match.group(1)
            args_str = match.group(2).strip()
            
            # Parse arguments
            args = {}
            # Handle key="value" and key={...} formats
            for m in re.finditer(r'(\w+)\s*=\s*(?:"([^"]*?)"|\'([^\']*?)\'|(\{[^}]+\})|(\[[^\]]+\]))', args_str):
                key = m.group(1)
                value = m.group(2) or m.group(3) or m.group(4) or m.group(5)
                
                # Try to parse as JSON
                if value and (value.startswith('{') or value.startswith('[')):
                    try:
                        value = json.loads(value.replace("'", '"'))
                    except:
                        pass
                
                args[key] = value
            
            calls.append({"tool": tool_name, "args": args})
        
        return calls

    def _execute_tool(self, tool_name: str, args: Dict) -> str:
        """Execute a tool and return REAL results"""
        
        if tool_name == "fetch":
            url = args.get("url", self.target_url)
            result = self.client.get(url)
            self.explored_urls.add(url)
            
            if result["success"]:
                # Extract useful info for the LLM
                body = result["body"]
                return json.dumps({
                    "url": result["url"],
                    "status": result["status"],
                    "content_type": result["content_type"],
                    "body_length": result["body_length"],
                    "body_preview": body[:3000] + ("..." if len(body) > 3000 else ""),
                    "headers": {k: v for k, v in result["headers"].items() 
                               if k.lower() in ["server", "x-powered-by", "content-type", "set-cookie"]}
                }, indent=2)
            return json.dumps(result, indent=2)
        
        elif tool_name == "read_source":
            url = args.get("url", self.target_url)
            result = self.client.get(url)
            
            if result["success"]:
                return f"=== SOURCE CODE ({result['body_length']} bytes) ===\n{result['body'][:8000]}"
            return f"Error: {result.get('error', 'Failed to fetch')}"
        
        elif tool_name == "find_forms":
            url = args.get("url", self.target_url)
            result = self.client.get(url)
            
            if not result["success"]:
                return json.dumps({"error": result.get("error")})
            
            forms = self._extract_forms(result["body"], url)
            self.discovered_forms.extend(forms)
            
            return json.dumps({
                "url": url,
                "forms_found": len(forms),
                "forms": forms
            }, indent=2)
        
        elif tool_name == "find_links":
            url = args.get("url", self.target_url)
            result = self.client.get(url)
            
            if not result["success"]:
                return json.dumps({"error": result.get("error")})
            
            links = self._extract_links(result["body"], url)
            params = self._extract_params(result["body"], url)
            self.discovered_params.update(params)
            
            return json.dumps({
                "url": url,
                "internal_links": links[:30],
                "parameters_found": list(params),
                "total_links": len(links)
            }, indent=2)
        
        elif tool_name == "inject":
            url = args.get("url", self.target_url)
            param = args.get("param", "")
            payload = args.get("payload", "")
            
            if not param or not payload:
                return json.dumps({"error": "param and payload required"})
            
            # Inject payload
            test_url = self._inject_param(url, param, payload)
            result = self.client.get(test_url)
            
            if result["success"]:
                body = result["body"]
                reflected = payload in body
                
                return json.dumps({
                    "url": test_url,
                    "param": param,
                    "payload": payload,
                    "status": result["status"],
                    "reflected": reflected,
                    "reflection_context": self._find_reflection_context(body, payload) if reflected else None,
                    "body_preview": body[:2000],
                    "body_length": len(body)
                }, indent=2)
            return json.dumps(result, indent=2)
        
        elif tool_name == "post_form":
            url = args.get("url", self.target_url)
            data = args.get("data", {})
            
            if isinstance(data, str):
                try:
                    data = json.loads(data.replace("'", '"'))
                except:
                    data = {}
            
            result = self.client.post(url, data)
            
            if result["success"]:
                return json.dumps({
                    "url": result["url"],
                    "status": result["status"],
                    "body_preview": result["body"][:3000],
                    "body_length": result["body_length"]
                }, indent=2)
            return json.dumps(result, indent=2)
        
        elif tool_name == "send_request":
            method = args.get("method", "GET")
            url = args.get("url", self.target_url)
            headers = args.get("headers", {})
            data = args.get("data", {})
            
            if isinstance(headers, str):
                try:
                    headers = json.loads(headers.replace("'", '"'))
                except:
                    headers = {}
            
            if isinstance(data, str):
                try:
                    data = json.loads(data.replace("'", '"'))
                except:
                    data = {}
            
            result = self.client.request(method, url, headers=headers, data=data)
            
            if result["success"]:
                return json.dumps({
                    "url": result["url"],
                    "status": result["status"],
                    "body_preview": result["body"][:3000],
                    "body_length": result["body_length"]
                }, indent=2)
            return json.dumps(result, indent=2)
        
        elif tool_name == "report_finding":
            finding = {
                "type": args.get("type", "Unknown"),
                "url": args.get("url", ""),
                "param": args.get("param", ""),
                "payload": args.get("payload", ""),
                "evidence": args.get("evidence", ""),
                "severity": args.get("severity", "medium"),
                "confirmed": True,
                "timestamp": datetime.now().isoformat()
            }
            self.findings.append(finding)
            
            return json.dumps({
                "status": "VULNERABILITY RECORDED",
                "finding": finding
            }, indent=2)
        
        else:
            return json.dumps({"error": f"Unknown tool: {tool_name}"})
    
    def _extract_forms(self, html: str, base_url: str) -> List[Dict]:
        """Extract forms from HTML"""
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
                inputs.append({"name": ta.group(1), "type": "textarea", "value": ""})
            
            for sel in re.finditer(r'<select[^>]*name=["\']([^"\']*)["\']', content, re.I):
                inputs.append({"name": sel.group(1), "type": "select", "value": ""})
            
            if inputs:
                forms.append({
                    "action": urljoin(base_url, action.group(1)) if action else base_url,
                    "method": method.group(1).upper() if method else "GET",
                    "inputs": inputs
                })
        
        return forms
    
    def _extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract internal links"""
        links = set()
        base_netloc = urlparse(base_url).netloc
        
        for href in re.findall(r'href=["\']([^"\']+)["\']', html, re.I):
            if href.startswith('#') or href.startswith('javascript:') or href.startswith('mailto:'):
                continue
            full = urljoin(base_url, href.split('#')[0])
            if urlparse(full).netloc == base_netloc:
                links.add(full)
        
        return list(links)
    
    def _extract_params(self, html: str, base_url: str) -> set:
        """Extract URL parameters"""
        params = set()
        for href in re.findall(r'href=["\']([^"\']*\?[^"\']*)["\']', html, re.I):
            full = urljoin(base_url, href)
            for p in parse_qs(urlparse(full).query):
                params.add(p)
        return params
    
    def _inject_param(self, url: str, param: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
    
    def _find_reflection_context(self, body: str, payload: str) -> str:
        """Find where payload is reflected in response"""
        idx = body.find(payload)
        if idx == -1:
            return "Not found"
        
        start = max(0, idx - 50)
        end = min(len(body), idx + len(payload) + 50)
        context = body[start:end]
        
        # Determine context type
        if '<script' in context.lower() or 'javascript' in context.lower():
            return f"JavaScript context: ...{context}..."
        elif 'value="' in context or "value='" in context:
            return f"Attribute context: ...{context}..."
        elif '<' in context and '>' in context:
            return f"HTML context: ...{context}..."
        else:
            return f"Text context: ...{context}..."
    
    def chat(self, message: str) -> str:
        """Chat with the AI hunter"""
        self.conversation.append({"role": "user", "content": message})
        
        messages = [
            {"role": "system", "content": self.system_prompt},
            *self.conversation
        ]
        
        try:
            response = ollama.chat(model=self.model, messages=messages)
            reply = response['message']['content']
            
            # Parse and execute any tool calls
            tool_calls = self._parse_tool_calls(reply)
            
            if tool_calls:
                # Execute tools and collect results
                tool_results = []
                for call in tool_calls:
                    result = self._execute_tool(call["tool"], call["args"])
                    tool_results.append(f"=== {call['tool']} result ===\n{result}")
                
                # Add to conversation
                self.conversation.append({"role": "assistant", "content": reply})
                
                # Send results back to LLM for analysis
                results_msg = "\n\n".join(tool_results)
                return self.chat(f"Tool results:\n{results_msg}\n\nAnalyze these results and continue hunting. What did you observe? What will you try next?")
            
            self.conversation.append({"role": "assistant", "content": reply})
            return reply
            
        except Exception as e:
            return f"Error: {e}"
    
    def start(self, target_url: str) -> str:
        """Start hunting on a target"""
        self.target_url = target_url
        self.conversation = []
        self.findings = []
        self.explored_urls = set()
        self.discovered_params = set()
        self.discovered_forms = []
        
        return self.chat(f"""TARGET: {target_url}

START NOW. First discover the attack surface:

TOOL: find_forms(url="{target_url}")
TOOL: find_links(url="{target_url}")

After you get results, analyze what you found and test each parameter for vulnerabilities. 
Use XSS, SQLi, LFI, SSRF payloads as appropriate.
Report any confirmed vulnerabilities.
Keep going until you've tested everything.""")
    
    def continue_hunt(self, instruction: str = "") -> str:
        """Continue hunting with optional instruction"""
        if instruction:
            return self.chat(instruction)
        return self.chat("Continue your security analysis. What have you found so far? What will you test next?")
    
    def get_findings(self) -> List[Dict]:
        """Get confirmed findings"""
        return self.findings
    
    def get_report(self) -> str:
        """Get hunt report"""
        if not self.findings:
            return f"""# Security Assessment Report
Target: {self.target_url}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}

## Summary
No confirmed vulnerabilities found.

## Exploration Summary
- URLs explored: {len(self.explored_urls)}
- Forms discovered: {len(self.discovered_forms)}
- Parameters found: {len(self.discovered_params)}
- Total requests made: {self.client.request_count}
"""
        
        report = f"""# Security Assessment Report
Target: {self.target_url}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}

## Summary
Found {len(self.findings)} CONFIRMED vulnerabilities.

## Findings
"""
        for i, f in enumerate(self.findings, 1):
            report += f"""
### {i}. {f['type']} - {f['severity'].upper()}
- **URL:** {f['url']}
- **Parameter:** {f['param']}
- **Payload:** `{f['payload']}`
- **Evidence:** {f['evidence']}
- **Confirmed:** {f['confirmed']}
"""
        
        report += f"""
## Hunt Statistics
- URLs explored: {len(self.explored_urls)}
- Forms discovered: {len(self.discovered_forms)}  
- Parameters found: {len(self.discovered_params)}
- Total requests made: {self.client.request_count}
"""
        return report


# Convenience functions
def quick_scan(url: str) -> Dict:
    """Quick scan - but still uses real requests, not simulation"""
    client = RealWebClient()
    result = client.get(url)
    
    if not result["success"]:
        return {"error": result.get("error"), "vulnerabilities": []}
    
    findings = []
    body = result["body"]
    base_url = url
    
    # Extract params from URL
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    # Quick tests on each param
    for param in params:
        # XSS test
        xss_payload = '<script>alert(1)</script>'
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?"
        test_params = {**params, param: [xss_payload]}
        test_url += urlencode(test_params, doseq=True)
        
        xss_result = client.get(test_url)
        if xss_result["success"] and xss_payload in xss_result["body"]:
            # Check if in HTML context
            if '<html' in xss_result["body"].lower() or '<body' in xss_result["body"].lower():
                findings.append({
                    "type": "XSS",
                    "url": url,
                    "param": param,
                    "payload": xss_payload,
                    "confirmed": True
                })
        
        # SQLi test
        sqli_payload = "'"
        test_params = {**params, param: [sqli_payload]}
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?" + urlencode(test_params, doseq=True)
        
        sqli_result = client.get(test_url)
        if sqli_result["success"]:
            sqli_indicators = ["sql", "mysql", "syntax", "query", "ora-", "postgresql"]
            body_lower = sqli_result["body"].lower()
            for indicator in sqli_indicators:
                if indicator in body_lower:
                    findings.append({
                        "type": "SQLi",
                        "url": url,
                        "param": param,
                        "payload": sqli_payload,
                        "evidence": f"SQL error indicator: {indicator}",
                        "confirmed": True
                    })
                    break
    
    return {
        "target": url,
        "vulnerabilities": findings,
        "vuln_count": len(findings),
        "requests_made": client.request_count
    }


def manual_scan(url: str, scan_type: str = "all") -> Dict:
    """Manual scan"""
    return quick_scan(url)
