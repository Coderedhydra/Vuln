"""
LLM Interface - Ollama integration for VulnHunter
This module provides the interface between Ollama LLM and the vulnerability hunting tools
"""

import json
import re
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False
    print("Warning: ollama package not installed. Install with: pip install ollama")

from tools.web_tools import WebTools
from tools.search_tools import SearchTools
from tools.report_tools import ReportTools


@dataclass
class ToolDefinition:
    """Definition of a tool for the LLM"""
    name: str
    description: str
    parameters: Dict[str, Any]
    function: Callable
    examples: List[str] = field(default_factory=list)


class VulnHunterLLM:
    """
    LLM-powered vulnerability hunter using Ollama
    
    This class provides:
    - Easy tool interface for any Ollama model
    - Automatic tool calling and result handling
    - Conversation memory for context
    - Simple API for the LLM to use all vulnerability hunting tools
    
    Usage:
        hunter = VulnHunterLLM(model="llama3.1:8b")
        hunter.start("https://example.com")
    """
    
    def __init__(self, model: str = "llama3.1:8b", proxy: Optional[str] = None):
        self.model = model
        self.web_tools = WebTools(proxy=proxy)
        self.search_tools = SearchTools()
        self.report_tools = ReportTools()
        
        # Conversation history
        self.conversation: List[Dict[str, str]] = []
        self.findings: List[Dict] = []
        
        # Target info
        self.target_url: str = ""
        self.target_info: Dict = {}
        
        # Build tool registry
        self.tools = self._build_tool_registry()
        
        # System prompt for the LLM
        self.system_prompt = self._build_system_prompt()

    def _build_tool_registry(self) -> Dict[str, ToolDefinition]:
        """Build the tool registry with all available tools"""
        tools = {}
        
        # ==================== Web Tools ====================
        tools["fetch"] = ToolDefinition(
            name="fetch",
            description="Fetch a URL and get the response. Use this to make HTTP requests.",
            parameters={
                "url": {"type": "string", "description": "The URL to fetch", "required": True},
                "method": {"type": "string", "description": "HTTP method (GET, POST, etc.)", "default": "GET"},
                "headers": {"type": "object", "description": "Custom headers"},
                "data": {"type": "object", "description": "Form data for POST requests"},
                "json_data": {"type": "object", "description": "JSON body for POST requests"}
            },
            function=self.web_tools.fetch,
            examples=[
                'fetch(url="https://example.com")',
                'fetch(url="https://example.com/api", method="POST", json_data={"user": "test"})'
            ]
        )
        
        tools["crawl"] = ToolDefinition(
            name="crawl",
            description="Crawl a website to discover URLs, forms, parameters, and structure.",
            parameters={
                "url": {"type": "string", "description": "Starting URL to crawl", "required": True},
                "depth": {"type": "integer", "description": "Crawl depth (1-3 recommended)", "default": 2}
            },
            function=self.web_tools.crawl,
            examples=['crawl(url="https://example.com", depth=2)']
        )
        
        tools["analyze"] = ToolDefinition(
            name="analyze",
            description="Deep analysis of a page including scripts, forms, hidden inputs, and security issues.",
            parameters={
                "url": {"type": "string", "description": "URL to analyze", "required": True}
            },
            function=self.web_tools.analyze,
            examples=['analyze(url="https://example.com/login")']
        )
        
        tools["read_source"] = ToolDefinition(
            name="read_source",
            description="Read the source code of a page for manual analysis.",
            parameters={
                "url": {"type": "string", "description": "URL to read", "required": True}
            },
            function=self.web_tools.read_source,
            examples=['read_source(url="https://example.com/page")']
        )
        
        tools["send_request"] = ToolDefinition(
            name="send_request",
            description="Send a fully customized HTTP request with any method, headers, and body.",
            parameters={
                "method": {"type": "string", "description": "HTTP method", "required": True},
                "url": {"type": "string", "description": "Target URL", "required": True},
                "headers": {"type": "object", "description": "Custom headers"},
                "params": {"type": "object", "description": "URL parameters"},
                "data": {"type": "object", "description": "Form data"},
                "json_data": {"type": "object", "description": "JSON body"},
                "cookies": {"type": "object", "description": "Custom cookies"},
                "raw_body": {"type": "string", "description": "Raw body string"}
            },
            function=self.web_tools.send_request,
            examples=[
                'send_request(method="POST", url="https://example.com/api", json_data={"action": "test"})'
            ]
        )
        
        tools["inject_payload"] = ToolDefinition(
            name="inject_payload",
            description="Inject a payload into a URL parameter. Easy way to test payloads.",
            parameters={
                "url": {"type": "string", "description": "Target URL", "required": True},
                "param": {"type": "string", "description": "Parameter to inject into", "required": True},
                "payload": {"type": "string", "description": "Payload to inject", "required": True},
                "method": {"type": "string", "description": "HTTP method", "default": "GET"}
            },
            function=self.web_tools.inject_payload,
            examples=[
                'inject_payload(url="https://example.com/search?q=test", param="q", payload="<script>alert(1)</script>")'
            ]
        )
        
        # ==================== Vulnerability Scanners ====================
        tools["scan_xss"] = ToolDefinition(
            name="scan_xss",
            description="Scan a parameter for XSS vulnerabilities.",
            parameters={
                "url": {"type": "string", "description": "Target URL", "required": True},
                "param": {"type": "string", "description": "Parameter to test", "required": True},
                "method": {"type": "string", "description": "HTTP method", "default": "GET"},
                "category": {"type": "string", "description": "Payload category: basic, filter_bypass, polyglot, waf_bypass", "default": "basic"}
            },
            function=self.web_tools.scan_xss,
            examples=['scan_xss(url="https://example.com/search?q=test", param="q")']
        )
        
        tools["scan_sqli"] = ToolDefinition(
            name="scan_sqli",
            description="Scan a parameter for SQL injection vulnerabilities.",
            parameters={
                "url": {"type": "string", "description": "Target URL", "required": True},
                "param": {"type": "string", "description": "Parameter to test", "required": True},
                "method": {"type": "string", "description": "HTTP method", "default": "GET"},
                "test_types": {"type": "array", "description": "Types: error, boolean, time, union", "default": ["error", "boolean"]}
            },
            function=self.web_tools.scan_sqli,
            examples=['scan_sqli(url="https://example.com/user?id=1", param="id")']
        )
        
        tools["scan_ssrf"] = ToolDefinition(
            name="scan_ssrf",
            description="Scan for SSRF vulnerabilities to access internal resources.",
            parameters={
                "url": {"type": "string", "description": "Target URL", "required": True},
                "param": {"type": "string", "description": "URL parameter to test", "required": True},
                "categories": {"type": "array", "description": "Categories: localhost, cloud, internal", "default": ["localhost", "cloud"]}
            },
            function=self.web_tools.scan_ssrf,
            examples=['scan_ssrf(url="https://example.com/fetch?url=http://google.com", param="url")']
        )
        
        tools["scan_lfi"] = ToolDefinition(
            name="scan_lfi",
            description="Scan for Local File Inclusion vulnerabilities.",
            parameters={
                "url": {"type": "string", "description": "Target URL", "required": True},
                "param": {"type": "string", "description": "File parameter to test", "required": True},
                "os_type": {"type": "string", "description": "OS type: linux or windows", "default": "linux"}
            },
            function=self.web_tools.scan_lfi,
            examples=['scan_lfi(url="https://example.com/view?file=report.pdf", param="file")']
        )
        
        tools["scan_auth"] = ToolDefinition(
            name="scan_auth",
            description="Scan authentication for bypass vulnerabilities and weak credentials.",
            parameters={
                "login_url": {"type": "string", "description": "Login form URL", "required": True},
                "username_field": {"type": "string", "description": "Username field name", "default": "username"},
                "password_field": {"type": "string", "description": "Password field name", "default": "password"}
            },
            function=self.web_tools.scan_auth,
            examples=['scan_auth(login_url="https://example.com/login")']
        )
        
        tools["scan_idor"] = ToolDefinition(
            name="scan_idor",
            description="Scan for IDOR (Insecure Direct Object Reference) vulnerabilities.",
            parameters={
                "url": {"type": "string", "description": "Target URL", "required": True},
                "param": {"type": "string", "description": "ID parameter", "required": True},
                "current_id": {"type": "string", "description": "Your current user's ID", "required": True}
            },
            function=self.web_tools.scan_idor,
            examples=['scan_idor(url="https://example.com/user?id=123", param="id", current_id="123")']
        )
        
        tools["quick_scan"] = ToolDefinition(
            name="quick_scan",
            description="Quick scan for XSS, SQLi, and LFI on a parameter.",
            parameters={
                "url": {"type": "string", "description": "Target URL", "required": True},
                "param": {"type": "string", "description": "Parameter to test", "required": True}
            },
            function=self.web_tools.quick_scan,
            examples=['quick_scan(url="https://example.com/search?q=test", param="q")']
        )
        
        # ==================== Payload Tools ====================
        tools["generate_payload"] = ToolDefinition(
            name="generate_payload",
            description="Generate a sophisticated payload for a vulnerability type.",
            parameters={
                "vuln_type": {"type": "string", "description": "Type: xss, sqli, ssrf, lfi, cmd, ssti", "required": True},
                "context": {"type": "string", "description": "For XSS: html, attribute, javascript, url"},
                "technique": {"type": "string", "description": "For SQLi: union, error, blind_boolean, blind_time"},
                "db": {"type": "string", "description": "Database: mysql, mssql, postgresql, oracle"},
                "bypass": {"type": "string", "description": "Bypass technique: encoding, waf, quotes, tags"}
            },
            function=self.web_tools.generate_payload,
            examples=[
                'generate_payload(vuln_type="xss", context="html", bypass="waf")',
                'generate_payload(vuln_type="sqli", technique="union", db="mysql")'
            ]
        )
        
        tools["get_payloads"] = ToolDefinition(
            name="get_payloads",
            description="Get a list of pre-built payloads for a vulnerability category.",
            parameters={
                "category": {"type": "string", "description": "Category: xss, sqli, ssrf, lfi, cmd", "required": True}
            },
            function=self.web_tools.get_payloads,
            examples=['get_payloads(category="xss")']
        )
        
        tools["mutate_payload"] = ToolDefinition(
            name="mutate_payload",
            description="Generate variations/mutations of a payload to bypass filters.",
            parameters={
                "payload": {"type": "string", "description": "Original payload", "required": True},
                "count": {"type": "integer", "description": "Number of mutations", "default": 5}
            },
            function=self.web_tools.mutate_payload,
            examples=['mutate_payload(payload="<script>alert(1)</script>", count=5)']
        )
        
        # ==================== Session/Auth Tools ====================
        tools["login"] = ToolDefinition(
            name="login",
            description="Login to the application with credentials.",
            parameters={
                "login_url": {"type": "string", "description": "Login form URL", "required": True},
                "username": {"type": "string", "description": "Username", "required": True},
                "password": {"type": "string", "description": "Password", "required": True},
                "username_field": {"type": "string", "description": "Username field name", "default": "username"},
                "password_field": {"type": "string", "description": "Password field name", "default": "password"},
                "csrf_field": {"type": "string", "description": "CSRF token field name"}
            },
            function=self.web_tools.login,
            examples=['login(login_url="https://example.com/login", username="test", password="test123")']
        )
        
        tools["set_cookie"] = ToolDefinition(
            name="set_cookie",
            description="Set a cookie for subsequent requests.",
            parameters={
                "name": {"type": "string", "description": "Cookie name", "required": True},
                "value": {"type": "string", "description": "Cookie value", "required": True}
            },
            function=self.web_tools.set_cookie,
            examples=['set_cookie(name="session", value="abc123")']
        )
        
        tools["set_header"] = ToolDefinition(
            name="set_header",
            description="Set a header for subsequent requests.",
            parameters={
                "name": {"type": "string", "description": "Header name", "required": True},
                "value": {"type": "string", "description": "Header value", "required": True}
            },
            function=self.web_tools.set_header,
            examples=['set_header(name="Authorization", value="Bearer token123")']
        )
        
        # ==================== Search Tools ====================
        tools["search_cve"] = ToolDefinition(
            name="search_cve",
            description="Search for CVE details and vulnerability information.",
            parameters={
                "cve_id": {"type": "string", "description": "CVE ID (e.g., CVE-2021-44228)", "required": True}
            },
            function=self.search_tools.search_cve,
            examples=['search_cve(cve_id="CVE-2021-44228")']
        )
        
        tools["search_vulnerability"] = ToolDefinition(
            name="search_vulnerability",
            description="Search for vulnerability information and related payloads.",
            parameters={
                "query": {"type": "string", "description": "Search query", "required": True},
                "technology": {"type": "string", "description": "Technology filter"}
            },
            function=self.search_tools.search_vulnerability,
            examples=['search_vulnerability(query="XSS bypass", technology="react")']
        )
        
        tools["search_exploit"] = ToolDefinition(
            name="search_exploit",
            description="Search for exploits and POCs.",
            parameters={
                "query": {"type": "string", "description": "Search query", "required": True},
                "cve": {"type": "string", "description": "Specific CVE to search for"}
            },
            function=self.search_tools.search_exploit,
            examples=['search_exploit(query="log4j", cve="CVE-2021-44228")']
        )
        
        tools["search_technology_vulns"] = ToolDefinition(
            name="search_technology_vulns",
            description="Search for known vulnerabilities in a specific technology.",
            parameters={
                "technology": {"type": "string", "description": "Technology name", "required": True},
                "version": {"type": "string", "description": "Version number"}
            },
            function=self.search_tools.search_technology_vulns,
            examples=['search_technology_vulns(technology="wordpress", version="5.8")']
        )
        
        # ==================== Report Tools ====================
        tools["create_report"] = ToolDefinition(
            name="create_report",
            description="Create a detailed vulnerability report.",
            parameters={
                "vuln_type": {"type": "string", "description": "Vulnerability type", "required": True},
                "url": {"type": "string", "description": "Affected URL", "required": True},
                "parameter": {"type": "string", "description": "Vulnerable parameter"},
                "payload": {"type": "string", "description": "Payload used"}
            },
            function=lambda **kwargs: self.report_tools.create_report(**kwargs).to_dict(),
            examples=['create_report(vuln_type="xss", url="https://example.com", parameter="q", payload="<script>alert(1)</script>")']
        )
        
        tools["get_findings"] = ToolDefinition(
            name="get_findings",
            description="Get all vulnerabilities found so far.",
            parameters={},
            function=self.web_tools.get_findings,
            examples=['get_findings()']
        )
        
        return tools

    def _build_system_prompt(self) -> str:
        """Build the system prompt for the LLM"""
        return """You are VulnHunter, an expert AI security researcher specializing in web application vulnerability hunting. Your goal is to find critical security vulnerabilities like those reported on HackerOne.

## Your Capabilities
You have access to powerful tools for:
1. **Web Reconnaissance**: Crawl sites, analyze pages, read source code
2. **Vulnerability Scanning**: Test for XSS, SQLi, SSRF, LFI, IDOR, auth bypass
3. **Payload Generation**: Create sophisticated payloads with bypass techniques
4. **Research**: Search CVE databases, find exploits, research technologies
5. **Reporting**: Generate professional vulnerability reports

## Methodology
Follow this systematic approach:

### Phase 1: Reconnaissance
1. Crawl the target to discover URLs, forms, and parameters
2. Analyze the technology stack (frameworks, libraries)
3. Identify potential attack surfaces (forms, APIs, file uploads)
4. Read source code to understand the application

### Phase 2: Vulnerability Discovery
1. Test each parameter for common vulnerabilities
2. Start with quick_scan to identify obvious issues
3. Use specialized scanners for deeper testing
4. Generate custom payloads when filters are detected

### Phase 3: Exploitation & Validation
1. Confirm vulnerabilities are exploitable
2. Demonstrate maximum impact
3. Test bypass techniques if needed
4. Document reproduction steps

### Phase 4: Reporting
1. Create detailed reports for each finding
2. Include severity, impact, and remediation
3. Format reports suitable for HackerOne submission

## Tool Usage
Call tools using this format:
TOOL: tool_name(param1="value1", param2="value2")

Example:
TOOL: crawl(url="https://example.com")
TOOL: scan_xss(url="https://example.com/search?q=test", param="q")

## Important Guidelines
- Always validate findings before reporting
- Maximize impact (prove data access, demonstrate RCE, etc.)
- Use bypass techniques when filters are detected
- Research known CVEs for detected technologies
- Be thorough - check all parameters and endpoints
- Generate HackerOne-quality reports

Now, let's hunt for vulnerabilities!"""

    def _parse_tool_call(self, text: str) -> Optional[Dict[str, Any]]:
        """Parse tool call from LLM response"""
        # Look for TOOL: pattern
        pattern = r'TOOL:\s*(\w+)\((.*?)\)'
        match = re.search(pattern, text, re.DOTALL)
        
        if not match:
            return None
        
        tool_name = match.group(1)
        args_str = match.group(2)
        
        # Parse arguments
        args = {}
        if args_str.strip():
            # Handle key="value" format
            arg_pattern = r'(\w+)\s*=\s*(?:"([^"]*?)"|\'([^\']*?)\'|(\[.*?\]|\{.*?\}|\d+|True|False|None))'
            for arg_match in re.finditer(arg_pattern, args_str, re.DOTALL):
                key = arg_match.group(1)
                # Get the value from whichever group matched
                value = arg_match.group(2) or arg_match.group(3) or arg_match.group(4)
                
                # Parse JSON-like values
                if value and value.startswith(('[', '{')):
                    try:
                        value = json.loads(value.replace("'", '"'))
                    except:
                        pass
                elif value == 'True':
                    value = True
                elif value == 'False':
                    value = False
                elif value == 'None':
                    value = None
                elif value and value.isdigit():
                    value = int(value)
                
                args[key] = value
        
        return {"tool": tool_name, "args": args}

    def _execute_tool(self, tool_name: str, args: Dict) -> str:
        """Execute a tool and return result"""
        if tool_name not in self.tools:
            return f"Error: Unknown tool '{tool_name}'. Available tools: {', '.join(self.tools.keys())}"
        
        tool = self.tools[tool_name]
        
        try:
            result = tool.function(**args)
            return json.dumps(result, indent=2, default=str)
        except Exception as e:
            return f"Error executing {tool_name}: {str(e)}"

    def _get_tools_description(self) -> str:
        """Get description of all available tools"""
        desc = "## Available Tools\n\n"
        
        for name, tool in self.tools.items():
            desc += f"### {name}\n"
            desc += f"{tool.description}\n\n"
            desc += "Parameters:\n"
            for param, info in tool.parameters.items():
                required = info.get("required", False)
                default = info.get("default", "")
                desc += f"- `{param}`: {info.get('description', '')} "
                if required:
                    desc += "(required)"
                elif default:
                    desc += f"(default: {default})"
                desc += "\n"
            if tool.examples:
                desc += f"\nExample: `{tool.examples[0]}`\n"
            desc += "\n"
        
        return desc

    def chat(self, message: str) -> str:
        """
        Send a message to the LLM and get response with tool execution
        
        Args:
            message: User message
        
        Returns:
            LLM response
        """
        if not OLLAMA_AVAILABLE:
            return "Error: Ollama is not installed. Please install with: pip install ollama"
        
        # Add message to conversation
        self.conversation.append({"role": "user", "content": message})
        
        # Build full prompt with context
        messages = [
            {"role": "system", "content": self.system_prompt},
            *self.conversation
        ]
        
        try:
            # Get LLM response
            response = ollama.chat(
                model=self.model,
                messages=messages
            )
            
            assistant_message = response['message']['content']
            
            # Check for tool calls
            tool_call = self._parse_tool_call(assistant_message)
            
            if tool_call:
                # Execute tool
                tool_result = self._execute_tool(tool_call["tool"], tool_call["args"])
                
                # Add tool result to conversation
                self.conversation.append({
                    "role": "assistant", 
                    "content": f"I called {tool_call['tool']} and got:\n```json\n{tool_result}\n```\n\n{assistant_message}"
                })
                
                # Get follow-up analysis
                follow_up = f"Tool result for {tool_call['tool']}:\n```json\n{tool_result}\n```\n\nAnalyze this result and continue hunting."
                
                return self.chat(follow_up)
            
            # No tool call, just return response
            self.conversation.append({"role": "assistant", "content": assistant_message})
            return assistant_message
            
        except Exception as e:
            return f"Error communicating with Ollama: {str(e)}"

    def start(self, target_url: str) -> str:
        """
        Start a bug hunting session on a target
        
        Args:
            target_url: Target URL to hunt on
        
        Returns:
            Initial analysis
        """
        self.target_url = target_url
        self.conversation = []  # Reset conversation
        
        initial_message = f"""I want to hunt for vulnerabilities on: {target_url}

Please start by:
1. Crawling the site to discover the attack surface
2. Analyzing the technology stack
3. Identifying potential vulnerability points
4. Begin testing for critical vulnerabilities

Focus on finding high-impact bugs like:
- SQL Injection
- XSS with session hijacking potential
- SSRF with cloud metadata access
- Authentication bypass
- IDOR exposing sensitive data

Let's find some critical vulnerabilities!"""
        
        return self.chat(initial_message)

    def continue_hunt(self, instruction: str = "") -> str:
        """
        Continue the hunt with optional instruction
        
        Args:
            instruction: Optional specific instruction
        
        Returns:
            LLM response
        """
        if instruction:
            return self.chat(instruction)
        else:
            return self.chat("Continue hunting for vulnerabilities. What should we test next?")

    def get_report(self) -> str:
        """Get a summary report of all findings"""
        findings = self.web_tools.get_findings()
        
        if not findings:
            return "No vulnerabilities found yet."
        
        return self.report_tools.create_summary_report(findings)

    def interactive_session(self):
        """Run an interactive hunting session"""
        print("=" * 60)
        print("VulnHunter - AI-Powered Bug Hunting")
        print("=" * 60)
        print(f"Using model: {self.model}")
        print("Type 'quit' to exit, 'report' for findings summary")
        print("=" * 60)
        
        target = input("\nEnter target URL: ").strip()
        if not target:
            print("No target provided. Exiting.")
            return
        
        print("\nStarting hunt...")
        print(self.start(target))
        
        while True:
            user_input = input("\n> ").strip()
            
            if user_input.lower() == 'quit':
                print("\nFinal Report:")
                print(self.get_report())
                break
            elif user_input.lower() == 'report':
                print(self.get_report())
            elif user_input.lower() == 'tools':
                print(self._get_tools_description())
            else:
                response = self.continue_hunt(user_input)
                print(response)


# Simple execution functions for direct tool use without LLM
def quick_hunt(url: str, model: str = "llama3.1:8b") -> str:
    """Quick hunt function for simple usage"""
    hunter = VulnHunterLLM(model=model)
    return hunter.start(url)


def manual_scan(url: str, scan_type: str = "all") -> Dict[str, Any]:
    """Manual scan without LLM - direct tool usage"""
    tools = WebTools()
    
    results = {
        "target": url,
        "timestamp": datetime.now().isoformat(),
        "findings": []
    }
    
    # Crawl first
    print(f"Crawling {url}...")
    crawl_result = tools.crawl(url, depth=2)
    results["crawl"] = crawl_result
    
    # Get parameters to test
    params_to_test = crawl_result.get("parameters", {})
    forms = crawl_result.get("forms", [])
    
    print(f"Found {len(params_to_test)} parameters and {len(forms)} forms")
    
    # Test each discovered URL with parameters
    for discovered_url in crawl_result.get("urls_discovered", [])[:10]:
        if "?" in discovered_url:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(discovered_url)
            params = parse_qs(parsed.query)
            
            for param in params:
                print(f"Testing {param} on {discovered_url[:50]}...")
                
                if scan_type in ["all", "quick"]:
                    scan_result = tools.quick_scan(discovered_url, param)
                    for vuln_type, data in scan_result.items():
                        if isinstance(data, dict) and data.get("vulnerable"):
                            results["findings"].append({
                                "type": vuln_type,
                                "url": discovered_url,
                                "param": param,
                                **data
                            })
    
    return results
