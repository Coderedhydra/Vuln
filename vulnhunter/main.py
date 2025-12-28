#!/usr/bin/env python3
"""
VulnHunter - Autonomous AI Bug Bounty Hunter
"""

import sys
import json
import asyncio
import aiohttp
import time
import re
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from typing import Dict, List, Optional, Any
from datetime import datetime

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.prompt import Prompt
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

console = Console() if RICH_AVAILABLE else None


def print_banner():
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗██╗  ██╗██╗   ██╗      ║
║   ██║   ██║██║   ██║██║     ████╗  ██║██║  ██║██║   ██║      ║
║   ╚██╗ ██╔╝╚██████╔╝███████╗██║ ╚████║██║  ██║╚██████╔╝      ║
║    ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚═════╝       ║
║                                                               ║
║   Autonomous AI Bug Bounty Hunter                             ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""
    if console:
        console.print(banner, style="bold cyan")
    else:
        print(banner)


def get_ollama_models() -> List[str]:
    """Get list of available Ollama models"""
    if not OLLAMA_AVAILABLE:
        return []
    try:
        models = ollama.list()
        return [m['name'] for m in models.get('models', [])]
    except:
        return []


def select_model() -> str:
    """Let user select an Ollama model"""
    models = get_ollama_models()
    
    if not models:
        if console:
            console.print("[yellow]No Ollama models found. Make sure Ollama is running.[/yellow]")
            console.print("[dim]Run: ollama serve && ollama pull llama3.1:8b[/dim]")
        else:
            print("No Ollama models found. Run: ollama serve && ollama pull llama3.1:8b")
        return "llama3.1:8b"
    
    if console:
        table = Table(title="Available Models")
        table.add_column("#", style="cyan")
        table.add_column("Model", style="green")
        
        for i, model in enumerate(models, 1):
            table.add_row(str(i), model)
        
        console.print(table)
        choice = Prompt.ask("Select model", default="1")
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(models):
                return models[idx]
        except:
            pass
        return models[0]
    else:
        print("\nAvailable Models:")
        for i, model in enumerate(models, 1):
            print(f"  {i}. {model}")
        choice = input("Select model (number): ").strip()
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(models):
                return models[idx]
        except:
            pass
        return models[0]


class FastTester:
    """
    Fast parallel vulnerability tester
    Does the actual testing - LLM just analyzes
    """
    
    def __init__(self, timeout: int = 10, max_parallel: int = 10):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_parallel = max_parallel
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        self.findings = []
        self.tested = []
    
    async def fetch(self, url: str) -> Dict:
        """Fetch a URL"""
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(url, headers=self.headers, ssl=False) as resp:
                    body = await resp.text()
                    return {"success": True, "status": resp.status, "body": body, "url": str(resp.url)}
        except Exception as e:
            return {"success": False, "error": str(e), "url": url}
    
    async def test_payload(self, url: str, param: str, payload: str, vuln_type: str) -> Dict:
        """Test a single payload"""
        # Build test URL
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        
        result = await self.fetch(test_url)
        
        if not result["success"]:
            return {"tested": True, "vulnerable": False, "error": result.get("error")}
        
        body = result["body"]
        body_lower = body.lower()
        
        # Check for vulnerability indicators
        vulnerable = False
        evidence = ""
        
        if vuln_type == "xss":
            # Check if payload reflected in HTML context
            if payload in body:
                # Make sure it's in HTML, not JSON
                is_html = "<html" in body_lower or "<body" in body_lower or "<!doctype" in body_lower
                is_json = body.strip().startswith("{") or body.strip().startswith("[")
                
                if is_html and not is_json:
                    vulnerable = True
                    evidence = "Payload reflected in HTML response"
        
        elif vuln_type == "sqli":
            sql_errors = ["sql syntax", "mysql", "sqlite", "postgresql", "ora-", "sql server", 
                         "unclosed quotation", "quoted string", "syntax error"]
            for err in sql_errors:
                if err in body_lower:
                    vulnerable = True
                    evidence = f"SQL error detected: {err}"
                    break
        
        elif vuln_type == "lfi":
            lfi_indicators = ["root:", "nobody:", "[fonts]", "[extensions]", "daemon:"]
            for ind in lfi_indicators:
                if ind in body:
                    vulnerable = True
                    evidence = f"File content found: {ind}"
                    break
        
        elif vuln_type == "ssrf":
            # Only detect REAL SSRF - actual internal content, not reflection
            # Our payloads contain these URLs, so we need to check for ACTUAL AWS response content
            
            # These indicate REAL AWS metadata was returned (not just payload reflection)
            real_aws_content = [
                "ami-",           # ami-id values start with ami-
                "i-",             # instance IDs start with i-
                "ip-",            # internal hostnames
                "us-east-",       # AWS regions
                "us-west-",
                "eu-west-",
                "ap-",
            ]
            
            # Only vulnerable if we see actual AWS content, not our payload
            for indicator in real_aws_content:
                if indicator in body_lower:
                    vulnerable = True
                    evidence = f"AWS internal data found: {indicator}..."
                    break
        
        return {
            "tested": True,
            "url": url,
            "param": param,
            "payload": payload,
            "vuln_type": vuln_type,
            "vulnerable": vulnerable,
            "evidence": evidence,
            "status": result["status"],
            "response_length": len(body)
        }
    
    async def test_all_payloads(self, url: str, param: str, show_progress: bool = True) -> List[Dict]:
        """Test all payload types on a parameter"""
        payloads = [
            # XSS
            ("<script>alert(1)</script>", "xss"),
            ('"><img src=x onerror=alert(1)>', "xss"),
            ("<svg onload=alert(1)>", "xss"),
            # SQLi
            ("'", "sqli"),
            ("' OR '1'='1", "sqli"),
            ("' OR 1=1--", "sqli"),
            ("1' AND '1'='1", "sqli"),
            # LFI
            ("../../../etc/passwd", "lfi"),
            ("....//....//etc/passwd", "lfi"),
            # SSRF
            ("http://127.0.0.1", "ssrf"),
            ("http://169.254.169.254/latest/meta-data/", "ssrf"),
        ]
        
        # Run tests in parallel
        semaphore = asyncio.Semaphore(self.max_parallel)
        
        async def bounded_test(payload, vuln_type):
            async with semaphore:
                return await self.test_payload(url, param, payload, vuln_type)
        
        tasks = [bounded_test(p, t) for p, t in payloads]
        results = await asyncio.gather(*tasks)
        
        # Store results
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
            for inp in re.finditer(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>', content, re.I):
                inputs.append(inp.group(1))
            for ta in re.finditer(r'<textarea[^>]*name=["\']([^"\']*)["\']', content, re.I):
                inputs.append(ta.group(1))
            for sel in re.finditer(r'<select[^>]*name=["\']([^"\']*)["\']', content, re.I):
                inputs.append(sel.group(1))
            
            if inputs:
                forms.append({
                    "action": urljoin(base_url, action.group(1)) if action else base_url,
                    "method": method.group(1).upper() if method else "GET",
                    "inputs": inputs
                })
        
        return forms
    
    def extract_params(self, html: str, base_url: str) -> set:
        """Extract URL parameters"""
        params = set()
        # From current URL
        for p in parse_qs(urlparse(base_url).query):
            params.add(p)
        # From links
        for href in re.findall(r'href=["\']([^"\']*\?[^"\']*)["\']', html, re.I):
            full = urljoin(base_url, href)
            for p in parse_qs(urlparse(full).query):
                params.add(p)
        return params
    
    def extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract internal links"""
        links = set()
        base_netloc = urlparse(base_url).netloc
        for href in re.findall(r'href=["\']([^"\']+)["\']', html, re.I):
            if href.startswith('#') or href.startswith('javascript:'):
                continue
            full = urljoin(base_url, href.split('#')[0])
            if urlparse(full).netloc == base_netloc:
                links.add(full)
        return list(links)[:20]


class VulnHunter:
    """
    Main vulnerability hunter
    Uses FastTester for testing, LLM for analysis
    """
    
    def __init__(self, model: str = "llama3.1:8b"):
        self.model = model
        self.tester = FastTester()
        self.target_url = ""
        self.forms = []
        self.params = set()
        self.links = []
        self.conversation = []
    
    def run_async(self, coro):
        """Run async code"""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    return pool.submit(asyncio.run, coro).result()
            return loop.run_until_complete(coro)
        except RuntimeError:
            return asyncio.run(coro)
    
    def discover(self, url: str) -> Dict:
        """Discover attack surface"""
        result = self.run_async(self.tester.fetch(url))
        
        if not result["success"]:
            return {"error": result.get("error", "Failed to fetch")}
        
        html = result["body"]
        self.forms = self.tester.extract_forms(html, url)
        self.params = self.tester.extract_params(html, url)
        self.links = self.tester.extract_links(html, url)
        
        return {
            "forms": self.forms,
            "parameters": list(self.params),
            "links": self.links[:10],
            "total_links": len(self.links)
        }
    
    def test_parameter(self, url: str, param: str) -> List[Dict]:
        """Test a parameter with all payloads"""
        results = self.run_async(self.tester.test_all_payloads(url, param))
        return results
    
    def auto_test(self, url: str) -> Dict:
        """Automatically test all discovered parameters"""
        results = {
            "tested_params": 0,
            "vulnerabilities": [],
            "tests": []
        }
        
        # Build list of params to test
        test_targets = []
        
        # From URL
        for p in parse_qs(urlparse(url).query):
            test_targets.append((url, p))
        
        # From forms
        for form in self.forms[:5]:
            for inp in form["inputs"][:5]:
                action = form["action"]
                if "?" not in action:
                    action = f"{action}?{inp}=test"
                test_targets.append((action, inp))
        
        # From discovered params
        for p in list(self.params)[:10]:
            if (url, p) not in test_targets:
                test_url = url if "?" in url else f"{url}?{p}=test"
                test_targets.append((test_url, p))
        
        # Test each
        for test_url, param in test_targets[:15]:
            if console:
                console.print(f"[dim]Testing {param}...[/dim]")
            
            test_results = self.test_parameter(test_url, param)
            results["tested_params"] += 1
            
            for r in test_results:
                results["tests"].append(r)
                if r.get("vulnerable"):
                    results["vulnerabilities"].append(r)
        
        return results
    
    def get_llm_analysis(self, data: str, question: str = "") -> str:
        """Get LLM analysis of results"""
        if not OLLAMA_AVAILABLE:
            return "Ollama not available"
        
        prompt = f"""You are a security researcher analyzing vulnerability scan results.

{data}

{question if question else "Analyze these results. What vulnerabilities were confirmed? What should be tested next?"}

Be concise and actionable. Focus on confirmed vulnerabilities with evidence."""
        
        try:
            response = ollama.chat(
                model=self.model,
                messages=[{"role": "user", "content": prompt}]
            )
            return response['message']['content']
        except Exception as e:
            return f"LLM Error: {e}"
    
    def get_findings(self) -> List[Dict]:
        """Get confirmed findings"""
        return self.tester.findings
    
    def get_report(self) -> str:
        """Generate report"""
        findings = self.get_findings()
        
        report = f"""# Vulnerability Report
Target: {self.target_url}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}

## Summary
- Parameters tested: {len(self.tester.tested)}
- Confirmed vulnerabilities: {len(findings)}

"""
        if findings:
            report += "## Confirmed Vulnerabilities\n\n"
            for i, f in enumerate(findings, 1):
                report += f"""### {i}. {f['vuln_type'].upper()}
- URL: {f['url']}
- Parameter: {f['param']}
- Payload: `{f['payload']}`
- Evidence: {f['evidence']}

"""
        else:
            report += "## No confirmed vulnerabilities found.\n"
        
        return report


def hunt(target: str, model: str):
    """Main hunting function"""
    print_banner()
    
    if console:
        console.print(f"[bold blue]Target:[/bold blue] {target}")
        console.print(f"[bold blue]Model:[/bold blue] {model}")
        console.print()
    else:
        print(f"Target: {target}")
        print(f"Model: {model}")
        print()
    
    hunter = VulnHunter(model=model)
    hunter.target_url = target
    
    # Phase 1: Discovery
    if console:
        console.print("[yellow]Phase 1: Discovering attack surface...[/yellow]")
    else:
        print("Phase 1: Discovering attack surface...")
    
    discovery = hunter.discover(target)
    
    if "error" in discovery:
        if console:
            console.print(f"[red]Error: {discovery['error']}[/red]")
        else:
            print(f"Error: {discovery['error']}")
        return
    
    if console:
        console.print(f"[green]✓ Found {len(discovery['forms'])} forms[/green]")
        console.print(f"[green]✓ Found {len(discovery['parameters'])} parameters[/green]")
        console.print(f"[green]✓ Found {discovery['total_links']} internal links[/green]")
        console.print()
    else:
        print(f"Found {len(discovery['forms'])} forms")
        print(f"Found {len(discovery['parameters'])} parameters")
        print(f"Found {discovery['total_links']} internal links")
        print()
    
    # Show what was found
    if discovery['forms']:
        if console:
            console.print("[bold]Forms:[/bold]")
            for f in discovery['forms'][:5]:
                console.print(f"  • {f['method']} {f['action']} - inputs: {', '.join(f['inputs'][:3])}")
        else:
            print("Forms:")
            for f in discovery['forms'][:5]:
                print(f"  {f['method']} {f['action']} - {', '.join(f['inputs'][:3])}")
    
    if discovery['parameters']:
        if console:
            console.print(f"[bold]Parameters:[/bold] {', '.join(discovery['parameters'][:10])}")
        else:
            print(f"Parameters: {', '.join(discovery['parameters'][:10])}")
    
    print()
    
    # Phase 2: Testing
    if console:
        console.print("[yellow]Phase 2: Testing for vulnerabilities (parallel)...[/yellow]")
    else:
        print("Phase 2: Testing for vulnerabilities...")
    
    results = hunter.auto_test(target)
    
    if console:
        console.print(f"[green]✓ Tested {results['tested_params']} parameters[/green]")
        console.print(f"[green]✓ Found {len(results['vulnerabilities'])} potential vulnerabilities[/green]")
        console.print()
    else:
        print(f"Tested {results['tested_params']} parameters")
        print(f"Found {len(results['vulnerabilities'])} potential vulnerabilities")
        print()
    
    # Show findings
    if results['vulnerabilities']:
        if console:
            console.print("[bold red]CONFIRMED VULNERABILITIES:[/bold red]")
            for v in results['vulnerabilities']:
                console.print(f"[red]  • {v['vuln_type'].upper()}: {v['param']} - {v['evidence']}[/red]")
        else:
            print("CONFIRMED VULNERABILITIES:")
            for v in results['vulnerabilities']:
                print(f"  {v['vuln_type'].upper()}: {v['param']} - {v['evidence']}")
        print()
    
    # Phase 3: AI Analysis
    if console:
        console.print("[yellow]Phase 3: AI Analysis...[/yellow]")
    else:
        print("Phase 3: AI Analysis...")
    
    # Prepare data for LLM
    scan_summary = f"""
Target: {target}

Forms Found:
{json.dumps(discovery['forms'][:5], indent=2)}

Parameters Found: {', '.join(discovery['parameters'][:10])}

Test Results:
- Total tests: {len(results['tests'])}
- Vulnerabilities found: {len(results['vulnerabilities'])}

Vulnerability Details:
{json.dumps(results['vulnerabilities'], indent=2) if results['vulnerabilities'] else 'None confirmed'}
"""
    
    analysis = hunter.get_llm_analysis(scan_summary)
    
    if console:
        console.print(Panel(analysis, title="🔍 AI Analysis", border_style="cyan"))
    else:
        print("\n=== AI Analysis ===")
        print(analysis)
        print("==================\n")
    
    # Interactive loop
    if console:
        console.print("[dim]Commands: 'test <param>' to test specific param, 'report' for full report, 'quit' to exit[/dim]")
    else:
        print("Commands: 'test <param>', 'report', 'quit'")
    
    while True:
        try:
            cmd = input("\n> ").strip()
        except (KeyboardInterrupt, EOFError):
            break
        
        if not cmd:
            continue
        
        if cmd.lower() == 'quit' or cmd.lower() == 'q':
            print(hunter.get_report())
            break
        
        elif cmd.lower() == 'report' or cmd.lower() == 'r':
            print(hunter.get_report())
        
        elif cmd.lower().startswith('test '):
            param = cmd[5:].strip()
            if console:
                console.print(f"[yellow]Testing parameter: {param}[/yellow]")
            test_url = target if "?" in target else f"{target}?{param}=test"
            test_results = hunter.test_parameter(test_url, param)
            vulns = [r for r in test_results if r.get("vulnerable")]
            if vulns:
                if console:
                    console.print(f"[red]Found {len(vulns)} vulnerabilities![/red]")
                    for v in vulns:
                        console.print(f"[red]  • {v['vuln_type']}: {v['evidence']}[/red]")
                else:
                    print(f"Found {len(vulns)} vulnerabilities!")
            else:
                print("No vulnerabilities found for this parameter")
        
        else:
            # Ask LLM about the query
            response = hunter.get_llm_analysis(scan_summary, cmd)
            if console:
                console.print(Panel(response, title="🔍 AI Response", border_style="cyan"))
            else:
                print(f"\n{response}\n")
    
    print("\nHunt complete!")
    findings = hunter.get_findings()
    print(f"Total confirmed vulnerabilities: {len(findings)}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="VulnHunter - AI Bug Bounty Hunter")
    parser.add_argument('url', nargs='?', help='Target URL')
    parser.add_argument('-m', '--model', help='Ollama model to use')
    args = parser.parse_args()
    
    print_banner()
    
    # Get URL
    if args.url:
        url = args.url
    else:
        url = input("Enter target URL: ").strip()
    
    if not url:
        print("No URL provided")
        return
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Get model - use provided model or let user select
    if args.model:
        # User specified model - use it directly
        model = args.model
        if console:
            console.print(f"[green]Using model: {model}[/green]\n")
        else:
            print(f"Using model: {model}\n")
    else:
        # No model specified - show selection
        if console:
            console.print("\n[bold]Select AI Model:[/bold]")
        else:
            print("\nSelect AI Model:")
        
        model = select_model()
        
        if console:
            console.print(f"[green]Using model: {model}[/green]\n")
        else:
            print(f"Using model: {model}\n")
    
    # Start hunting
    hunt(url, model)


if __name__ == "__main__":
    main()
