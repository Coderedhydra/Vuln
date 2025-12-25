#!/usr/bin/env python3
"""
VulnHunter - Fast AI-Powered Vulnerability Scanner
Redesigned for speed, accuracy, and real exploitation
"""

import sys
import argparse
import json
import asyncio
from datetime import datetime
from typing import Optional

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from llm_interface import VulnHunterLLM, FastScanner, quick_scan


console = Console() if RICH_AVAILABLE else None


def print_banner():
    """Print banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║   ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗██╗  ██╗██╗   ██╗███╗  ║
║   ██║   ██║██║   ██║██║     ████╗  ██║██║  ██║██║   ██║████╗ ║
║   ╚██╗ ██╔╝╚██████╔╝███████╗██║ ╚████║██║  ██║╚██████╔╝██║ ╚█║
║     ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ║
║   Fast AI-Powered Vulnerability Hunter                        ║
╚═══════════════════════════════════════════════════════════════╝
"""
    if console:
        console.print(banner, style="bold cyan")
    else:
        print(banner)


def print_info(msg: str):
    if console:
        console.print(f"[blue][*][/blue] {msg}")
    else:
        print(f"[*] {msg}")


def print_success(msg: str):
    if console:
        console.print(f"[green][+][/green] {msg}")
    else:
        print(f"[+] {msg}")


def print_warning(msg: str):
    if console:
        console.print(f"[yellow][!][/yellow] {msg}")
    else:
        print(f"[!] {msg}")


def print_error(msg: str):
    if console:
        console.print(f"[red][-][/red] {msg}")
    else:
        print(f"[-] {msg}")


def print_vuln(vuln: dict):
    """Print vulnerability finding"""
    colors = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "blue"}
    severity = vuln.get("severity", "medium").lower()
    color = colors.get(severity, "white")
    
    if console:
        console.print(f"\n[bold {color}]{'='*50}[/bold {color}]")
        console.print(f"[bold {color}]CONFIRMED: {vuln.get('type', 'Unknown').upper()}[/bold {color}]")
        console.print(f"[bold {color}]{'='*50}[/bold {color}]")
        console.print(f"[bold]Severity:[/bold] [{color}]{severity.upper()}[/{color}]")
        console.print(f"[bold]URL:[/bold] {vuln.get('url', 'N/A')}")
        console.print(f"[bold]Parameter:[/bold] {vuln.get('param', 'N/A')}")
        console.print(f"[bold]Payload:[/bold] {vuln.get('payload', 'N/A')}")
        console.print(f"[bold]Evidence:[/bold] {vuln.get('evidence', 'N/A')}")
        if vuln.get('extracted_data'):
            console.print(f"[bold]Extracted:[/bold] {vuln.get('extracted_data', '')[:200]}")
    else:
        print(f"\n{'='*50}")
        print(f"CONFIRMED: {vuln.get('type', 'Unknown').upper()}")
        print(f"{'='*50}")
        print(f"Severity: {severity.upper()}")
        print(f"URL: {vuln.get('url', 'N/A')}")
        print(f"Parameter: {vuln.get('param', 'N/A')}")
        print(f"Payload: {vuln.get('payload', 'N/A')}")
        print(f"Evidence: {vuln.get('evidence', 'N/A')}")


def fast_scan_mode(target: str, output: Optional[str] = None):
    """Ultra-fast scan mode - parallel async scanning"""
    print_banner()
    print_info(f"Fast scanning: {target}")
    
    start_time = datetime.now()
    
    try:
        if console:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Scanning...", total=None)
                results = quick_scan(target)
        else:
            print_info("Scanning... (this is fast)")
            results = quick_scan(target)
    except Exception as e:
        print_error(f"Scan failed: {e}")
        return
    
    elapsed = (datetime.now() - start_time).total_seconds()
    
    # Print results
    print_success(f"Scan completed in {elapsed:.2f}s")
    print_info(f"Forms found: {results.get('forms_found', 0)}")
    print_info(f"Parameters tested: {results.get('params_tested', 0)}")
    print_info(f"Links discovered: {results.get('links_found', 0)}")
    
    vulns = results.get("vulnerabilities", [])
    
    if vulns:
        print_success(f"\nFound {len(vulns)} CONFIRMED vulnerabilities:")
        for vuln in vulns:
            print_vuln(vuln)
    else:
        print_info("\nNo confirmed vulnerabilities found.")
    
    # Save results
    if output:
        with open(output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print_success(f"Results saved to {output}")
    
    return results


def interactive_mode(model: str, target: Optional[str] = None):
    """Interactive AI mode"""
    print_banner()
    print_info(f"Using model: {model}")
    
    if not target:
        target = input("\nEnter target URL: ").strip()
    
    if not target:
        print_error("No target provided.")
        return
    
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    print_success(f"Target: {target}")
    print_info("Initializing AI...")
    
    try:
        hunter = VulnHunterLLM(model=model)
    except Exception as e:
        print_error(f"Failed to initialize: {e}")
        print_warning("Make sure Ollama is running: ollama serve")
        return
    
    print_info("Starting hunt...")
    print_info("Commands: 'quit' to exit, 'report' for findings, 'scan' for fast scan")
    print()
    
    response = hunter.start(target)
    
    if console:
        console.print(Panel(response, title="VulnHunter AI", border_style="cyan"))
    else:
        print(f"\n--- VulnHunter AI ---\n{response}\n---")
    
    while True:
        try:
            user_input = input("\nYou: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n")
            break
        
        if not user_input:
            continue
        
        if user_input.lower() == 'quit':
            print(hunter.get_report())
            break
        
        elif user_input.lower() == 'report':
            print(hunter.get_report())
        
        elif user_input.lower() == 'scan':
            # Run fast scan
            print_info("Running fast scan...")
            results = quick_scan(target)
            for vuln in results.get("vulnerabilities", []):
                print_vuln(vuln)
        
        else:
            response = hunter.continue_hunt(user_input)
            if console:
                console.print(Panel(response, title="VulnHunter AI", border_style="cyan"))
            else:
                print(f"\n--- VulnHunter AI ---\n{response}\n---")
    
    print_success("Hunt complete!")


def single_param_scan(url: str, param: str, vuln_type: str):
    """Scan single parameter"""
    print_banner()
    print_info(f"Testing {param} for {vuln_type}")
    
    from tools.web_tools import WebTools
    tools = WebTools()
    
    if vuln_type == "xss":
        results = tools.scan_xss(url, param)
    elif vuln_type == "sqli":
        results = tools.scan_sqli(url, param)
    elif vuln_type == "ssrf":
        results = tools.scan_ssrf(url, param)
    elif vuln_type == "lfi":
        results = tools.scan_lfi(url, param)
    elif vuln_type == "quick":
        results = tools.quick_scan(url, param)
    else:
        print_error(f"Unknown type: {vuln_type}")
        return
    
    print(json.dumps(results, indent=2))
    
    if results.get("summary", {}).get("vulnerable_count", 0) > 0:
        print_success("Vulnerabilities found!")
    else:
        print_info("No vulnerabilities found with current payloads.")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="VulnHunter - Fast AI-Powered Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fast automatic scan (recommended)
  python main.py -t https://example.com
  
  # Interactive AI mode
  python main.py -i -t https://example.com
  
  # Scan specific parameter
  python main.py -t "https://example.com/search?q=test" -p q --type xss
  
  # Save results to file
  python main.py -t https://example.com -o results.json
"""
    )
    
    parser.add_argument('-t', '--target', help='Target URL')
    parser.add_argument('-m', '--model', default='llama3.1:8b', help='Ollama model')
    parser.add_argument('-i', '--interactive', action='store_true', help='Interactive AI mode')
    parser.add_argument('-p', '--param', help='Parameter to test')
    parser.add_argument('--type', choices=['xss', 'sqli', 'ssrf', 'lfi', 'quick'], help='Vulnerability type')
    parser.add_argument('-o', '--output', help='Output file')
    
    args = parser.parse_args()
    
    if args.param and args.type:
        if not args.target:
            print_error("Target URL required")
            sys.exit(1)
        single_param_scan(args.target, args.param, args.type)
    
    elif args.interactive:
        interactive_mode(args.model, args.target)
    
    elif args.target:
        # Default: fast scan
        fast_scan_mode(args.target, args.output)
    
    else:
        # No args - show help and prompt
        print_banner()
        print_info("No target specified. Use -t URL or run interactively with -i")
        parser.print_help()


if __name__ == "__main__":
    main()
