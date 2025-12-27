#!/usr/bin/env python3
"""
VulnHunter - Autonomous AI Bug Bounty Hunter

Just give it a URL - the AI does everything:
- Discovers forms, parameters, endpoints
- Analyzes code and understands the application
- Creates smart payloads
- Tests and exploits vulnerabilities
- Reports confirmed findings
"""

import sys
import argparse
from datetime import datetime

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.markdown import Markdown
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from llm_interface import VulnHunterLLM

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
║   Just give me a URL - I do the rest                          ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""
    if console:
        console.print(banner, style="bold cyan")
    else:
        print(banner)


def show_response(response: str, title: str = "🔍 AI Hunter"):
    """Display AI response"""
    if console:
        console.print(Panel(Markdown(response), title=title, border_style="cyan"))
    else:
        print(f"\n{'='*60}")
        print(f" {title}")
        print('='*60)
        print(response)
        print('='*60 + "\n")


def hunt(target: str, model: str = "llama3.1:8b"):
    """
    Start autonomous bug hunting
    
    The AI will automatically:
    1. Fetch and analyze the target
    2. Find all forms, parameters, endpoints
    3. Understand the technology stack
    4. Create intelligent payloads
    5. Test for vulnerabilities
    6. Confirm and report findings
    """
    print_banner()
    
    if console:
        console.print(f"[bold blue][*] Target:[/bold blue] {target}")
        console.print(f"[bold blue][*] Model:[/bold blue] {model}")
        console.print()
        console.print("[yellow]Initializing AI Hunter...[/yellow]")
    else:
        print(f"[*] Target: {target}")
        print(f"[*] Model: {model}")
        print("\nInitializing AI Hunter...")
    
    try:
        hunter = VulnHunterLLM(model=model)
    except Exception as e:
        if console:
            console.print(f"[red][-] Error: {e}[/red]")
            console.print("[yellow][!] Make sure Ollama is running: ollama serve[/yellow]")
            console.print(f"[yellow][!] And model is available: ollama pull {model}[/yellow]")
        else:
            print(f"[-] Error: {e}")
            print(f"[!] Make sure Ollama is running: ollama serve")
            print(f"[!] And model is available: ollama pull {model}")
        return
    
    if console:
        console.print("[green][+] AI Hunter ready[/green]")
        console.print()
        console.print("[bold]The AI will now autonomously:[/bold]")
        console.print("  • Explore and analyze the target")
        console.print("  • Find forms, parameters, and endpoints")
        console.print("  • Create intelligent payloads")
        console.print("  • Test for vulnerabilities")
        console.print("  • Confirm and report real findings")
        console.print()
    else:
        print("[+] AI Hunter ready")
        print("\nThe AI will autonomously explore, test, and find vulnerabilities.\n")
    
    # Start the autonomous hunt
    response = hunter.start(target)
    show_response(response)
    
    # Interactive loop for guidance
    if console:
        console.print("[dim]Commands: 'c' = continue, 'r' = report, 'q' = quit, or type instructions[/dim]")
    else:
        print("Commands: 'c' = continue, 'r' = report, 'q' = quit, or type instructions")
    
    while True:
        try:
            user_input = input("\n> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n")
            break
        
        if not user_input or user_input.lower() == 'c':
            response = hunter.continue_hunt()
            show_response(response)
        
        elif user_input.lower() == 'q':
            print("\n" + hunter.get_report())
            break
        
        elif user_input.lower() == 'r':
            print(hunter.get_report())
        
        elif user_input.lower() == 'f':
            findings = hunter.get_findings()
            if findings:
                if console:
                    console.print(f"[green][+] {len(findings)} confirmed vulnerabilities:[/green]")
                else:
                    print(f"[+] {len(findings)} confirmed vulnerabilities:")
                for f in findings:
                    print(f"    • [{f['severity'].upper()}] {f['type']}: {f['url']}")
            else:
                print("[*] No confirmed vulnerabilities yet")
        
        else:
            # Custom instruction to the AI
            response = hunter.continue_hunt(user_input)
            show_response(response)
    
    # Final report
    findings = hunter.get_findings()
    if console:
        console.print(f"\n[bold green]Hunt Complete![/bold green]")
        console.print(f"[*] Requests made: {hunter.client.request_count}")
        console.print(f"[*] Confirmed vulnerabilities: {len(findings)}")
    else:
        print(f"\nHunt Complete!")
        print(f"[*] Requests made: {hunter.client.request_count}")
        print(f"[*] Confirmed vulnerabilities: {len(findings)}")


def main():
    parser = argparse.ArgumentParser(
        description="VulnHunter - Autonomous AI Bug Bounty Hunter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Just give me a URL - I do the rest.

The AI will automatically:
  • Explore the target and analyze source code
  • Find all forms, parameters, and endpoints  
  • Understand the technology stack
  • Create intelligent, context-aware payloads
  • Test for XSS, SQLi, SSRF, LFI, and more
  • Confirm vulnerabilities through real exploitation
  • Report only real, confirmed findings

Examples:
  python main.py https://target.com
  python main.py https://target.com -m llama3.1:70b
"""
    )
    
    parser.add_argument('url', nargs='?', help='Target URL to hunt')
    parser.add_argument('-m', '--model', default='llama3.1:8b', 
                        help='Ollama model (default: llama3.1:8b)')
    
    args = parser.parse_args()
    
    # Get URL
    if args.url:
        url = args.url
    else:
        print_banner()
        url = input("Enter target URL: ").strip()
    
    if not url:
        print("[-] No URL provided")
        sys.exit(1)
    
    # Ensure URL has protocol
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Start hunting
    hunt(url, args.model)


if __name__ == "__main__":
    main()
