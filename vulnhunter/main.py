#!/usr/bin/env python3
"""
VulnHunter - AI-Powered Web Application Vulnerability Scanner
Main entry point with CLI interface
"""

import sys
import argparse
import json
from datetime import datetime
from typing import Optional

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.markdown import Markdown
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.prompt import Prompt, Confirm
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("Note: Install 'rich' for better UI: pip install rich")

from llm_interface import VulnHunterLLM, manual_scan
from tools.web_tools import WebTools
from tools.search_tools import SearchTools
from tools.report_tools import ReportTools


# Initialize console
console = Console() if RICH_AVAILABLE else None


def print_banner():
    """Print the VulnHunter banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗██╗  ██╗██╗   ██╗███╗  ║
║   ██║   ██║██║   ██║██║     ████╗  ██║██║  ██║██║   ██║████╗ ║
║   ██║   ██║██║   ██║██║     ██╔██╗ ██║███████║██║   ██║██╔██╗║
║   ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══██║██║   ██║██║╚██║
║    ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║  ██║╚██████╔╝██║ ╚█║
║     ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ║
║                                                               ║
║   AI-Powered Web Vulnerability Hunter                         ║
║   Powered by Ollama LLM                                       ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""
    if console:
        console.print(banner, style="bold cyan")
    else:
        print(banner)


def print_info(message: str):
    """Print info message"""
    if console:
        console.print(f"[blue][*][/blue] {message}")
    else:
        print(f"[*] {message}")


def print_success(message: str):
    """Print success message"""
    if console:
        console.print(f"[green][+][/green] {message}")
    else:
        print(f"[+] {message}")


def print_warning(message: str):
    """Print warning message"""
    if console:
        console.print(f"[yellow][!][/yellow] {message}")
    else:
        print(f"[!] {message}")


def print_error(message: str):
    """Print error message"""
    if console:
        console.print(f"[red][-][/red] {message}")
    else:
        print(f"[-] {message}")


def print_finding(finding: dict):
    """Print a vulnerability finding"""
    severity_colors = {
        "critical": "red",
        "high": "orange3",
        "medium": "yellow",
        "low": "blue",
        "info": "gray"
    }
    
    severity = finding.get("severity", "medium").lower()
    color = severity_colors.get(severity, "white")
    
    if console:
        console.print(f"\n[bold {color}]{'='*60}[/bold {color}]")
        console.print(f"[bold {color}]VULNERABILITY FOUND: {finding.get('type', 'Unknown').upper()}[/bold {color}]")
        console.print(f"[bold {color}]{'='*60}[/bold {color}]")
        console.print(f"[bold]Severity:[/bold] [{color}]{severity.upper()}[/{color}]")
        console.print(f"[bold]URL:[/bold] {finding.get('url', 'N/A')}")
        console.print(f"[bold]Parameter:[/bold] {finding.get('param', 'N/A')}")
        console.print(f"[bold]Payload:[/bold] {finding.get('payload', 'N/A')}")
    else:
        print(f"\n{'='*60}")
        print(f"VULNERABILITY FOUND: {finding.get('type', 'Unknown').upper()}")
        print(f"{'='*60}")
        print(f"Severity: {severity.upper()}")
        print(f"URL: {finding.get('url', 'N/A')}")
        print(f"Parameter: {finding.get('param', 'N/A')}")
        print(f"Payload: {finding.get('payload', 'N/A')}")


def select_model() -> str:
    """Let user select Ollama model"""
    models = [
        ("llama3.1:8b", "Fast and efficient, good for quick scans"),
        ("llama3.1:70b", "More capable, better analysis"),
        ("llama3.2:1b", "Ultra-fast, basic scanning"),
        ("llama3.2:3b", "Fast, lightweight scanning"),
        ("codellama:7b", "Code-focused, good for source analysis"),
        ("mixtral:8x7b", "Very capable, thorough analysis"),
        ("phi3:medium", "Microsoft Phi-3, fast and smart"),
        ("gemma2:9b", "Google Gemma 2, balanced"),
        ("qwen2.5:7b", "Alibaba Qwen, multilingual"),
        ("deepseek-coder:6.7b", "DeepSeek, code-focused"),
    ]
    
    if console:
        table = Table(title="Available Models")
        table.add_column("Option", style="cyan")
        table.add_column("Model", style="green")
        table.add_column("Description")
        
        for i, (model, desc) in enumerate(models, 1):
            table.add_row(str(i), model, desc)
        
        console.print(table)
        
        choice = Prompt.ask(
            "Select model",
            choices=[str(i) for i in range(1, len(models) + 1)] + ["custom"],
            default="1"
        )
        
        if choice == "custom":
            return Prompt.ask("Enter custom model name")
        return models[int(choice) - 1][0]
    else:
        print("\nAvailable Models:")
        for i, (model, desc) in enumerate(models, 1):
            print(f"  {i}. {model} - {desc}")
        
        choice = input("\nSelect model (1-10, or custom): ").strip()
        if choice.lower() == "custom":
            return input("Enter custom model name: ").strip()
        try:
            return models[int(choice) - 1][0]
        except:
            return "llama3.1:8b"


def interactive_mode(model: str, target: Optional[str] = None):
    """Run interactive hunting session"""
    print_banner()
    print_info(f"Using model: {model}")
    
    # Get target if not provided
    if not target:
        if console:
            target = Prompt.ask("\n[bold]Enter target URL[/bold]")
        else:
            target = input("\nEnter target URL: ").strip()
    
    if not target:
        print_error("No target provided. Exiting.")
        return
    
    # Validate URL
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    print_success(f"Target: {target}")
    print_info("Initializing VulnHunter AI...")
    
    try:
        hunter = VulnHunterLLM(model=model)
    except Exception as e:
        print_error(f"Failed to initialize: {e}")
        print_warning("Make sure Ollama is running: ollama serve")
        return
    
    print_info("Starting vulnerability hunt...")
    print_info("Type 'quit' to exit, 'report' for findings, 'help' for commands")
    print()
    
    # Start the hunt
    response = hunter.start(target)
    
    if console:
        console.print(Panel(Markdown(response), title="VulnHunter AI", border_style="cyan"))
    else:
        print(f"\n--- VulnHunter AI ---\n{response}\n---")
    
    # Interactive loop
    while True:
        try:
            if console:
                user_input = Prompt.ask("\n[bold cyan]You[/bold cyan]")
            else:
                user_input = input("\nYou: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n")
            break
        
        if not user_input:
            continue
        
        if user_input.lower() == 'quit':
            print_info("Generating final report...")
            print(hunter.get_report())
            break
        
        elif user_input.lower() == 'report':
            report = hunter.get_report()
            if console:
                console.print(Panel(Markdown(report), title="Findings Report", border_style="green"))
            else:
                print(report)
        
        elif user_input.lower() == 'help':
            help_text = """
## Commands
- `quit` - Exit and show final report
- `report` - Show current findings
- `tools` - List available tools
- `clear` - Clear conversation history
- `save` - Save findings to file

## Tips
- Ask the AI to focus on specific vulnerability types
- Request deeper testing of interesting parameters
- Ask for HackerOne-style reports of findings
- Request payload mutations for bypass attempts
"""
            if console:
                console.print(Panel(Markdown(help_text), title="Help", border_style="blue"))
            else:
                print(help_text)
        
        elif user_input.lower() == 'tools':
            tools_desc = hunter._get_tools_description()
            if console:
                console.print(Panel(Markdown(tools_desc), title="Available Tools", border_style="yellow"))
            else:
                print(tools_desc)
        
        elif user_input.lower() == 'save':
            filename = f"vulnhunter_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            report = hunter.get_report()
            with open(filename, 'w') as f:
                f.write(report)
            print_success(f"Report saved to {filename}")
        
        elif user_input.lower() == 'clear':
            hunter.conversation = []
            print_success("Conversation cleared")
        
        else:
            response = hunter.continue_hunt(user_input)
            
            if console:
                console.print(Panel(Markdown(response), title="VulnHunter AI", border_style="cyan"))
            else:
                print(f"\n--- VulnHunter AI ---\n{response}\n---")
    
    print_success("Hunt complete!")


def auto_scan_mode(target: str, output: Optional[str] = None):
    """Run automatic scan without LLM"""
    print_banner()
    print_info(f"Starting automatic scan of {target}")
    
    results = manual_scan(target)
    
    # Print findings
    for finding in results.get("findings", []):
        print_finding(finding)
    
    # Summary
    findings_count = len(results.get("findings", []))
    print_info(f"\nScan complete. Found {findings_count} potential vulnerabilities.")
    
    # Save results
    if output:
        with open(output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print_success(f"Results saved to {output}")
    
    return results


def single_scan(url: str, param: str, vuln_type: str):
    """Run a single vulnerability scan"""
    print_banner()
    print_info(f"Scanning {param} parameter for {vuln_type}")
    
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
        print_error(f"Unknown vulnerability type: {vuln_type}")
        return
    
    print(json.dumps(results, indent=2))
    
    if results.get("summary", {}).get("vulnerable_count", 0) > 0:
        print_success(f"Found vulnerabilities! Check results above.")
    else:
        print_info("No vulnerabilities found with current payloads.")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="VulnHunter - AI-Powered Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive AI-powered hunting
  python main.py -i -t https://example.com
  
  # Quick automatic scan
  python main.py --auto -t https://example.com
  
  # Scan specific parameter
  python main.py -t "https://example.com/search?q=test" -p q --type xss
  
  # Use specific model
  python main.py -i -t https://example.com -m llama3.1:70b
"""
    )
    
    parser.add_argument('-t', '--target', help='Target URL')
    parser.add_argument('-m', '--model', default='llama3.1:8b', help='Ollama model to use')
    parser.add_argument('-i', '--interactive', action='store_true', help='Interactive AI mode')
    parser.add_argument('--auto', action='store_true', help='Automatic scan without AI')
    parser.add_argument('-p', '--param', help='Parameter to test')
    parser.add_argument('--type', choices=['xss', 'sqli', 'ssrf', 'lfi', 'quick'], help='Vulnerability type')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('--select-model', action='store_true', help='Interactively select model')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    
    args = parser.parse_args()
    
    # Model selection
    model = args.model
    if args.select_model:
        model = select_model()
    
    # Determine mode
    if args.param and args.type:
        # Single scan mode
        if not args.target:
            print_error("Target URL required for single scan mode")
            sys.exit(1)
        single_scan(args.target, args.param, args.type)
    
    elif args.auto:
        # Automatic scan mode
        if not args.target:
            print_error("Target URL required for automatic scan mode")
            sys.exit(1)
        auto_scan_mode(args.target, args.output)
    
    elif args.interactive or args.target:
        # Interactive mode (default)
        interactive_mode(model, args.target)
    
    else:
        # No arguments - show help and enter interactive mode
        print_banner()
        print_info("Starting in interactive mode...")
        model = select_model()
        interactive_mode(model)


if __name__ == "__main__":
    main()
