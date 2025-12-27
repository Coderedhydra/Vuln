#!/usr/bin/env python3
"""
VulnHunter - Autonomous AI Bug Bounty Hunter

This is NOT a static scanner. This is an autonomous AI security researcher that:
- Thinks and reasons like a human bug bounty hunter
- Adapts its approach based on what it discovers
- Creates custom payloads based on code analysis
- Confirms vulnerabilities through real exploitation
- Never simulates or fakes results
"""

import sys
import argparse
import json
from datetime import datetime
from typing import Optional

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.markdown import Markdown
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from llm_interface import VulnHunterLLM, quick_scan


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
║   Not a scanner - An intelligent security researcher          ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""
    if console:
        console.print(banner, style="bold cyan")
    else:
        print(banner)


def print_msg(msg: str, style: str = ""):
    if console:
        console.print(msg, style=style)
    else:
        print(msg)


def print_info(msg: str):
    print_msg(f"[*] {msg}", "blue")


def print_success(msg: str):
    print_msg(f"[+] {msg}", "green")


def print_warning(msg: str):
    print_msg(f"[!] {msg}", "yellow")


def print_error(msg: str):
    print_msg(f"[-] {msg}", "red")


def autonomous_hunt(target: str, model: str = "llama3.1:8b"):
    """
    Start an autonomous AI-driven bug hunt
    
    The AI will:
    1. Explore the target like a human researcher
    2. Analyze code and understand the application
    3. Identify attack surfaces
    4. Create intelligent, context-aware payloads
    5. Adapt based on responses
    6. Confirm vulnerabilities through exploitation
    7. Report only real, confirmed findings
    """
    print_banner()
    print_info(f"Target: {target}")
    print_info(f"AI Model: {model}")
    print_info("Initializing autonomous hunter...")
    print()
    
    try:
        hunter = VulnHunterLLM(model=model)
    except Exception as e:
        print_error(f"Failed to initialize: {e}")
        print_warning("Make sure Ollama is running: ollama serve")
        print_warning(f"And the model is available: ollama pull {model}")
        return
    
    print_success("AI Hunter initialized")
    print_info("Starting autonomous security research...")
    print_info("The AI will explore, analyze, and hunt for vulnerabilities")
    print_info("This is real testing - every request is made to the actual target")
    print()
    print_info("=" * 60)
    print()
    
    # Start the hunt
    response = hunter.start(target)
    
    if console:
        console.print(Panel(Markdown(response), title="🔍 AI Hunter", border_style="cyan"))
    else:
        print(f"\n=== AI Hunter ===\n{response}\n================\n")
    
    # Interactive loop
    print()
    print_info("Commands: 'continue', 'report', 'findings', 'quit'")
    print_info("Or give specific instructions to the AI")
    print()
    
    while True:
        try:
            user_input = input("\n[You] > ").strip()
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
            print(hunter.get_report())
        
        elif user_input.lower() == 'findings':
            findings = hunter.get_findings()
            if findings:
                print_success(f"Confirmed vulnerabilities: {len(findings)}")
                for f in findings:
                    print(f"  - {f['type']}: {f['url']} ({f['severity']})")
            else:
                print_info("No confirmed vulnerabilities yet")
        
        elif user_input.lower() == 'continue':
            response = hunter.continue_hunt()
            if console:
                console.print(Panel(Markdown(response), title="🔍 AI Hunter", border_style="cyan"))
            else:
                print(f"\n=== AI Hunter ===\n{response}\n================\n")
        
        else:
            # Custom instruction to the AI
            response = hunter.continue_hunt(user_input)
            if console:
                console.print(Panel(Markdown(response), title="🔍 AI Hunter", border_style="cyan"))
            else:
                print(f"\n=== AI Hunter ===\n{response}\n================\n")
    
    print_success("Hunt complete!")
    
    findings = hunter.get_findings()
    if findings:
        print_success(f"Total confirmed vulnerabilities: {len(findings)}")
    else:
        print_info("No confirmed vulnerabilities found")


def quick_mode(target: str, output: Optional[str] = None):
    """Quick scan mode - still uses real requests"""
    print_banner()
    print_info(f"Quick scan: {target}")
    print_warning("Note: For thorough hunting, use autonomous mode (-i)")
    print()
    
    result = quick_scan(target)
    
    print_info(f"Requests made: {result.get('requests_made', 0)}")
    
    vulns = result.get("vulnerabilities", [])
    if vulns:
        print_success(f"Found {len(vulns)} confirmed vulnerabilities:")
        for v in vulns:
            print(f"  [{v['type']}] {v['param']} - {v.get('payload', '')[:50]}")
    else:
        print_info("No confirmed vulnerabilities in quick scan")
        print_info("Try autonomous mode for deeper analysis: -i")
    
    if output:
        with open(output, 'w') as f:
            json.dump(result, f, indent=2)
        print_success(f"Results saved to {output}")
    
    return result


def main():
    parser = argparse.ArgumentParser(
        description="VulnHunter - Autonomous AI Bug Bounty Hunter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This is NOT a static scanner. This is an autonomous AI security researcher.

The AI will:
  - Think and reason like a human bug bounty hunter
  - Explore and understand the target application
  - Create custom payloads based on code analysis
  - Adapt its approach based on responses
  - Confirm vulnerabilities through real exploitation
  - Never simulate or fake results

Examples:
  # Start autonomous AI hunting (recommended)
  python main.py -i -t https://target.com
  
  # Use a specific AI model
  python main.py -i -t https://target.com -m llama3.1:70b
  
  # Quick scan (less thorough)
  python main.py -t https://target.com
"""
    )
    
    parser.add_argument('-t', '--target', required=False, help='Target URL')
    parser.add_argument('-m', '--model', default='llama3.1:8b', help='Ollama model (default: llama3.1:8b)')
    parser.add_argument('-i', '--interactive', action='store_true', help='Autonomous AI mode (recommended)')
    parser.add_argument('-o', '--output', help='Save results to file')
    
    args = parser.parse_args()
    
    if not args.target:
        print_banner()
        print_info("Autonomous AI Bug Bounty Hunter")
        print()
        print_info("Usage: python main.py -i -t <target_url>")
        print()
        print_info("The AI will autonomously:")
        print_info("  1. Explore and understand the target")
        print_info("  2. Identify attack surfaces")
        print_info("  3. Create intelligent payloads")
        print_info("  4. Confirm vulnerabilities through exploitation")
        print_info("  5. Report only real, confirmed findings")
        print()
        
        target = input("Enter target URL: ").strip()
        if target:
            if not target.startswith(('http://', 'https://')):
                target = 'https://' + target
            autonomous_hunt(target, args.model)
        return
    
    target = args.target
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    if args.interactive:
        autonomous_hunt(target, args.model)
    else:
        # Quick mode with warning
        quick_mode(target, args.output)


if __name__ == "__main__":
    main()
