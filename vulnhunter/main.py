#!/usr/bin/env python3
"""
VulnHunter - LLM-Powered Web Vulnerability Framework
Main entry point and CLI interface

Usage:
    python -m vulnhunter https://target.com
    python -m vulnhunter https://target.com --model llama3.1:8b --interactive
"""

import sys
import argparse
from typing import Optional
from loguru import logger

# Configure logging
logger.remove()
logger.add(sys.stderr, level="INFO", format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | {message}")


def print_banner():
    """Print VulnHunter banner"""
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
║           LLM-Powered Web Vulnerability Hunter                ║
║                       v1.0.0                                  ║
╚═══════════════════════════════════════════════════════════════╝
"""
    print(banner)


def list_ollama_models(host: str = "http://localhost:11434") -> list:
    """List available Ollama models"""
    try:
        import ollama
        client = ollama.Client(host=host)
        models = client.list()
        return [m['name'] for m in models.get('models', [])]
    except Exception as e:
        logger.error(f"Could not list models: {e}")
        return []


def select_model(host: str = "http://localhost:11434") -> Optional[str]:
    """Interactive model selection"""
    models = list_ollama_models(host)
    
    if not models:
        print("\n⚠️  No Ollama models found. Please pull a model first:")
        print("   ollama pull llama3.1:8b")
        return None
    
    print("\n📦 Available Models:")
    for i, model in enumerate(models, 1):
        print(f"   {i}. {model}")
    
    print()
    while True:
        try:
            choice = input("Select model number (or press Enter for first): ").strip()
            if not choice:
                return models[0]
            idx = int(choice) - 1
            if 0 <= idx < len(models):
                return models[idx]
            print("Invalid choice. Try again.")
        except ValueError:
            print("Please enter a number.")
        except KeyboardInterrupt:
            return None


def run_autonomous_scan(target_url: str, model: str, ollama_host: str,
                       max_pages: int, max_iterations: int):
    """Run autonomous vulnerability scan"""
    from .agents import VulnHunterAgent
    from .reports import ReportGenerator
    
    print(f"\n🎯 Target: {target_url}")
    print(f"🤖 Model: {model}")
    print(f"📄 Max Pages: {max_pages}")
    print(f"🔄 Max Iterations: {max_iterations}")
    print("\n" + "="*60)
    
    # Initialize agent
    agent = VulnHunterAgent(
        target_url=target_url,
        model=model,
        ollama_host=ollama_host
    )
    agent.config.scan.max_pages = max_pages
    
    # Run scan
    print("\n🚀 Starting autonomous vulnerability hunt...\n")
    findings = agent.run(max_iterations=max_iterations)
    
    # Generate reports
    if findings:
        print(f"\n✅ Found {len(findings)} potential vulnerabilities!")
        
        report_gen = ReportGenerator()
        reports = report_gen.generate_all_reports(findings)
        
        print(f"\n📝 Reports generated:")
        print(f"   - Markdown: {reports['markdown']}")
        print(f"   - JSON: {reports['json']}")
        
        # Print summary
        print("\n" + agent.get_findings_summary())
    else:
        print("\n✨ No vulnerabilities found in this scan.")
    
    return findings


def run_interactive_mode(target_url: str, model: str, ollama_host: str):
    """Run interactive hunting mode"""
    from .agents import VulnHunterAgent
    
    print(f"\n🎯 Target: {target_url}")
    print(f"🤖 Model: {model}")
    
    agent = VulnHunterAgent(
        target_url=target_url,
        model=model,
        ollama_host=ollama_host
    )
    
    return agent.interactive_hunt()


def run_quick_scan(target_url: str):
    """Run a quick scan without LLM (just automated scanners)"""
    from .tools import LLMToolkit
    from .scanners import SQLiScanner, XSSScanner, AuthScanner
    from .reports import ReportGenerator
    
    print(f"\n🎯 Target: {target_url}")
    print("🔍 Running quick automated scan (no LLM)...\n")
    
    toolkit = LLMToolkit(target_url)
    findings = []
    
    # Crawl
    print("📡 Crawling website...")
    crawl_result = toolkit.crawl(max_pages=50)
    
    if crawl_result.success:
        print(f"   Found {crawl_result.data.get('urls_found', 0)} URLs, "
              f"{crawl_result.data.get('forms_found', 0)} forms")
        
        # Get forms
        forms_result = toolkit.get_forms()
        forms = forms_result.data if forms_result.success else []
        
        # Analyze main page
        print("\n🔬 Analyzing source code...")
        analysis = toolkit.analyze_page()
        if analysis.success:
            findings.extend(analysis.data.get('findings', []))
        
        # Test forms
        print(f"\n🧪 Testing {len(forms)} forms for vulnerabilities...")
        
        sqli_scanner = SQLiScanner(toolkit.http)
        xss_scanner = XSSScanner(toolkit.http)
        
        for form in forms[:10]:
            action = form.get('action', '')
            method = form.get('method', 'POST')
            inputs = form.get('inputs', [])
            
            # SQLi test
            result = sqli_scanner.scan_form(action, method, inputs)
            for v in result.vulnerabilities:
                findings.append(v.to_dict())
            
            # XSS test
            result = xss_scanner.scan_form(action, method, inputs)
            for v in result.vulnerabilities:
                findings.append(v.to_dict())
    
    # Generate report
    if findings:
        print(f"\n✅ Found {len(findings)} potential vulnerabilities!")
        report_gen = ReportGenerator()
        reports = report_gen.generate_all_reports(findings, "quick_scan")
        print(f"\n📝 Report: {reports['markdown']}")
    else:
        print("\n✨ No vulnerabilities found.")
    
    return findings


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="VulnHunter - LLM-Powered Web Vulnerability Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  vulnhunter https://example.com                    # Autonomous scan
  vulnhunter https://example.com --interactive      # Interactive mode
  vulnhunter https://example.com --quick            # Quick scan (no LLM)
  vulnhunter https://example.com --model mistral    # Use specific model
        """
    )
    
    parser.add_argument("target", nargs="?", help="Target URL to scan")
    parser.add_argument("--model", "-m", help="Ollama model to use (e.g., llama3.1:8b)")
    parser.add_argument("--ollama-host", default="http://localhost:11434", 
                       help="Ollama server host")
    parser.add_argument("--interactive", "-i", action="store_true",
                       help="Run in interactive mode")
    parser.add_argument("--quick", "-q", action="store_true",
                       help="Quick scan without LLM (automated scanners only)")
    parser.add_argument("--max-pages", type=int, default=100,
                       help="Maximum pages to crawl (default: 100)")
    parser.add_argument("--max-iterations", type=int, default=50,
                       help="Maximum test iterations (default: 50)")
    parser.add_argument("--list-models", action="store_true",
                       help="List available Ollama models")
    parser.add_argument("--version", "-v", action="store_true",
                       help="Show version")
    
    args = parser.parse_args()
    
    print_banner()
    
    if args.version:
        print("VulnHunter v1.0.0")
        return
    
    if args.list_models:
        models = list_ollama_models(args.ollama_host)
        if models:
            print("\nAvailable Ollama models:")
            for m in models:
                print(f"  - {m}")
        else:
            print("\nNo models found. Pull a model with: ollama pull llama3.1:8b")
        return
    
    if not args.target:
        # Interactive mode - ask for URL
        print("\n🌐 Enter target URL:")
        args.target = input("   URL: ").strip()
        
        if not args.target:
            print("Error: No target URL provided")
            sys.exit(1)
    
    # Validate URL
    if not args.target.startswith('http://') and not args.target.startswith('https://'):
        args.target = 'https://' + args.target
    
    # Quick scan mode
    if args.quick:
        run_quick_scan(args.target)
        return
    
    # Select model if not specified
    if not args.model:
        args.model = select_model(args.ollama_host)
        if not args.model:
            print("\nError: No model selected")
            sys.exit(1)
    
    try:
        if args.interactive:
            run_interactive_mode(args.target, args.model, args.ollama_host)
        else:
            run_autonomous_scan(
                args.target, 
                args.model, 
                args.ollama_host,
                args.max_pages,
                args.max_iterations
            )
    except KeyboardInterrupt:
        print("\n\n👋 Scan interrupted by user")
    except Exception as e:
        logger.error(f"Error during scan: {e}")
        raise


if __name__ == "__main__":
    main()
