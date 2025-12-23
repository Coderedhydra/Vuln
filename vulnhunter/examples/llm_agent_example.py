#!/usr/bin/env python3
"""
VulnHunter LLM Agent Example
Demonstrates how to use the LLM-powered vulnerability hunting agent
"""

import sys
sys.path.insert(0, '..')

from vulnhunter import VulnHunterAgent, OllamaAgent


def example_autonomous_scan():
    """
    Example: Run an autonomous vulnerability scan
    The LLM agent will crawl, analyze, and test the target automatically
    """
    print("=" * 60)
    print("Example: Autonomous LLM-Powered Scan")
    print("=" * 60)
    
    # Initialize the agent
    # Requires Ollama running with a model like llama3.1:8b
    agent = VulnHunterAgent(
        target_url="https://example.com",
        model="llama3.1:8b",
        ollama_host="http://localhost:11434"
    )
    
    # Configure the scan
    agent.config.scan.max_pages = 50
    agent.config.scan.max_depth = 3
    
    # Run the scan (will take some time)
    print("\nStarting autonomous scan...")
    findings = agent.run(max_iterations=30)
    
    # Print results
    print(f"\nScan complete! Found {len(findings)} vulnerabilities.")
    print(agent.get_findings_summary())
    
    return findings


def example_interactive_mode():
    """
    Example: Interactive hunting mode
    User guides the LLM agent with prompts
    """
    print("=" * 60)
    print("Example: Interactive Mode")
    print("=" * 60)
    
    agent = VulnHunterAgent(
        target_url="https://example.com",
        model="llama3.1:8b"
    )
    
    # Start interactive hunting
    # User can give commands like:
    # - "Crawl the website and find all forms"
    # - "Test the login form for SQL injection"
    # - "Analyze the JavaScript files for API endpoints"
    # - "Search for SSRF vulnerabilities in URL parameters"
    
    print("\nStarting interactive mode...")
    print("You can guide the agent with natural language commands.\n")
    
    # This would start the interactive session
    # findings = agent.interactive_hunt()
    
    print("Interactive mode example (would start REPL)")
    

def example_direct_llm_usage():
    """
    Example: Using the Ollama agent directly for analysis
    """
    print("=" * 60)
    print("Example: Direct LLM Analysis")
    print("=" * 60)
    
    # Initialize just the LLM agent
    llm = OllamaAgent(model="llama3.1:8b")
    llm.set_system_prompt("""You are a security researcher analyzing web applications 
    for vulnerabilities. Provide detailed, technical analysis.""")
    
    # Analyze some content
    sample_code = """
    <script>
        var userInput = location.search.split('q=')[1];
        document.getElementById('result').innerHTML = userInput;
    </script>
    """
    
    print("\nAnalyzing code for vulnerabilities...")
    
    # This would call the LLM
    # response = llm.chat(
    #     "Analyze this code for security vulnerabilities:",
    #     context=sample_code
    # )
    # print(response)
    
    print("LLM analysis example (requires running Ollama)")
    

def example_custom_workflow():
    """
    Example: Custom vulnerability hunting workflow
    """
    print("=" * 60)
    print("Example: Custom Workflow")
    print("=" * 60)
    
    from vulnhunter import LLMToolkit, PayloadGenerator, ReportGenerator
    
    # Initialize components
    toolkit = LLMToolkit("https://example.com")
    generator = PayloadGenerator()
    reporter = ReportGenerator("./reports")
    
    # Custom workflow:
    # 1. Reconnaissance
    print("\n[1] Reconnaissance phase...")
    # toolkit.crawl(max_pages=100)
    
    # 2. Identify interesting endpoints
    print("[2] Finding interesting endpoints...")
    # urls = toolkit.get_urls(pattern="/api/")
    # forms = toolkit.get_forms()
    
    # 3. Test for specific vulnerabilities
    print("[3] Testing for SQLi in login form...")
    # sqli_payloads = generator.sqli_payloads(context="login")
    # for payload in sqli_payloads:
    #     result = toolkit.send_payload("/login", "POST", payload, "username")
    #     if "error" in result.data.get('body_preview', '').lower():
    #         toolkit.report_finding(
    #             title="SQL Injection in Login",
    #             description="...",
    #             severity="high",
    #             url="/login",
    #             evidence="SQL error in response",
    #             category="sqli"
    #         )
    #         break
    
    # 4. Check for SSRF in URL parameters
    print("[4] Testing for SSRF...")
    # ssrf_payloads = generator.ssrf_payloads(target_type="cloud")
    # result = toolkit.send_payload("/fetch", "GET", ssrf_payloads[0], "url")
    
    # 5. Generate report
    print("[5] Generating reports...")
    # findings = toolkit.get_findings()
    # reporter.generate_all_reports(findings.data, "custom_assessment")
    
    print("\nCustom workflow example complete!")


def main():
    """Main entry point"""
    print("\n" + "=" * 60)
    print("VulnHunter LLM Agent Examples")
    print("=" * 60)
    print("\nThese examples show LLM-powered vulnerability hunting.")
    print("Note: Requires Ollama running with a compatible model.\n")
    print("To run Ollama:")
    print("  1. Install: curl -fsSL https://ollama.com/install.sh | sh")
    print("  2. Start: ollama serve")
    print("  3. Pull model: ollama pull llama3.1:8b")
    print()
    
    # Show examples (actual execution requires Ollama)
    example_direct_llm_usage()
    example_custom_workflow()
    
    print("\n" + "=" * 60)
    print("To run actual scans:")
    print("  python -m vulnhunter https://target.com")
    print("  python -m vulnhunter https://target.com --interactive")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
