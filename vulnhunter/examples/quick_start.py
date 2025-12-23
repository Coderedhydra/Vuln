#!/usr/bin/env python3
"""
VulnHunter Quick Start Example
Demonstrates basic usage of the framework
"""

import sys
sys.path.insert(0, '..')

from vulnhunter import VulnHunterLLM, WebTools, PayloadTemplates


def example_ai_hunting():
    """Example: AI-powered vulnerability hunting"""
    print("=" * 60)
    print("Example 1: AI-Powered Hunting")
    print("=" * 60)
    
    # Initialize the AI hunter
    hunter = VulnHunterLLM(model="llama3.1:8b")
    
    # Start hunting on a target
    target = "https://example.com"
    print(f"\nStarting hunt on {target}...")
    
    # The AI will automatically crawl, analyze, and test
    result = hunter.start(target)
    print(result)
    
    # Continue with specific instructions
    result = hunter.continue_hunt("Focus on finding XSS in the search functionality")
    print(result)
    
    # Get the report
    report = hunter.get_report()
    print("\n=== Final Report ===")
    print(report)


def example_direct_tools():
    """Example: Using tools directly without AI"""
    print("=" * 60)
    print("Example 2: Direct Tool Usage")
    print("=" * 60)
    
    tools = WebTools()
    
    # Fetch a page
    print("\n1. Fetching page...")
    response = tools.fetch("https://example.com")
    print(f"Status: {response['status']}")
    print(f"Body length: {response['body_length']} bytes")
    
    # Crawl the site
    print("\n2. Crawling site...")
    crawl_result = tools.crawl("https://example.com", depth=1)
    print(f"Pages crawled: {crawl_result['pages_crawled']}")
    print(f"URLs discovered: {len(crawl_result['urls_discovered'])}")
    print(f"Forms found: {len(crawl_result['forms'])}")
    
    # Analyze a page
    print("\n3. Analyzing page...")
    analysis = tools.analyze("https://example.com")
    print(f"Technologies: {analysis['technologies']}")
    print(f"Security issues: {analysis['summary']['security_issues']}")


def example_vulnerability_scanning():
    """Example: Scanning for specific vulnerabilities"""
    print("=" * 60)
    print("Example 3: Vulnerability Scanning")
    print("=" * 60)
    
    tools = WebTools()
    
    # Quick scan a parameter
    print("\n1. Quick scan...")
    quick_result = tools.quick_scan(
        url="https://example.com/search?q=test",
        param="q"
    )
    print(f"XSS vulnerable: {quick_result['xss'].get('vulnerable', False)}")
    print(f"SQLi vulnerable: {quick_result['sqli'].get('vulnerable', False)}")
    
    # Detailed XSS scan
    print("\n2. Detailed XSS scan...")
    xss_result = tools.scan_xss(
        url="https://example.com/search?q=test",
        param="q",
        category="filter_bypass"
    )
    print(f"Vulnerable payloads: {xss_result['summary']['vulnerable_count']}")
    
    # SQLi scan
    print("\n3. SQL Injection scan...")
    sqli_result = tools.scan_sqli(
        url="https://example.com/user?id=1",
        param="id",
        test_types=["error", "boolean"]
    )
    print(f"Databases detected: {sqli_result['summary']['databases_detected']}")


def example_payload_generation():
    """Example: Generating sophisticated payloads"""
    print("=" * 60)
    print("Example 4: Payload Generation")
    print("=" * 60)
    
    tools = WebTools()
    
    # Generate XSS payload
    print("\n1. XSS Payload with WAF bypass...")
    xss_payload = tools.generate_payload(
        vuln_type="xss",
        context="html",
        bypass="waf"
    )
    print(f"Payload: {xss_payload['payload']}")
    print(f"Variants: {list(xss_payload['encoded_variants'].keys())}")
    
    # Generate SQLi payload
    print("\n2. SQLi Union payload...")
    sqli_payload = tools.generate_payload(
        vuln_type="sqli",
        technique="union",
        db="mysql",
        columns=3
    )
    print(f"Payload: {sqli_payload['payload']}")
    
    # Generate SSRF payload
    print("\n3. SSRF payload for AWS...")
    ssrf_payload = tools.generate_payload(
        vuln_type="ssrf",
        target="aws",
        bypass="encoding"
    )
    print(f"Payload: {ssrf_payload['payload']}")
    
    # Mutate a payload
    print("\n4. Payload mutations...")
    mutations = tools.mutate_payload("<script>alert(1)</script>", count=5)
    for i, m in enumerate(mutations):
        print(f"  {i+1}. {m}")


def example_authentication():
    """Example: Testing authentication"""
    print("=" * 60)
    print("Example 5: Authentication Testing")
    print("=" * 60)
    
    tools = WebTools()
    
    # Login to application
    print("\n1. Testing login...")
    login_result = tools.login(
        login_url="https://example.com/login",
        username="testuser",
        password="testpass123",
        username_field="email",
        password_field="password"
    )
    print(f"Login successful: {login_result.get('success', False)}")
    
    # Set custom headers
    print("\n2. Setting auth headers...")
    tools.set_header("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9...")
    tools.set_cookie("session", "abc123def456")
    
    # Check session
    session_info = tools.get_session_info()
    print(f"Session info: {session_info}")


def example_pre_built_payloads():
    """Example: Using pre-built payload templates"""
    print("=" * 60)
    print("Example 6: Pre-built Payload Templates")
    print("=" * 60)
    
    # Get all XSS payloads
    print("\n1. XSS Payloads (sample)...")
    xss_payloads = PayloadTemplates.xss_all()
    for p in xss_payloads[:5]:
        print(f"  - {p}")
    print(f"  ... and {len(xss_payloads) - 5} more")
    
    # Get SQLi payloads
    print("\n2. SQLi Payloads (sample)...")
    sqli_payloads = PayloadTemplates.sqli_all()
    for p in sqli_payloads[:5]:
        print(f"  - {p}")
    
    # Get cloud metadata payloads
    print("\n3. Cloud Metadata SSRF Payloads...")
    for cloud, payloads in PayloadTemplates.SSRF_CLOUD_META.items():
        print(f"  {cloud.upper()}: {payloads[0]}")
    
    # Quick test payloads
    print("\n4. Quick Test Payloads...")
    quick = PayloadTemplates.get_quick_test()
    for vuln_type, payload in quick.items():
        print(f"  {vuln_type}: {payload}")


def main():
    """Run all examples"""
    print("\n" + "=" * 60)
    print("VulnHunter Examples")
    print("=" * 60)
    
    examples = [
        ("Direct Tools", example_direct_tools),
        ("Vulnerability Scanning", example_vulnerability_scanning),
        ("Payload Generation", example_payload_generation),
        ("Pre-built Payloads", example_pre_built_payloads),
    ]
    
    for name, func in examples:
        try:
            func()
        except Exception as e:
            print(f"\nError in {name}: {e}")
            print("(This is expected if running without a real target)")
        print()
    
    print("=" * 60)
    print("Examples complete!")
    print("=" * 60)
    print("\nTo run AI-powered hunting:")
    print("  python ../main.py -i -t https://your-target.com")
    print("\nOr in Python:")
    print("  from vulnhunter import VulnHunterLLM")
    print("  hunter = VulnHunterLLM()")
    print("  hunter.start('https://your-target.com')")


if __name__ == "__main__":
    main()
