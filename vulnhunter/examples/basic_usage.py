#!/usr/bin/env python3
"""
VulnHunter Basic Usage Examples
Demonstrates how to use the framework for vulnerability hunting
"""

import sys
sys.path.insert(0, '..')

from vulnhunter import (
    LLMToolkit,
    PayloadGenerator,
    WebSearcher,
    SQLiScanner,
    XSSScanner,
    ReportGenerator
)


def example_basic_scanning():
    """
    Example: Basic vulnerability scanning workflow
    """
    print("=" * 60)
    print("Example 1: Basic Vulnerability Scanning")
    print("=" * 60)
    
    # Initialize toolkit
    toolkit = LLMToolkit("https://example.com")
    
    # Step 1: Crawl the website
    print("\n[1] Crawling website...")
    result = toolkit.crawl(max_pages=50)
    print(f"    Found {result.data.get('urls_found', 0)} URLs")
    print(f"    Found {result.data.get('forms_found', 0)} forms")
    
    # Step 2: Get forms for testing
    print("\n[2] Analyzing forms...")
    forms = toolkit.get_forms()
    if forms.success:
        for form in forms.data[:3]:
            print(f"    Form: {form.get('action')} ({form.get('method')})")
    
    # Step 3: Analyze page source
    print("\n[3] Analyzing source code...")
    analysis = toolkit.analyze_page()
    if analysis.success:
        findings = analysis.data.get('findings', [])
        print(f"    Found {len(findings)} potential issues")
    
    # Step 4: Report findings
    print("\n[4] Getting findings summary...")
    findings = toolkit.get_findings()
    print(f"    Total findings: {len(findings.data)}")
    
    return toolkit


def example_payload_testing():
    """
    Example: Testing with payloads
    """
    print("\n" + "=" * 60)
    print("Example 2: Payload Testing")
    print("=" * 60)
    
    # Initialize
    toolkit = LLMToolkit("https://example.com")
    generator = PayloadGenerator()
    
    # Generate SQL injection payloads
    print("\n[1] SQL Injection payloads for login context:")
    sqli_payloads = generator.sqli_payloads(context="login", db_type="mysql")
    for p in sqli_payloads[:5]:
        print(f"    {p}")
    
    # Generate XSS payloads with bypass
    print("\n[2] XSS payloads with filter bypass:")
    xss_payloads = generator.xss_payloads(context="html", bypass_filter=True)
    for p in xss_payloads[:5]:
        print(f"    {p}")
    
    # Generate SSRF payloads
    print("\n[3] SSRF payloads for cloud metadata:")
    ssrf_payloads = generator.ssrf_payloads(target_type="cloud")
    for p in ssrf_payloads[:5]:
        print(f"    {p}")
    
    # Example: Send a payload
    print("\n[4] Sending test payload...")
    # result = toolkit.send_payload("/search", "GET", "' OR 1=1--", "q")
    # print(f"    Response status: {result.data.get('status')}")
    # print(f"    Payload reflected: {result.data.get('payload_reflected')}")
    
    return generator


def example_authentication():
    """
    Example: Authentication testing
    """
    print("\n" + "=" * 60)
    print("Example 3: Authentication Testing")
    print("=" * 60)
    
    toolkit = LLMToolkit("https://example.com")
    
    # Attempt login
    print("\n[1] Login attempt...")
    # result = toolkit.login("/login", {
    #     "username": "testuser",
    #     "password": "testpass123"
    # })
    # print(f"    Login status: {result.data.get('status')}")
    
    # Get CSRF token
    print("\n[2] Getting CSRF token...")
    # csrf = toolkit.get_csrf_token("/login")
    # print(f"    CSRF token found: {csrf.success}")
    
    # Set auth token
    print("\n[3] Setting auth token...")
    result = toolkit.set_auth_token("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
    print(f"    Token set: {result.success}")
    
    return toolkit


def example_web_search():
    """
    Example: Web search for vulnerability research
    """
    print("\n" + "=" * 60)
    print("Example 4: Vulnerability Research")
    print("=" * 60)
    
    searcher = WebSearcher()
    
    # Search for exploits
    print("\n[1] Searching for Apache Struts vulnerabilities...")
    # results = searcher.search_exploit("Apache Struts", "2.5.20")
    # for r in results[:3]:
    #     print(f"    {r.title}")
    
    # Search CVE
    print("\n[2] Getting CVE details...")
    # info = searcher.search_cve("CVE-2021-44228")
    # print(f"    Title: {info.title}")
    # print(f"    Severity: {info.severity}")
    
    # Search HackerOne
    print("\n[3] Searching HackerOne reports...")
    # results = searcher.search_hackerone("SSRF", "AWS")
    # for r in results[:3]:
    #     print(f"    {r.title}")
    
    return searcher


def example_scanner_usage():
    """
    Example: Using vulnerability scanners directly
    """
    print("\n" + "=" * 60)
    print("Example 5: Direct Scanner Usage")
    print("=" * 60)
    
    from vulnhunter.core import HTTPClient
    
    # Create HTTP client
    http = HTTPClient(base_url="https://example.com")
    
    # Initialize scanners
    sqli_scanner = SQLiScanner(http)
    xss_scanner = XSSScanner(http)
    
    print("\n[1] SQL Injection scanner...")
    print("    sqli_scanner.scan_url('/search', 'GET', {'q': 'test'})")
    # results = sqli_scanner.scan_url("/search", "GET", {"q": "test"})
    # print(f"    Vulnerabilities found: {len(results.vulnerabilities)}")
    
    print("\n[2] XSS scanner...")
    print("    xss_scanner.scan_form('/comment', 'POST', inputs)")
    # results = xss_scanner.scan_form("/comment", "POST", [
    #     {"name": "text", "type": "text"},
    #     {"name": "submit", "type": "submit"}
    # ])
    # print(f"    Vulnerabilities found: {len(results.vulnerabilities)}")
    
    print("\n[3] Getting payloads for manual testing...")
    payloads = sqli_scanner.get_payloads("error")
    print(f"    {len(payloads)} error-based SQLi payloads available")
    
    return sqli_scanner


def example_report_generation():
    """
    Example: Generating vulnerability reports
    """
    print("\n" + "=" * 60)
    print("Example 6: Report Generation")
    print("=" * 60)
    
    generator = ReportGenerator("./reports")
    
    # Example findings
    findings = [
        {
            "id": "vuln-001",
            "title": "SQL Injection in Search Parameter",
            "description": "The 'q' parameter is vulnerable to SQL injection",
            "severity": "high",
            "category": "sqli",
            "url": "/search?q=test",
            "parameter": "q",
            "method": "GET",
            "payload": "' OR 1=1--",
            "evidence": "SQL syntax error in response",
        },
        {
            "id": "vuln-002",
            "title": "Reflected XSS in Comment Form",
            "description": "User input is reflected without sanitization",
            "severity": "medium",
            "category": "xss",
            "url": "/comment",
            "parameter": "text",
            "method": "POST",
            "payload": "<script>alert(1)</script>",
            "evidence": "Script tag reflected in response",
        }
    ]
    
    print("\n[1] Creating reports from findings...")
    for finding in findings:
        report = generator.create_report_from_finding(finding)
        print(f"    Created report: {report.title}")
    
    print("\n[2] Generating markdown report...")
    # md_path = generator.generate_markdown_report("test_report.md")
    # print(f"    Saved to: {md_path}")
    
    print("\n[3] Report preview:")
    if generator.reports:
        print(generator.reports[0].to_markdown()[:500] + "...")
    
    return generator


def main():
    """Run all examples"""
    print("\n" + "=" * 60)
    print("VulnHunter Usage Examples")
    print("=" * 60)
    print("\nThese examples demonstrate the framework's capabilities.")
    print("Note: Actual HTTP requests are commented out for safety.")
    print()
    
    # Run examples
    example_basic_scanning()
    example_payload_testing()
    example_authentication()
    example_web_search()
    example_scanner_usage()
    example_report_generation()
    
    print("\n" + "=" * 60)
    print("Examples Complete!")
    print("=" * 60)
    print("\nFor actual scanning, uncomment the HTTP request lines")
    print("and ensure you have authorization to test the target.\n")


if __name__ == "__main__":
    main()
