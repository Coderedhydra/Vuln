# VulnHunter 🎯

**LLM-Powered Web Vulnerability Framework**

VulnHunter is a sophisticated security testing framework that uses Ollama LLM models to intelligently hunt for vulnerabilities in web applications. It's designed to be easy for LLM agents to use, enabling even 8B parameter models to perform research-level bug hunting.

## Features

🤖 **LLM-Powered Intelligence**
- Uses Ollama models for intelligent vulnerability detection
- Autonomous scanning with LLM decision-making
- Interactive hunting mode for guided testing

🕷️ **Comprehensive Crawling**
- Intelligent web crawler with form detection
- JavaScript analysis for API endpoint discovery
- Source code analysis for secrets and vulnerabilities

🎯 **Multi-Vector Scanning**
- SQL Injection (Error, Boolean, Time-based)
- Cross-Site Scripting (Reflected, Stored, DOM)
- IDOR (Insecure Direct Object Reference)
- SSRF (Server-Side Request Forgery)
- Authentication vulnerabilities
- Business logic flaws

🔧 **Easy-to-Use Tools**
- Simple toolkit interface for LLM agents
- Pre-built payload collections
- Web search for vulnerability research
- Automatic bypass technique generation

📝 **Professional Reporting**
- HackerOne-style vulnerability reports
- Markdown and JSON output formats
- Detailed remediation guidance

## Installation

```bash
# Clone the repository
git clone https://github.com/your-repo/vulnhunter.git
cd vulnhunter

# Install dependencies
pip install -r requirements.txt

# Ensure Ollama is running
ollama serve

# Pull a model (recommended: llama3.1:8b or mistral)
ollama pull llama3.1:8b
```

## Quick Start

### Command Line

```bash
# Autonomous scan
python -m vulnhunter https://target.com

# Interactive mode
python -m vulnhunter https://target.com --interactive

# Quick scan (no LLM, automated scanners only)
python -m vulnhunter https://target.com --quick

# Specify model
python -m vulnhunter https://target.com --model mistral
```

### Python API

```python
from vulnhunter import VulnHunterAgent

# Initialize the agent
agent = VulnHunterAgent(
    target_url="https://target.com",
    model="llama3.1:8b"
)

# Run autonomous scan
findings = agent.run()

# Print summary
print(agent.get_findings_summary())
```

### Using the Toolkit (for LLM agents)

```python
from vulnhunter import LLMToolkit

# Initialize toolkit
toolkit = LLMToolkit("https://target.com")

# Fetch a page
result = toolkit.fetch("/login")

# Get forms from a page
forms = toolkit.get_forms("/login")

# Submit a form
response = toolkit.submit_form("/login", {
    "username": "test",
    "password": "test123"
})

# Send a payload
result = toolkit.send_payload("/search", "GET", "' OR 1=1--", "q")

# Analyze page source
analysis = toolkit.analyze_page("/admin")

# Report a finding
toolkit.report_finding(
    title="SQL Injection in search",
    description="The search parameter is vulnerable to SQL injection",
    severity="high",
    url="/search?q=test",
    evidence="SQL error in response",
    category="sqli"
)
```

## Architecture

```
vulnhunter/
├── agents/           # LLM agent orchestration
│   ├── ollama_agent.py    # Ollama integration
│   └── prompts.py         # System prompts
├── core/             # Core functionality
│   ├── http_client.py     # HTTP client with session management
│   ├── crawler.py         # Web crawler
│   ├── session_manager.py # Auth and session handling
│   └── source_analyzer.py # Source code analysis
├── scanners/         # Vulnerability scanners
│   ├── sqli_scanner.py    # SQL Injection
│   ├── xss_scanner.py     # Cross-Site Scripting
│   ├── idor_scanner.py    # IDOR
│   ├── ssrf_scanner.py    # SSRF
│   └── auth_scanner.py    # Authentication
├── tools/            # LLM tools
│   ├── llm_tools.py       # Unified toolkit
│   ├── payload_generator.py # Payload generation
│   └── web_search.py      # Web search for research
├── reports/          # Report generation
│   └── report_generator.py
├── payloads/         # Pre-built payload collections
│   └── collections.py
└── utils/            # Helper utilities
```

## Available Tools for LLM

The toolkit provides these easy-to-use methods:

### HTTP Operations
- `fetch(url, params)` - GET request
- `post(url, data, json_data)` - POST request
- `request(method, url, data, headers)` - Custom request
- `send_payload(url, method, payload, param)` - Send test payload

### Crawling
- `crawl(max_pages)` - Crawl website
- `get_urls(pattern)` - Get discovered URLs
- `get_forms(url)` - Get forms
- `get_endpoints()` - Get API endpoints

### Analysis
- `analyze_page(url)` - Analyze for vulnerabilities
- `read_source(url)` - Read page source

### Authentication
- `login(url, credentials)` - Perform login
- `register(url, data)` - Register account
- `set_auth_token(token)` - Set auth token
- `get_csrf_token(url)` - Extract CSRF token

### Session
- `set_cookie(name, value)` - Set cookie
- `set_header(name, value)` - Set header
- `get_cookies()` - Get all cookies

### Scanning
```python
from vulnhunter import SQLiScanner, XSSScanner

# Scan for SQL injection
scanner = SQLiScanner(http_client)
results = scanner.scan_url("/search", "GET", {"q": "test"})

# Scan for XSS
scanner = XSSScanner(http_client)
results = scanner.scan_form("/comment", "POST", inputs)
```

### Payload Generation
```python
from vulnhunter import PayloadGenerator

generator = PayloadGenerator()

# Get SQL injection payloads
payloads = generator.sqli_payloads(context="login", db_type="mysql")

# Get XSS payloads with bypass
payloads = generator.xss_payloads(context="attribute", bypass_filter=True)

# Encode payload
encoded = generator.encode_payload("<script>alert(1)</script>", "url")
```

### Web Search
```python
from vulnhunter import WebSearcher

searcher = WebSearcher()

# Search for exploits
results = searcher.search_exploit("Apache Struts", "2.5.20")

# Search HackerOne reports
results = searcher.search_hackerone("IDOR", "API")

# Get CVE details
info = searcher.search_cve("CVE-2021-44228")
```

## Reporting

```python
from vulnhunter import ReportGenerator

generator = ReportGenerator("./reports")

# Generate from findings
reports = generator.generate_all_reports(findings, "assessment")
print(f"Markdown report: {reports['markdown']}")
print(f"JSON report: {reports['json']}")
```

## Example Workflow

```python
from vulnhunter import VulnHunterAgent, LLMToolkit, PayloadGenerator

# 1. Initialize
toolkit = LLMToolkit("https://target.com")

# 2. Reconnaissance
toolkit.crawl(max_pages=100)
forms = toolkit.get_forms()
endpoints = toolkit.get_endpoints()

# 3. Analysis
for url in toolkit.crawl_results.urls:
    analysis = toolkit.analyze_page(url)
    # Review findings...

# 4. Testing
generator = PayloadGenerator()
payloads = generator.sqli_payloads(context="search")

for form in forms:
    for payload in payloads:
        result = toolkit.send_payload(
            form['action'], 
            "POST", 
            payload, 
            form['inputs'][0]['name']
        )
        if "error" in result.data.get('body_preview', '').lower():
            toolkit.report_finding(
                title="SQL Injection",
                description="...",
                severity="high",
                url=form['action'],
                payload=payload
            )

# 5. Get findings
findings = toolkit.get_findings()
```

## Configuration

```yaml
# config.yaml
target_url: https://target.com

ollama:
  host: http://localhost:11434
  model: llama3.1:8b
  timeout: 120

scan:
  max_depth: 5
  max_pages: 500
  timeout: 30
  rate_limit: 0.5

payload:
  test_sqli: true
  test_xss: true
  test_idor: true
  test_ssrf: true
  aggressive_mode: false

report:
  output_format: markdown
  output_dir: ./reports
```

## Security Notice

⚠️ **Important**: This tool is designed for authorized security testing only. Always:
- Get written permission before testing
- Stay within defined scope
- Report vulnerabilities responsibly
- Follow responsible disclosure practices

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests.

## License

MIT License - See LICENSE file for details.

---

**VulnHunter** - Making security testing accessible to LLM agents 🤖🔒
