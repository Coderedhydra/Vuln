# 🎯 VulnHunter

## AI-Powered Web Application Vulnerability Scanner

VulnHunter is a sophisticated bug hunting framework that uses Ollama LLM models to find critical security vulnerabilities in web applications. Designed to be **extremely easy for AI models to use** while being powerful enough to find HackerOne-level vulnerabilities.

![VulnHunter Banner](https://img.shields.io/badge/Version-1.0.0-blue) ![Python](https://img.shields.io/badge/Python-3.8+-green) ![Ollama](https://img.shields.io/badge/Ollama-Required-orange)

---

## ✨ Features

### 🤖 LLM-First Design
- **Simple tool interface** for any Ollama model (8B models work great!)
- **Natural language control** - tell the AI what to find
- **Automatic tool execution** - the LLM decides what tools to use
- **Context-aware** - remembers previous findings for deeper analysis

### 🔍 Comprehensive Scanning
- **XSS** - Reflected, Stored, DOM-based with WAF bypasses
- **SQL Injection** - Error, Boolean, Time-based, Union attacks
- **SSRF** - Cloud metadata, internal network, protocol smuggling
- **LFI/RFI** - Path traversal, PHP wrappers, null byte injection
- **Authentication** - Bypass, default credentials, brute force detection
- **IDOR** - Access control testing, ID enumeration
- **And more...** - SSTI, XXE, Command Injection

### 🛠️ Easy-to-Use Tools
- **Web Crawler** - Discover URLs, forms, parameters, APIs
- **Source Analyzer** - Find secrets, sinks, dangerous functions
- **Payload Generator** - Create sophisticated bypass payloads
- **Session Manager** - Handle authentication, cookies, tokens
- **CVE Search** - Research known vulnerabilities
- **Report Generator** - HackerOne-quality reports

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
cd vulnhunter

# Install dependencies
pip install -r requirements.txt

# Make sure Ollama is running
ollama serve

# Pull a model (8B models are recommended for efficiency)
ollama pull llama3.1:8b
```

### Start Hunting

```bash
# Interactive AI mode (recommended)
python main.py -i -t https://example.com

# Or just run and select model interactively
python main.py
```

---

## 📖 Usage

### CLI Options

```bash
# Interactive AI-powered hunting
python main.py -i -t https://example.com

# Use a specific model
python main.py -i -t https://example.com -m llama3.1:70b

# Automatic scan without AI
python main.py --auto -t https://example.com

# Scan specific parameter for XSS
python main.py -t "https://example.com/search?q=test" -p q --type xss

# Save results to file
python main.py --auto -t https://example.com -o results.json

# Select model interactively
python main.py --select-model

# Use proxy (for Burp Suite)
python main.py -i -t https://example.com --proxy http://127.0.0.1:8080
```

### Python API

```python
from vulnhunter import VulnHunterLLM, WebTools

# AI-Powered Hunting
hunter = VulnHunterLLM(model="llama3.1:8b")
hunter.start("https://example.com")

# Direct Tool Usage (without AI)
tools = WebTools()

# Crawl a website
result = tools.crawl("https://example.com", depth=2)
print(f"Found {len(result['forms'])} forms")

# Scan for XSS
xss_result = tools.scan_xss("https://example.com/search?q=test", param="q")
if xss_result['summary']['vulnerable_count'] > 0:
    print("XSS Found!")

# Generate payloads
payload = tools.generate_payload(vuln_type="sqli", technique="union", db="mysql")
print(payload['payload'])
```

---

## 🔧 Available Tools

The LLM has access to these tools:

### Web Reconnaissance
| Tool | Description |
|------|-------------|
| `fetch(url)` | Fetch a URL and get response |
| `crawl(url, depth)` | Crawl site to discover structure |
| `analyze(url)` | Deep page analysis |
| `read_source(url)` | Read page source code |

### HTTP Requests
| Tool | Description |
|------|-------------|
| `send_request(method, url, ...)` | Full custom HTTP request |
| `inject_payload(url, param, payload)` | Inject payload into parameter |

### Vulnerability Scanners
| Tool | Description |
|------|-------------|
| `scan_xss(url, param)` | Scan for XSS |
| `scan_sqli(url, param)` | Scan for SQL injection |
| `scan_ssrf(url, param)` | Scan for SSRF |
| `scan_lfi(url, param)` | Scan for LFI |
| `scan_auth(login_url)` | Scan authentication |
| `scan_idor(url, param, current_id)` | Scan for IDOR |
| `quick_scan(url, param)` | Quick multi-vuln scan |

### Payload Tools
| Tool | Description |
|------|-------------|
| `generate_payload(vuln_type, ...)` | Generate sophisticated payload |
| `get_payloads(category)` | Get pre-built payloads |
| `mutate_payload(payload)` | Create bypass variations |

### Session Management
| Tool | Description |
|------|-------------|
| `login(url, username, password)` | Login to application |
| `set_cookie(name, value)` | Set a cookie |
| `set_header(name, value)` | Set a header |

### Research
| Tool | Description |
|------|-------------|
| `search_cve(cve_id)` | Get CVE details |
| `search_vulnerability(query)` | Search vulnerabilities |
| `search_exploit(query)` | Find exploits |
| `search_technology_vulns(tech, version)` | Technology-specific vulns |

### Reporting
| Tool | Description |
|------|-------------|
| `create_report(vuln_type, url, ...)` | Generate vulnerability report |
| `get_findings()` | Get all findings |

---

## 🎮 Interactive Commands

During an interactive session:

| Command | Description |
|---------|-------------|
| `quit` | Exit and show final report |
| `report` | Show current findings |
| `tools` | List all available tools |
| `save` | Save findings to file |
| `clear` | Clear conversation history |
| `help` | Show help |

---

## 💡 LLM Tool Calling

The AI uses tools with this format:

```
TOOL: tool_name(param1="value1", param2="value2")
```

### Examples

```
# Crawl a website
TOOL: crawl(url="https://example.com", depth=2)

# Scan for XSS
TOOL: scan_xss(url="https://example.com/search?q=test", param="q")

# Inject a custom payload
TOOL: inject_payload(url="https://example.com/page?id=1", param="id", payload="' OR '1'='1")

# Generate SQLi payload
TOOL: generate_payload(vuln_type="sqli", technique="union", db="mysql", columns=3)

# Search for CVE
TOOL: search_cve(cve_id="CVE-2021-44228")
```

---

## 📊 Example Workflow

### 1. Start a Hunt
```
You: Hunt for vulnerabilities on https://example.com

AI: I'll start by crawling the site to discover the attack surface.
TOOL: crawl(url="https://example.com", depth=2)
```

### 2. Analyze Results
```
AI: Found 15 URLs, 3 forms, and 8 parameters. Let me test the search function.
TOOL: scan_xss(url="https://example.com/search?q=test", param="q")
```

### 3. Deep Testing
```
AI: Basic XSS is filtered, trying bypass payloads.
TOOL: scan_xss(url="https://example.com/search?q=test", param="q", category="filter_bypass")
```

### 4. Generate Report
```
You: Create a report for the XSS finding

AI: TOOL: create_report(vuln_type="xss", url="https://example.com/search", parameter="q", payload="<img src=x onerror=alert(1)>")
```

---

## 🔐 Supported Vulnerability Types

### Cross-Site Scripting (XSS)
- Reflected XSS
- DOM-based XSS  
- Filter bypass techniques
- WAF bypass payloads
- Polyglot payloads

### SQL Injection
- Error-based
- Boolean-based blind
- Time-based blind
- UNION-based
- Stacked queries
- Multi-database support (MySQL, PostgreSQL, MSSQL, Oracle)

### Server-Side Request Forgery (SSRF)
- Localhost access
- Cloud metadata (AWS, GCP, Azure)
- Internal network scanning
- Protocol smuggling (gopher, dict, file)
- Bypass techniques

### Local File Inclusion (LFI)
- Path traversal
- PHP wrappers
- Null byte injection
- Double encoding
- Log poisoning detection

### Authentication Vulnerabilities
- SQL injection bypass
- Default credentials
- Weak password policies
- Session security
- Brute force detection

### Insecure Direct Object Reference (IDOR)
- ID enumeration
- Cross-user access
- Sequential ID testing
- UUID prediction

---

## 📋 Report Generation

VulnHunter generates HackerOne-quality reports:

```markdown
# Cross-Site Scripting (XSS) in `q` parameter on /search

## Summary
- **Severity:** High
- **Type:** XSS
- **URL:** https://example.com/search?q=test
- **CWE:** CWE-79
- **CVSS Score:** 6.1

## Description
A Cross-Site Scripting vulnerability was discovered...

## Steps to Reproduce
1. Navigate to https://example.com/search
2. Enter payload: `<script>alert(1)</script>`
3. Submit the search
4. Observe script execution

## Impact
An attacker can:
- Steal session cookies
- Perform actions as the user
- Redirect to malicious sites

## Remediation
- Implement output encoding
- Use Content Security Policy
- Set HTTPOnly cookies
```

---

## ⚙️ Configuration

### Recommended Models

| Model | Speed | Capability | Use Case |
|-------|-------|------------|----------|
| `llama3.1:8b` | ⚡⚡⚡ | ⭐⭐⭐ | Daily hunting |
| `llama3.1:70b` | ⚡ | ⭐⭐⭐⭐⭐ | Deep analysis |
| `llama3.2:3b` | ⚡⚡⚡⚡ | ⭐⭐ | Quick scans |
| `codellama:7b` | ⚡⚡⚡ | ⭐⭐⭐ | Code analysis |
| `mixtral:8x7b` | ⚡⚡ | ⭐⭐⭐⭐ | Thorough hunting |

### Environment Variables

```bash
# Optional: Set default model
export VULNHUNTER_MODEL="llama3.1:8b"

# Optional: Ollama host
export OLLAMA_HOST="http://localhost:11434"
```

---

## 🛡️ Ethical Use

This tool is for **authorized security testing only**.

⚠️ **Important:**
- Only test applications you have permission to test
- Follow responsible disclosure practices
- Don't use for malicious purposes
- Respect rate limits and don't DoS targets
- Store findings securely

---

## 🤝 Contributing

Contributions welcome! Areas to improve:
- Additional vulnerability scanners
- More payload templates
- Better WAF detection/bypass
- Integration with other tools
- UI improvements

---

## 📜 License

MIT License - See LICENSE file

---

## 🙏 Acknowledgments

- Ollama team for the amazing LLM runtime
- Security research community
- HackerOne for inspiration on report formats
- OWASP for vulnerability references

---

**Happy Hunting! 🎯**
