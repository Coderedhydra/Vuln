# VulnHunter - Fast AI-Powered Vulnerability Scanner

A fast, accurate vulnerability scanner that uses async parallel requests for speed and confirms vulnerabilities before reporting.

## Features

- **Ultra-Fast Scanning** - Async parallel requests, scans in seconds not minutes
- **Accurate Detection** - Confirms vulnerabilities with actual exploitation, no false positives
- **Smart Payloads** - Context-aware payloads that adapt to the target
- **Data Extraction** - Proves impact by extracting data from confirmed vulnerabilities
- **AI-Powered** - Optional LLM integration for intelligent hunting (via Ollama)

## Quick Start

```bash
# Install dependencies
pip install aiohttp requests httpx rich

# Fast automatic scan (recommended)
python main.py -t https://target.com

# Scan specific parameter
python main.py -t "https://target.com/search?q=test" -p q --type xss

# Interactive AI mode (requires Ollama)
python main.py -i -t https://target.com

# Save results to file
python main.py -t https://target.com -o results.json
```

## Usage

### Fast Automatic Scan
The default mode scans the target for XSS, SQLi, LFI, and SSRF vulnerabilities:

```bash
python main.py -t https://target.com
```

### Scan Specific Parameter
Test a specific parameter for a vulnerability type:

```bash
python main.py -t "https://target.com/page?id=1" -p id --type sqli
```

### Interactive AI Mode
Uses Ollama LLM for intelligent hunting:

```bash
# Start Ollama first
ollama serve

# Run interactive mode
python main.py -i -t https://target.com -m llama3.1:8b
```

## Python API

```python
from vulnhunter import quick_scan, VulnHunterLLM

# Fast scan (no LLM needed)
result = quick_scan("https://target.com/search?q=test")
print(f"Found {result['vuln_count']} vulnerabilities")
for vuln in result['vulnerabilities']:
    print(f"  - {vuln['type']}: {vuln['payload']}")

# AI-powered hunting
hunter = VulnHunterLLM(model="llama3.1:8b")
hunter.start("https://target.com")
```

## Detected Vulnerabilities

| Type | Detection Method |
|------|-----------------|
| **XSS** | Payload reflection in HTML context |
| **SQLi** | Error-based, Boolean-based, Time-based, UNION |
| **LFI** | File content indicators (/etc/passwd, etc.) |
| **SSRF** | Internal resource access confirmation |
| **IDOR** | Cross-user data access |
| **Auth Bypass** | SQL injection in login forms |

## How It Works

1. **Discovery** - Finds forms, parameters, and internal links
2. **Verification** - Confirms URLs exist before testing (no dead link reports)
3. **Testing** - Sends smart payloads in parallel for speed
4. **Confirmation** - Verifies vulnerabilities with actual exploitation
5. **Extraction** - Proves impact by extracting data when possible

## Example Output

```
╔═══════════════════════════════════════════════════════════════╗
║   Fast AI-Powered Vulnerability Hunter                        ║
╚═══════════════════════════════════════════════════════════════╝

[*] Fast scanning: https://target.com/search?q=test
[+] Scan completed in 1.23s
[*] Forms found: 2
[*] Parameters tested: 5
[*] Links discovered: 12

==================================================
CONFIRMED: SQLI
==================================================
Severity: CRITICAL
URL: https://target.com/search?q=test
Parameter: q
Payload: ' OR '1'='1
Evidence: SQL error detected: mysql
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `-t, --target` | Target URL to scan |
| `-p, --param` | Specific parameter to test |
| `--type` | Vulnerability type: xss, sqli, ssrf, lfi, quick |
| `-i, --interactive` | Interactive AI mode |
| `-m, --model` | Ollama model (default: llama3.1:8b) |
| `-o, --output` | Save results to JSON file |

## Requirements

- Python 3.8+
- aiohttp (for async requests)
- requests, httpx (for HTTP)
- rich (for pretty output)
- ollama (optional, for AI mode)

## License

MIT License
