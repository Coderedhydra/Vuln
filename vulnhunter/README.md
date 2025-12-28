# VulnHunter - Full AI-Controlled Bug Bounty Framework

**The LLM has FULL CONTROL** - sends requests, reads responses, crafts payloads, exploits vulnerabilities.

## Features

- **LLM Drives Everything** - The AI decides what to test, crafts payloads, analyzes responses
- **Real HTTP Requests** - Tools for GET, POST, custom requests
- **Smart Discovery** - Find forms, links, endpoints, technologies
- **Payload Injection** - Inject into URL params or POST fields
- **Research Tools** - Search CVEs, find exploits
- **Confirmation** - Only report after the LLM confirms with evidence

## Quick Start

```bash
# Install dependencies
pip install aiohttp ollama rich

# Start Ollama
ollama serve

# Run
python hunter.py https://target.com
```

## Usage

```bash
# Interactive mode - prompts for URL and model
python hunter.py

# With URL
python hunter.py https://target.com

# With specific model
python hunter.py https://target.com -m llama3.1:8b
```

## How It Works

The LLM calls tools directly using `[TOOL: name(args)]` syntax:

```
AI: Let me start by discovering the attack surface...

[TOOL: find_forms(https://target.com)]
[TOOL: find_links(https://target.com)]
[TOOL: detect_tech(https://target.com)]

--- Results returned to AI ---

AI: I found 3 forms and detected PHP/WordPress. Let me test for XSS...

[TOOL: get_payloads(xss)]

--- Payloads returned ---

[TOOL: inject(https://target.com/search?q=test, q, <script>alert(1)</script>)]

--- Response shows payload reflected ---

AI: CONFIRMED XSS vulnerability! Recording...

[TOOL: report(XSS, https://target.com/search, q, <script>alert(1)</script>, Reflected in HTML, high)]
```

## Available Tools

### HTTP Tools
| Tool | Description | Example |
|------|-------------|---------|
| `get(url)` | GET request | `[TOOL: get(https://target.com)]` |
| `post(url, data)` | POST with JSON data | `[TOOL: post(https://target.com/login, {"user":"test"})]` |
| `request(method, url, headers, data)` | Custom request | `[TOOL: request(PUT, https://api.com/user, {}, {"name":"x"})]` |

### Discovery Tools
| Tool | Description |
|------|-------------|
| `find_forms(url)` | Find all HTML forms and inputs |
| `find_links(url)` | Find internal links and URL parameters |
| `read_source(url)` | Read full HTML source code |
| `find_endpoints(url)` | Find API endpoints in JavaScript |
| `detect_tech(url)` | Detect server technologies |

### Testing Tools
| Tool | Description |
|------|-------------|
| `inject(url, param, payload)` | Inject payload into URL parameter |
| `post_inject(url, data, field, payload)` | Inject into POST field |

### Research Tools
| Tool | Description |
|------|-------------|
| `get_payloads(type)` | Get payloads (xss, sqli, lfi, ssrf, ssti, cmd) |
| `search_cve(technology)` | Search CVEs for a technology |
| `search_exploit(query)` | Search for exploits |

### Reporting Tools
| Tool | Description |
|------|-------------|
| `report(type, url, param, payload, evidence, severity)` | Record a vulnerability |
| `get_findings()` | List all findings |
| `summary()` | Get full hunt summary |

## Example Session

```
$ python hunter.py https://example.com -m llama3.1:8b

╔═══════════════════════════════════════════════════════════════╗
║   VulnHunter Framework - Full AI Control                      ║
╚═══════════════════════════════════════════════════════════════╝

Target: https://example.com
Model: llama3.1:8b

Starting autonomous hunt...

╭─────────────────────────────────────────────────────────────────╮
│ 🔍 AI Hunter                                                    │
│                                                                 │
│ Starting reconnaissance on https://example.com...               │
│                                                                 │
│ [TOOL: find_forms(https://example.com)]                        │
│ [TOOL: find_links(https://example.com)]                        │
│ [TOOL: detect_tech(https://example.com)]                       │
│                                                                 │
│ --- After tools execute ---                                     │
│                                                                 │
│ Found 2 forms with inputs: username, password, search, id      │
│ Detected: nginx, PHP 7.4, WordPress 6.0                        │
│                                                                 │
│ Testing search parameter for XSS...                             │
│ [TOOL: inject(https://example.com/?s=test, s, <script>alert(1)</script>)] │
│                                                                 │
│ Response shows reflected:true - VULNERABLE!                     │
│ [TOOL: report(XSS, https://example.com/?s=test, s, <script>alert(1)</script>, Reflected in HTML, high)] │
╰─────────────────────────────────────────────────────────────────╯

Commands: 'c'=continue, 'r'=report, 'q'=quit
> c

╭─────────────────────────────────────────────────────────────────╮
│ 🔍 AI Hunter                                                    │
│                                                                 │
│ Continuing with SQL injection tests...                          │
│ [TOOL: inject(https://example.com/product?id=1, id, 1' OR '1'='1)] │
│ ...                                                             │
╰─────────────────────────────────────────────────────────────────╯

> q

=== Hunt Complete ===
Requests made: 15
Vulnerabilities found: 2
```

## Interactive Commands

| Command | Description |
|---------|-------------|
| `c` or `continue` | Continue hunting automatically |
| `r` or `report` | Show current findings |
| `q` or `quit` | Exit and show summary |
| Any text | Give instructions to the AI |

## Example Instructions

```
> test the login form for SQL injection

> try to bypass authentication

> look for IDOR vulnerabilities in the user endpoint

> search for CVEs related to WordPress 6.0

> read the source of the admin page
```

## Requirements

- Python 3.8+
- aiohttp
- ollama (with server running)
- rich (for pretty output)

## Install

```bash
pip install -r requirements.txt

# Or manually
pip install aiohttp ollama rich
```

## License

MIT
