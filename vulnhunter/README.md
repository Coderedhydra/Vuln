# VulnHunter - Autonomous AI Bug Bounty Hunter

Fast, automated vulnerability scanner with AI analysis.

## Features

- **Model Selection** - Shows available Ollama models, you pick one
- **Parallel Testing** - Tests multiple payloads simultaneously  
- **Automatic Discovery** - Finds forms, parameters, links automatically
- **Confirmation** - Only reports vulnerabilities with real evidence
- **AI Analysis** - LLM analyzes results and provides recommendations

## Quick Start

```bash
# Install dependencies
pip install aiohttp requests ollama rich

# Start Ollama
ollama serve
ollama pull llama3.1:8b

# Run
python main.py
```

## Usage

```bash
# Interactive mode (prompts for URL and model)
python main.py

# Or provide URL directly
python main.py https://target.com
```

## How It Works

1. **Enter URL** → You provide the target
2. **Select Model** → Shows all available Ollama models
3. **Discovery** → Automatically finds forms, parameters, links
4. **Parallel Testing** → Tests XSS, SQLi, LFI, SSRF in parallel
5. **Confirmation** → Only reports vulnerabilities with evidence
6. **AI Analysis** → LLM analyzes and provides recommendations

## Output Example

```
Target: https://target.com
Model: llama3.1:8b

Phase 1: Discovering attack surface...
✓ Found 3 forms
✓ Found 5 parameters
✓ Found 12 internal links

Forms:
  • POST /login - inputs: username, password
  • GET /search - inputs: q

Parameters: q, id, page, sort, filter

Phase 2: Testing for vulnerabilities (parallel)...
Testing q...
Testing id...
✓ Tested 5 parameters
✓ Found 2 potential vulnerabilities

CONFIRMED VULNERABILITIES:
  • XSS: q - Payload reflected in HTML
  • SQLI: id - SQL error: mysql

Phase 3: AI Analysis...
╭─────────────────────────────────────────────────────╮
│ 🔍 AI Analysis                                      │
│                                                     │
│ Found 2 critical vulnerabilities:                   │
│                                                     │
│ 1. XSS in search parameter - allows script          │
│    injection, could steal sessions                  │
│                                                     │
│ 2. SQL injection in id parameter - could           │
│    expose database contents                         │
│                                                     │
│ Recommendations:                                    │
│ - Input validation on all parameters               │
│ - Use parameterized queries                        │
│ - Implement CSP headers                            │
╰─────────────────────────────────────────────────────╯

Commands: 'test <param>', 'report', 'quit'
```

## Commands During Session

- `test <param>` - Test a specific parameter
- `report` or `r` - Show full report
- `quit` or `q` - Exit and show report
- Any text - Ask the AI a question

## Vulnerability Types

| Type | Payloads | Detection |
|------|----------|-----------|
| XSS | `<script>alert(1)</script>` | Payload in HTML response |
| SQLi | `' OR '1'='1` | SQL error messages |
| LFI | `../../../etc/passwd` | File content (root:) |
| SSRF | `http://169.254.169.254/` | AWS metadata |

## Requirements

- Python 3.8+
- aiohttp, requests
- ollama (+ running Ollama server)
- rich (optional, for pretty output)

## License

MIT
