# VulnHunter - Autonomous AI Bug Bounty Hunter

**Just give it a URL - the AI does everything.**

VulnHunter is an autonomous AI security researcher that hunts for vulnerabilities like a human bug bounty hunter.

## Quick Start

```bash
# Install
pip install aiohttp requests ollama rich

# Start Ollama
ollama serve
ollama pull llama3.1:8b

# Hunt!
python main.py https://target.com
```

## Usage

```bash
# Basic - just provide URL
python main.py https://target.com

# With different model
python main.py https://target.com -m llama3.1:70b

# Or just run and enter URL when prompted
python main.py
```

## What It Does

The AI automatically:

1. **Discovers** - Finds all forms, parameters, endpoints
2. **Analyzes** - Reads source code, understands the application
3. **Tests** - Creates smart payloads, tests each input
4. **Exploits** - Confirms vulnerabilities with real exploitation
5. **Reports** - Documents confirmed findings with proof

## Commands During Hunt

While hunting, you can:
- Press `Enter` or type `c` - Continue hunting
- Type `r` - Show current report
- Type `f` - Show confirmed findings
- Type `q` - Quit and show final report
- Or give specific instructions like "focus on the login form"

## Example

```
$ python main.py https://target.com

╔═══════════════════════════════════════════════════════════════╗
║   Autonomous AI Bug Bounty Hunter                             ║
║   Just give me a URL - I do the rest                          ║
╚═══════════════════════════════════════════════════════════════╝

[*] Target: https://target.com
[*] Model: llama3.1:8b
[+] AI Hunter ready

═══════════════════════════════════════════════════════════════
 🔍 AI Hunter
═══════════════════════════════════════════════════════════════
Starting reconnaissance on target...

TOOL: find_forms(url="https://target.com")

Found 2 forms:
1. Search form with 'q' parameter
2. Login form with username/password

Let me test the search parameter for XSS:

TOOL: inject(url="https://target.com/search?q=test", param="q", 
             payload="<script>alert(1)</script>")

The payload is reflected in the HTML! Confirmed XSS.

TOOL: report_finding(type="XSS", url="https://target.com/search",
                     param="q", payload="<script>alert(1)</script>",
                     evidence="Reflected unencoded in HTML body",
                     severity="high")

Now testing the login form for SQL injection...
═══════════════════════════════════════════════════════════════

> c
(continues hunting...)
```

## Requirements

- Python 3.8+
- Ollama with a model (llama3.1:8b recommended)
- aiohttp, requests, ollama, rich

## How It's Different

| Traditional Scanner | VulnHunter AI |
|---------------------|---------------|
| Fixed payloads | Creates custom payloads based on context |
| No understanding | Analyzes code to understand the app |
| Can't adapt | Adapts approach based on responses |
| Reports anything | Only reports CONFIRMED vulnerabilities |
| Simulates results | Every request is REAL |

## License

MIT
