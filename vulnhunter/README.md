# VulnHunter - Autonomous AI Bug Bounty Hunter

**This is NOT a static scanner. This is an autonomous AI security researcher.**

VulnHunter is an intelligent bug bounty hunter that thinks and acts like a human security researcher. It explores, analyzes, adapts, and confirms - never simulating or faking results.

## How It Works

The AI autonomously:

1. **Explores** - Fetches pages, reads source code, understands the application
2. **Analyzes** - Identifies technologies, attack surfaces, input points
3. **Reasons** - Creates custom payloads based on what it observes
4. **Adapts** - Adjusts approach based on responses
5. **Confirms** - Exploits vulnerabilities to prove they're real
6. **Reports** - Documents only confirmed, real findings

## Quick Start

```bash
# Install dependencies
pip install aiohttp requests ollama rich

# Start Ollama
ollama serve

# Pull a model
ollama pull llama3.1:8b

# Start autonomous hunting
python main.py -i -t https://target.com
```

## Usage

### Autonomous AI Mode (Recommended)

The AI will explore and hunt autonomously:

```bash
python main.py -i -t https://target.com
```

You can interact with the AI:
- `continue` - Let it keep hunting
- `report` - Show current findings
- `findings` - List confirmed vulnerabilities
- Or give specific instructions like "focus on the login form"

### Different AI Models

```bash
# Faster, lighter model
python main.py -i -t https://target.com -m llama3.2:3b

# More capable model
python main.py -i -t https://target.com -m llama3.1:70b

# Code-focused model
python main.py -i -t https://target.com -m codellama:7b
```

## What Makes This Different

### Traditional Scanner
- Fixed payloads
- No understanding of context
- High false positive rate
- Can't adapt
- Reports anything that "looks" vulnerable

### VulnHunter AI
- **Intelligent** - Understands what it's testing
- **Adaptive** - Changes approach based on responses
- **Context-aware** - Creates payloads specific to the target
- **Confirming** - Proves vulnerabilities through exploitation
- **Real** - Every request is made to the actual target, nothing is simulated

## The AI's Tools

The AI has these tools to interact with targets:

| Tool | Purpose |
|------|---------|
| `fetch(url)` | Get a URL and analyze the response |
| `read_source(url)` | Read HTML source for code analysis |
| `find_forms(url)` | Discover forms and input fields |
| `find_links(url)` | Find internal links and parameters |
| `inject(url, param, payload)` | Test a payload on a parameter |
| `post_form(url, data)` | Submit forms with custom data |
| `send_request(method, url, ...)` | Make any HTTP request |
| `report_finding(...)` | Report a confirmed vulnerability |

## Example Session

```
╔═══════════════════════════════════════════════════════════════╗
║   Autonomous AI Bug Bounty Hunter                             ║
╚═══════════════════════════════════════════════════════════════╝

[*] Target: https://target.com
[*] Initializing autonomous hunter...
[+] AI Hunter initialized

=== AI Hunter ===
I'll start by exploring the target to understand its structure.

TOOL: fetch(url="https://target.com")

Analyzing the response... I see this is a PHP application with a 
login form. Let me examine the form more closely.

TOOL: find_forms(url="https://target.com")

Found 2 forms:
1. Login form with username/password fields
2. Search form with 'q' parameter

The search form looks interesting. Let me analyze how it handles input.

TOOL: inject(url="https://target.com/search?q=test", param="q", 
             payload="<script>alert(1)</script>")

The payload is reflected in the HTML response without encoding!
This is a confirmed XSS vulnerability.

TOOL: report_finding(type="XSS", url="https://target.com/search", 
                     param="q", payload="<script>alert(1)</script>",
                     evidence="Payload reflected unencoded in HTML body",
                     severity="high")

Now let me test the login form for SQL injection...
================

[You] > continue
```

## Requirements

- Python 3.8+
- Ollama (running locally)
- An LLM model (llama3.1:8b recommended)

```bash
# Install Python packages
pip install aiohttp requests ollama rich

# Install and start Ollama
# See: https://ollama.ai

# Pull a model
ollama pull llama3.1:8b
```

## Key Principles

1. **Never Simulate** - Every request is real
2. **Never Fake** - Every finding is confirmed through actual exploitation
3. **Think Like a Human** - Reason about what you're seeing
4. **Adapt** - If something doesn't work, try a different approach
5. **Confirm** - Don't report until you have proof

## License

MIT License
