# VulnHunter - Autonomous AI Bug Bounty Hunter

**Just give it a URL - the AI automatically tests for vulnerabilities.**

## Quick Start

```bash
# 1. Install dependencies
pip install aiohttp requests ollama rich

# 2. Start Ollama and pull any model
ollama serve
ollama pull llama3.1:8b    # or any model you prefer

# 3. Hunt!
python main.py https://target.com
```

## Usage

```bash
# Default model (llama3.1:8b)
python main.py https://target.com

# Any Ollama model works
python main.py https://target.com -m llama3.1:70b
python main.py https://target.com -m codellama:7b
python main.py https://target.com -m mixtral:8x7b
python main.py https://target.com -m qwen2:7b
python main.py https://target.com -m phi3:medium
python main.py https://target.com -m gemma2:9b
```

## How It Works

1. **You provide URL** → `python main.py https://target.com`
2. **Tool automatically fetches** forms, parameters, links
3. **AI receives the data** and sees what to test
4. **AI uses tools** to inject payloads and test vulnerabilities
5. **AI confirms** vulnerabilities before reporting

## The AI Has Real Tools

The AI can actually:
- `fetch(url)` - Fetch any page
- `inject(url, param, payload)` - Test payloads on parameters
- `post_form(url, data)` - Submit forms
- `report_finding(...)` - Report confirmed vulnerabilities

Every tool call makes a REAL HTTP request to the target.

## Commands During Hunt

```
> c          # Continue testing
> r          # Show report  
> f          # Show confirmed findings
> q          # Quit

# Or give specific instructions:
> test the login form for SQL injection
> check the search parameter for XSS
> try to exploit that IDOR vulnerability
```

## Example Session

```
$ python main.py https://target.com

[*] Target: https://target.com
[*] Model: llama3.1:8b
[+] AI Hunter ready

🔍 AI Hunter
═══════════════════════════════════════════
I found 2 forms with these parameters:
- search form: q parameter
- login form: username, password

Let me test the search parameter for XSS:

TOOL: inject(url="https://target.com/search?q=test", param="q", payload="<script>alert(1)</script>")

Result: reflected: true - the payload appears in the response!

TOOL: report_finding(type="XSS", url="https://target.com/search", param="q", payload="<script>alert(1)</script>", evidence="Payload reflected unencoded", severity="high")

Now testing login for SQLi...
═══════════════════════════════════════════

> c
(continues testing...)
```

## Requirements

- Python 3.8+
- Ollama running locally with any model
- `pip install aiohttp requests ollama rich`

## License

MIT
