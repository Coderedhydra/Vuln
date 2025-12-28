# VulnHunter (evidence-driven)

VulnHunter is an **evidence-driven** web vulnerability scanner designed to keep false positives **near zero** by enforcing strict confirmation rules.

## What changed (why false positives were high)

Earlier versions treated **reflection**, **error keywords**, and **status/length differences** as “confirmed” vulnerabilities (and even allowed the LLM to decide confirmation). That produces many false positives and can lead to hallucinated reports.

This version separates concerns:

- **Ollama (LLM) is reasoning-only**: proposes hypotheses, payload ideas, and what proof would be required.
- **Code/tools do execution + verification**: send requests, measure timing, and perform OOB checks.
- **Only deterministic verifiers can confirm findings**.

## Confirmation rules (enforced)

A finding is **confirmed only when exploitation is proven** via an accepted proof signal:

- **Timing**: statistically consistent delay vs both baseline and a **zero-delay control**
- **OOB**: an out-of-band callback (pollable collaborator), with a **control test** proving the collaborator isn’t noisy

Response text/status/length differences are **not accepted as proof**.

Every confirmed finding includes:

- **Payload used**
- **Proof signal**
- **Control test** showing why it’s not a false positive

## Usage

```bash
python -m vulnhunter https://target.example
```

### JSON output

```bash
python -m vulnhunter https://target.example --json
```

### SSRF OOB confirmation (optional)

To confirm SSRF, you must provide a pollable collaborator protocol:

- `--oob-callback-template`: URL the target will request (SSRF) — includes `{token}`
- `--oob-poll-template`: URL the scanner polls to verify the hit — includes `{token}`

```bash
python -m vulnhunter https://target.example \
  --enable-ssrf-oob \
  --oob-callback-template "https://collab.example/cb/{token}" \
  --oob-poll-template "https://collab.example/poll/{token}"
```

The poll endpoint must return JSON like:

```json
{"hit": true, "first_seen": "...", "raw": "..."}
```

