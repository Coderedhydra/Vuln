#!/usr/bin/env python3
"""
VulnHunter CLI (evidence-driven).

Key guarantee:
- Confirmed findings are produced ONLY by deterministic verifiers and include:
  payload, proof signal, and a control test.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict

if __package__ in (None, ""):
    # Allow running as a standalone script from inside the package directory:
    #   cd vulnhunter && python3 cli.py ...
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from vulnhunter.config import DEFAULT_CONFIG  # type: ignore
    from vulnhunter.engine.scanner import EvidenceDrivenScanner, ScanConfig  # type: ignore
else:
    from .config import DEFAULT_CONFIG
    from .engine.scanner import EvidenceDrivenScanner, ScanConfig


def _print_human_summary(result: Dict[str, Any]) -> None:
    confirmed = result.get("confirmed_findings") or []
    hypotheses = result.get("hypotheses") or []

    print(f"Target: {result.get('target')}")
    print(f"Injection points: {len(result.get('injection_points') or [])}")
    print(f"Confirmed findings: {len(confirmed)}")
    print(f"Hypotheses (unverified): {len(hypotheses)}")
    print()

    if confirmed:
        print("== Confirmed Findings (proof-backed) ==")
        for i, f in enumerate(confirmed, 1):
            proof = f.get("proof") or {}
            control = (proof.get("control") or {})
            print(f"{i}. {f.get('type')} @ {f.get('url')} param={f.get('param')}")
            print(f"   payload: {f.get('payload')}")
            print(f"   proof: {proof.get('kind')} - {proof.get('signal')}")
            print(f"   control: {control.get('description')} -> {control.get('observation')}")
    else:
        print("No confirmed findings (proof-backed) were produced.")
        print("This is expected unless the scanner can prove exploitability (timing/OOB).")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="vulnhunter", description="Evidence-driven vulnerability scanner")
    parser.add_argument("url", help="Target URL (include scheme)")
    parser.add_argument("-m", "--model", default=DEFAULT_CONFIG.default_model, help="Ollama model for reasoning")
    parser.add_argument("--crawl-depth", type=int, default=DEFAULT_CONFIG.crawl_depth)
    parser.add_argument("--max-pages", type=int, default=DEFAULT_CONFIG.max_pages)
    parser.add_argument("--chat", action="store_true", help="Print step-by-step (ChatGPT-like) progress output")

    parser.add_argument("--sqli-delay", type=float, default=float(DEFAULT_CONFIG.time_based_delay))
    parser.add_argument("--sqli-samples", type=int, default=3)

    parser.add_argument("--enable-ssrf-oob", action="store_true", help="Enable SSRF OOB confirmation (requires templates)")
    parser.add_argument("--oob-callback-template", default="", help="e.g. https://collab.example/cb/{token}")
    parser.add_argument("--oob-poll-template", default="", help="e.g. https://collab.example/poll/{token}")

    parser.add_argument("--json", action="store_true", help="Output full JSON result")

    args = parser.parse_args(argv)

    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    cfg = ScanConfig(
        model=args.model,
        crawl_depth=args.crawl_depth,
        max_pages=args.max_pages,
        verify_sqli_timing=True,
        verify_ssrf_oob=bool(args.enable_ssrf_oob),
        sqli_delay_s=float(args.sqli_delay),
        sqli_samples=int(args.sqli_samples),
        oob_callback_template=args.oob_callback_template,
        oob_poll_template=args.oob_poll_template,
    )

    scanner = EvidenceDrivenScanner(target_url=url, config=cfg)
    if args.chat:
        result = scanner.scan(on_event=lambda m: print(f"[scanner] {m}"))
    else:
        result = scanner.scan()

    if args.json:
        print(json.dumps(result, indent=2))
        return

    _print_human_summary(result)


if __name__ == "__main__":
    main()

