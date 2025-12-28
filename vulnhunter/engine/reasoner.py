"""
Ollama-backed reasoning engine.

Strict separation:
- This module may propose hypotheses and payload ideas.
- It must never claim a vulnerability is confirmed (no "evidence from the web").
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from .models import Hypothesis, ProofKind

try:
    import ollama  # type: ignore

    OLLAMA_AVAILABLE = True
except Exception:
    OLLAMA_AVAILABLE = False


class Reasoner:
    def __init__(self, model: str):
        self.model = model

    def propose_hypotheses(
        self,
        target_url: str,
        crawl_summary: Dict[str, Any],
        max_hypotheses: int = 25,
    ) -> List[Hypothesis]:
        """
        Return hypotheses as structured JSON parsed into dataclasses.

        If Ollama is unavailable or the model returns invalid JSON, fall back to a
        safe empty list (the scanner can still run deterministic verifiers).
        """
        if not OLLAMA_AVAILABLE:
            return []

        prompt = f"""
You are a security analyst. You DO NOT run requests and you DO NOT claim confirmation.
Your job is to propose vulnerability hypotheses and what proof would be required to confirm them.

Target: {target_url}
Crawl summary (JSON):
{json.dumps(crawl_summary, indent=2)[:12000]}

Rules:
- Never claim a vulnerability is confirmed.
- Do NOT use keyword heuristics as "proof".
- Confirmation requires a proof signal like OOB callback or statistically significant timing delay.

Return ONLY valid JSON with this schema:
{{
  "hypotheses": [
    {{
      "vuln_type": "sqli|ssrf|xss|lfi|idor|auth|other",
      "target_url": "<url to test>",
      "parameter": "<parameter name>",
      "rationale": "<short>",
      "payload_ideas": ["..."],
      "required_proof": ["timing"|"oob"]
    }}
  ]
}}

Keep it concise. Provide at most {max_hypotheses} hypotheses.
"""

        try:
            resp = ollama.chat(model=self.model, messages=[{"role": "user", "content": prompt}])
            content = resp["message"]["content"]
            data = json.loads(content)
        except Exception:
            return []

        out: List[Hypothesis] = []
        for item in (data.get("hypotheses") or [])[:max_hypotheses]:
            required = []
            for k in item.get("required_proof") or []:
                if k == "timing":
                    required.append(ProofKind.TIMING)
                elif k == "oob":
                    required.append(ProofKind.OOB)
            out.append(
                Hypothesis(
                    vuln_type=str(item.get("vuln_type") or "other"),
                    target_url=str(item.get("target_url") or target_url),
                    parameter=str(item.get("parameter") or ""),
                    rationale=str(item.get("rationale") or ""),
                    payload_ideas=[str(p) for p in (item.get("payload_ideas") or [])][:10],
                    required_proof=required,
                )
            )

        return [h for h in out if h.parameter]

