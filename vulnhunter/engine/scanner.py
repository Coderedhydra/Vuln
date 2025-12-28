"""
Evidence-driven scanner pipeline.

Flow:
1) Crawl and collect candidate injection points (URLs + parameters).
2) Ask the LLM (optional) for hypotheses and payload ideas (no execution).
3) Run deterministic verifiers. Only these can confirm findings.
4) Emit reports with payload + proof signal + control test for confirmed findings.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

from ..config import DEFAULT_CONFIG
from ..core.crawler import WebCrawler
from ..core.http_client import HTTPClient
from .models import Finding, Hypothesis
from .oob import SimplePollOOBClient
from .reasoner import Reasoner
from .triage import TriageRunner, rank_for_sqli_timing, rank_for_ssrf
from .verifiers import OOBSSRFVerifier, TimeBasedSQLiVerifier, TimingConfig


@dataclass(frozen=True)
class ScanConfig:
    model: str = DEFAULT_CONFIG.default_model
    crawl_depth: int = DEFAULT_CONFIG.crawl_depth
    max_pages: int = DEFAULT_CONFIG.max_pages
    verify_sqli_timing: bool = True
    verify_ssrf_oob: bool = False
    sqli_delay_s: float = float(DEFAULT_CONFIG.time_based_delay)
    sqli_samples: int = 3
    oob_callback_template: str = ""
    oob_poll_template: str = ""
    autopilot: bool = False
    max_rounds: int = 3
    triage_concurrency: int = 25
    verify_concurrency: int = 2
    max_verify_per_round: int = 12


class EvidenceDrivenScanner:
    def __init__(self, target_url: str, config: Optional[ScanConfig] = None):
        self.target_url = target_url
        self.config = config or ScanConfig()

        self.http = HTTPClient(timeout=DEFAULT_CONFIG.timeout, verify_ssl=DEFAULT_CONFIG.verify_ssl, proxy=DEFAULT_CONFIG.proxy)
        self.crawler = WebCrawler(client=self.http, max_pages=self.config.max_pages, same_domain=True)

        self.reasoner = Reasoner(model=self.config.model)
        self.oob = SimplePollOOBClient(
            http=self.http,
            callback_template=self.config.oob_callback_template,
            poll_template=self.config.oob_poll_template,
        )

        self.sqli_verifier = TimeBasedSQLiVerifier(
            http=self.http,
            config=TimingConfig(delay_s=self.config.sqli_delay_s, samples=self.config.sqli_samples),
        )
        self.ssrf_verifier = OOBSSRFVerifier(http=self.http, oob=self.oob)

    def _collect_injection_points(self, crawl_summary: Dict[str, Any]) -> List[Tuple[str, str]]:
        """
        Return list of (url, parameter) pairs for testing.
        """
        points: Set[Tuple[str, str]] = set()

        # Parameters discovered from crawler summary (across pages/forms).
        for p in (crawl_summary.get("parameters") or {}).keys():
            # Need a concrete URL to test; we will test against start URL by default.
            points.add((self.target_url, p))

        # Query params on discovered URLs (crawler internal state).
        for url in list(getattr(self.crawler, "discovered_urls", set()))[:200]:
            parsed = urlparse(url)
            if parsed.query:
                for p in parse_qs(parsed.query).keys():
                    points.add((url, p))

        # Also include params on the target URL itself.
        for p in parse_qs(urlparse(self.target_url).query).keys():
            points.add((self.target_url, p))

        return sorted(points)

    def scan(self, on_event: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
        def emit(msg: str) -> None:
            if on_event:
                on_event(msg)

        emit("Starting crawl…")
        crawl_summary = self.crawler.crawl_site(self.target_url, depth=self.config.crawl_depth)

        injection_points = self._collect_injection_points(crawl_summary)
        emit(f"Crawl complete. Candidate injection points: {len(injection_points)}")

        emit(f"Running parallel triage (concurrency={self.config.triage_concurrency})…")
        triage_signals: List[Dict[str, Any]] = []
        triage_ranked_sqli: List[tuple[int, str, str]] = []
        triage_ranked_ssrf: List[tuple[int, str, str]] = []
        try:
            import asyncio

            runner = TriageRunner(
                timeout_s=min(12.0, float(DEFAULT_CONFIG.timeout)),
                concurrency=self.config.triage_concurrency,
                verify_ssl=DEFAULT_CONFIG.verify_ssl,
                proxy=DEFAULT_CONFIG.proxy or "",
            )
            sigs = asyncio.run(runner.run(injection_points))
            triage_signals = [s.to_dict() for s in sigs]
            triage_ranked_sqli = sorted([(rank_for_sqli_timing(s), s.url, s.param) for s in sigs], reverse=True)
            triage_ranked_ssrf = sorted([(rank_for_ssrf(s), s.url, s.param) for s in sigs], reverse=True)
            emit(f"Triage complete. Signals: {len(triage_signals)}")
        except Exception as e:
            emit(f"Triage failed (continuing without it): {e}")

        # Optional AI hypotheses (never used as confirmation)
        emit(f"Requesting AI hypotheses from Ollama model '{self.config.model}'…")
        hypotheses: List[Hypothesis] = self.reasoner.propose_hypotheses(self.target_url, crawl_summary)
        if getattr(self.reasoner, "last_error", None):
            emit(f"AI hypotheses unavailable: {self.reasoner.last_error}")
        else:
            emit(f"AI hypotheses received: {len(hypotheses)}")

        confirmed: List[Finding] = []
        hypotheses_out: List[Finding] = []

        # Deterministic verification (expensive). Autopilot = multiple rounds of prioritized attempts.
        import concurrent.futures

        def verify_one(url: str, param: str) -> Optional[Finding]:
            if self.config.verify_sqli_timing:
                f = self.sqli_verifier.verify(url, param)
                if f:
                    return f
            if self.config.verify_ssrf_oob and self.oob.enabled():
                f = self.ssrf_verifier.verify(url, param)
                if f:
                    return f
            return None

        rounds = self.config.max_rounds if self.config.autopilot else 1
        for r in range(1, rounds + 1):
            # Build a prioritized queue for this round from triage (fallback to all points).
            queue: List[Tuple[str, str]] = []
            if triage_ranked_sqli:
                queue.extend([(u, p) for score, u, p in triage_ranked_sqli if score > 0])
            if self.config.verify_ssrf_oob and triage_ranked_ssrf:
                queue.extend([(u, p) for score, u, p in triage_ranked_ssrf if score > 0])
            if not queue:
                queue = list(injection_points)

            # Deduplicate while keeping order.
            seen = set()
            pruned: List[Tuple[str, str]] = []
            for u, p in queue:
                key = (u, p)
                if key not in seen:
                    seen.add(key)
                    pruned.append(key)

            pruned = pruned[: self.config.max_verify_per_round]
            emit(f"Round {r}/{rounds}: running proof verifiers on {len(pruned)} prioritized targets…")

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.verify_concurrency) as pool:
                futs = {pool.submit(verify_one, u, p): (u, p) for (u, p) in pruned}
                for fut in concurrent.futures.as_completed(futs):
                    u, p = futs[fut]
                    try:
                        finding = fut.result()
                    except Exception as e:
                        emit(f"Verifier error for {p} @ {u}: {e}")
                        continue
                    if finding:
                        emit(f"CONFIRMED ({finding.vuln_type}): param={p} @ {u}")
                        confirmed.append(finding)

            if confirmed:
                break

        # Convert AI hypotheses into non-confirmed findings for reporting/triage.
        for h in hypotheses:
            hypotheses_out.append(
                Finding(
                    vuln_type=h.vuln_type,
                    target_url=h.target_url,
                    parameter=h.parameter,
                    confirmed=False,
                    payload=h.payload_ideas[0] if h.payload_ideas else "",
                    supporting_evidence=[f"LLM rationale: {h.rationale}".strip()] if h.rationale else [],
                    notes="Hypothesis only (not verified). Confirmation requires proof signals and control tests.",
                )
            )

        return {
            "target": self.target_url,
            "crawl": crawl_summary,
            "injection_points": [{"url": u, "param": p} for (u, p) in injection_points],
            "triage": triage_signals,
            "confirmed_findings": [f.to_dict() for f in confirmed],
            "hypotheses": [f.to_dict() for f in hypotheses_out],
            "reasoner": {
                "model": self.config.model,
                "ok": getattr(self.reasoner, "last_error", None) is None,
                "error": getattr(self.reasoner, "last_error", None),
                "hypotheses_count": len(hypotheses),
            },
        }

