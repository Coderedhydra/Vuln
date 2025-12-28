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
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

from ..config import DEFAULT_CONFIG
from ..core.crawler import WebCrawler
from ..core.http_client import HTTPClient
from .models import Finding, Hypothesis
from .oob import SimplePollOOBClient
from .reasoner import Reasoner
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

    def scan(self) -> Dict[str, Any]:
        crawl_summary = self.crawler.crawl_site(self.target_url, depth=self.config.crawl_depth)

        injection_points = self._collect_injection_points(crawl_summary)

        # Optional AI hypotheses (never used as confirmation)
        hypotheses: List[Hypothesis] = self.reasoner.propose_hypotheses(self.target_url, crawl_summary)

        confirmed: List[Finding] = []
        hypotheses_out: List[Finding] = []

        # Deterministic verification.
        for url, param in injection_points:
            if self.config.verify_sqli_timing:
                finding = self.sqli_verifier.verify(url, param)
                if finding:
                    confirmed.append(finding)
                    continue

            if self.config.verify_ssrf_oob and self.oob.enabled():
                finding = self.ssrf_verifier.verify(url, param)
                if finding:
                    confirmed.append(finding)
                    continue

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
            "confirmed_findings": [f.to_dict() for f in confirmed],
            "hypotheses": [f.to_dict() for f in hypotheses_out],
        }

