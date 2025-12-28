"""
Fast parallel triage (NOT confirmation).

Goal: cheaply prioritize where to spend expensive proof-grade verification.

Triage signals may use heuristics (param names, lightweight probes), but MUST NOT
be treated as proof of exploitability.
"""

from __future__ import annotations

import asyncio
import random
import re
import string
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx


def _inject_query_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))


def _rand_token(n: int = 8) -> str:
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(n))


@dataclass(frozen=True)
class TriageSignal:
    url: str
    param: str
    base_status: int
    base_len: int
    reflected: bool
    has_sql_error_hint: bool
    looks_like_url_param: bool
    looks_like_id_param: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "param": self.param,
            "base_status": self.base_status,
            "base_len": self.base_len,
            "reflected": self.reflected,
            "has_sql_error_hint": self.has_sql_error_hint,
            "looks_like_url_param": self.looks_like_url_param,
            "looks_like_id_param": self.looks_like_id_param,
        }


SQL_ERROR_HINTS = re.compile(
    r"(sql syntax|mysql|postgresql|sqlite|ora-\d|sqlstate|\bsyntax error\b|unclosed quotation)",
    re.IGNORECASE,
)


def _param_looks_like_url(name: str) -> bool:
    n = name.lower()
    return any(k in n for k in ["url", "uri", "link", "next", "return", "redirect", "dest", "callback", "fetch", "proxy"])


def _param_looks_like_id(name: str) -> bool:
    n = name.lower()
    return n in {"id", "uid"} or n.endswith("_id") or "id" == n[-2:]


class TriageRunner:
    def __init__(self, timeout_s: float = 12.0, concurrency: int = 25, verify_ssl: bool = True, proxy: str = ""):
        self.timeout_s = timeout_s
        self.concurrency = concurrency
        self.verify_ssl = verify_ssl
        self.proxy = proxy

    async def _triage_one(self, client: httpx.AsyncClient, url: str, param: str) -> Optional[TriageSignal]:
        # Baseline request with benign token to ensure param exists in query.
        tok = _rand_token()
        base_url = _inject_query_param(url, param, tok)
        try:
            r0 = await client.get(base_url, follow_redirects=True)
        except Exception:
            return None

        body0 = r0.text or ""
        reflected = tok in body0

        # Very cheap SQL error hint probe (not proof): append a single quote
        test_url = _inject_query_param(url, param, tok + "'")
        try:
            r1 = await client.get(test_url, follow_redirects=True)
        except Exception:
            r1 = None

        has_sql_error_hint = False
        if r1 is not None:
            has_sql_error_hint = bool(SQL_ERROR_HINTS.search(r1.text or ""))

        return TriageSignal(
            url=url,
            param=param,
            base_status=int(r0.status_code),
            base_len=len(body0),
            reflected=reflected,
            has_sql_error_hint=has_sql_error_hint,
            looks_like_url_param=_param_looks_like_url(param),
            looks_like_id_param=_param_looks_like_id(param),
        )

    async def run(self, points: Sequence[Tuple[str, str]]) -> List[TriageSignal]:
        limits = httpx.Limits(max_connections=self.concurrency, max_keepalive_connections=self.concurrency)
        timeout = httpx.Timeout(self.timeout_s)

        kwargs: Dict[str, Any] = {"timeout": timeout, "limits": limits, "verify": self.verify_ssl}
        if self.proxy:
            kwargs["proxy"] = self.proxy

        sem = asyncio.Semaphore(self.concurrency)
        out: List[TriageSignal] = []

        async with httpx.AsyncClient(**kwargs) as client:

            async def worker(u: str, p: str) -> None:
                async with sem:
                    sig = await self._triage_one(client, u, p)
                    if sig:
                        out.append(sig)

            tasks = [worker(u, p) for (u, p) in points]
            await asyncio.gather(*tasks)

        return out


def rank_for_sqli_timing(sig: TriageSignal) -> int:
    # Only a prioritization score, never confirmation.
    score = 0
    if sig.looks_like_id_param:
        score += 3
    if sig.has_sql_error_hint:
        score += 2
    if sig.base_status in (200, 201):
        score += 1
    return score


def rank_for_ssrf(sig: TriageSignal) -> int:
    score = 0
    if sig.looks_like_url_param:
        score += 4
    if sig.base_status in (200, 201):
        score += 1
    return score

