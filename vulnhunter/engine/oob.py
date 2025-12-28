"""
Out-of-band (OOB) collaborator interface.

This project cannot assume a specific external OOB provider. Instead, we support a
simple pollable protocol via user-supplied templates:

- callback_template: a URL template that will be *requested by the target* (SSRF).
  Example: "https://collab.example/cb/{token}"

- poll_template: a URL template that the scanner polls to verify hit.
  Example: "https://collab.example/poll/{token}"
  The poll endpoint must return JSON like: {"hit": true, "first_seen": "...", "raw": "..."}

If not configured, OOB-based verifiers are disabled.
"""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from ..core.http_client import HTTPClient


@dataclass(frozen=True)
class OOBHit:
    token: str
    hit: bool
    details: Dict[str, Any]


class SimplePollOOBClient:
    def __init__(
        self,
        http: Optional[HTTPClient] = None,
        callback_template: str = "",
        poll_template: str = "",
        poll_interval_s: float = 1.0,
        poll_timeout_s: float = 15.0,
    ):
        self.http = http or HTTPClient()
        self.callback_template = callback_template
        self.poll_template = poll_template
        self.poll_interval_s = poll_interval_s
        self.poll_timeout_s = poll_timeout_s

    def enabled(self) -> bool:
        return bool(self.callback_template and self.poll_template)

    def new_token(self) -> str:
        return secrets.token_urlsafe(18)

    def callback_url(self, token: str) -> str:
        return self.callback_template.format(token=token)

    def poll(self, token: str) -> OOBHit:
        if not self.enabled():
            return OOBHit(token=token, hit=False, details={"error": "oob_not_configured"})

        poll_url = self.poll_template.format(token=token)
        deadline = time.time() + self.poll_timeout_s

        last_error: Optional[str] = None
        while time.time() < deadline:
            resp = self.http.get(poll_url)
            if resp.status_code == 200:
                try:
                    data = json.loads(resp.body)
                    if bool(data.get("hit")):
                        return OOBHit(token=token, hit=True, details=data)
                    # keep polling until timeout
                except Exception as e:  # invalid JSON
                    last_error = f"invalid_json: {e}"
            else:
                last_error = f"status={resp.status_code}"

            time.sleep(self.poll_interval_s)

        return OOBHit(token=token, hit=False, details={"error": last_error or "timeout"})

