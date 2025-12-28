"""
Core data models for the evidence-driven scanner.

Design goals:
- The LLM may suggest hypotheses and payload ideas, but it must never "confirm" a vuln.
- Only deterministic verification code can set `confirmed=True`.
- "Response text / status / length differences alone" are not accepted as proof.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ProofKind(str, Enum):
    """Accepted proof signals for confirmation."""

    TIMING = "timing"
    OOB = "oob"


@dataclass(frozen=True)
class RequestSpec:
    """A reproducible HTTP request specification."""

    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    data: Optional[Dict[str, Any]] = None


@dataclass(frozen=True)
class ControlTest:
    """A control test demonstrating the finding is not a false positive."""

    description: str
    request: RequestSpec
    observation: str


@dataclass(frozen=True)
class Proof:
    """Machine-produced proof signal."""

    kind: ProofKind
    signal: str  # e.g. timing deltas summary, or OOB hit details
    request: RequestSpec  # request that produced the proof signal
    control: ControlTest  # paired control showing non-false-positive


@dataclass(frozen=True)
class Hypothesis:
    """LLM (or heuristic) hypothesis to be verified."""

    vuln_type: str
    target_url: str
    parameter: str
    rationale: str = ""
    payload_ideas: List[str] = field(default_factory=list)
    required_proof: List[ProofKind] = field(default_factory=list)


@dataclass
class Finding:
    """
    Output finding.

    - `confirmed=True` ONLY when `proof` is present (and created by verifier code).
    - `supporting_evidence` is allowed for triage but does not confirm anything.
    """

    vuln_type: str
    target_url: str
    parameter: str
    confirmed: bool
    payload: str = ""
    proof: Optional[Proof] = None
    supporting_evidence: List[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.vuln_type,
            "url": self.target_url,
            "param": self.parameter,
            "confirmed": self.confirmed,
            "payload": self.payload,
            "proof": None
            if not self.proof
            else {
                "kind": self.proof.kind.value,
                "signal": self.proof.signal,
                "request": {
                    "method": self.proof.request.method,
                    "url": self.proof.request.url,
                    "headers": self.proof.request.headers,
                    "data": self.proof.request.data,
                },
                "control": {
                    "description": self.proof.control.description,
                    "request": {
                        "method": self.proof.control.request.method,
                        "url": self.proof.control.request.url,
                        "headers": self.proof.control.request.headers,
                        "data": self.proof.control.request.data,
                    },
                    "observation": self.proof.control.observation,
                },
            },
            "supporting_evidence": self.supporting_evidence,
            "notes": self.notes,
        }

