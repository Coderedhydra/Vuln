"""
Legacy module name kept for compatibility.

The previous implementation granted the LLM direct tool control and allowed
"confirmation" via response keywords/reflection, which caused high false
positives and could hallucinate findings.

Use the evidence-driven CLI:
- python -m vulnhunter <url>
- vulnhunter <url>
"""

from .cli import main

__all__ = ["main"]

