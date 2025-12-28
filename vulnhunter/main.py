"""
Legacy module name kept for compatibility.

The scanner previously confirmed vulnerabilities via reflection/keywords, which
creates large false-positive rates. The new default entrypoint is the
evidence-driven CLI in `vulnhunter.cli`.
"""

from .cli import main  # re-export


__all__ = ["main"]

