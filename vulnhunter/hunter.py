"""
Legacy module name kept for compatibility.

The previous implementation granted the LLM direct tool control and allowed
"confirmation" via response keywords/reflection, which caused high false
positives and could hallucinate findings.

Use the evidence-driven CLI:
- python -m vulnhunter <url>
- vulnhunter <url>
"""

import os
import sys

if __package__ in (None, ""):
    # Support: cd vulnhunter && python3 hunter.py ...
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from vulnhunter.cli import main  # type: ignore
else:
    from .cli import main

__all__ = ["main"]

if __name__ == "__main__":
    main()

