"""
Legacy module name kept for compatibility.

The scanner previously confirmed vulnerabilities via reflection/keywords, which
creates large false-positive rates. The new default entrypoint is the
evidence-driven CLI in `vulnhunter.cli`.
"""

import os
import sys

if __package__ in (None, ""):
    # Support: cd vulnhunter && python3 main.py ...
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from vulnhunter.cli import main  # type: ignore
else:
    from .cli import main  # re-export


__all__ = ["main"]

if __name__ == "__main__":
    main()

