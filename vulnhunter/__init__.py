"""
VulnHunter - Autonomous AI Bug Bounty Hunter

Just give it a URL - the AI does everything:
- Discovers forms, parameters, endpoints
- Analyzes code and understands the app
- Creates smart payloads
- Tests and exploits vulnerabilities  
- Reports confirmed findings

Usage:
    from vulnhunter import VulnHunterLLM
    
    hunter = VulnHunterLLM(model="llama3.1:8b")
    hunter.start("https://example.com")

Or via CLI:
    python main.py https://example.com
"""

from .llm_interface import VulnHunterLLM, RealWebClient, quick_scan, manual_scan
from .tools.web_tools import WebTools
from .tools.search_tools import SearchTools
from .tools.report_tools import ReportTools, VulnerabilityReport
from .payloads.generator import PayloadGenerator
from .payloads.templates import PayloadTemplates

__version__ = "1.0.0"
__author__ = "VulnHunter Team"

__all__ = [
    'VulnHunterLLM',
    'RealWebClient',
    'quick_scan',
    'manual_scan',
    'WebTools',
    'SearchTools',
    'ReportTools',
    'VulnerabilityReport',
    'PayloadGenerator',
    'PayloadTemplates'
]
