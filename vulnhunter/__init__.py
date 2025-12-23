"""
VulnHunter - AI-Powered Web Application Vulnerability Scanner

A sophisticated framework for finding security vulnerabilities in web applications
using Ollama LLM models. Designed to be easy for AI models to use while being
powerful enough to find critical vulnerabilities.

Usage:
    from vulnhunter import VulnHunterLLM
    
    hunter = VulnHunterLLM(model="llama3.1:8b")
    hunter.start("https://example.com")

Or via CLI:
    python -m vulnhunter -i -t https://example.com
"""

from .llm_interface import VulnHunterLLM, quick_hunt, manual_scan
from .tools.web_tools import WebTools
from .tools.search_tools import SearchTools
from .tools.report_tools import ReportTools, VulnerabilityReport
from .payloads.generator import PayloadGenerator
from .payloads.templates import PayloadTemplates

__version__ = "1.0.0"
__author__ = "VulnHunter Team"

__all__ = [
    'VulnHunterLLM',
    'quick_hunt',
    'manual_scan',
    'WebTools',
    'SearchTools',
    'ReportTools',
    'VulnerabilityReport',
    'PayloadGenerator',
    'PayloadTemplates'
]
