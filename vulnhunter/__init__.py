"""
VulnHunter - LLM-Powered Web Vulnerability Framework

A comprehensive security testing framework that uses Ollama LLM models
to intelligently hunt for vulnerabilities in web applications.

Features:
- Easy-to-use interface for LLM agents
- Comprehensive HTTP client with session management
- Intelligent web crawler and source code analyzer
- Multiple vulnerability scanners (SQLi, XSS, IDOR, SSRF, etc.)
- Payload generation with bypass techniques
- Web search for vulnerability research
- Professional HackerOne-style report generation
- Interactive and autonomous hunting modes

Usage:
    from vulnhunter import VulnHunterAgent
    
    agent = VulnHunterAgent("https://target.com", model="llama3.1:8b")
    findings = agent.run()
"""

__version__ = "1.0.0"
__author__ = "VulnHunter Team"

from .core import HTTPClient, SessionManager, WebCrawler, SourceCodeAnalyzer, Config
from .tools import LLMToolkit, WebSearcher, PayloadGenerator
from .scanners import SQLiScanner, XSSScanner, IDORScanner, SSRFScanner, AuthScanner
from .agents import OllamaAgent, VulnHunterAgent
from .reports import ReportGenerator

__all__ = [
    # Version
    '__version__',
    
    # Core
    'HTTPClient',
    'SessionManager', 
    'WebCrawler',
    'SourceCodeAnalyzer',
    'Config',
    
    # Tools
    'LLMToolkit',
    'WebSearcher',
    'PayloadGenerator',
    
    # Scanners
    'SQLiScanner',
    'XSSScanner',
    'IDORScanner',
    'SSRFScanner',
    'AuthScanner',
    
    # Agents
    'OllamaAgent',
    'VulnHunterAgent',
    
    # Reports
    'ReportGenerator',
]
