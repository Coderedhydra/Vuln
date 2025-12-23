"""
VulnHunter Configuration
Default settings and configuration options
"""

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Config:
    """VulnHunter configuration"""
    
    # Ollama Settings
    ollama_host: str = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    default_model: str = os.getenv("VULNHUNTER_MODEL", "llama3.1:8b")
    
    # HTTP Settings
    timeout: int = 30
    max_redirects: int = 10
    verify_ssl: bool = True
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    
    # Crawling Settings
    max_pages: int = 100
    crawl_depth: int = 2
    same_domain_only: bool = True
    
    # Scanning Settings
    max_payloads_per_param: int = 50
    time_based_delay: int = 5  # seconds
    scan_timeout: int = 300  # seconds
    
    # Rate Limiting
    requests_per_second: float = 10.0
    delay_between_requests: float = 0.1  # seconds
    
    # Output Settings
    save_responses: bool = False
    output_dir: str = "./vulnhunter_output"
    report_format: str = "markdown"  # markdown, json, html
    
    # Security
    respect_robots_txt: bool = False
    follow_external_links: bool = False
    
    # Payloads
    custom_payloads_dir: Optional[str] = None
    
    # Proxy
    proxy: Optional[str] = None  # e.g., "http://127.0.0.1:8080"
    
    def to_dict(self) -> Dict:
        """Convert config to dictionary"""
        return {
            "ollama_host": self.ollama_host,
            "default_model": self.default_model,
            "timeout": self.timeout,
            "max_pages": self.max_pages,
            "crawl_depth": self.crawl_depth,
            "proxy": self.proxy
        }


# Default configuration
DEFAULT_CONFIG = Config()


# Severity levels
SEVERITY_LEVELS = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0
}


# CVSS to Severity mapping
def cvss_to_severity(score: float) -> str:
    """Convert CVSS score to severity level"""
    if score >= 9.0:
        return "critical"
    elif score >= 7.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    elif score >= 0.1:
        return "low"
    return "info"


# Interesting file extensions
INTERESTING_EXTENSIONS = [
    ".php", ".asp", ".aspx", ".jsp", ".py", ".rb", ".pl",
    ".cgi", ".do", ".action", ".html", ".htm", ".json",
    ".xml", ".txt", ".conf", ".config", ".ini", ".yml",
    ".yaml", ".env", ".bak", ".backup", ".old", ".zip",
    ".tar", ".gz", ".sql", ".db", ".log"
]


# Interesting paths to check
INTERESTING_PATHS = [
    # Admin paths
    "/admin", "/administrator", "/admin.php", "/admin.html",
    "/wp-admin", "/wp-login.php", "/phpmyadmin", "/adminer.php",
    "/manager", "/dashboard", "/cpanel", "/controlpanel",
    
    # API paths
    "/api", "/api/v1", "/api/v2", "/rest", "/graphql",
    "/swagger", "/swagger-ui", "/api-docs", "/openapi.json",
    
    # Auth paths
    "/login", "/signin", "/auth", "/authenticate",
    "/logout", "/signout", "/register", "/signup",
    "/forgot-password", "/reset-password", "/oauth",
    
    # Config/Info paths
    "/.env", "/.git", "/.git/config", "/.svn",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/phpinfo.php", "/info.php", "/server-status",
    "/server-info", "/.htaccess", "/web.config",
    
    # Backup paths
    "/backup", "/backups", "/db", "/database",
    "/dump.sql", "/backup.sql", "/data.sql",
    
    # Debug paths
    "/debug", "/test", "/dev", "/staging",
    "/console", "/shell", "/cmd",
]


# Common parameters that might be vulnerable
INTERESTING_PARAMS = {
    # XSS candidates
    "xss": ["q", "search", "query", "keyword", "s", "name", "title",
            "message", "comment", "text", "content", "body", "input",
            "value", "data", "redirect", "url", "return", "next"],
    
    # SQLi candidates
    "sqli": ["id", "user_id", "uid", "userid", "item_id", "product_id",
             "category", "cat", "page", "article", "news", "post",
             "order", "sort", "limit", "offset", "filter"],
    
    # LFI candidates
    "lfi": ["file", "page", "path", "doc", "document", "template",
            "include", "load", "read", "view", "display", "show"],
    
    # SSRF candidates  
    "ssrf": ["url", "link", "src", "source", "dest", "destination",
             "redirect", "return", "next", "fetch", "proxy", "request"],
    
    # Command injection candidates
    "cmd": ["cmd", "command", "exec", "execute", "run", "ping",
            "host", "ip", "query", "process", "daemon"],
}
