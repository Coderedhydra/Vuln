"""
Configuration management for VulnHunter
"""

import os
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from pathlib import Path
import yaml
from loguru import logger


@dataclass
class OllamaConfig:
    """Ollama LLM Configuration"""
    host: str = "http://localhost:11434"
    model: str = "llama3.1:8b"
    timeout: int = 120
    context_length: int = 8192
    temperature: float = 0.7
    top_p: float = 0.9


@dataclass
class ScanConfig:
    """Scan Configuration"""
    max_depth: int = 5
    max_pages: int = 500
    timeout: int = 30
    concurrent_requests: int = 10
    rate_limit: float = 0.5  # seconds between requests
    follow_redirects: bool = True
    verify_ssl: bool = False
    user_agent: str = "VulnHunter/1.0 (Security Research)"


@dataclass  
class PayloadConfig:
    """Payload Testing Configuration"""
    test_sqli: bool = True
    test_xss: bool = True
    test_csrf: bool = True
    test_idor: bool = True
    test_ssrf: bool = True
    test_lfi: bool = True
    test_rce: bool = True
    test_auth_bypass: bool = True
    test_business_logic: bool = True
    aggressive_mode: bool = False


@dataclass
class ReportConfig:
    """Reporting Configuration"""
    output_format: str = "markdown"  # markdown, html, json
    output_dir: str = "./reports"
    include_requests: bool = True
    include_responses: bool = True
    severity_threshold: str = "low"  # low, medium, high, critical


@dataclass
class Config:
    """Main Configuration Container"""
    target_url: str = ""
    ollama: OllamaConfig = field(default_factory=OllamaConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    payload: PayloadConfig = field(default_factory=PayloadConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    
    # Authentication
    auth_username: Optional[str] = None
    auth_password: Optional[str] = None
    auth_token: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    
    # Scope
    in_scope_domains: List[str] = field(default_factory=list)
    out_of_scope_paths: List[str] = field(default_factory=list)
    
    @classmethod
    def from_yaml(cls, path: str) -> 'Config':
        """Load configuration from YAML file"""
        with open(path, 'r') as f:
            data = yaml.safe_load(f)
        return cls._from_dict(data)
    
    @classmethod
    def _from_dict(cls, data: Dict[str, Any]) -> 'Config':
        """Create config from dictionary"""
        config = cls()
        
        if 'target_url' in data:
            config.target_url = data['target_url']
        
        if 'ollama' in data:
            config.ollama = OllamaConfig(**data['ollama'])
            
        if 'scan' in data:
            config.scan = ScanConfig(**data['scan'])
            
        if 'payload' in data:
            config.payload = PayloadConfig(**data['payload'])
            
        if 'report' in data:
            config.report = ReportConfig(**data['report'])
            
        if 'auth_username' in data:
            config.auth_username = data['auth_username']
        if 'auth_password' in data:
            config.auth_password = data['auth_password']
        if 'auth_token' in data:
            config.auth_token = data['auth_token']
        if 'cookies' in data:
            config.cookies = data['cookies']
        if 'headers' in data:
            config.headers = data['headers']
        if 'in_scope_domains' in data:
            config.in_scope_domains = data['in_scope_domains']
        if 'out_of_scope_paths' in data:
            config.out_of_scope_paths = data['out_of_scope_paths']
            
        return config
    
    def to_yaml(self, path: str):
        """Save configuration to YAML file"""
        data = {
            'target_url': self.target_url,
            'ollama': {
                'host': self.ollama.host,
                'model': self.ollama.model,
                'timeout': self.ollama.timeout,
                'context_length': self.ollama.context_length,
                'temperature': self.ollama.temperature,
            },
            'scan': {
                'max_depth': self.scan.max_depth,
                'max_pages': self.scan.max_pages,
                'timeout': self.scan.timeout,
                'concurrent_requests': self.scan.concurrent_requests,
            },
            'payload': {
                'test_sqli': self.payload.test_sqli,
                'test_xss': self.payload.test_xss,
                'test_csrf': self.payload.test_csrf,
                'aggressive_mode': self.payload.aggressive_mode,
            },
            'report': {
                'output_format': self.report.output_format,
                'output_dir': self.report.output_dir,
            }
        }
        
        with open(path, 'w') as f:
            yaml.dump(data, f, default_flow_style=False)
        
        logger.info(f"Configuration saved to {path}")
