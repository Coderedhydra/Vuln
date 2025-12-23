"""
HTML Parser - Deep code analysis for LLM
Extract and analyze source code for vulnerabilities
"""

import re
import json
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin


@dataclass
class CodeBlock:
    """Represents a code block in the page"""
    code_type: str  # javascript, css, html, json, inline
    content: str
    location: str  # src URL or 'inline'
    line_count: int = 0
    
    def to_dict(self) -> Dict:
        return {
            "type": self.code_type,
            "content": self.content[:2000] if len(self.content) > 2000 else self.content,
            "full_length": len(self.content),
            "location": self.location,
            "lines": self.line_count
        }


@dataclass
class SecurityFinding:
    """A potential security issue in code"""
    severity: str  # critical, high, medium, low, info
    category: str  # xss, sqli, hardcoded_secret, etc.
    description: str
    code_snippet: str
    line_number: int = 0
    recommendation: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "code_snippet": self.code_snippet,
            "line_number": self.line_number,
            "recommendation": self.recommendation
        }


class HTMLParser:
    """
    Deep HTML and code parser for vulnerability analysis
    
    Usage for LLM:
    - parser.parse(html) - Parse HTML and extract all code
    - parser.analyze_security(html) - Find security issues
    - parser.extract_secrets(html) - Find hardcoded secrets
    - parser.get_javascript(html) - Get all JavaScript code
    - parser.find_sinks(html) - Find dangerous sinks (eval, innerHTML, etc.)
    """
    
    def __init__(self):
        # Patterns for security analysis
        self.secret_patterns = {
            "api_key": [
                r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
                r'apikey["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
            ],
            "aws_key": [
                r'AKIA[0-9A-Z]{16}',
                r'aws[_-]?access[_-]?key[_-]?id["\']?\s*[:=]\s*["\']([A-Z0-9]{20})["\']',
            ],
            "password": [
                r'password["\']?\s*[:=]\s*["\']([^"\']{4,})["\']',
                r'passwd["\']?\s*[:=]\s*["\']([^"\']{4,})["\']',
                r'secret["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',
            ],
            "jwt": [
                r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
            ],
            "private_key": [
                r'-----BEGIN (?:RSA )?PRIVATE KEY-----',
            ],
            "github_token": [
                r'gh[pousr]_[A-Za-z0-9_]{36}',
            ],
            "database_url": [
                r'(?:mysql|postgres|mongodb)://[^"\'\s]+',
            ],
        }
        
        self.xss_sinks = [
            'innerHTML', 'outerHTML', 'document.write', 'document.writeln',
            'eval', 'setTimeout', 'setInterval', 'Function',
            'insertAdjacentHTML', 'createContextualFragment',
            '.html(', '.append(', '.prepend(', '.after(', '.before(',
            'v-html', 'dangerouslySetInnerHTML',
        ]
        
        self.xss_sources = [
            'location.href', 'location.search', 'location.hash',
            'location.pathname', 'document.URL', 'document.documentURI',
            'document.referrer', 'window.name',
            '.val()', '.text()', '.attr(',
            'URLSearchParams', 'queryString',
        ]
        
        self.sqli_patterns = [
            r'SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*\+',
            r'query\s*\(\s*["\']SELECT.*\+',
            r'execute\s*\(\s*["\']SELECT.*\+',
            r'\$_(GET|POST|REQUEST)\[["\'][^\]]+["\']\].*(?:SELECT|INSERT|UPDATE|DELETE)',
        ]

    def parse(self, html: str, base_url: str = "") -> Dict[str, Any]:
        """
        Parse HTML and extract all relevant information
        
        Returns:
            Dict with scripts, styles, forms, comments, etc.
        """
        return {
            "scripts": self.get_javascript(html, base_url),
            "inline_scripts": self.get_inline_scripts(html),
            "styles": self.get_styles(html, base_url),
            "comments": self.get_comments(html),
            "hidden_inputs": self.get_hidden_inputs(html),
            "data_attributes": self.get_data_attributes(html),
            "event_handlers": self.get_event_handlers(html),
            "iframes": self.get_iframes(html),
            "config_objects": self.find_config_objects(html),
        }

    def get_javascript(self, html: str, base_url: str = "") -> List[Dict]:
        """Extract all JavaScript including external sources"""
        scripts = []
        
        # External scripts
        pattern = r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>'
        for match in re.finditer(pattern, html, re.IGNORECASE):
            src = match.group(1)
            if base_url:
                src = urljoin(base_url, src)
            scripts.append({
                "type": "external",
                "src": src,
                "content": None  # Would need to fetch
            })
        
        # Inline scripts
        pattern = r'<script[^>]*>(.*?)</script>'
        for match in re.finditer(pattern, html, re.IGNORECASE | re.DOTALL):
            content = match.group(1).strip()
            if content:
                scripts.append({
                    "type": "inline",
                    "src": None,
                    "content": content,
                    "lines": content.count('\n') + 1
                })
        
        return scripts

    def get_inline_scripts(self, html: str) -> List[str]:
        """Get only inline script content"""
        scripts = []
        pattern = r'<script[^>]*>(.*?)</script>'
        for match in re.finditer(pattern, html, re.IGNORECASE | re.DOTALL):
            content = match.group(1).strip()
            if content and 'src=' not in match.group(0):
                scripts.append(content)
        return scripts

    def get_styles(self, html: str, base_url: str = "") -> List[Dict]:
        """Extract CSS"""
        styles = []
        
        # External stylesheets
        pattern = r'<link[^>]*href=["\']([^"\']+\.css[^"\']*)["\'][^>]*>'
        for match in re.finditer(pattern, html, re.IGNORECASE):
            href = match.group(1)
            if base_url:
                href = urljoin(base_url, href)
            styles.append({"type": "external", "href": href})
        
        # Inline styles
        pattern = r'<style[^>]*>(.*?)</style>'
        for match in re.finditer(pattern, html, re.IGNORECASE | re.DOTALL):
            content = match.group(1).strip()
            if content:
                styles.append({"type": "inline", "content": content})
        
        return styles

    def get_comments(self, html: str) -> List[Dict]:
        """Extract HTML comments with context"""
        comments = []
        pattern = r'<!--(.*?)-->'
        for match in re.finditer(pattern, html, re.DOTALL):
            content = match.group(1).strip()
            if len(content) > 5:  # Skip empty/trivial comments
                # Check if it contains interesting patterns
                interesting = False
                keywords = ['todo', 'fixme', 'hack', 'bug', 'password', 'secret', 
                           'api', 'key', 'token', 'debug', 'admin', 'test']
                for kw in keywords:
                    if kw in content.lower():
                        interesting = True
                        break
                
                comments.append({
                    "content": content,
                    "interesting": interesting,
                    "length": len(content)
                })
        
        return comments

    def get_hidden_inputs(self, html: str) -> List[Dict]:
        """Extract hidden input fields"""
        inputs = []
        pattern = r'<input[^>]*type=["\']hidden["\'][^>]*>'
        for match in re.finditer(pattern, html, re.IGNORECASE):
            input_html = match.group(0)
            name_match = re.search(r'name=["\']([^"\']+)["\']', input_html)
            value_match = re.search(r'value=["\']([^"\']*)["\']', input_html)
            
            if name_match:
                inputs.append({
                    "name": name_match.group(1),
                    "value": value_match.group(1) if value_match else "",
                    "html": input_html
                })
        
        return inputs

    def get_data_attributes(self, html: str) -> List[Dict]:
        """Extract data-* attributes"""
        data_attrs = []
        pattern = r'data-([a-zA-Z0-9_-]+)=["\']([^"\']*)["\']'
        for match in re.finditer(pattern, html):
            data_attrs.append({
                "name": f"data-{match.group(1)}",
                "value": match.group(2)
            })
        return data_attrs

    def get_event_handlers(self, html: str) -> List[Dict]:
        """Extract inline event handlers (potential XSS)"""
        handlers = []
        event_attrs = [
            'onclick', 'onload', 'onerror', 'onmouseover', 'onfocus',
            'onblur', 'onsubmit', 'onchange', 'onkeyup', 'onkeydown',
            'onmouseenter', 'onmouseleave', 'ondblclick', 'oncontextmenu'
        ]
        
        for event in event_attrs:
            pattern = rf'{event}=["\']([^"\']+)["\']'
            for match in re.finditer(pattern, html, re.IGNORECASE):
                handlers.append({
                    "event": event,
                    "code": match.group(1)
                })
        
        return handlers

    def get_iframes(self, html: str) -> List[Dict]:
        """Extract iframes"""
        iframes = []
        pattern = r'<iframe([^>]*)>'
        for match in re.finditer(pattern, html, re.IGNORECASE):
            attrs = match.group(1)
            src_match = re.search(r'src=["\']([^"\']+)["\']', attrs)
            sandbox_match = re.search(r'sandbox=["\']([^"\']*)["\']', attrs)
            
            iframes.append({
                "src": src_match.group(1) if src_match else None,
                "sandbox": sandbox_match.group(1) if sandbox_match else None,
                "has_sandbox": 'sandbox' in attrs.lower()
            })
        
        return iframes

    def find_config_objects(self, html: str) -> List[Dict]:
        """Find JavaScript config objects that may contain sensitive data"""
        configs = []
        
        # Look for common config patterns
        patterns = [
            r'(?:var|let|const)\s+(?:config|CONFIG|settings|SETTINGS|options|OPTIONS)\s*=\s*(\{[^}]+\})',
            r'window\.(?:config|CONFIG|settings|SETTINGS)\s*=\s*(\{[^}]+\})',
            r'(?:config|settings|options)\s*:\s*(\{[^}]+\})',
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, html, re.DOTALL):
                try:
                    # Try to parse as JSON
                    obj_str = match.group(1)
                    # Clean up for JSON parsing
                    obj_str = re.sub(r'(\w+):', r'"\1":', obj_str)
                    obj_str = obj_str.replace("'", '"')
                    configs.append({
                        "raw": match.group(1),
                        "location": "inline_script"
                    })
                except:
                    pass
        
        return configs

    def analyze_security(self, html: str) -> Dict[str, List[SecurityFinding]]:
        """
        Analyze code for security issues
        
        Returns:
            Dict with findings by category
        """
        findings = {
            "secrets": self.extract_secrets(html),
            "xss_sinks": self.find_xss_sinks(html),
            "dangerous_functions": self.find_dangerous_functions(html),
            "insecure_patterns": self.find_insecure_patterns(html),
        }
        return findings

    def extract_secrets(self, html: str) -> List[SecurityFinding]:
        """Find hardcoded secrets and credentials"""
        findings = []
        
        for secret_type, patterns in self.secret_patterns.items():
            for pattern in patterns:
                for match in re.finditer(pattern, html, re.IGNORECASE):
                    # Get surrounding context
                    start = max(0, match.start() - 50)
                    end = min(len(html), match.end() + 50)
                    context = html[start:end]
                    
                    findings.append(SecurityFinding(
                        severity="critical" if secret_type in ["aws_key", "private_key", "jwt"] else "high",
                        category=f"hardcoded_{secret_type}",
                        description=f"Potential {secret_type.replace('_', ' ')} found in source code",
                        code_snippet=context,
                        recommendation=f"Remove hardcoded {secret_type} and use environment variables"
                    ))
        
        return findings

    def find_xss_sinks(self, html: str) -> List[SecurityFinding]:
        """Find potential XSS sinks in JavaScript"""
        findings = []
        scripts = self.get_inline_scripts(html)
        
        for script in scripts:
            lines = script.split('\n')
            for i, line in enumerate(lines):
                for sink in self.xss_sinks:
                    if sink in line:
                        # Check if it uses user input
                        uses_source = any(source in line for source in self.xss_sources)
                        severity = "high" if uses_source else "medium"
                        
                        findings.append(SecurityFinding(
                            severity=severity,
                            category="xss_sink",
                            description=f"Potential XSS sink: {sink}",
                            code_snippet=line.strip(),
                            line_number=i + 1,
                            recommendation=f"Sanitize input before using {sink}"
                        ))
        
        return findings

    def find_dangerous_functions(self, html: str) -> List[SecurityFinding]:
        """Find dangerous JavaScript functions"""
        findings = []
        dangerous = {
            'eval(': ('critical', 'Code injection risk'),
            'Function(': ('critical', 'Code injection risk'),
            'setTimeout(.*\\+': ('high', 'Potential code injection'),
            'setInterval(.*\\+': ('high', 'Potential code injection'),
            'document.write(': ('medium', 'DOM XSS risk'),
            'innerHTML.*=.*\\+': ('high', 'DOM XSS risk'),
            'outerHTML.*=.*\\+': ('high', 'DOM XSS risk'),
            '\\.html\\(': ('medium', 'jQuery XSS risk'),
            'location\\.href\\s*=': ('medium', 'Open redirect risk'),
            'window\\.open\\(': ('low', 'Popup/redirect risk'),
        }
        
        scripts = self.get_inline_scripts(html)
        for script in scripts:
            for pattern, (severity, desc) in dangerous.items():
                for match in re.finditer(pattern, script, re.IGNORECASE):
                    # Get line context
                    start = max(0, match.start() - 50)
                    end = min(len(script), match.end() + 50)
                    
                    findings.append(SecurityFinding(
                        severity=severity,
                        category="dangerous_function",
                        description=desc,
                        code_snippet=script[start:end],
                        recommendation="Review and sanitize inputs"
                    ))
        
        return findings

    def find_insecure_patterns(self, html: str) -> List[SecurityFinding]:
        """Find insecure coding patterns"""
        findings = []
        
        patterns = {
            # Insecure form actions
            r'<form[^>]*action=["\']http://': (
                'medium', 'insecure_form', 'Form submits over HTTP'
            ),
            # Missing CSRF tokens
            r'<form[^>]*method=["\']post["\'][^>]*>(?:(?!</form>).)*?<input[^>]*type=["\']submit["\']': (
                'medium', 'missing_csrf', 'Form may be missing CSRF protection'
            ),
            # Autocomplete on sensitive fields
            r'<input[^>]*type=["\']password["\'][^>]*(?!autocomplete=["\']off)': (
                'low', 'autocomplete_password', 'Password field allows autocomplete'
            ),
            # Debug mode indicators
            r'(?:debug|DEBUG)\s*[:=]\s*(?:true|1|True)': (
                'medium', 'debug_mode', 'Debug mode may be enabled'
            ),
            # Source maps
            r'//# sourceMappingURL=': (
                'low', 'source_map', 'Source map exposed'
            ),
        }
        
        for pattern, (severity, category, description) in patterns.items():
            for match in re.finditer(pattern, html, re.IGNORECASE | re.DOTALL):
                findings.append(SecurityFinding(
                    severity=severity,
                    category=category,
                    description=description,
                    code_snippet=match.group(0)[:200]
                ))
        
        return findings

    def extract_urls_from_js(self, js_code: str) -> List[str]:
        """Extract URLs from JavaScript code"""
        urls = []
        patterns = [
            r'["\']((https?://|/)[^"\']+)["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
            r'\$\.(ajax|get|post)\s*\(\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, js_code):
                url = match.group(1)
                if url and len(url) > 3:
                    urls.append(url)
        
        return list(set(urls))

    def extract_api_info(self, html: str) -> Dict[str, Any]:
        """Extract API-related information from JavaScript"""
        info = {
            "endpoints": [],
            "methods": [],
            "auth_headers": [],
            "content_types": []
        }
        
        scripts = self.get_inline_scripts(html)
        for script in scripts:
            # Find endpoints
            info["endpoints"].extend(self.extract_urls_from_js(script))
            
            # Find HTTP methods
            methods = re.findall(r'method\s*:\s*["\'](\w+)["\']', script, re.IGNORECASE)
            info["methods"].extend(methods)
            
            # Find auth headers
            auth_patterns = [
                r'Authorization["\']?\s*:\s*["\']([^"\']+)["\']',
                r'X-API-Key["\']?\s*:\s*["\']([^"\']+)["\']',
                r'Bearer\s+([a-zA-Z0-9_\-\.]+)',
            ]
            for pattern in auth_patterns:
                matches = re.findall(pattern, script, re.IGNORECASE)
                info["auth_headers"].extend(matches)
            
            # Find content types
            ct_matches = re.findall(r'Content-Type["\']?\s*:\s*["\']([^"\']+)["\']', script, re.IGNORECASE)
            info["content_types"].extend(ct_matches)
        
        # Deduplicate
        for key in info:
            info[key] = list(set(info[key]))
        
        return info

    def get_full_analysis(self, html: str, base_url: str = "") -> Dict[str, Any]:
        """
        Complete page analysis for LLM
        
        Returns comprehensive analysis including:
        - All code extracted
        - Security findings
        - API information
        - Interesting elements
        """
        parsed = self.parse(html, base_url)
        security = self.analyze_security(html)
        api_info = self.extract_api_info(html)
        
        return {
            "parsed_elements": parsed,
            "security_findings": {
                k: [f.to_dict() for f in v] 
                for k, v in security.items()
            },
            "api_info": api_info,
            "summary": {
                "total_scripts": len(parsed["scripts"]),
                "total_comments": len(parsed["comments"]),
                "hidden_inputs": len(parsed["hidden_inputs"]),
                "event_handlers": len(parsed["event_handlers"]),
                "security_issues": sum(len(v) for v in security.values()),
                "endpoints_found": len(api_info["endpoints"])
            }
        }
