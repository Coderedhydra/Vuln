"""
Source Code Analyzer for VulnHunter
Analyzes HTML, JavaScript, and other client-side code for vulnerabilities
"""

import re
from typing import Optional, Dict, List, Set, Any, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse
from loguru import logger


@dataclass
class CodeFinding:
    """A finding in source code analysis"""
    finding_type: str  # secret, endpoint, vulnerability, etc.
    severity: str  # info, low, medium, high, critical
    description: str
    location: str  # file or URL
    line_number: int = 0
    code_snippet: str = ""
    confidence: str = "medium"  # low, medium, high
    
    def to_dict(self) -> Dict:
        return {
            "type": self.finding_type,
            "severity": self.severity,
            "description": self.description,
            "location": self.location,
            "line": self.line_number,
            "snippet": self.code_snippet[:200],
            "confidence": self.confidence,
        }


@dataclass
class SourceAnalysisResult:
    """Complete source analysis results"""
    url: str
    findings: List[CodeFinding] = field(default_factory=list)
    
    # Extracted data
    api_endpoints: List[str] = field(default_factory=list)
    secrets: List[Dict] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)
    hidden_fields: List[Dict] = field(default_factory=list)
    
    # Technology detection
    frameworks: List[str] = field(default_factory=list)
    libraries: List[str] = field(default_factory=list)
    
    def to_llm_summary(self) -> str:
        """Generate summary for LLM"""
        findings_by_severity = {}
        for f in self.findings:
            if f.severity not in findings_by_severity:
                findings_by_severity[f.severity] = []
            findings_by_severity[f.severity].append(f)
            
        summary = f"""
=== Source Analysis: {self.url} ===

Findings by Severity:
  Critical: {len(findings_by_severity.get('critical', []))}
  High: {len(findings_by_severity.get('high', []))}
  Medium: {len(findings_by_severity.get('medium', []))}
  Low: {len(findings_by_severity.get('low', []))}
  Info: {len(findings_by_severity.get('info', []))}

API Endpoints Found: {len(self.api_endpoints)}
Secrets/Keys Found: {len(self.secrets)}
Hidden Fields: {len(self.hidden_fields)}

Detected Technologies:
  Frameworks: {', '.join(self.frameworks) or 'Unknown'}
  Libraries: {', '.join(self.libraries) or 'Unknown'}

Top Findings:
{self._format_top_findings()}
===============================
"""
        return summary
    
    def _format_top_findings(self) -> str:
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_findings = sorted(self.findings, key=lambda f: severity_order.get(f.severity, 5))
        
        lines = []
        for f in sorted_findings[:10]:
            lines.append(f"  [{f.severity.upper()}] {f.description[:80]}")
        return "\n".join(lines) if lines else "  (none)"


class SourceCodeAnalyzer:
    """
    Analyzes source code for vulnerabilities, secrets, and useful information
    """
    
    def __init__(self):
        # Secret patterns
        self.secret_patterns = {
            'aws_access_key': r'AKIA[0-9A-Z]{16}',
            'aws_secret_key': r'[A-Za-z0-9/+=]{40}',
            'api_key': r'["\']?(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            'bearer_token': r'["\']?bearer["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            'jwt_token': r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
            'private_key': r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
            'google_api': r'AIza[0-9A-Za-z_-]{35}',
            'github_token': r'gh[ps]_[A-Za-z0-9_]{36}',
            'slack_token': r'xox[baprs]-[0-9a-zA-Z]{10,48}',
            'stripe_key': r'sk_live_[0-9a-zA-Z]{24}',
            'password_field': r'["\']?(?:password|passwd|pwd|secret)["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            'connection_string': r'(?:mongodb|mysql|postgresql|redis)://[^\s"\']+',
            'basic_auth': r'Basic\s+[A-Za-z0-9+/=]+',
        }
        
        # Vulnerability patterns in code
        self.vuln_patterns = {
            'innerHTML': {
                'pattern': r'\.innerHTML\s*=',
                'description': 'Potential DOM XSS via innerHTML',
                'severity': 'medium',
            },
            'document.write': {
                'pattern': r'document\.write\s*\(',
                'description': 'Potential DOM XSS via document.write',
                'severity': 'medium',
            },
            'eval': {
                'pattern': r'\beval\s*\(',
                'description': 'Use of eval() - potential code injection',
                'severity': 'high',
            },
            'location.href': {
                'pattern': r'location\.href\s*=',
                'description': 'Dynamic location change - potential open redirect',
                'severity': 'low',
            },
            'url_param_direct': {
                'pattern': r'(?:location\.search|URLSearchParams).*(?:innerHTML|document\.write)',
                'description': 'URL parameter directly used in DOM - XSS',
                'severity': 'high',
            },
            'postMessage': {
                'pattern': r'addEventListener\s*\(\s*["\']message["\']',
                'description': 'postMessage listener - check origin validation',
                'severity': 'medium',
            },
            'localStorage': {
                'pattern': r'localStorage\.(getItem|setItem)',
                'description': 'localStorage usage - check for sensitive data',
                'severity': 'info',
            },
            'cookie_access': {
                'pattern': r'document\.cookie',
                'description': 'Direct cookie access',
                'severity': 'info',
            },
            'setTimeout_string': {
                'pattern': r'setTimeout\s*\(\s*["\']',
                'description': 'setTimeout with string argument - potential injection',
                'severity': 'medium',
            },
            'jquery_html': {
                'pattern': r'\$\([^)]+\)\.html\s*\(',
                'description': 'jQuery .html() usage - potential XSS',
                'severity': 'medium',
            },
            'unsafe_link': {
                'pattern': r'href\s*=\s*["\']javascript:',
                'description': 'JavaScript in href - potential XSS',
                'severity': 'medium',
            },
            'cors_wildcard': {
                'pattern': r'Access-Control-Allow-Origin["\']?\s*[:=]\s*["\']?\*',
                'description': 'CORS wildcard origin',
                'severity': 'medium',
            },
        }
        
        # Framework detection
        self.framework_signatures = {
            'React': [r'react', r'ReactDOM', r'__REACT_DEVTOOLS'],
            'Angular': [r'ng-app', r'angular', r'@angular'],
            'Vue': [r'Vue\.', r'v-bind', r'v-model', r'__VUE__'],
            'jQuery': [r'jQuery', r'\$\('],
            'Bootstrap': [r'bootstrap', r'class="[^"]*btn-'],
            'Laravel': [r'laravel', r'_token', r'csrf-token'],
            'Django': [r'csrfmiddlewaretoken', r'django'],
            'WordPress': [r'wp-content', r'wp-includes', r'wordpress'],
            'Express': [r'express', r'X-Powered-By.*Express'],
            'Next.js': [r'__NEXT_DATA__', r'_next/static'],
            'Nuxt.js': [r'__NUXT__', r'_nuxt'],
        }
        
    def analyze_html(self, html: str, url: str) -> SourceAnalysisResult:
        """
        Analyze HTML source code
        
        LLM Usage:
            result = analyzer.analyze_html(page_content, "https://target.com/page")
        """
        from bs4 import BeautifulSoup
        
        result = SourceAnalysisResult(url=url)
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Extract comments
            comments = soup.find_all(string=lambda text: isinstance(text, str) and '<!--' in str(text) or '-->' in str(text))
            for comment in comments:
                result.comments.append(str(comment)[:500])
                
            # Also find comment nodes
            import re
            html_comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
            for comment in html_comments:
                comment = comment.strip()
                if comment and len(comment) > 5:
                    result.comments.append(comment[:500])
                    
                    # Check for sensitive info in comments
                    if any(kw in comment.lower() for kw in ['password', 'secret', 'key', 'token', 'todo', 'fixme', 'hack', 'admin']):
                        result.findings.append(CodeFinding(
                            finding_type='sensitive_comment',
                            severity='info',
                            description=f'Potentially sensitive comment: {comment[:100]}',
                            location=url,
                            code_snippet=comment[:200],
                        ))
            
            # Hidden form fields
            for hidden in soup.find_all('input', {'type': 'hidden'}):
                name = hidden.get('name', '')
                value = hidden.get('value', '')
                result.hidden_fields.append({'name': name, 'value': value[:100]})
                
                # Check for interesting hidden values
                if any(kw in name.lower() for kw in ['id', 'user', 'admin', 'role', 'debug']):
                    result.findings.append(CodeFinding(
                        finding_type='hidden_field',
                        severity='info',
                        description=f'Interesting hidden field: {name}={value[:50]}',
                        location=url,
                        code_snippet=str(hidden),
                    ))
            
            # Inline scripts
            for script in soup.find_all('script'):
                if script.string:
                    script_findings = self.analyze_javascript(script.string, f"{url}#inline")
                    result.findings.extend(script_findings.findings)
                    result.api_endpoints.extend(script_findings.api_endpoints)
                    result.secrets.extend(script_findings.secrets)
                    
            # Detect frameworks
            result.frameworks = self._detect_frameworks(html)
            
            # Check for debug mode indicators
            debug_patterns = [
                (r'debug\s*[:=]\s*true', 'Debug mode enabled'),
                (r'development', 'Development mode indicator'),
                (r'console\.(log|debug|error)', 'Console output in production'),
                (r'sourceMappingURL', 'Source map available'),
            ]
            
            for pattern, desc in debug_patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    result.findings.append(CodeFinding(
                        finding_type='debug_indicator',
                        severity='info',
                        description=desc,
                        location=url,
                    ))
                    
        except Exception as e:
            logger.error(f"Error analyzing HTML: {e}")
            
        return result
    
    def analyze_javascript(self, js_code: str, source: str) -> SourceAnalysisResult:
        """
        Analyze JavaScript code
        
        LLM Usage:
            result = analyzer.analyze_javascript(js_content, "https://target.com/app.js")
        """
        result = SourceAnalysisResult(url=source)
        
        # Check for secrets
        for secret_type, pattern in self.secret_patterns.items():
            matches = re.finditer(pattern, js_code, re.IGNORECASE)
            for match in matches:
                # Get context
                start = max(0, match.start() - 50)
                end = min(len(js_code), match.end() + 50)
                snippet = js_code[start:end]
                
                # Find line number
                line_num = js_code[:match.start()].count('\n') + 1
                
                result.secrets.append({
                    'type': secret_type,
                    'value': match.group()[:50] + '...',
                    'line': line_num,
                })
                
                result.findings.append(CodeFinding(
                    finding_type='secret',
                    severity='high' if 'key' in secret_type or 'token' in secret_type else 'medium',
                    description=f'Potential {secret_type} found',
                    location=source,
                    line_number=line_num,
                    code_snippet=snippet,
                    confidence='medium',
                ))
                
        # Check for vulnerability patterns
        for vuln_name, vuln_info in self.vuln_patterns.items():
            matches = re.finditer(vuln_info['pattern'], js_code, re.IGNORECASE)
            for match in matches:
                start = max(0, match.start() - 30)
                end = min(len(js_code), match.end() + 50)
                snippet = js_code[start:end]
                line_num = js_code[:match.start()].count('\n') + 1
                
                result.findings.append(CodeFinding(
                    finding_type='vulnerability',
                    severity=vuln_info['severity'],
                    description=vuln_info['description'],
                    location=source,
                    line_number=line_num,
                    code_snippet=snippet,
                ))
                
        # Extract API endpoints
        api_patterns = [
            r'["\']/(api|v\d+)/[^"\']+["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
            r'url:\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, js_code, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0] if match[0] else match[1] if len(match) > 1 else ''
                if match and ('/' in match or 'http' in match):
                    result.api_endpoints.append(match)
                    
        # Deduplicate endpoints
        result.api_endpoints = list(set(result.api_endpoints))
        
        # Detect libraries
        lib_patterns = {
            'jQuery': r'\$\.',
            'Axios': r'axios\.',
            'Lodash': r'_\.[a-z]+',
            'Moment': r'moment\(',
            'Socket.io': r'io\s*\(',
            'Chart.js': r'Chart\(',
        }
        
        for lib, pattern in lib_patterns.items():
            if re.search(pattern, js_code):
                result.libraries.append(lib)
                
        return result
    
    def _detect_frameworks(self, html: str) -> List[str]:
        """Detect web frameworks from HTML"""
        detected = []
        
        for framework, patterns in self.framework_signatures.items():
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    if framework not in detected:
                        detected.append(framework)
                    break
                    
        return detected
    
    def analyze_headers(self, headers: Dict[str, str]) -> List[CodeFinding]:
        """
        Analyze HTTP response headers for security issues
        
        LLM Usage:
            findings = analyzer.analyze_headers(response.headers)
        """
        findings = []
        
        # Security headers to check
        security_headers = {
            'X-Frame-Options': ('missing_xfo', 'medium', 'Missing X-Frame-Options header - clickjacking possible'),
            'X-Content-Type-Options': ('missing_xcto', 'low', 'Missing X-Content-Type-Options header'),
            'X-XSS-Protection': ('missing_xss', 'low', 'Missing X-XSS-Protection header'),
            'Content-Security-Policy': ('missing_csp', 'medium', 'Missing Content-Security-Policy header'),
            'Strict-Transport-Security': ('missing_hsts', 'medium', 'Missing HSTS header'),
        }
        
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        for header, (finding_type, severity, desc) in security_headers.items():
            if header.lower() not in headers_lower:
                findings.append(CodeFinding(
                    finding_type=finding_type,
                    severity=severity,
                    description=desc,
                    location='HTTP Headers',
                ))
                
        # Check for information disclosure
        info_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']
        for header in info_headers:
            if header.lower() in headers_lower:
                value = headers_lower[header.lower()]
                findings.append(CodeFinding(
                    finding_type='info_disclosure',
                    severity='info',
                    description=f'Information disclosure in {header}: {value}',
                    location='HTTP Headers',
                    code_snippet=f'{header}: {value}',
                ))
                
        # Check for insecure cookies
        if 'set-cookie' in headers_lower:
            cookie = headers_lower['set-cookie']
            
            if 'httponly' not in cookie.lower():
                findings.append(CodeFinding(
                    finding_type='insecure_cookie',
                    severity='low',
                    description='Cookie missing HttpOnly flag',
                    location='HTTP Headers',
                    code_snippet=cookie[:100],
                ))
                
            if 'secure' not in cookie.lower():
                findings.append(CodeFinding(
                    finding_type='insecure_cookie',
                    severity='low',
                    description='Cookie missing Secure flag',
                    location='HTTP Headers',
                    code_snippet=cookie[:100],
                ))
                
            if 'samesite' not in cookie.lower():
                findings.append(CodeFinding(
                    finding_type='insecure_cookie',
                    severity='low',
                    description='Cookie missing SameSite attribute',
                    location='HTTP Headers',
                    code_snippet=cookie[:100],
                ))
                
        # Check CORS
        if 'access-control-allow-origin' in headers_lower:
            origin = headers_lower['access-control-allow-origin']
            if origin == '*':
                findings.append(CodeFinding(
                    finding_type='cors_misconfiguration',
                    severity='medium',
                    description='CORS allows any origin (*)',
                    location='HTTP Headers',
                ))
                
        return findings
    
    def full_analysis(self, html: str, headers: Dict[str, str], url: str) -> SourceAnalysisResult:
        """
        Perform complete analysis of a page
        
        LLM Usage:
            result = analyzer.full_analysis(response.body, response.headers, response.url)
        """
        result = self.analyze_html(html, url)
        
        # Add header findings
        header_findings = self.analyze_headers(headers)
        result.findings.extend(header_findings)
        
        return result
