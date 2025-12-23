"""
Web Search Module for VulnHunter
Search the internet for vulnerability information, CVEs, and security research
"""

import re
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field
from loguru import logger


@dataclass
class SearchResult:
    """A single search result"""
    title: str
    url: str
    snippet: str
    source: str = ""


@dataclass
class VulnerabilityInfo:
    """Vulnerability information from research"""
    cve_id: str = ""
    title: str = ""
    description: str = ""
    severity: str = ""
    cvss_score: float = 0.0
    affected_products: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    exploit_available: bool = False
    poc_url: str = ""


class WebSearcher:
    """
    Web search for vulnerability research
    Uses DuckDuckGo and other sources for security information
    """
    
    def __init__(self):
        self._ddg_available = False
        try:
            from duckduckgo_search import DDGS
            self._ddg_available = True
        except ImportError:
            logger.warning("duckduckgo-search not installed. Web search limited.")
    
    def search(self, query: str, max_results: int = 10) -> List[SearchResult]:
        """
        Perform a web search
        
        LLM Usage:
            results = searcher.search("SQL injection bypass techniques")
        """
        results = []
        
        if self._ddg_available:
            try:
                from duckduckgo_search import DDGS
                
                with DDGS() as ddgs:
                    search_results = ddgs.text(query, max_results=max_results)
                    
                    for r in search_results:
                        results.append(SearchResult(
                            title=r.get('title', ''),
                            url=r.get('href', ''),
                            snippet=r.get('body', ''),
                            source='duckduckgo'
                        ))
            except Exception as e:
                logger.error(f"Search error: {e}")
        
        return results
    
    def search_vulnerability(self, tech: str, vuln_type: str) -> List[SearchResult]:
        """
        Search for vulnerabilities in specific technology
        
        LLM Usage:
            results = searcher.search_vulnerability("WordPress 6.0", "SQL injection")
        """
        query = f"{tech} {vuln_type} vulnerability exploit CVE"
        return self.search(query)
    
    def search_cve(self, cve_id: str) -> VulnerabilityInfo:
        """
        Search for CVE details
        
        LLM Usage:
            info = searcher.search_cve("CVE-2021-44228")
        """
        info = VulnerabilityInfo(cve_id=cve_id)
        
        # Search for CVE info
        results = self.search(f"{cve_id} vulnerability details")
        
        if results:
            info.title = results[0].title
            info.description = results[0].snippet
            info.references = [r.url for r in results[:5]]
        
        # Try to extract severity from results
        for r in results:
            snippet_lower = r.snippet.lower()
            if 'critical' in snippet_lower:
                info.severity = 'critical'
            elif 'high' in snippet_lower:
                info.severity = 'high'
            elif 'medium' in snippet_lower:
                info.severity = 'medium'
            
            # Look for CVSS score
            cvss_match = re.search(r'cvss[:\s]*(\d+\.?\d*)', snippet_lower)
            if cvss_match:
                info.cvss_score = float(cvss_match.group(1))
        
        return info
    
    def search_exploit(self, technology: str, version: str = "") -> List[SearchResult]:
        """
        Search for exploits for a technology
        
        LLM Usage:
            results = searcher.search_exploit("Apache Struts", "2.5.20")
        """
        query = f"{technology} {version} exploit poc github".strip()
        return self.search(query)
    
    def search_hackerone(self, technology: str, vuln_type: str = "") -> List[SearchResult]:
        """
        Search HackerOne reports for similar vulnerabilities
        
        LLM Usage:
            results = searcher.search_hackerone("IDOR", "API")
        """
        query = f"site:hackerone.com {technology} {vuln_type} disclosed"
        return self.search(query)
    
    def search_payloads(self, vuln_type: str) -> List[SearchResult]:
        """
        Search for vulnerability payloads
        
        LLM Usage:
            results = searcher.search_payloads("XSS filter bypass")
        """
        query = f"{vuln_type} payload bypass cheatsheet"
        return self.search(query)
    
    def search_writeups(self, vuln_type: str, target_type: str = "") -> List[SearchResult]:
        """
        Search for bug bounty writeups
        
        LLM Usage:
            results = searcher.search_writeups("SSRF", "AWS")
        """
        query = f"{vuln_type} {target_type} bug bounty writeup medium"
        return self.search(query)
    
    def search_bypass_techniques(self, protection: str) -> List[SearchResult]:
        """
        Search for WAF/protection bypass techniques
        
        LLM Usage:
            results = searcher.search_bypass_techniques("Cloudflare WAF")
        """
        query = f"{protection} bypass techniques security research"
        return self.search(query)
    
    def get_technology_vulns(self, technology: str, version: str = "") -> List[Dict]:
        """
        Get known vulnerabilities for a technology
        
        LLM Usage:
            vulns = searcher.get_technology_vulns("nginx", "1.18.0")
        """
        vulns = []
        
        # Search for CVEs
        query = f"{technology} {version} CVE vulnerability list".strip()
        results = self.search(query)
        
        for r in results:
            # Extract CVE IDs from results
            cve_matches = re.findall(r'CVE-\d{4}-\d+', r.title + ' ' + r.snippet, re.I)
            
            for cve in set(cve_matches):
                vulns.append({
                    'cve': cve,
                    'title': r.title,
                    'source': r.url,
                })
        
        return vulns
    
    def research_target(self, domain: str) -> Dict[str, Any]:
        """
        Research a target domain for security information
        
        LLM Usage:
            info = searcher.research_target("example.com")
        """
        research = {
            'domain': domain,
            'technologies': [],
            'vulnerabilities': [],
            'subdomains': [],
            'related_reports': [],
        }
        
        # Search for technology stack
        tech_results = self.search(f"site:{domain} technology stack")
        
        # Search for disclosed vulnerabilities
        vuln_results = self.search(f"{domain} vulnerability disclosed hackerone")
        research['related_reports'] = [
            {'title': r.title, 'url': r.url} for r in vuln_results[:5]
        ]
        
        # Search for subdomains
        subdomain_results = self.search(f"site:*.{domain}")
        
        return research
    
    def format_results_for_llm(self, results: List[SearchResult]) -> str:
        """Format search results for LLM consumption"""
        if not results:
            return "No results found."
        
        output = "=== Search Results ===\n\n"
        
        for i, r in enumerate(results, 1):
            output += f"{i}. {r.title}\n"
            output += f"   URL: {r.url}\n"
            output += f"   {r.snippet[:200]}...\n\n"
        
        return output
