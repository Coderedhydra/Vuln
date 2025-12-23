"""
Ollama LLM Agent for VulnHunter
Main orchestrator for LLM-powered vulnerability hunting
"""

import json
import re
from typing import Optional, Dict, List, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
from loguru import logger

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False
    logger.warning("Ollama not installed. Install with: pip install ollama")

from .prompts import SystemPrompts
from ..tools.llm_tools import LLMToolkit, ToolResult
from ..tools.web_search import WebSearcher
from ..tools.payload_generator import PayloadGenerator
from ..scanners import SQLiScanner, XSSScanner, IDORScanner, SSRFScanner, AuthScanner
from ..core.config import Config


@dataclass
class AgentMessage:
    """A message in the agent conversation"""
    role: str  # system, user, assistant
    content: str
    tool_calls: List[Dict] = field(default_factory=list)
    tool_results: List[Dict] = field(default_factory=list)


@dataclass
class AgentState:
    """Current state of the agent"""
    phase: str = "init"  # init, recon, analysis, exploit, report
    target_url: str = ""
    discovered_urls: List[str] = field(default_factory=list)
    discovered_forms: List[Dict] = field(default_factory=list)
    discovered_endpoints: List[Dict] = field(default_factory=list)
    findings: List[Dict] = field(default_factory=list)
    tested_params: List[str] = field(default_factory=list)
    iteration: int = 0
    max_iterations: int = 50


class OllamaAgent:
    """
    Ollama-based LLM agent for autonomous operation
    """
    
    def __init__(self, model: str = "llama3.1:8b", host: str = "http://localhost:11434"):
        if not OLLAMA_AVAILABLE:
            raise ImportError("Ollama package not installed. Install with: pip install ollama")
        
        self.model = model
        self.host = host
        self.client = ollama.Client(host=host)
        
        self.conversation: List[AgentMessage] = []
        self.system_prompt = ""
        
    def set_system_prompt(self, prompt: str):
        """Set the system prompt"""
        self.system_prompt = prompt
        
    def chat(self, message: str, context: Optional[str] = None) -> str:
        """
        Send a message and get a response
        
        LLM Usage:
            response = agent.chat("Analyze this response for XSS", context=response_body)
        """
        # Build messages
        messages = []
        
        if self.system_prompt:
            messages.append({"role": "system", "content": self.system_prompt})
        
        # Add conversation history
        for msg in self.conversation[-10:]:  # Last 10 messages for context
            messages.append({"role": msg.role, "content": msg.content})
        
        # Add current message
        full_message = message
        if context:
            full_message = f"{message}\n\n---\nContext:\n{context[:5000]}"
        
        messages.append({"role": "user", "content": full_message})
        
        try:
            response = self.client.chat(
                model=self.model,
                messages=messages,
            )
            
            assistant_message = response['message']['content']
            
            # Store in conversation
            self.conversation.append(AgentMessage(role="user", content=full_message))
            self.conversation.append(AgentMessage(role="assistant", content=assistant_message))
            
            return assistant_message
            
        except Exception as e:
            logger.error(f"Ollama chat error: {e}")
            return f"Error: {str(e)}"
    
    def generate(self, prompt: str, system: Optional[str] = None) -> str:
        """
        Generate a completion (one-shot, no conversation)
        """
        try:
            response = self.client.generate(
                model=self.model,
                prompt=prompt,
                system=system or self.system_prompt,
            )
            return response['response']
        except Exception as e:
            logger.error(f"Ollama generate error: {e}")
            return f"Error: {str(e)}"
    
    def analyze(self, data: str, task: str) -> str:
        """
        Analyze data with a specific task
        
        LLM Usage:
            analysis = agent.analyze(source_code, "Find security vulnerabilities")
        """
        prompt = f"""Task: {task}

Data to analyze:
{data[:8000]}

Provide a detailed analysis:"""
        
        return self.generate(prompt)
    
    def decide_next_action(self, state: Dict, available_actions: List[str]) -> str:
        """
        Decide the next action based on current state
        """
        prompt = f"""Current State:
{json.dumps(state, indent=2, default=str)}

Available Actions:
{json.dumps(available_actions, indent=2)}

Based on the current state, what should be the next action? Respond with just the action name."""
        
        response = self.generate(prompt)
        
        # Extract action from response
        for action in available_actions:
            if action.lower() in response.lower():
                return action
        
        return available_actions[0]  # Default to first action
    
    def clear_conversation(self):
        """Clear conversation history"""
        self.conversation = []


class VulnHunterAgent:
    """
    Main vulnerability hunting agent
    Orchestrates the LLM, tools, and scanners for autonomous bug hunting
    """
    
    def __init__(self, target_url: str, model: str = "llama3.1:8b",
                 ollama_host: str = "http://localhost:11434",
                 config: Optional[Config] = None):
        
        self.target_url = target_url.rstrip('/')
        self.config = config or Config(target_url=target_url)
        
        # Initialize LLM
        self.llm = OllamaAgent(model=model, host=ollama_host)
        self.llm.set_system_prompt(SystemPrompts.MAIN_AGENT + "\n\n" + SystemPrompts.TOOL_USE_GUIDE)
        
        # Initialize toolkit
        self.toolkit = LLMToolkit(target_url, {
            'rate_limit': self.config.scan.rate_limit
        })
        
        # Initialize scanners
        self.sqli_scanner = SQLiScanner(self.toolkit.http)
        self.xss_scanner = XSSScanner(self.toolkit.http)
        self.idor_scanner = IDORScanner(self.toolkit.http)
        self.ssrf_scanner = SSRFScanner(self.toolkit.http)
        self.auth_scanner = AuthScanner(self.toolkit.http)
        
        # Initialize other tools
        self.searcher = WebSearcher()
        self.payload_generator = PayloadGenerator()
        
        # Agent state
        self.state = AgentState(target_url=target_url)
        self.findings: List[Dict] = []
        
        logger.info(f"VulnHunter initialized for {target_url} using model {model}")
    
    def run(self, max_iterations: int = 50) -> List[Dict]:
        """
        Run the vulnerability hunting agent
        
        Returns list of discovered vulnerabilities
        """
        self.state.max_iterations = max_iterations
        
        logger.info("Starting VulnHunter autonomous scan...")
        
        # Phase 1: Reconnaissance
        self._run_recon_phase()
        
        # Phase 2: Analysis
        self._run_analysis_phase()
        
        # Phase 3: Exploitation
        self._run_exploit_phase()
        
        # Phase 4: Report Generation
        self._generate_reports()
        
        return self.findings
    
    def _run_recon_phase(self):
        """Run reconnaissance phase"""
        self.state.phase = "recon"
        logger.info("Phase 1: Reconnaissance")
        
        # Crawl the website
        crawl_result = self.toolkit.crawl(max_pages=self.config.scan.max_pages)
        
        if crawl_result.success:
            self.state.discovered_urls = crawl_result.data.get('sample_urls', [])
            
            # Get forms
            forms_result = self.toolkit.get_forms()
            if forms_result.success:
                self.state.discovered_forms = forms_result.data
            
            # Get API endpoints
            endpoints_result = self.toolkit.get_endpoints()
            if endpoints_result.success:
                self.state.discovered_endpoints = endpoints_result.data
            
            # Ask LLM to analyze recon results
            recon_summary = f"""
Crawl Results:
- URLs found: {len(self.state.discovered_urls)}
- Forms found: {len(self.state.discovered_forms)}
- API endpoints: {len(self.state.discovered_endpoints)}

Sample URLs: {self.state.discovered_urls[:10]}
Forms: {json.dumps(self.state.discovered_forms[:5], indent=2, default=str)}
Endpoints: {json.dumps(self.state.discovered_endpoints[:5], indent=2, default=str)}
"""
            
            analysis = self.llm.chat(
                "Analyze these reconnaissance results. Identify the most interesting targets for vulnerability testing. "
                "Look for authentication forms, API endpoints with parameters, file upload functionality, etc.",
                context=recon_summary
            )
            
            logger.info(f"LLM Recon Analysis:\n{analysis[:500]}...")
    
    def _run_analysis_phase(self):
        """Run source code analysis phase"""
        self.state.phase = "analysis"
        logger.info("Phase 2: Source Analysis")
        
        # Analyze main page
        analysis_result = self.toolkit.analyze_page(self.target_url)
        
        if analysis_result.success:
            findings = analysis_result.data.get('findings', [])
            
            for finding in findings:
                if finding.get('severity') in ['high', 'critical', 'medium']:
                    self.findings.append(finding)
            
            # Analyze key pages
            key_pages = []
            for url in self.state.discovered_urls[:20]:
                if any(kw in url.lower() for kw in ['login', 'admin', 'api', 'user', 'account', 'upload']):
                    key_pages.append(url)
            
            for page in key_pages[:5]:
                page_analysis = self.toolkit.analyze_page(page)
                if page_analysis.success:
                    for finding in page_analysis.data.get('findings', []):
                        if finding.get('severity') in ['high', 'critical', 'medium']:
                            self.findings.append(finding)
            
            logger.info(f"Analysis phase found {len(self.findings)} potential issues")
    
    def _run_exploit_phase(self):
        """Run vulnerability testing phase"""
        self.state.phase = "exploit"
        logger.info("Phase 3: Vulnerability Testing")
        
        # Test forms for SQLi and XSS
        for form in self.state.discovered_forms[:10]:
            action = form.get('action', '')
            method = form.get('method', 'POST')
            inputs = form.get('inputs', [])
            
            # Build test params
            params = {}
            for inp in inputs:
                name = inp.get('name', '')
                if name:
                    params[name] = 'test'
            
            if not params:
                continue
            
            # Test for SQLi
            if self.config.payload.test_sqli:
                sqli_result = self.sqli_scanner.scan_form(action, method, inputs)
                for vuln in sqli_result.vulnerabilities:
                    self.findings.append(vuln.to_dict())
            
            # Test for XSS
            if self.config.payload.test_xss:
                xss_result = self.xss_scanner.scan_form(action, method, inputs)
                for vuln in xss_result.vulnerabilities:
                    self.findings.append(vuln.to_dict())
            
            self.state.iteration += 1
            if self.state.iteration >= self.state.max_iterations:
                break
        
        # Test API endpoints
        for endpoint in self.state.discovered_endpoints[:10]:
            url = endpoint.get('url', '')
            method = endpoint.get('method', 'GET')
            
            if not url:
                continue
            
            # Simple parameter detection
            if '?' in url or method != 'GET':
                # Test for IDOR if numeric IDs present
                if self.config.payload.test_idor:
                    idor_result = self.idor_scanner.scan_url(url, method)
                    for vuln in idor_result.vulnerabilities:
                        self.findings.append(vuln.to_dict())
            
            self.state.iteration += 1
            if self.state.iteration >= self.state.max_iterations:
                break
        
        # Test for SSRF if URL parameters found
        url_params = self._find_url_parameters()
        for url, param in url_params[:5]:
            if self.config.payload.test_ssrf:
                ssrf_result = self.ssrf_scanner.scan_url(url, "GET", {param: "https://example.com"})
                for vuln in ssrf_result.vulnerabilities:
                    self.findings.append(vuln.to_dict())
        
        logger.info(f"Exploit phase found {len(self.findings)} vulnerabilities")
    
    def _find_url_parameters(self) -> List[tuple]:
        """Find parameters that likely accept URLs"""
        url_params = []
        
        for form in self.state.discovered_forms:
            for inp in form.get('inputs', []):
                name = inp.get('name', '').lower()
                if any(kw in name for kw in ['url', 'link', 'redirect', 'return', 'callback', 'next']):
                    url_params.append((form.get('action', ''), inp.get('name', '')))
        
        return url_params
    
    def _generate_reports(self):
        """Generate vulnerability reports"""
        self.state.phase = "report"
        logger.info("Phase 4: Report Generation")
        
        if not self.findings:
            logger.info("No vulnerabilities found to report")
            return
        
        # Deduplicate findings
        seen = set()
        unique_findings = []
        
        for finding in self.findings:
            key = f"{finding.get('category', '')}:{finding.get('url', '')}:{finding.get('parameter', '')}"
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
        
        self.findings = unique_findings
        
        # Ask LLM to prioritize and enhance reports
        findings_summary = json.dumps(self.findings[:20], indent=2, default=str)
        
        enhanced_report = self.llm.chat(
            "Review these vulnerability findings and create a prioritized summary. "
            "Identify the most critical issues and suggest any additional testing that might be valuable. "
            "Format as a professional security assessment summary.",
            context=findings_summary
        )
        
        logger.info(f"Generated reports for {len(self.findings)} unique vulnerabilities")
        logger.info(f"\nLLM Security Assessment:\n{enhanced_report}")
    
    def interactive_hunt(self):
        """
        Interactive mode - LLM-guided vulnerability hunting
        User can guide the agent with prompts
        """
        print("\n" + "="*60)
        print("VulnHunter Interactive Mode")
        print(f"Target: {self.target_url}")
        print("Type 'quit' to exit, 'report' to see findings")
        print("="*60 + "\n")
        
        # Initial reconnaissance
        print("Performing initial reconnaissance...")
        crawl_result = self.toolkit.crawl(max_pages=50)
        
        if crawl_result.success:
            print(f"Found {crawl_result.data.get('urls_found', 0)} URLs, "
                  f"{crawl_result.data.get('forms_found', 0)} forms")
        
        while True:
            try:
                user_input = input("\nYou: ").strip()
                
                if user_input.lower() == 'quit':
                    break
                elif user_input.lower() == 'report':
                    print(f"\nFindings ({len(self.findings)}):")
                    for f in self.findings:
                        print(f"  [{f.get('severity', 'unknown').upper()}] {f.get('title', 'Unknown')}")
                    continue
                elif user_input.lower() == 'help':
                    print(self.toolkit.get_tool_list())
                    continue
                
                # Process with LLM
                response = self._process_interactive_input(user_input)
                print(f"\nVulnHunter: {response}")
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error: {e}")
        
        print("\nExiting interactive mode.")
        return self.findings
    
    def _process_interactive_input(self, user_input: str) -> str:
        """Process user input and execute appropriate actions"""
        
        # Build context
        context = f"""
Current State:
- Phase: {self.state.phase}
- URLs discovered: {len(self.state.discovered_urls)}
- Forms discovered: {len(self.state.discovered_forms)}
- Findings so far: {len(self.findings)}

Available tools: {self.toolkit.get_tool_list()[:1000]}
"""
        
        # Get LLM decision
        response = self.llm.chat(user_input, context=context)
        
        # Check if LLM wants to use a tool
        tool_actions = self._extract_tool_calls(response)
        
        if tool_actions:
            # Execute tool calls
            results = []
            for action in tool_actions:
                result = self._execute_tool(action)
                results.append(result)
            
            # Get LLM to summarize results
            results_summary = "\n".join([r.to_llm_output() for r in results])
            final_response = self.llm.chat(
                "Summarize the results of these tool executions:",
                context=results_summary
            )
            return final_response
        
        return response
    
    def _extract_tool_calls(self, response: str) -> List[Dict]:
        """Extract tool calls from LLM response"""
        # Look for patterns like toolkit.method(args) or scanner.method(args)
        pattern = r'(toolkit|scanner)\.([\w]+)\(([^)]*)\)'
        matches = re.findall(pattern, response, re.IGNORECASE)
        
        actions = []
        for obj, method, args in matches:
            actions.append({
                'object': obj,
                'method': method,
                'args': args
            })
        
        return actions
    
    def _execute_tool(self, action: Dict) -> ToolResult:
        """Execute a tool action"""
        obj = action['object']
        method = action['method']
        args = action['args']
        
        try:
            if obj == 'toolkit':
                if hasattr(self.toolkit, method):
                    func = getattr(self.toolkit, method)
                    # Parse args (simplified)
                    if args:
                        # Try to evaluate as Python literals
                        try:
                            parsed_args = eval(f"({args})")
                            if isinstance(parsed_args, tuple):
                                return func(*parsed_args)
                            else:
                                return func(parsed_args)
                        except:
                            return func(args)
                    else:
                        return func()
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=f"{obj}.{method}",
                data=None,
                summary="",
                error=str(e)
            )
        
        return ToolResult(
            success=False,
            tool_name=f"{obj}.{method}",
            data=None,
            summary="",
            error="Unknown tool or method"
        )
    
    def get_findings_summary(self) -> str:
        """Get a summary of all findings"""
        if not self.findings:
            return "No vulnerabilities discovered."
        
        summary = f"=== VulnHunter Findings Summary ===\n"
        summary += f"Target: {self.target_url}\n"
        summary += f"Total Findings: {len(self.findings)}\n\n"
        
        # Group by severity
        by_severity = {}
        for f in self.findings:
            sev = f.get('severity', 'unknown')
            if sev not in by_severity:
                by_severity[sev] = []
            by_severity[sev].append(f)
        
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            if sev in by_severity:
                summary += f"\n{sev.upper()} ({len(by_severity[sev])}):\n"
                for f in by_severity[sev]:
                    summary += f"  - {f.get('title', 'Unknown')}\n"
                    summary += f"    URL: {f.get('url', 'N/A')}\n"
        
        return summary
