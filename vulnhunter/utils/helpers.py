"""
Helper utilities for VulnHunter
"""

import re
import random
import string
from typing import List, Dict, Optional, Set
from urllib.parse import urlparse, parse_qs, urljoin


def extract_urls(text: str) -> List[str]:
    """
    Extract URLs from text
    
    LLM Usage:
        urls = extract_urls(page_content)
    """
    url_pattern = r'https?://[^\s<>"\'{}|\\^`\[\]]+'
    urls = re.findall(url_pattern, text)
    # Clean up trailing punctuation
    cleaned = []
    for url in urls:
        url = url.rstrip('.,;:!?)')
        if url:
            cleaned.append(url)
    return list(set(cleaned))


def extract_emails(text: str) -> List[str]:
    """
    Extract email addresses from text
    
    LLM Usage:
        emails = extract_emails(page_content)
    """
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    return list(set(re.findall(email_pattern, text)))


def extract_params_from_url(url: str) -> Dict[str, str]:
    """
    Extract query parameters from URL
    
    LLM Usage:
        params = extract_params_from_url("https://example.com?id=1&name=test")
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    # Flatten single-value lists
    return {k: v[0] if len(v) == 1 else v for k, v in params.items()}


def is_valid_url(url: str) -> bool:
    """
    Check if URL is valid
    
    LLM Usage:
        if is_valid_url(url):
            # proceed
    """
    try:
        parsed = urlparse(url)
        return bool(parsed.scheme and parsed.netloc)
    except:
        return False


def normalize_url(url: str, base_url: str = "") -> str:
    """
    Normalize a URL (make absolute, remove fragments)
    
    LLM Usage:
        full_url = normalize_url("/path/to/page", "https://example.com")
    """
    # Remove fragment
    url = url.split('#')[0]
    
    # Make absolute
    if base_url and not url.startswith('http'):
        url = urljoin(base_url, url)
    
    return url


def get_domain(url: str) -> str:
    """
    Extract domain from URL
    
    LLM Usage:
        domain = get_domain("https://www.example.com/path")  # "www.example.com"
    """
    parsed = urlparse(url)
    return parsed.netloc


def generate_random_string(length: int = 8, 
                          include_special: bool = False) -> str:
    """
    Generate random string for testing
    
    LLM Usage:
        marker = generate_random_string(12)
    """
    chars = string.ascii_letters + string.digits
    if include_special:
        chars += "!@#$%"
    return ''.join(random.choices(chars, k=length))


def calculate_similarity(s1: str, s2: str) -> float:
    """
    Calculate similarity between two strings (0-1)
    
    LLM Usage:
        sim = calculate_similarity(response1, response2)
        if sim > 0.9:
            print("Responses are very similar")
    """
    if not s1 or not s2:
        return 0.0
    
    # Simple length-based comparison
    len1, len2 = len(s1), len(s2)
    if len1 == 0 and len2 == 0:
        return 1.0
    
    # Calculate ratio
    ratio = min(len1, len2) / max(len1, len2)
    
    # Sample content comparison
    sample_len = min(500, len1, len2)
    s1_sample = s1[:sample_len]
    s2_sample = s2[:sample_len]
    
    # Count matching characters
    matches = sum(1 for a, b in zip(s1_sample, s2_sample) if a == b)
    content_ratio = matches / sample_len if sample_len > 0 else 0
    
    return (ratio + content_ratio) / 2


def extract_json_from_text(text: str) -> Optional[Dict]:
    """
    Try to extract JSON from text (useful for API responses)
    
    LLM Usage:
        data = extract_json_from_text(response_body)
    """
    import json
    
    # Try direct parse
    try:
        return json.loads(text)
    except:
        pass
    
    # Try to find JSON in text
    json_patterns = [
        r'\{[^{}]*\}',  # Simple object
        r'\[[^\[\]]*\]',  # Simple array
        r'\{.*\}',  # Complex object (greedy)
    ]
    
    for pattern in json_patterns:
        matches = re.findall(pattern, text, re.DOTALL)
        for match in matches:
            try:
                return json.loads(match)
            except:
                continue
    
    return None


def detect_technology(headers: Dict[str, str], body: str) -> List[str]:
    """
    Detect technologies from headers and body
    
    LLM Usage:
        techs = detect_technology(response.headers, response.body)
    """
    technologies = []
    
    # Header-based detection
    header_patterns = {
        'X-Powered-By': {
            'PHP': 'PHP',
            'ASP.NET': 'ASP.NET',
            'Express': 'Express.js',
        },
        'Server': {
            'nginx': 'Nginx',
            'Apache': 'Apache',
            'Microsoft-IIS': 'IIS',
            'cloudflare': 'Cloudflare',
        }
    }
    
    for header, patterns in header_patterns.items():
        if header in headers:
            value = headers[header]
            for pattern, tech in patterns.items():
                if pattern.lower() in value.lower():
                    technologies.append(tech)
    
    # Body-based detection
    body_patterns = {
        'wp-content': 'WordPress',
        'drupal': 'Drupal',
        'joomla': 'Joomla',
        'react': 'React',
        'angular': 'Angular',
        'vue': 'Vue.js',
        'jquery': 'jQuery',
        'bootstrap': 'Bootstrap',
        'laravel': 'Laravel',
        'django': 'Django',
        'rails': 'Ruby on Rails',
        'spring': 'Spring',
    }
    
    body_lower = body.lower()
    for pattern, tech in body_patterns.items():
        if pattern in body_lower and tech not in technologies:
            technologies.append(tech)
    
    return technologies


def format_http_request(method: str, url: str, headers: Dict[str, str],
                       body: str = "") -> str:
    """
    Format HTTP request for display/reporting
    
    LLM Usage:
        formatted = format_http_request("POST", "/api/login", headers, body)
    """
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    
    lines = [f"{method} {path} HTTP/1.1"]
    lines.append(f"Host: {parsed.netloc}")
    
    for name, value in headers.items():
        if name.lower() != 'host':
            lines.append(f"{name}: {value}")
    
    if body:
        lines.append("")
        lines.append(body)
    
    return "\n".join(lines)


def format_http_response(status_code: int, headers: Dict[str, str],
                        body: str, max_body: int = 1000) -> str:
    """
    Format HTTP response for display/reporting
    
    LLM Usage:
        formatted = format_http_response(200, headers, body)
    """
    lines = [f"HTTP/1.1 {status_code}"]
    
    for name, value in headers.items():
        lines.append(f"{name}: {value}")
    
    lines.append("")
    
    if len(body) > max_body:
        lines.append(body[:max_body] + f"\n... [truncated {len(body) - max_body} bytes]")
    else:
        lines.append(body)
    
    return "\n".join(lines)
