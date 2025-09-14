"""
Domain and URL Security Detection Module
Clean, organized version for phishing email detection
"""

import re
import urllib.parse
import ipaddress
from difflib import SequenceMatcher
from typing import List, Dict, Set, Optional


class DomainURLDetector:
    """
    Detects suspicious domains and URLs in emails for phishing detection
    """
    
    def __init__(self):
        self.legitimate_domains = self._initialize_legitimate_domains()
        self.suspicious_patterns = self._initialize_suspicious_patterns()
        self.phishing_domain_keywords = self._initialize_phishing_keywords()
        self.suspicious_tlds = self._initialize_suspicious_tlds()
        self.shortener_domains = self._initialize_shortener_domains()
    
    def _initialize_legitimate_domains(self) -> Set[str]:
        """Initialize set of known legitimate domains"""
        return {
            # Banking and Financial
            'paypal.com', 'square.com', 'venmo.com', 'stripe.com',
            'citibank.com', 'bankofamerica.com', 'wellsfargo.com',
            'americanexpress.com', 'chase.com', 'discover.com',
            
            # Government and Educational
            'gov.sg', 'gov.uk', 'gov.au', 'canada.ca',
            'sit.singaporetech.edu.sg', 'nus.edu.sg', 'ntu.edu.sg',
            'mit.edu', 'harvard.edu', 'stanford.edu',
            
            # Major Email Providers
            'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
            'aol.com', 'icloud.com', 'protonmail.com', 'mail.com',
            
            # Tech Companies
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'facebook.com', 'meta.com', 'twitter.com', 'x.com',
            'linkedin.com', 'instagram.com', 'tiktok.com', 'youtube.com',
            'github.com', 'stackoverflow.com', 'reddit.com',
            
            # Popular Services
            'netflix.com', 'spotify.com', 'dropbox.com', 'zoom.us',
            'adobe.com', 'salesforce.com', 'shopify.com', 'ebay.com',
            'uber.com', 'lyft.com', 'airbnb.com', 'booking.com',
            
            # News and Media
            'cnn.com', 'bbc.com', 'reuters.com', 'bloomberg.com',
            'nytimes.com', 'wsj.com', 'guardian.com'
        }
    
    def _initialize_suspicious_patterns(self) -> List[str]:
        """Initialize suspicious URL regex patterns"""
        return [
            r'bit\.ly', r'tinyurl\.com', r't\.co', r'goo\.gl',  # URL shorteners
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP addresses
            r'[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\.',  # Multiple hyphens
            r'secure[a-z0-9]*\.', r'security[a-z0-9]*\.',  # Fake security terms
            r'verification[a-z0-9]*\.', r'verify[a-z0-9]*\.',
            r'update[a-z0-9]*\.', r'urgent[a-z0-9]*\.',
            r'confirm[a-z0-9]*\.', r'account[a-z0-9]*\.',
            r'suspended[a-z0-9]*\.', r'limited[a-z0-9]*\.',
        ]
    
    def _initialize_phishing_keywords(self) -> List[str]:
        """Initialize common phishing keywords found in domains"""
        return [
            'secure', 'verify', 'update', 'confirm', 'urgent', 'suspended',
            'blocked', 'limited', 'restricted', 'temporary', 'alert',
            'warning', 'notice', 'action', 'required', 'immediate',
            'account', 'banking', 'payment', 'billing', 'invoice'
        ]
    
    def _initialize_suspicious_tlds(self) -> List[str]:
        """Initialize suspicious top-level domains"""
        return [
            '.tk', '.ml', '.ga', '.cf', '.click', '.download',
            '.top', '.win', '.bid', '.loan', '.work', '.date',
            '.racing', '.accountant', '.science', '.party'
        ]
    
    def _initialize_shortener_domains(self) -> List[str]:
        """Initialize URL shortener domains"""
        return [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 
            'short.link', 'rb.gy', 'cutt.ly', 'is.gd', 'buff.ly'
        ]
    
    def extract_urls_from_text(self, text: str) -> List[str]:
        """
        Extract URLs from email text using multiple patterns
        
        Args:
            text: Text to extract URLs from
            
        Returns:
            List of unique, cleaned URLs
        """
        if not text:
            return []
        
        # URL extraction patterns
        url_patterns = [
            r'https?://[^\s<>"\'\[\]{}]+',  # Standard HTTP/HTTPS URLs
            r'www\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s<>"\'\[\]{}]*)?',  # www.domain.com
            r'(?<!@)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s<>"\'\[\]{}]*)?',  # domain.com/path
        ]
        
        urls = set()
        
        for pattern in url_patterns:
            found_urls = re.findall(pattern, text, re.IGNORECASE)
            
            for url in found_urls:
                cleaned_url = self._clean_url(url)
                if cleaned_url and self._is_valid_url(cleaned_url):
                    urls.add(cleaned_url)
        
        return list(urls)
    
    def _clean_url(self, url: str) -> Optional[str]:
        """Clean and normalize URL"""
        if not url:
            return None
        
        # Remove trailing punctuation and brackets
        url = re.sub(r'[.,;!?\]\}]+$', '', url.strip())
        
        # Remove leading/trailing quotes
        url = url.strip('\'"')
        
        return url if url else None
    
    def _is_valid_url(self, url: str) -> bool:
        """Basic URL validation"""
        if not url or len(url) < 4:
            return False
            
        # Must contain a dot for domain
        if '.' not in url:
            return False
            
        # Shouldn't contain spaces
        if ' ' in url:
            return False
            
        # Should look like a reasonable URL
        return bool(re.match(r'^(https?://|www\.)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', url))
    
    def analyze_url_suspicious_patterns(self, url: str) -> Dict:
        """
        Analyze URL for suspicious patterns and characteristics
        
        Args:
            url: URL to analyze
            
        Returns:
            Dictionary with analysis results
        """
        if not url:
            return self._create_analysis_result(False, [], url, '')
        
        reasons = []
        domain = ''
        
        try:
            # Normalize URL for parsing
            normalized_url = self._normalize_url(url)
            
            # Parse URL
            parsed_url = urllib.parse.urlparse(normalized_url)
            domain = parsed_url.netloc.lower()
            
            # Remove www. prefix for analysis
            analysis_domain = domain[4:] if domain.startswith('www.') else domain
            
            # Perform various security checks
            self._check_ip_address(analysis_domain, reasons)
            self._check_suspicious_patterns(analysis_domain, reasons)
            self._check_url_shorteners(analysis_domain, reasons)
            self._check_subdomain_count(analysis_domain, reasons)
            self._check_suspicious_tlds(analysis_domain, reasons)
            self._check_character_patterns(analysis_domain, reasons)
            self._check_homograph_attacks(analysis_domain, reasons)
            self._check_url_path(parsed_url.path, reasons)
            
        except Exception as e:
            reasons.append(f'URL analysis error: {str(e)}')
        
        return self._create_analysis_result(len(reasons) > 0, reasons, url, domain)
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL for parsing"""
        if not url.startswith(('http://', 'https://')):
            if url.startswith('www.'):
                return 'http://' + url
            elif '.' in url and not url.startswith('mailto:'):
                return 'http://' + url
        return url
    
    def _check_ip_address(self, domain: str, reasons: List[str]) -> None:
        """Check if domain is an IP address"""
        if self._is_ip_address(domain):
            reasons.append('Uses IP address instead of domain name')
    
    def _check_suspicious_patterns(self, domain: str, reasons: List[str]) -> None:
        """Check for suspicious patterns in domain"""
        for pattern in self.suspicious_patterns:
            if re.search(pattern, domain):
                reasons.append(f'Matches suspicious pattern: {pattern}')
    
    def _check_url_shorteners(self, domain: str, reasons: List[str]) -> None:
        """Check for URL shortener services"""
        if any(shortener in domain for shortener in self.shortener_domains):
            reasons.append('Uses URL shortener service')
    
    def _check_subdomain_count(self, domain: str, reasons: List[str]) -> None:
        """Check for excessive subdomains"""
        domain_parts = domain.split('.')
        if len(domain_parts) > 4:  # More than typical subdomain.domain.tld
            reasons.append('Excessive number of subdomains')
    
    def _check_suspicious_tlds(self, domain: str, reasons: List[str]) -> None:
        """Check for suspicious top-level domains"""
        if any(domain.endswith(tld) for tld in self.suspicious_tlds):
            reasons.append('Uses suspicious top-level domain')
    
    def _check_character_patterns(self, domain: str, reasons: List[str]) -> None:
        """Check for suspicious character patterns"""
        if re.search(r'[0-9].*[a-z].*[0-9]', domain):
            reasons.append('Suspicious alternating numbers and letters')
        
        if domain.count('-') >= 3:
            reasons.append('Excessive use of hyphens')
    
    def _check_homograph_attacks(self, domain: str, reasons: List[str]) -> None:
        """Check for potential homograph attacks"""
        if any(char in domain for char in ['0', '1', 'l', 'I']):
            # Check similarity to legitimate domains
            for legit_domain in list(self.legitimate_domains)[:20]:  # Check top domains
                similarity = SequenceMatcher(None, domain, legit_domain).ratio()
                if similarity > 0.8 and similarity < 1.0:  # Similar but not exact
                    reasons.append(f'Potentially mimics legitimate domain: {legit_domain}')
                    break
    
    def _check_url_path(self, path: str, reasons: List[str]) -> None:
        """Check URL path for suspicious patterns"""
        if path:
            path_lower = path.lower()
            suspicious_path_patterns = [
                'verify', 'confirm', 'secure', 'update', 'login',
                'account', 'suspended', 'locked', 'urgent'
            ]
            if any(pattern in path_lower for pattern in suspicious_path_patterns):
                reasons.append('Suspicious keywords in URL path')
    
    def _is_ip_address(self, domain: str) -> bool:
        """Check if a domain is actually an IP address"""
        if not domain:
            return False
            
        try:
            ipaddress.ip_address(domain)
            return True
        except ValueError:
            return False
    
    def _create_analysis_result(self, is_suspicious: bool, reasons: List[str], 
                              url: str, domain: str) -> Dict:
        """Create standardized analysis result"""
        return {
            'is_suspicious': is_suspicious,
            'reasons': reasons,
            'analyzed_url': url,
            'domain': domain,
            'risk_score': len(reasons)  # Simple scoring based on number of issues
        }
    
    def analyze_sender_domain(self, sender_email: str) -> Dict:
        """
        Analyze sender email domain for legitimacy
        
        Args:
            sender_email: Email address to analyze
            
        Returns:
            Dictionary with sender domain analysis
        """
        if not sender_email or '@' not in sender_email:
            return {'is_suspicious': True, 'reason': 'Invalid email format'}
        
        domain = sender_email.split('@')[1].lower()
        
        # Check if it's a known legitimate domain
        if domain in self.legitimate_domains:
            return {'is_suspicious': False, 'reason': 'Known legitimate domain'}
        
        # Check for suspicious characteristics
        reasons = []
        if any(keyword in domain for keyword in self.phishing_domain_keywords):
            reasons.append('Contains phishing keywords')
        
        if self._is_ip_address(domain):
            reasons.append('Uses IP address as domain')
        
        if any(domain.endswith(tld) for tld in self.suspicious_tlds):
            reasons.append('Uses suspicious TLD')
        
        # Check for typosquatting
        for legit_domain in self.legitimate_domains:
            similarity = SequenceMatcher(None, domain, legit_domain).ratio()
            if similarity > 0.8 and similarity < 1.0:
                reasons.append(f'Similar to legitimate domain: {legit_domain}')
                break
        
        return {
            'is_suspicious': len(reasons) > 0,
            'reasons': reasons,
            'domain': domain,
            'risk_score': len(reasons)
        }


def analyze_email_domain_and_urls(sender_email: str, email_body: str, 
                                 email_subject: str = "") -> Dict:
    """
    Main function to analyze email domains and URLs for security threats
    
    Args:
        sender_email: Sender's email address
        email_body: Email body text
        email_subject: Email subject line
        
    Returns:
        Dictionary with comprehensive analysis results
    """
    detector = DomainURLDetector()
    
    # Analyze sender domain
    sender_analysis = detector.analyze_sender_domain(sender_email)
    
    # Extract and analyze URLs
    subject_urls = detector.extract_urls_from_text(email_subject or "")
    body_urls = detector.extract_urls_from_text(email_body or "")
    all_urls = list(set(subject_urls + body_urls))
    
    # Analyze each URL
    url_analyses = []
    suspicious_urls = []
    total_risk_score = 0
    
    for url in all_urls:
        analysis = detector.analyze_url_suspicious_patterns(url)
        url_analyses.append(analysis)
        total_risk_score += analysis['risk_score']
        
        if analysis['is_suspicious']:
            suspicious_urls.append(analysis)
    
    # Calculate overall risk
    risk_factors = []
    
    if sender_analysis['is_suspicious']:
        risk_factors.extend(sender_analysis.get('reasons', []))
    
    if suspicious_urls:
        risk_factors.append(f"{len(suspicious_urls)} suspicious URLs found")
    
    # Determine risk level
    if total_risk_score >= 5 or len(suspicious_urls) >= 2:
        risk_level = 'HIGH'
    elif total_risk_score >= 2 or len(suspicious_urls) >= 1:
        risk_level = 'MEDIUM'
    else:
        risk_level = 'LOW'
    
    return {
        'risk_level': risk_level,
        'risk_score': total_risk_score,
        'risk_factors': risk_factors,
        'sender_analysis': sender_analysis,
        'urls_found': all_urls,
        'url_analyses': url_analyses,
        'suspicious_urls': suspicious_urls,
        'total_urls_analyzed': len(all_urls),
        'suspicious_url_count': len(suspicious_urls),
        'summary': {
            'sender_suspicious': sender_analysis['is_suspicious'],
            'urls_found': len(all_urls),
            'suspicious_urls': len(suspicious_urls),
            'total_risk_factors': len(risk_factors)
        }
    }