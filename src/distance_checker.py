import re
import urllib.parse
import ipaddress
from difflib import SequenceMatcher
from typing import List, Dict, Set, Optional

class DomainURLDetector:
    """
    A class for detecting suspicious domains and URLs in emails to help with phishing detection.
    """

    def __init__(self):
        self.legitimate_domains = self._initialize_legitimate_domains()
        self.suspicious_patterns = self._initialize_suspicious_patterns()
        self.phishing_domain_keywords = self._initialize_phishing_keywords()
        self.suspicious_tlds = self._initialize_suspicious_tlds()
        self.shortener_domains = self._initialize_shortener_domains()

    def _initialize_legitimate_domains(self) -> Set[str]:
        """
        Returns a set of known legitimate domains to compare against.
        """
        return {
            # Banking and Financial
            'paypal.com', 'citibank.com', 'americanexpress.com',

            # Government and Education
            'gov.sg', 'sit.singaporetech.edu.sg', 'nus.edu.sg', 'ntu.edu.sg',

            # Email Providers
            'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
            'icloud.com', 'mail.com',

            # Tech Companies
            'google.com', 'accounts.google.com', 'gmail.google.com',
            'googlemail.com', 'youtube.com', 'googlemessages.com','accounts.google.com',
            'android.com', 'gmail.com',
            'microsoft.com', 'live.com', 'outlook.com',
            'apple.com', 'icloud.com', 'me.com',
            'amazon.com', 'amazonses.com',
            'facebook.com', 'meta.com', 'instagram.com',
            'twitter.com', 'x.com', 'tiktok.com',
            'github.com', 'stackoverflow.com', 'reddit.com',
        }

    def _initialize_suspicious_patterns(self) -> List[str]:
        """
        Initialise suspicious domain regex patterns often found in phishing URLs.
        """
        return [
            r'bit\.ly', r'tinyurl\.com', r't\.co', r'goo\.gl',                   # Shorteners
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',                               # IP-based URLs
            r'[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\.',                                  # Excessive hyphens
            r'secure[a-z0-9]*\.', r'security[a-z0-9]*\.',                        # Security bait
            r'verification[a-z0-9]*\.', r'verify[a-z0-9]*\.',
            r'update[a-z0-9]*\.', r'urgent[a-z0-9]*\.',
            r'confirm[a-z0-9]*\.', r'suspended[a-z0-9]*\.',
            r'limited[a-z0-9]*\.',
        ]

    def _initialize_phishing_keywords(self) -> List[str]:
        """
        Initialize keywords frequently used in phishing domain names.
        """
        return [
            'secure', 'verify', 'update', 'confirm', 'urgent', 'suspended',
            'blocked', 'limited', 'restricted', 'temporary', 'alert',
            'warning', 'notice', 'action', 'required', 'immediate',
            'banking', 'payment', 'billing', 'invoice'
        ]

    def _initialize_suspicious_tlds(self) -> List[str]:
        """
        Initialize suspicious top-level domains often abused in phishing attacks.
        """
        return [
            '.tk', '.ml', '.ga', '.cf', '.click', '.download',
            '.top', '.win', '.bid', '.loan', '.work', '.date',
            '.racing', '.accountant', '.science', '.party'
        ]

    def _initialize_shortener_domains(self) -> List[str]:
        """
        Initialize commonly used URL shorteners.
        """
        return ['bit.ly', 'tinyurl.com', 'goo.gl']

    def extract_urls_from_text(self, text: str) -> List[str]:
        """
        Extracts all URLs from email text using regex patterns.

        Args:
            text (str): Email text (subject or body)

        Returns:
            List[str]: Unique list of cleaned and validated URLs.
        """
        if not text:
            return []

        url_patterns = [
            r'https?://[^\s<>"\'\[\]{}]+',
            r'www\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s<>"\'\[\]{}]*)?',
            r'(?<!@)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s<>"\'\[\]{}]*)?',
            # Add pattern to catch IP addresses as URLs
            r'https?://(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/[^\s<>"\'\[\]{}]*)?',
            r'(?<!@)(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/[^\s<>"\'\[\]{}]*)?'
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
        """
        Strips punctuation and trailing characters from URL.
        """
        if not url:
            return None
        url = re.sub(r'[.,;!?\]\}]+$', '', url.strip())
        return url.strip('\'"')

    def _is_valid_url(self, url: str) -> bool:
        """
        Validates structure of a URL including IP.
        """
        if not url or ' ' in url or '.' not in url:
            return False
                
        # Check if it's an IP address URL or a bare IP address
        if re.match(r'^https?://(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', url) or re.match(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', url):
            return True

        return bool(re.match(r'^(https?://|www\.)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', url))

    def analyze_url_suspicious_patterns(self, url: str) -> Dict:
        """
        Performs a detailed analysis of a single URL to identify phishing patterns.
        """
        reasons = []
        domain = ''

        try:
            normalized_url = self._normalize_url(url)
            parsed_url = urllib.parse.urlparse(normalized_url)
            domain = parsed_url.netloc.lower()
            analysis_domain = domain[4:] if domain.startswith('www.') else domain

            if self._is_legitimate_domain(analysis_domain):
                return self._create_analysis_result(False, ['Legitimate domain'], url, domain)

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
        """
        Normalizes the URL with a protocol prefix for parsing.
        """
        if not url.startswith(('http://', 'https://')):
            return 'http://' + url
        return url

    def _check_ip_address(self, domain: str, reasons: List[str]) -> None:
        if self._is_ip_address(domain):
            reasons.append('Uses IP address instead of domain name')

    def _check_suspicious_patterns(self, domain: str, reasons: List[str]) -> None:
        for pattern in self.suspicious_patterns:
            if re.search(pattern, domain):
                reasons.append(f'Matches suspicious pattern: {pattern}')

    def _check_url_shorteners(self, domain: str, reasons: List[str]) -> None:
        if any(shortener in domain for shortener in self.shortener_domains):
            reasons.append('Uses URL shortener service')

    def _check_subdomain_count(self, domain: str, reasons: List[str]) -> None:
        if len(domain.split('.')) > 4:
            reasons.append('Excessive number of subdomains')

    def _check_suspicious_tlds(self, domain: str, reasons: List[str]) -> None:
        if any(domain.endswith(tld) for tld in self.suspicious_tlds):
            reasons.append('Uses suspicious top-level domain')

    def _check_character_patterns(self, domain: str, reasons: List[str]) -> None:
        if re.search(r'[0-9].*[a-z].*[0-9]', domain):
            reasons.append('Suspicious alternating numbers and letters')
        if domain.count('-') >= 3:
            reasons.append('Excessive use of hyphens')

    def _check_homograph_attacks(self, domain: str, reasons: List[str]) -> None:
        """Check for potential homograph attacks"""
        suspicious_chars = set('0oO1lI')
        if any(char in domain for char in suspicious_chars):
            for legit_domain in list(self.legitimate_domains):
                similarity = SequenceMatcher(None, domain, legit_domain).ratio()
                
                # If very high similarity threshold and domain isn't legit
                if 0.9 < similarity < 1.0 and not domain.endswith('.' + legit_domain):
                    reasons.append(f'Potentially mimics legitimate domain: {legit_domain}')
                    break

    def _check_url_path(self, path: str, reasons: List[str]) -> None:
        """Check URL path for suspicious patterns"""
        if path:
            keywords = ['verify', 'confirm', 'secure', 'update', 'login', 'suspended', 'locked', 'urgent']
            if any(keyword in path.lower() for keyword in keywords):
                reasons.append('Suspicious keywords in URL path')

    def _is_ip_address(self, domain: str) -> bool:
        ''' Check if a domain is actually an IP address '''        
        try:
            ipaddress.ip_address(domain)
            return True
        except ValueError:
            return False

    def _create_analysis_result(self, is_suspicious: bool, reasons: List[str], url: str, domain: str) -> Dict:
        '''Create analysis results'''
        return {
            'is_suspicious': is_suspicious,
            'reasons': reasons,
            'analyzed_url': url,
            'domain': domain,
            'risk_score': len(reasons) if is_suspicious else 0
        }

    def _is_legitimate_domain(self, domain: str) -> bool:
        """
        Checks whether the domain is in the known list or a subdomain of one.
        """
        if not domain:
            return False
        domain_lower = domain.lower()
        if domain_lower in self.legitimate_domains:
            return True
        return any(domain_lower.endswith('.' + legit) for legit in self.legitimate_domains)

    def analyze_sender_domain(self, sender_email: str) -> Dict:
        """
        Analyzes sender's email domain to detect spoofing or phishing.
        """
        if not sender_email or '@' not in sender_email:
            return {
                'is_suspicious': True,
                'reasons': ['Invalid email format'],
                'domain': '',
                'risk_score': 1
            }

        domain = sender_email.split('@')[1].lower()

        if self._is_legitimate_domain(domain):
            return {
                'is_suspicious': False,
                'reasons': ['Known legitimate domain'],
                'domain': domain,
                'risk_score': 0
            }

        reasons = []

        # Check for phishing keywords
        matched = [kw for kw in self.phishing_domain_keywords if kw in domain]
        if matched:
            reasons.append(f'Contains phishing keywords: {", ".join(matched)}')

        if self._is_ip_address(domain):
            reasons.append('Uses IP address as domain')

        suspicious_tld = [tld for tld in self.suspicious_tlds if domain.endswith(tld)]
        if suspicious_tld:
            reasons.append(f'Uses suspicious TLD: {", ".join(suspicious_tld)}')

        # Check similarity to legit domains
        for legit in self.legitimate_domains:
            similarity = SequenceMatcher(None, domain, legit).ratio()
            if 0.9 < similarity < 1.0 and not domain.endswith('.' + legit):
                reasons.append(f'Similar to legitimate domain: {legit}')
                break

        if not reasons:
            reasons = ['Unknown domain - not in legitimate domains list']

        return {
            'is_suspicious': True,
            'reasons': reasons,
            'domain': domain,
            'risk_score': len(reasons)
        }

def analyze_email_domain_and_urls(sender_email: str, email_body: str, email_subject: str = "") -> Dict:
    """
    Analyzes sender domain and all URLs in email subject & body to identify phishing risks.

    Args:
        sender_email (str): The sender's email address.
        email_body (str): The body of the email.
        email_subject (str): (Optional) Subject line of the email.

    Returns:
        Dict: Dictionary summarizing the risk level and analysis results.
    """
    detector = DomainURLDetector()

    # Analyze sender domain
    sender_analysis = detector.analyze_sender_domain(sender_email)

    # Extract URLs from subject and body
    subject_urls = detector.extract_urls_from_text(email_subject or "")
    body_urls = detector.extract_urls_from_text(email_body or "")
    all_urls = list(set(subject_urls + body_urls))

    url_analyses = []
    suspicious_urls = []
    total_risk_score = sender_analysis.get('risk_score', 0)

    # Analyze each URL
    for url in all_urls:
        analysis = detector.analyze_url_suspicious_patterns(url)
        url_analyses.append(analysis)
        total_risk_score += analysis['risk_score']
        if analysis['is_suspicious']:
            suspicious_urls.append(analysis)

    # Determine risk level
    risk_factors = []
    if sender_analysis['is_suspicious']:
        risk_factors.extend(sender_analysis.get('reasons', []))
    if suspicious_urls:
        risk_factors.append(f"{len(suspicious_urls)} suspicious URLs found")

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
