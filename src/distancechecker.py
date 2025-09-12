"""
Domain and URL Security Detection Module
Detects suspicious domains using edit distance and identifies malicious URLs
"""

import re
import urllib.parse
import ipaddress
from difflib import SequenceMatcher
from get_data import GetData

class DomainURLDetector:
    """
    Detects suspicious domains and URLs in emails using edit distance and pattern analysis
    """
    
    def __init__(self):
        """Initialize with known legitimate domains and suspicious patterns"""
        self.service = GetData.gmail_service()
        # Common legitimate domains to compare against
        self.legitimate_domains = {
            # Banking and Financial
            'paypal.com', 'stripe.com', 'square.com', 'venmo.com',
            'bankofamerica.com', 'chase.com', 'wellsfargo.com', 'citibank.com',
            'americanexpress.com', 'discover.com', 'capitalone.com',
            
            # Major Email Providers
            'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
            'aol.com', 'icloud.com', 'protonmail.com',
            
            # Tech Companies
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'facebook.com', 'meta.com', 'twitter.com', 'x.com',
            'linkedin.com', 'instagram.com', 'tiktok.com',
            
            # Government and Official
            'irs.gov', 'usa.gov', 'medicare.gov', 'ssa.gov',
            'usps.com', 'fedex.com', 'ups.com', 'dhl.com',
            
            # Popular Services
            'netflix.com', 'spotify.com', 'dropbox.com', 'zoom.us',
            'adobe.com', 'salesforce.com', 'shopify.com', 'ebay.com'
        }
        
        # Suspicious URL patterns
        self.suspicious_patterns = [
            r'bit\.ly', r'tinyurl\.com', r't\.co',  # URL shorteners
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP addresses
            r'[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\.',  # Multiple hyphens
            r'secure[a-z0-9]*\.',  # Fake security terms
            r'verification[a-z0-9]*\.',
            r'update[a-z0-9]*\.',
            r'confirm[a-z0-9]*\.',
        ]
        
        # Common phishing keywords in domains
        self.phishing_domain_keywords = [
            'secure', 'verify', 'update', 'confirm', 'urgent', 'suspended',
            'blocked', 'limited', 'restricted', 'temporary', 'alert'
        ]
    
    def calculate_edit_distance_similarity(self, str1, str2):
        """
        Calculate similarity between two strings using edit distance
        
        Args:
            str1 (str): First string
            str2 (str): Second string
            
        Returns:
            float: Similarity ratio (0-1, where 1 is identical)
        """
        return SequenceMatcher(None, str1.lower(), str2.lower()).ratio()
    
    def extract_domain_from_email(self, email_address):
        """
        Extract domain from email address
        
        Args:
            email_address (str): Email address
            
        Returns:
            str: Domain part of email, or None if invalid
        """
        try:
            if '@' in email_address:
                # Handle cases like "Name <email@domain.com>"
                if '<' in email_address and '>' in email_address:
                    email_match = re.search(r'<([^>]+)>', email_address)
                    if email_match:
                        email_address = email_match.group(1)
                
                domain = email_address.split('@')[-1].strip()
                # Remove any trailing characters
                domain = re.sub(r'[^a-zA-Z0-9.-].*$', '', domain)
                return domain.lower()
        except Exception:
            pass
        return None
    
    def check_domain_similarity(self, suspicious_domain, threshold=0.8):
        """
        Check if a domain is suspiciously similar to legitimate domains
        
        Args:
            suspicious_domain (str): Domain to check
            threshold (float): Similarity threshold (0-1)
            
        Returns:
            dict: Analysis results including matches and scores
        """
        if not suspicious_domain:
            return {'is_suspicious': False, 'matches': [], 'max_similarity': 0}
        
        suspicious_domain = suspicious_domain.lower()
        matches = []
        max_similarity = 0
        
        # Check against legitimate domains
        for legit_domain in self.legitimate_domains:
            similarity = self.calculate_edit_distance_similarity(suspicious_domain, legit_domain)
            
            if similarity > max_similarity:
                max_similarity = similarity
            
            # If very similar but not identical, it's suspicious
            if threshold <= similarity < 1.0:
                matches.append({
                    'legitimate_domain': legit_domain,
                    'similarity': round(similarity, 3),
                    'suspicious_domain': suspicious_domain
                })
        
        # Additional checks for suspicious patterns in domain
        has_phishing_keywords = any(keyword in suspicious_domain for keyword in self.phishing_domain_keywords)
        has_multiple_hyphens = suspicious_domain.count('-') >= 2
        has_numbers_and_letters_mixed = bool(re.search(r'[0-9].*[a-z]|[a-z].*[0-9]', suspicious_domain))
        
        # Sort matches by similarity
        matches.sort(key=lambda x: x['similarity'], reverse=True)
        
        is_suspicious = (
            len(matches) > 0 or 
            has_phishing_keywords or 
            has_multiple_hyphens or 
            (has_numbers_and_letters_mixed and len(suspicious_domain) > 15)
        )
        
        return {
            'is_suspicious': is_suspicious,
            'matches': matches,
            'max_similarity': round(max_similarity, 3),
            'has_phishing_keywords': has_phishing_keywords,
            'has_multiple_hyphens': has_multiple_hyphens,
            'suspicious_domain': suspicious_domain
        }
    
    def extract_urls_from_text(self, text):
        """
        Extract URLs from email text
        
        Args:
            text (str): Email text content
            
        Returns:
            list: List of found URLs
        """
        if not text:
            return []
        
        # Enhanced URL pattern to catch various formats
        url_patterns = [
            r'https?://[^\s<>"\']+',  # Standard HTTP/HTTPS URLs
            r'www\.[^\s<>"\']+',  # www.domain.com
            r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s<>"\']*)?',  # domain.com/path
        ]
        
        urls = []
        for pattern in url_patterns:
            found_urls = re.findall(pattern, text, re.IGNORECASE)
            urls.extend(found_urls)
        
        # Clean up URLs and remove duplicates
        cleaned_urls = []
        for url in urls:
            # Remove trailing punctuation
            url = re.sub(r'[.,;!?]+$', '', url)
            if url and url not in cleaned_urls:
                cleaned_urls.append(url)
        
        return cleaned_urls
    
    def is_ip_address(self, domain):
        """
        Check if a domain is actually an IP address
        
        Args:
            domain (str): Domain to check
            
        Returns:
            bool: True if it's an IP address
        """
        try:
            ipaddress.ip_address(domain)
            return True
        except ValueError:
            return False
    
    def analyze_url_suspicious_patterns(self, url):
        """
        Analyze URL for suspicious patterns
        
        Args:
            url (str): URL to analyze
            
        Returns:
            dict: Analysis results
        """
        if not url:
            return {'is_suspicious': False, 'reasons': []}
        
        reasons = []
        
        try:
            # Parse URL
            if not url.startswith(('http://', 'https://', 'www.')):
                if '.' in url:
                    url = 'http://' + url
                else:
                    return {'is_suspicious': False, 'reasons': ['Invalid URL format']}
            
            if url.startswith('www.'):
                url = 'http://' + url
                
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc.lower()
            
            # Remove www. prefix for analysis
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # Check for IP address instead of domain
            if self.is_ip_address(domain):
                reasons.append('Uses IP address instead of domain name')
            
            # Check for suspicious patterns
            for pattern in self.suspicious_patterns:
                if re.search(pattern, domain):
                    reasons.append(f'Matches suspicious pattern: {pattern}')
            
            # Check for URL shorteners
            shortener_domains = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link']
            if any(shortener in domain for shortener in shortener_domains):
                reasons.append('Uses URL shortener')
            
            # Check for excessive subdomains
            parts = domain.split('.')
            if len(parts) > 4:  # More than typical domain.subdomain.tld
                reasons.append('Excessive subdomains')
            
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                reasons.append('Suspicious top-level domain')
            
            # Check for mixed character sets or confusing characters
            if re.search(r'[0-9].*[a-z].*[0-9]', domain) or domain.count('-') >= 3:
                reasons.append('Suspicious character patterns')
            
        except Exception as e:
            reasons.append(f'URL parsing error: {str(e)}')
        
        return {
            'is_suspicious': len(reasons) > 0,
            'reasons': reasons,
            'analyzed_url': url,
            'domain': domain if 'domain' in locals() else 'Unknown'
        }
    
    def analyze_email_security(self, sender_email, email_body, email_subject=""):
        """
        Complete security analysis of email sender and content
        
        Args:
            sender_email (str): Sender's email address
            email_body (str): Email content
            email_subject (str): Email subject line
            
        Returns:
            dict: Complete security analysis
        """
        # Extract sender domain
        sender_domain = self.extract_domain_from_email(sender_email)
        
        # Check sender domain similarity
        domain_analysis = self.check_domain_similarity(sender_domain)
        
        # Extract URLs from email content
        body_urls = self.extract_urls_from_text(email_body)
        subject_urls = self.extract_urls_from_text(email_subject)
        all_urls = body_urls + subject_urls
        
        # Analyze each URL
        url_analyses = []
        for url in all_urls:
            url_analysis = self.analyze_url_suspicious_patterns(url)
            if url_analysis['is_suspicious']:
                url_analyses.append(url_analysis)
        
        # Calculate overall risk score
        risk_score = 0
        risk_factors = []
        
        if domain_analysis['is_suspicious']:
            if domain_analysis['matches']:
                risk_score += len(domain_analysis['matches']) * 25
                risk_factors.append('Sender domain similar to legitimate domain')
            if domain_analysis['has_phishing_keywords']:
                risk_score += 15
                risk_factors.append('Sender domain contains phishing keywords')
            if domain_analysis['has_multiple_hyphens']:
                risk_score += 10
                risk_factors.append('Sender domain has suspicious structure')
        
        if url_analyses:
            risk_score += len(url_analyses) * 20
            risk_factors.append(f'Contains {len(url_analyses)} suspicious URLs')
        
        # Determine risk level
        if risk_score >= 50:
            risk_level = 'HIGH'
        elif risk_score >= 25:
            risk_level = 'MEDIUM'
        elif risk_score >= 10:
            risk_level = 'LOW'
        else:
            risk_level = 'MINIMAL'
        
        return {
            'sender_email': sender_email,
            'sender_domain': sender_domain,
            'domain_analysis': domain_analysis,
            'urls_found': all_urls,
            'suspicious_urls': url_analyses,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'total_urls_analyzed': len(all_urls),
            'suspicious_url_count': len(url_analyses)
        }
    
    def print_security_analysis(self, analysis):
        """
        Print formatted security analysis results
        
        Args:
            analysis (dict): Security analysis results
        """
        print(f"\n{'='*60}")
        print(f"DOMAIN & URL SECURITY ANALYSIS")
        print(f"{'='*60}")
        
        print(f"Sender: {analysis['sender_email']}")
        print(f"Domain: {analysis['sender_domain']}")
        print(f"Risk Level: {analysis['risk_level']}")
        print(f"Risk Score: {analysis['risk_score']}")
        print()
        
        # Domain analysis
        domain_info = analysis['domain_analysis']
        if domain_info['is_suspicious']:
            print("🚨 SUSPICIOUS SENDER DOMAIN:")
            if domain_info['matches']:
                print("  Similar to legitimate domains:")
                for match in domain_info['matches'][:3]:  # Show top 3
                    print(f"    {match['suspicious_domain']} ≈ {match['legitimate_domain']} "
                          f"({match['similarity']:.1%} similar)")
            
            if domain_info['has_phishing_keywords']:
                print("  ⚠️  Contains phishing-related keywords")
            if domain_info['has_multiple_hyphens']:
                print("  ⚠️  Suspicious domain structure (multiple hyphens)")
            print()
        
        # URL analysis
        if analysis['urls_found']:
            print(f"URLs FOUND: {len(analysis['urls_found'])}")
            if analysis['suspicious_urls']:
                print(f"🚨 SUSPICIOUS URLs: {len(analysis['suspicious_urls'])}")
                for url_info in analysis['suspicious_urls']:
                    print(f"  URL: {url_info['analyzed_url']}")
                    print(f"  Domain: {url_info['domain']}")
                    print(f"  Issues: {', '.join(url_info['reasons'])}")
                    print()
            else:
                print("✅ No suspicious URLs detected")
        else:
            print("No URLs found in email")
        
        if analysis['risk_factors']:
            print("RISK FACTORS:")
            for factor in analysis['risk_factors']:
                print(f"  • {factor}")
        
        print(f"{'='*60}")


# Integration function to be called from email_integration.py
def analyze_email_domain_and_urls(sender_email, email_body, email_subject=""):
    """
    Main function to be called from email_integration.py
    
    Args:
        sender_email (str): Sender's email address
        email_body (str): Email content
        email_subject (str): Email subject line
        
    Returns:
        dict: Security analysis results
    """
    detector = DomainURLDetector()
    return detector.analyze_email_security(sender_email, email_body, email_subject)


# Example usage and testing
if __name__ == "__main__":
    detector = DomainURLDetector()

    subject = GetData.get_email_subject(msg_data)
    body = GetData.get_email_body(msg_data)
    sender = GetData.get_email_sender(msg_data)

    
    print("DOMAIN & URL SECURITY DETECTOR - TEST RESULTS")
    print("=" * 80)
    
    for i, test in enumerate(test_cases, 1):
        print(f"\nTEST CASE {i}:")
        analysis = detector.analyze_email_security(
            sender['sender'], 
            body['body'], 
            subject['subject']
        )
        detector.print_security_analysis(analysis)