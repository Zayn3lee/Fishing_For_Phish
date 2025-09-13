"""
Domain and URL Security Detection Module
Detects suspicious domains using edit distance and identifies malicious URLs
Fixed version with proper imports and error handling
"""

import re
import urllib.parse
import ipaddress
from difflib import SequenceMatcher

# Import the fixed GetData class
try:
    from get_data import GetData
except ImportError:
    print("Warning: get_data module not found. Some features may not work.")
    GetData = None

class DomainURLDetector:
    """
    Detects suspicious domains and URLs in emails using edit distance and pattern analysis
    """
    
    def __init__(self):
        """Initialize with known legitimate domains and suspicious patterns"""
        # Initialize Gmail service if GetData is available
        if GetData:
            try:
                self.service = GetData.gmail_service()
            except Exception as e:
                print(f"Warning: Could not initialize Gmail service: {e}")
                self.service = None
        else:
            self.service = None
        
        # Common legitimate domains to compare against
        self.legitimate_domains = {
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
        
        # Suspicious URL patterns
        self.suspicious_patterns = [
            r'bit\.ly', r'tinyurl\.com', r't\.co', r'goo\.gl',  # URL shorteners
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP addresses
            r'[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\.',  # Multiple hyphens
            r'secure[a-z0-9]*\.', r'security[a-z0-9]*\.',  # Fake security terms
            r'verification[a-z0-9]*\.', r'verify[a-z0-9]*\.',
            r'update[a-z0-9]*\.', r'urgent[a-z0-9]*\.',
            r'confirm[a-z0-9]*\.', r'account[a-z0-9]*\.',
            r'suspended[a-z0-9]*\.', r'limited[a-z0-9]*\.',
        ]
        
        # Common phishing keywords in domains
        self.phishing_domain_keywords = [
            'secure', 'verify', 'update', 'confirm', 'urgent', 'suspended',
            'blocked', 'limited', 'restricted', 'temporary', 'alert',
            'warning', 'notice', 'action', 'required', 'immediate',
            'account', 'banking', 'payment', 'billing', 'invoice'
        ]
        
        # Suspicious TLDs
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.click', '.download',
            '.top', '.win', '.bid', '.loan', '.work', '.date',
            '.racing', '.accountant', '.science', '.party'
        ]
        
        # URL shortener domains
        self.shortener_domains = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 
            'short.link', 'rb.gy', 'cutt.ly', 'is.gd', 'buff.ly'
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
        if not str1 or not str2:
            return 0.0
        return SequenceMatcher(None, str1.lower(), str2.lower()).ratio()
    
    def extract_domain_from_email(self, email_address):
        """
        Extract domain from email address
        
        Args:
            email_address (str): Email address
            
        Returns:
            str: Domain part of email, or None if invalid
        """
        if not email_address:
            return None
            
        try:
            # Handle cases like "Name <email@domain.com>"
            if '<' in email_address and '>' in email_address:
                email_match = re.search(r'<([^>]+)>', email_address)
                if email_match:
                    email_address = email_match.group(1)
            
            # Extract domain part
            if '@' in email_address:
                domain = email_address.split('@')[-1].strip()
                # Remove any trailing characters that aren't part of domain
                domain = re.sub(r'[^a-zA-Z0-9.-].*$', '', domain)
                return domain.lower()
                
        except Exception as e:
            print(f"Error extracting domain from {email_address}: {e}")
        
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
            return {
                'is_suspicious': False, 
                'matches': [], 
                'max_similarity': 0,
                'suspicious_domain': None
            }
        
        suspicious_domain = suspicious_domain.lower().strip()
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
        
        # Additional suspicious pattern checks
        has_phishing_keywords = any(
            keyword in suspicious_domain 
            for keyword in self.phishing_domain_keywords
        )
        
        has_multiple_hyphens = suspicious_domain.count('-') >= 2
        
        has_suspicious_tld = any(
            suspicious_domain.endswith(tld) 
            for tld in self.suspicious_tlds
        )
        
        has_numbers_and_letters_mixed = bool(
            re.search(r'[0-9].*[a-z]|[a-z].*[0-9]', suspicious_domain)
        )
        
        # Check for excessive length with mixed characters
        is_excessively_long = (
            has_numbers_and_letters_mixed and 
            len(suspicious_domain) > 15
        )
        
        # Sort matches by similarity (highest first)
        matches.sort(key=lambda x: x['similarity'], reverse=True)
        
        # Determine if suspicious
        is_suspicious = (
            len(matches) > 0 or 
            has_phishing_keywords or 
            has_multiple_hyphens or 
            has_suspicious_tld or
            is_excessively_long
        )
        
        return {
            'is_suspicious': is_suspicious,
            'matches': matches,
            'max_similarity': round(max_similarity, 3),
            'has_phishing_keywords': has_phishing_keywords,
            'has_multiple_hyphens': has_multiple_hyphens,
            'has_suspicious_tld': has_suspicious_tld,
            'suspicious_domain': suspicious_domain
        }
    
    def extract_urls_from_text(self, text):
        """
        Extract URLs from email text using comprehensive patterns
        
        Args:
            text (str): Email text content
            
        Returns:
            list: List of found URLs
        """
        if not text:
            return []
        
        # Enhanced URL patterns to catch various formats
        url_patterns = [
            r'https?://[^\s<>"\'\[\]{}]+',  # Standard HTTP/HTTPS URLs
            r'www\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s<>"\'\[\]{}]*)?',  # www.domain.com
            r'(?<!@)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s<>"\'\[\]{}]*)?',  # domain.com/path
        ]
        
        urls = set()  # Use set to avoid duplicates
        
        for pattern in url_patterns:
            found_urls = re.findall(pattern, text, re.IGNORECASE)
            for url in found_urls:
                # Clean up URL and validate
                cleaned_url = self._clean_url(url)
                if cleaned_url and self._is_valid_url(cleaned_url):
                    urls.add(cleaned_url)
        
        return list(urls)
    
    def _clean_url(self, url):
        """Clean and normalize URL"""
        if not url:
            return None
            
        # Remove trailing punctuation and brackets
        url = re.sub(r'[.,;!?\]\}]+$', '', url.strip())
        
        # Remove leading/trailing quotes
        url = url.strip('\'"')
        
        return url if url else None
    
    def _is_valid_url(self, url):
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
    
    def is_ip_address(self, domain):
        """
        Check if a domain is actually an IP address
        
        Args:
            domain (str): Domain to check
            
        Returns:
            bool: True if it's an IP address
        """
        if not domain:
            return False
            
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
            return {'is_suspicious': False, 'reasons': [], 'analyzed_url': '', 'domain': ''}
        
        reasons = []
        domain = ''
        
        try:
            # Normalize URL for parsing
            normalized_url = url
            if not url.startswith(('http://', 'https://')):
                if url.startswith('www.'):
                    normalized_url = 'http://' + url
                elif '.' in url and not url.startswith('mailto:'):
                    normalized_url = 'http://' + url
            
            # Parse URL
            try:
                parsed_url = urllib.parse.urlparse(normalized_url)
                domain = parsed_url.netloc.lower()
            except Exception:
                reasons.append('Invalid URL format')
                return {
                    'is_suspicious': True,
                    'reasons': reasons,
                    'analyzed_url': url,
                    'domain': domain
                }
            
            # Remove www. prefix for analysis
            analysis_domain = domain
            if analysis_domain.startswith('www.'):
                analysis_domain = analysis_domain[4:]
            
            # Check for IP address instead of domain
            if self.is_ip_address(analysis_domain):
                reasons.append('Uses IP address instead of domain name')
            
            # Check for suspicious patterns in domain
            for pattern in self.suspicious_patterns:
                if re.search(pattern, analysis_domain):
                    reasons.append(f'Matches suspicious pattern: {pattern}')
            
            # Check for URL shorteners
            if any(shortener in analysis_domain for shortener in self.shortener_domains):
                reasons.append('Uses URL shortener service')
            
            # Check for excessive subdomains
            domain_parts = analysis_domain.split('.')
            if len(domain_parts) > 4:  # More than typical subdomain.domain.tld
                reasons.append('Excessive number of subdomains')
            
            # Check for suspicious TLDs
            if any(analysis_domain.endswith(tld) for tld in self.suspicious_tlds):
                reasons.append('Uses suspicious top-level domain')
            
            # Check for suspicious character patterns
            if re.search(r'[0-9].*[a-z].*[0-9]', analysis_domain):
                reasons.append('Suspicious alternating numbers and letters')
            
            if analysis_domain.count('-') >= 3:
                reasons.append('Excessive use of hyphens')
            
            # Check for homograph attacks (basic)
            if any(char in analysis_domain for char in ['0', '1', 'l', 'I']):
                # Look for potential character substitution
                for legit_domain in list(self.legitimate_domains)[:10]:  # Check top domains
                    if self.calculate_edit_distance_similarity(analysis_domain, legit_domain) > 0.8:
                        reasons.append(f'Potentially mimics legitimate domain: {legit_domain}')
                        break
            
            # Check URL path for suspicious patterns
            if parsed_url.path:
                path = parsed_url.path.lower()
                suspicious_path_patterns = [
                    'verify', 'confirm', 'secure', 'update', 'login',
                    'account', 'suspended', 'locked', 'urgent'
                ]
                if any(pattern in path for pattern in suspicious_path_patterns):
                    reasons.append('Suspicious keywords in URL path')
            
        except Exception as e:
            reasons.append(f'URL analysis error: {str(e)}')
        
        return {
            'is_suspicious': len(reasons) > 0,
            'reasons': reasons,
            'analyzed_url': url,
            'domain': domain
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
        # Initialize results
        analysis_results = {
            'sender_email': sender_email or 'Unknown',
            'sender_domain': None,
            'domain_analysis': {},
            'urls_found': [],
            'suspicious_urls': [],
            'risk_score': 0,
            'risk_level': 'MINIMAL',
            'risk_factors': [],
            'total_urls_analyzed': 0,
            'suspicious_url_count': 0
        }
        
        try:
            # Extract sender domain
            sender_domain = self.extract_domain_from_email(sender_email)
            analysis_results['sender_domain'] = sender_domain
            
            # Check sender domain similarity
            if sender_domain:
                domain_analysis = self.check_domain_similarity(sender_domain)
                analysis_results['domain_analysis'] = domain_analysis
            
            # Extract URLs from email content
            body_urls = self.extract_urls_from_text(email_body or "")
            subject_urls = self.extract_urls_from_text(email_subject or "")
            all_urls = list(set(body_urls + subject_urls))  # Remove duplicates
            
            analysis_results['urls_found'] = all_urls
            analysis_results['total_urls_analyzed'] = len(all_urls)
            
            # Analyze each URL
            suspicious_url_analyses = []
            for url in all_urls:
                url_analysis = self.analyze_url_suspicious_patterns(url)
                if url_analysis['is_suspicious']:
                    suspicious_url_analyses.append(url_analysis)
            
            analysis_results['suspicious_urls'] = suspicious_url_analyses
            analysis_results['suspicious_url_count'] = len(suspicious_url_analyses)
            
            # Calculate overall risk score and factors
            risk_score = 0
            risk_factors = []
            
            # Domain-based risk scoring
            if analysis_results['domain_analysis'].get('is_suspicious'):
                domain_info = analysis_results['domain_analysis']
                
                if domain_info.get('matches'):
                    risk_score += len(domain_info['matches']) * 25
                    risk_factors.append('Sender domain similar to legitimate domain')
                
                if domain_info.get('has_phishing_keywords'):
                    risk_score += 20
                    risk_factors.append('Sender domain contains phishing keywords')
                
                if domain_info.get('has_multiple_hyphens'):
                    risk_score += 15
                    risk_factors.append('Sender domain has suspicious structure')
                
                if domain_info.get('has_suspicious_tld'):
                    risk_score += 25
                    risk_factors.append('Sender domain uses suspicious TLD')
            
            # URL-based risk scoring
            if suspicious_url_analyses:
                risk_score += len(suspicious_url_analyses) * 15
                risk_factors.append(f'Contains {len(suspicious_url_analyses)} suspicious URLs')
                
                # Additional scoring for specific URL risks
                for url_analysis in suspicious_url_analyses:
                    if 'IP address' in ' '.join(url_analysis.get('reasons', [])):
                        risk_score += 10
                    if 'shortener' in ' '.join(url_analysis.get('reasons', [])):
                        risk_score += 5
            
            # Determine risk level based on score
            if risk_score >= 60:
                risk_level = 'HIGH'
            elif risk_score >= 35:
                risk_level = 'MEDIUM'
            elif risk_score >= 15:
                risk_level = 'LOW'
            else:
                risk_level = 'MINIMAL'
            
            analysis_results.update({
                'risk_score': risk_score,
                'risk_level': risk_level,
                'risk_factors': risk_factors
            })
            
        except Exception as e:
            print(f"Error in email security analysis: {e}")
            analysis_results.update({
                'error': str(e),
                'risk_level': 'UNKNOWN'
            })
        
        return analysis_results
    
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
        domain_info = analysis.get('domain_analysis', {})
        if domain_info.get('is_suspicious'):
            print("🚨 SUSPICIOUS SENDER DOMAIN:")
            
            if domain_info.get('matches'):
                print("  Similar to legitimate domains:")
                for match in domain_info['matches'][:3]:  # Show top 3
                    similarity_pct = match['similarity'] * 100
                    print(f"    {match['suspicious_domain']} ≈ {match['legitimate_domain']} "
                          f"({similarity_pct:.1f}% similar)")
            
            if domain_info.get('has_phishing_keywords'):
                print("  ⚠️  Contains phishing-related keywords")
            if domain_info.get('has_multiple_hyphens'):
                print("  ⚠️  Suspicious domain structure (multiple hyphens)")
            if domain_info.get('has_suspicious_tld'):
                print("  ⚠️  Uses suspicious top-level domain")
            print()
        else:
            print("✅ Sender domain appears legitimate")
            print()
        
        # URL analysis
        total_urls = analysis.get('total_urls_analyzed', 0)
        suspicious_urls = analysis.get('suspicious_urls', [])
        
        print(f"URLs FOUND: {total_urls}")
        
        if suspicious_urls:
            print(f"🚨 SUSPICIOUS URLs: {len(suspicious_urls)}")
            for i, url_info in enumerate(suspicious_urls, 1):
                print(f"  {i}. URL: {url_info['analyzed_url']}")
                print(f"     Domain: {url_info['domain']}")
                print(f"     Issues: {', '.join(url_info['reasons'])}")
                print()
        else:
            if total_urls > 0:
                print("✅ No suspicious URLs detected")
            else:
                print("ℹ️  No URLs found in email")
        
        # Risk factors summary
        if analysis.get('risk_factors'):
            print("RISK FACTORS IDENTIFIED:")
            for i, factor in enumerate(analysis['risk_factors'], 1):
                print(f"  {i}. {factor}")
        else:
            print("✅ No significant risk factors identified")
        
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
    try:
        print("Testing Domain & URL Detection System")
        print("="*50)
        
        # Initialize detector
        detector = DomainURLDetector()
        
        # Perform analysis
        print("Analyzing test email...")
        #analysis = detector.analyze_email_security(sender, body, subject)
        
        # Print results
        #detector.print_security_analysis(analysis)
        
        print("\nTest completed successfully!")
        
    except Exception as e:
        print(f"Error during testing: {e}")
        import traceback
        traceback.print_exc()