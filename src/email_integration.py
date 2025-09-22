"""
Complete Gmail API Integration using your existing distancechecker.py
Enhanced with improved risk assessment for legitimate vs fraudulent emails
"""

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import base64
import re

# Import data from email
from get_data import GetData
from get_data_manual import GetDataManual

# Import your existing keyword detection components
from keyword_detector import KeywordDetector
from position_scorer import PositionScorer
from keyword_lists import SuspiciousKeywords

# Import your existing domain/URL detection
from distancechecker import analyze_email_domain_and_urls, DomainURLDetector

# Import attachment analyzer
from attachment_analyzer import AttachmentRiskAnalyzer

# Gmail API scopes required
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

class PhishingEmailAnalyzer:
    """
    Complete phishing email analyzer using your existing systems
    Enhanced with better legitimate vs fraudulent detection
    """
    
    def __init__(self, service=None):
        """Initialize Gmail service and detection components"""
        self.service = None
        self.keyword_detector = KeywordDetector()
        self.position_scorer = PositionScorer()
        self.attachment_analyzer = AttachmentRiskAnalyzer()
        
        # Use your existing domain detector
        self.domain_detector = DomainURLDetector()
        
        # Use your existing keyword system
        self.keyword_categories = SuspiciousKeywords.get_keyword_categories()
        self.category_weights = SuspiciousKeywords.get_category_weights()
        
        # Enhanced trusted domains - more comprehensive list
        self.highly_trusted_domains = {
            'gmail.com', 'google.com', 'accounts.google.com', 
            'security.google.com', 'support.google.com', 'googlemail.com',
            'microsoft.com', 'outlook.com', 'live.com', 'hotmail.com',
            'apple.com', 'icloud.com', 'me.com', 'mac.com',
            'paypal.com', 'paypal-communications.com',
            'amazonses.com', 'amazon.com', 'amazon.co.uk',
            'facebook.com', 'meta.com', 'instagram.com',
            'twitter.com', 'x.com', 'linkedin.com',
            'github.com', 'stackoverflow.com'
        }
        
        # Security notification patterns for context
        self.security_patterns = [
            r'security alert', r'new sign-?in', r'login from', r'new device',
            r'unusual activity', r'password changed', r'two-?factor',
            r'verification code', r'account activity', r'suspicious activity',
            r'access granted', r'permission granted', r'allowed.*access'
        ]
        
        # Obvious scam patterns that should INCREASE risk for anonymous senders
        self.obvious_scam_patterns = [
            r'free money', r'you.*won', r'claim.*prize', r'lottery.*winner',
            r'inherit.*million', r'nigerian prince', r'deceased.*relative',
            r'lottery.*notification', r'congratulations.*winner', r'selected.*beneficiary',
            r'transfer.*funds', r'business.*proposal', r'urgent.*assistance',
            r'confidential.*transaction', r'next.*of.*kin', r'beneficiary.*fund',
            r'claim.*\$\d+', r'won.*\$\d+', r'prize.*\$\d+', r'millions.*dollars',
            r'inheritance.*fund', r'trust.*fund.*transfer', r'cash.*prize.*claim'
        ]

    def initialize_service(self):
        """Run Gmail OAuth only once when Flask calls it"""
        if not self.service:
            self.service = GetData.gmail_service()

    def analyze_emails(self, max_results=5):
        if not self.service:
            raise Exception("Gmail service not initialized. Call initialize_service() first.")
        return self.analyze_recent_emails(max_results)

    def is_highly_trusted_sender(self, sender_email):
        """Check if sender is from a highly trusted domain"""
        if not sender_email or '@' not in sender_email:
            return False
        
        domain = sender_email.split('@')[1].lower()
        return domain in self.highly_trusted_domains

    def is_trusted_sender(self, sender_email):
        """Use your distancechecker's legitimate domain logic"""
        return self.domain_detector.analyze_sender_domain(sender_email).get('is_suspicious') == False

    def calculate_sender_trust_score(self, sender_email):
        """Calculate trust score based on sender characteristics"""
        if not sender_email:
            return 0
        
        # Highly trusted domains get maximum trust
        if self.is_highly_trusted_sender(sender_email):
            return 100
        
        # Known legitimate domains get high trust
        if self.is_trusted_sender(sender_email):
            return 80
        
        # Check for suspicious sender patterns
        domain = sender_email.split('@')[1].lower() if '@' in sender_email else ''
        
        # Suspicious characteristics
        trust_score = 50  # Neutral starting point
        
        # Reduce trust for suspicious domain patterns
        if re.search(r'\d{3,}', domain):  # Many numbers in domain
            trust_score -= 20
        
        if len(domain.split('.')) > 3:  # Too many subdomains
            trust_score -= 15
        
        if re.search(r'(temp|fake|test|spam)', domain):
            trust_score -= 30
        
        return max(0, trust_score)

    def enhanced_google_security_detection(self, sender_email, subject, body):
        """Specific detection for Google security notifications"""
        if not sender_email:
            return False
        
        # Check if it's from Google
        google_domains = ['gmail.com', 'google.com', 'accounts.google.com', 'security.google.com']
        sender_domain = sender_email.split('@')[1].lower() if '@' in sender_email else ''
        
        if sender_domain not in google_domains:
            return False
        
        # Check for legitimate Google security patterns
        combined_text = f"{subject} {body}".lower()
        
        google_security_patterns = [
            r'google.*security.*alert',
            r'new.*sign.*in.*to.*your.*google.*account',
            r'security.*activity.*on.*your.*google.*account',
            r'new.*device.*sign.*in',
            r'review.*your.*account.*activity',
            r'google.*account.*security.*checkup',
            r'sign.*in.*blocked.*on.*your.*google.*account',
            r'someone.*just.*used.*your.*password'
        ]
        
        for pattern in google_security_patterns:
            if re.search(pattern, combined_text):
                return True
        
        return False

    def detect_obvious_financial_scams(self, subject, body, sender_email):
        """Detect obvious financial scam patterns that should be HIGH risk"""
        combined_text = f"{subject} {body}".lower()
        
        # Get sender trust level
        sender_trust = self.calculate_sender_trust_score(sender_email)
        
        scam_count = 0
        matched_patterns = []
        
        for pattern in self.obvious_scam_patterns:
            if re.search(pattern, combined_text):
                scam_count += 1
                matched_patterns.append(pattern)
        
        # If low-trust sender + scam patterns = definite high risk
        if sender_trust < 60 and scam_count > 0:
            return {
                'is_obvious_scam': True,
                'scam_score_boost': scam_count * 25,  # 25 points per pattern
                'matched_patterns': matched_patterns
            }
        elif scam_count > 0:
            return {
                'is_obvious_scam': True,
                'scam_score_boost': scam_count * 15,  # 15 points for unknown senders
                'matched_patterns': matched_patterns
            }
        
        return {
            'is_obvious_scam': False,
            'scam_score_boost': 0,
            'matched_patterns': []
        }

    def is_legitimate_security_notification(self, subject, body, sender_email):
        """Check if this is a legitimate security notification"""
        if not self.is_trusted_sender(sender_email):
            return False
        
        combined_text = f"{subject} {body}".lower()
        
        for pattern in self.security_patterns:
            if re.search(pattern, combined_text):
                return True
        
        return False

    def smart_domain_url_analysis(self, sender_email, email_body, email_subject):
        """
        Enhanced wrapper around your existing domain/URL analysis
        """
        # Use your existing analysis function
        original_analysis = analyze_email_domain_and_urls(sender_email, email_body, email_subject)
        
        # Check if this is a trusted sender with security notification
        is_trusted = self.is_trusted_sender(sender_email)
        is_security_notification = self.is_legitimate_security_notification(email_subject, email_body, sender_email)
        
        # Apply smart adjustments to your existing analysis
        if is_trusted and is_security_notification:
            # For legitimate security notifications, heavily reduce risk
            original_analysis['risk_level'] = 'MINIMAL'
            original_analysis['risk_score'] = min(original_analysis.get('risk_score', 0), 2)
            
            # Filter out legitimate URLs from suspicious list
            suspicious_urls = original_analysis.get('suspicious_urls', [])
            filtered_urls = []
            
            for url_analysis in suspicious_urls:
                url = url_analysis.get('analyzed_url', '')
                domain = url_analysis.get('domain', '')
                
                # Skip URLs that are from the same trusted domain
                if domain in self.domain_detector.legitimate_domains:
                    continue
                
                # Keep only genuinely suspicious URLs
                reasons = url_analysis.get('reasons', [])
                serious_reasons = [r for r in reasons if 'similar to' in r.lower() or 'ip address' in r.lower()]
                
                if serious_reasons:
                    filtered_urls.append(url_analysis)
            
            original_analysis['suspicious_urls'] = filtered_urls
            original_analysis['suspicious_url_count'] = len(filtered_urls)
            
        elif is_trusted:
            # For trusted senders, reduce risk moderately
            original_score = original_analysis.get('risk_score', 0)
            original_analysis['risk_score'] = int(original_score * 0.6)
            
            # Adjust risk level based on new score
            new_score = original_analysis['risk_score']
            if new_score >= 15:
                original_analysis['risk_level'] = 'MEDIUM'
            elif new_score >= 5:
                original_analysis['risk_level'] = 'LOW'
            else:
                original_analysis['risk_level'] = 'MINIMAL'
        
        return original_analysis

    def calculate_attachment_risk_score(self, attachment_results):
        """Calculate attachment risk using your existing attachment analyzer"""
        if not attachment_results:
            return {
                'attachment_risk_score': 0,
                'attachment_risk_level': 'NONE',
                'has_attachments': False,
                'suspicious_attachment_count': 0
            }
        
        total_attachments = len(attachment_results)
        suspicious_count = sum(1 for att in attachment_results if att['is_suspicious'])
        
        risk_score = 0
        for att in attachment_results:
            if att['is_suspicious']:
                base_score = 15
                risk_score += base_score
                
                for risk_factor in att.get('risk_factors', []):
                    factor_lower = risk_factor.lower()
                    if 'critical' in factor_lower:
                        risk_score += 30
                    elif 'high-risk extension' in factor_lower:
                        risk_score += 20
                    elif 'macro' in factor_lower:
                        risk_score += 15
                    elif 'archive' in factor_lower:
                        risk_score += 10
                    elif 'context mismatch' in factor_lower:
                        risk_score += 25
        
        if risk_score >= 40:
            risk_level = 'HIGH'
        elif risk_score >= 20:
            risk_level = 'MEDIUM'
        elif risk_score >= 5:
            risk_level = 'LOW'
        else:
            risk_level = 'MINIMAL'
        
        return {
            'attachment_risk_score': risk_score,
            'attachment_risk_level': risk_level,
            'has_attachments': True,
            'total_attachments': total_attachments,
            'suspicious_attachment_count': suspicious_count
        }

    def calculate_link_risk_score(self, domain_url_analysis, sender_email="", subject="", body=""):
        """Calculate link risk using your existing domain analysis results"""
        if not domain_url_analysis:
            return {
                'link_risk_score': 0,
                'link_risk_level': 'NONE',
                'has_links': False,
                'suspicious_link_count': 0,
                'link_details': []
            }
        
        # Use the risk score and analysis from your distancechecker
        base_score = domain_url_analysis.get('risk_score', 0)
        risk_level = domain_url_analysis.get('risk_level', 'MINIMAL')
        suspicious_urls = domain_url_analysis.get('suspicious_urls', [])
        all_urls = domain_url_analysis.get('urls_found', [])
        
        # Create link details from your analysis
        link_details = []
        for url_analysis in suspicious_urls:
            url_risk = 'MEDIUM'  # Default
            score = 10  # Default
            
            reasons = url_analysis.get('reasons', [])
            for reason in reasons:
                if 'similar to' in reason.lower():
                    url_risk = 'HIGH'
                    score = 25
                    break
                elif 'ip address' in reason.lower():
                    url_risk = 'HIGH'
                    score = 20
                    break
            
            link_details.append({
                'type': 'url',
                'url': url_analysis.get('analyzed_url', ''),
                'domain': url_analysis.get('domain', ''),
                'description': '; '.join(reasons),
                'risk_level': url_risk,
                'score': score
            })
        
        return {
            'link_risk_score': base_score,
            'link_risk_level': risk_level,
            'has_links': len(all_urls) > 0,
            'total_links': len(all_urls),
            'suspicious_link_count': len(suspicious_urls),
            'link_details': link_details,
            'sender_suspicious': domain_url_analysis.get('sender_analysis', {}).get('is_suspicious', False)
        }

    def enhanced_risk_calculation(self, sender_email, subject, body, keyword_score, 
                                attachment_score, link_score):
        """Enhanced risk calculation with better context awareness"""
        
        # Get trust score
        sender_trust = self.calculate_sender_trust_score(sender_email)
        
        # Check for legitimate security notification
        is_security_notif = self.is_legitimate_security_notification(subject, body, sender_email)
        is_google_security = self.enhanced_google_security_detection(sender_email, subject, body)
        
        # Check for obvious scam language
        scam_detection = self.detect_obvious_financial_scams(subject, body, sender_email)
        
        # Base total score
        total_score = keyword_score + attachment_score + link_score
        
        # Apply trust-based adjustments
        if is_google_security or (sender_trust >= 95 and is_security_notif):
            # Highly trusted + security notification: massive reduction
            adjusted_score = total_score * 0.05  # 95% reduction
            risk_level = 'MINIMAL'
            adjustment_reason = "Legitimate security notification from highly trusted sender"
            
        elif sender_trust >= 80 and is_security_notif:
            # Trusted + security notification: large reduction
            adjusted_score = total_score * 0.15  # 85% reduction
            risk_level = 'LOW' if adjusted_score > 10 else 'MINIMAL'
            adjustment_reason = "Security notification from trusted sender"
            
        elif sender_trust >= 80:
            # Trusted sender: moderate reduction
            adjusted_score = total_score * 0.4  # 60% reduction
            adjustment_reason = "Trusted sender"
            
        else:
            # No trust-based adjustments yet
            adjusted_score = total_score
            adjustment_reason = "Standard risk assessment"
        
        # Apply scam detection boost
        if scam_detection['is_obvious_scam']:
            adjusted_score += scam_detection['scam_score_boost']
            adjustment_reason = f"Obvious financial scam detected: {', '.join(scam_detection['matched_patterns'][:2])}"
        
        # Determine final risk level
        if adjusted_score >= 60:
            risk_level = 'HIGH'
        elif adjusted_score >= 30:
            risk_level = 'MEDIUM'
        elif adjusted_score >= 10:
            risk_level = 'LOW'
        else:
            risk_level = 'MINIMAL'
        
        return {
            'adjusted_score': round(adjusted_score, 2),
            'risk_level': risk_level,
            'original_score': total_score,
            'sender_trust_score': sender_trust,
            'is_security_notification': is_security_notif,
            'is_google_security': is_google_security,
            'scam_patterns_found': scam_detection['matched_patterns'],
            'adjustment_reason': adjustment_reason,
            'scam_score_boost': scam_detection['scam_score_boost']
        }

    def analyze_manual_email(self):
        """Analyze manually inputted email using your existing systems"""
        print("Paste your raw email and end with a single line 'EOF'\n")
        lines = []
        while True:
            line = input()
            if line.strip().upper() == "EOF":
                break
            lines.append(line)
        manual_data = "\n".join(lines)

        email = GetDataManual.extract_email_info_from_txt(manual_data)

        subject_matches = self.keyword_detector.find_keywords_in_text(email["Subject"], is_subject=True)
        body_matches = self.keyword_detector.find_keywords_in_text(email["Body"], is_subject=False)
        all_matches = subject_matches + body_matches
        
        email_length = len(email["Subject"]) + len(email["Body"])
        scoring_result = self.position_scorer.calculate_comprehensive_score(all_matches, email_length)
        
        # Use enhanced domain analysis
        domain_url_analysis = self.smart_domain_url_analysis(
            sender_email=email["From"],
            email_body=email["Body"],
            email_subject=email["Subject"]
        )
        
        analysis = {
            'sender': email["From"],
            'subject': email["Subject"],
            'body_length': len(email["Body"]),
            'subject_length': len(email["Subject"]),
            'total_matches': len(all_matches),
            'subject_matches': len(subject_matches),
            'body_matches': len(body_matches),
            'domain_url_analysis': domain_url_analysis,
            **scoring_result
        }
        
        return analysis

    def analyze_single_email(self, msg_data):
        """Analyze single email using all your existing systems with smart enhancements"""
        subject = GetData.get_email_subject(msg_data)
        body = GetData.get_email_body(msg_data)
        sender = GetData.get_email_sender(msg_data)
        
        # Use your existing keyword detection system
        subject_matches = self.keyword_detector.find_keywords_in_text(subject, is_subject=True)
        body_matches = self.keyword_detector.find_keywords_in_text(body, is_subject=False)
        all_matches = subject_matches + body_matches
        
        email_length = len(subject) + len(body)
        scoring_result = self.position_scorer.calculate_comprehensive_score(all_matches, email_length)
        
        # Use your enhanced domain/URL analysis
        domain_url_analysis = self.smart_domain_url_analysis(sender, body, subject)

        # Use your existing attachment analysis
        raw_attachments = self.attachment_analyzer.extract_gmail_attachments(msg_data)
        parsed_attachments = self.attachment_analyzer.parse_gmail_attachment_data(
            self.service, msg_data["id"], raw_attachments
        )
        attachment_results = self.attachment_analyzer.analyze_attachments(
            parsed_attachments, subject, body
        )
        
        # Calculate risks
        attachment_risk = self.calculate_attachment_risk_score(attachment_results)
        link_risk = self.calculate_link_risk_score(domain_url_analysis, sender, subject, body)
        
        # NEW: Use enhanced risk calculation
        enhanced_risk = self.enhanced_risk_calculation(
            sender, subject, body,
            scoring_result['total_score'],
            attachment_risk['attachment_risk_score'],
            link_risk['link_risk_score']
        )
        
        # Combine all results with enhanced scoring
        analysis = {
            'sender': sender,
            'subject': subject,
            'body_length': len(body),
            'subject_length': len(subject),
            'total_matches': len(all_matches),
            'subject_matches': len(subject_matches),
            'body_matches': len(body_matches),
            'domain_url_analysis': domain_url_analysis,
            'attachment_results': attachment_results,
            'attachment_risk': attachment_risk,
            'link_risk': link_risk,
            
            # Enhanced risk results
            'enhanced_risk': enhanced_risk,
            'final_risk_score': enhanced_risk['adjusted_score'],
            'final_risk_level': enhanced_risk['risk_level'],
            'risk_adjustment_reason': enhanced_risk['adjustment_reason'],
            'sender_trust_score': enhanced_risk['sender_trust_score'],
            
            # Keep original scores for comparison
            'original_keyword_score': scoring_result['total_score'],
            'original_total_score': enhanced_risk['original_score'],
            
            **scoring_result  # Include all existing scoring results
        }
        
        return analysis
    
    def analyze_recent_emails(self, max_results=10):
        """Analyze recent emails using your complete system"""
        results = self.service.users().messages().list(
            userId="me", 
            maxResults=max_results
        ).execute()
        messages = results.get("messages", [])
        
        analyses = []
        
        print(f"Analyzing {len(messages)} recent emails...\n")
        
        for i, msg in enumerate(messages, 1):
            try:
                msg_data = self.service.users().messages().get(
                    userId="me", 
                    id=msg["id"], 
                    format="full"
                ).execute()
                
                analysis = self.analyze_single_email(msg_data)
                analyses.append(analysis)
                
                self.print_email_analysis(analysis, i)
                
            except Exception as e:
                print(f"Error analyzing email {i}: {str(e)}")
        
        return analyses
    
    def print_email_analysis(self, analysis, email_number):
        """Print analysis results with enhanced information"""
        print(f"{'='*60}")
        print(f"EMAIL {email_number} ANALYSIS")
        print(f"{'='*60}")
        
        print(f"From: {analysis['sender']}")
        print(f"Subject: {analysis['subject']}")
        print(f"Body Length: {analysis['body_length']} characters")
        
        # Show enhanced risk assessment
        enhanced = analysis.get('enhanced_risk', {})
        print(f"\nENHANCED RISK ASSESSMENT:")
        print(f"  Final Risk Level: {analysis.get('final_risk_level', 'UNKNOWN')}")
        print(f"  Final Risk Score: {analysis.get('final_risk_score', 0)}")
        print(f"  Sender Trust Score: {enhanced.get('sender_trust_score', 0)}/100")
        print(f"  Adjustment Reason: {enhanced.get('adjustment_reason', 'None')}")
        
        if enhanced.get('scam_patterns_found'):
            print(f"  🚨 Scam Patterns: {', '.join(enhanced['scam_patterns_found'][:3])}")
        
        if enhanced.get('is_security_notification'):
            print(f"  ✅ LEGITIMATE SECURITY NOTIFICATION")
        
        if enhanced.get('is_google_security'):
            print(f"  ✅ GOOGLE SECURITY NOTIFICATION")
        
        print(f"\nORIGINAL SCORES (for comparison):")
        print(f"  Original Total Score: {enhanced.get('original_score', 0)}")
        print(f"  Keyword Score: {analysis.get('original_keyword_score', 0)}")
        
        # Show combined risk
        print(f"\nDETAILED BREAKDOWN:")
        print(f"  Keywords Found: {analysis['total_matches']}")
        
        # Link analysis
        link_risk = analysis.get('link_risk', {})
        if link_risk.get('has_links'):
            print(f"  Links: {link_risk['total_links']} total, {link_risk['suspicious_link_count']} suspicious")
        
        # Attachment analysis
        attachment_risk = analysis.get('attachment_risk', {})
        if attachment_risk.get('has_attachments'):
            print(f"  Attachments: {attachment_risk['total_attachments']} total, {attachment_risk['suspicious_attachment_count']} suspicious")
        
        print(f"\n{'='*60}\n")
    
    def get_integration_summary(self, analyses):
        """Get summary statistics using your existing data structure"""
        if not analyses:
            return {}
        
        total_emails = len(analyses)
        high_risk = sum(1 for a in analyses if a.get('final_risk_level') == 'HIGH')
        medium_risk = sum(1 for a in analyses if a.get('final_risk_level') == 'MEDIUM')
        trusted_senders = sum(1 for a in analyses if a.get('sender_trust_score', 0) >= 80)
        security_notifications = sum(1 for a in analyses 
                                   if a.get('enhanced_risk', {}).get('is_security_notification'))
        google_security = sum(1 for a in analyses 
                            if a.get('enhanced_risk', {}).get('is_google_security'))
        
        # Keep your existing summary structure
        domain_high_risk = sum(1 for a in analyses 
                             if a.get('domain_url_analysis', {}).get('risk_level') == 'HIGH')
        total_suspicious_urls = sum(a.get('domain_url_analysis', {}).get('suspicious_url_count', 0) 
                                  for a in analyses)
        
        avg_score = sum(a['total_score'] for a in analyses) / total_emails
        avg_final_score = sum(a.get('final_risk_score', 0) for a in analyses) / total_emails
        
        return {
            'total_emails_analyzed': total_emails,
            'high_risk_emails': high_risk,
            'medium_risk_emails': medium_risk,
            'suspicious_emails': sum(1 for a in analyses if a.get('final_risk_score', 0) >= 10),
            'domain_high_risk_emails': domain_high_risk,
            'total_suspicious_urls': total_suspicious_urls,
            'trusted_senders': trusted_senders,
            'security_notifications': security_notifications,
            'google_security_notifications': google_security,
            'average_keyword_score': round(avg_score, 2),
            'average_final_score': round(avg_final_score, 2),
            'highest_score': max(a['total_score'] for a in analyses),
            'highest_final_score': max(a.get('final_risk_score', 0) for a in analyses),
            'most_suspicious_email': max(analyses, key=lambda x: x.get('final_risk_score', 0))
        }