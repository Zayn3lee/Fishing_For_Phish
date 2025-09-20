"""
Complete Gmail API Integration using your existing distancechecker.py
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
        
        # Security notification patterns for context
        self.security_patterns = [
            r'security alert', r'new sign-?in', r'login from', r'new device',
            r'unusual activity', r'password changed', r'two-?factor',
            r'verification code', r'account activity', r'suspicious activity',
            r'access granted', r'permission granted', r'allowed.*access'
        ]

    def initialize_service(self):
        """Run Gmail OAuth only once when Flask calls it"""
        if not self.service:
            self.service = GetData.gmail_service()

    def analyze_emails(self, max_results=5):
        if not self.service:
            raise Exception("Gmail service not initialized. Call initialize_service() first.")
        return self.analyze_recent_emails(max_results)

    def is_trusted_sender(self, sender_email):
        """Use your distancechecker's legitimate domain logic"""
        return self.domain_detector.analyze_sender_domain(sender_email).get('is_suspicious') == False

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
        
        # Check context using your systems
        is_trusted = self.is_trusted_sender(sender)
        is_security_notification = self.is_legitimate_security_notification(subject, body, sender)
        
        # Use your existing keyword detection system
        subject_matches = self.keyword_detector.find_keywords_in_text(subject, is_subject=True)
        body_matches = self.keyword_detector.find_keywords_in_text(body, is_subject=False)
        all_matches = subject_matches + body_matches
        
        email_length = len(subject) + len(body)
        scoring_result = self.position_scorer.calculate_comprehensive_score(all_matches, email_length)
        
        # Apply smart keyword adjustment
        original_keyword_score = scoring_result['total_score']
        if is_trusted and is_security_notification:
            adjusted_keyword_score = original_keyword_score * 0.1  # 90% reduction
            adjusted_risk_level = 'MINIMAL'
        elif is_trusted:
            adjusted_keyword_score = original_keyword_score * 0.5  # 50% reduction
            if adjusted_keyword_score >= 25:
                adjusted_risk_level = 'MEDIUM'
            elif adjusted_keyword_score >= 10:
                adjusted_risk_level = 'LOW'
            else:
                adjusted_risk_level = 'MINIMAL'
        else:
            adjusted_keyword_score = original_keyword_score
            adjusted_risk_level = scoring_result['risk_level']
        
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
        
        # Combine all scoring systems
        keyword_score = adjusted_keyword_score
        attachment_score = attachment_risk['attachment_risk_score']
        link_score = link_risk['link_risk_score']
        
        total_risk_score = keyword_score + attachment_score + link_score
        
        # Determine combined risk level
        if total_risk_score >= 80:
            combined_risk_level = 'HIGH'
        elif total_risk_score >= 40:
            combined_risk_level = 'MEDIUM'
        elif total_risk_score >= 15:
            combined_risk_level = 'LOW'
        else:
            combined_risk_level = 'MINIMAL'
        
        # STRONG override for legitimate security notifications
        if is_trusted and is_security_notification:
            combined_risk_level = 'MINIMAL'
            total_risk_score = min(total_risk_score, 5)  # Cap the score
        
        # Combine all results
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
            'combined_risk_score': total_risk_score,
            'combined_risk_level': combined_risk_level,
            'is_trusted_sender': is_trusted,
            'is_security_notification': is_security_notification,
            'adjusted_keyword_score': adjusted_keyword_score,
            'adjusted_keyword_risk_level': adjusted_risk_level,
            **scoring_result  # Include all your existing scoring results
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
        """Print analysis results"""
        print(f"{'='*60}")
        print(f"EMAIL {email_number} ANALYSIS")
        print(f"{'='*60}")
        
        print(f"From: {analysis['sender']}")
        print(f"Subject: {analysis['subject']}")
        print(f"Body Length: {analysis['body_length']} characters")
        
        # Show context indicators
        if analysis.get('is_trusted_sender'):
            print(f"✓ TRUSTED SENDER")
        if analysis.get('is_security_notification'):
            print(f"✓ LEGITIMATE SECURITY NOTIFICATION")
        print()
        
        # Show combined risk
        print(f"COMBINED RISK ASSESSMENT:")
        print(f"  Combined Risk Level: {analysis['combined_risk_level']}")
        print(f"  Combined Risk Score: {analysis['combined_risk_score']}")
        print()
        
        # Show keyword analysis
        print(f"KEYWORD ANALYSIS:")
        print(f"  Adjusted Risk Level: {analysis.get('adjusted_keyword_risk_level', 'UNKNOWN')}")
        print(f"  Adjusted Score: {analysis.get('adjusted_keyword_score', 0):.1f}")
        print(f"  Original Score: {analysis['total_score']}")
        print(f"  Keywords Found: {analysis['total_matches']}")
        print()
        
        # Link analysis
        link_risk = analysis.get('link_risk', {})
        if link_risk.get('has_links'):
            print(f"LINK/URL ANALYSIS:")
            print(f"  Link Risk Level: {link_risk['link_risk_level']}")
            print(f"  Link Risk Score: {link_risk['link_risk_score']}")
            print(f"  Total Links: {link_risk['total_links']}")
            print(f"  Suspicious Links: {link_risk['suspicious_link_count']}")
            print()
        
        # Attachment analysis
        attachment_risk = analysis.get('attachment_risk', {})
        if attachment_risk.get('has_attachments'):
            print(f"ATTACHMENT ANALYSIS:")
            print(f"  Attachment Risk Level: {attachment_risk['attachment_risk_level']}")
            print(f"  Attachment Risk Score: {attachment_risk['attachment_risk_score']}")
            print(f"  Total Attachments: {attachment_risk['total_attachments']}")
            print(f"  Suspicious Attachments: {attachment_risk['suspicious_attachment_count']}")
            print()
        
        print(f"\n{'='*60}\n")
    
    def get_integration_summary(self, analyses):
        """Get summary statistics using your existing data structure"""
        if not analyses:
            return {}
        
        total_emails = len(analyses)
        high_risk = sum(1 for a in analyses if a.get('combined_risk_level') == 'HIGH')
        medium_risk = sum(1 for a in analyses if a.get('combined_risk_level') == 'MEDIUM')
        trusted_senders = sum(1 for a in analyses if a.get('is_trusted_sender'))
        security_notifications = sum(1 for a in analyses if a.get('is_security_notification'))
        
        # Keep your existing summary structure
        domain_high_risk = sum(1 for a in analyses 
                             if a.get('domain_url_analysis', {}).get('risk_level') == 'HIGH')
        total_suspicious_urls = sum(a.get('domain_url_analysis', {}).get('suspicious_url_count', 0) 
                                  for a in analyses)
        
        avg_score = sum(a['total_score'] for a in analyses) / total_emails
        
        return {
            'total_emails_analyzed': total_emails,
            'high_risk_emails': high_risk,
            'medium_risk_emails': medium_risk,
            'suspicious_emails': sum(1 for a in analyses if a['total_score'] >= 10),
            'domain_high_risk_emails': domain_high_risk,
            'total_suspicious_urls': total_suspicious_urls,
            'trusted_senders': trusted_senders,
            'security_notifications': security_notifications,
            'average_keyword_score': round(avg_score, 2),
            'highest_score': max(a['total_score'] for a in analyses),
            'most_suspicious_email': max(analyses, key=lambda x: x['total_score'])
        }