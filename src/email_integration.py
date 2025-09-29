"""
Simple Gmail API Integration for Phishing Email Detection
Using existing keyword detection, domain analysis, and attachment analysis
"""

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import base64

# Import data from email
from get_data import GetData

# Import your existing detection components
from keyword_detector import KeywordDetector
from position_scorer import PositionScorer
from distancechecker import analyze_email_domain_and_urls
from attachment_analyzer import AttachmentRiskAnalyzer

# Gmail API scopes required
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

class PhishingEmailAnalyzer:
    """
    Simple phishing email analyzer using your existing systems
    """
    
    def __init__(self, service=None):
        """Initialize Gmail service and detection components"""
        self.service = None
        self.keyword_detector = KeywordDetector()
        self.position_scorer = PositionScorer()
        self.attachment_analyzer = AttachmentRiskAnalyzer()

    def initialize_service(self):
        """Run Gmail OAuth only once when Flask calls it"""
        if not self.service:
            self.service = GetData.gmail_service()

    def analyze_emails(self, max_results=10):
        """Main entry point for analyzing Gmail emails"""
        if not self.service:
            raise Exception("Gmail service not initialized. Call initialize_service() first.")
        
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

    def calculate_link_risk_score(self, domain_url_analysis):
        """Calculate link risk using your existing domain analysis results"""
        if not domain_url_analysis:
            return {
                'link_risk_score': 0,
                'link_risk_level': 'NONE',
                'has_links': False,
                'suspicious_link_count': 0
            }
        
        # Use the risk score and analysis from your distancechecker
        base_score = domain_url_analysis.get('risk_score', 0)
        risk_level = domain_url_analysis.get('risk_level', 'MINIMAL')
        suspicious_urls = domain_url_analysis.get('suspicious_urls', [])
        all_urls = domain_url_analysis.get('urls_found', [])
        
        return {
            'link_risk_score': base_score,
            'link_risk_level': risk_level,
            'has_links': len(all_urls) > 0,
            'total_links': len(all_urls),
            'suspicious_link_count': len(suspicious_urls),
            'sender_suspicious': domain_url_analysis.get('sender_analysis', {}).get('is_suspicious', False)
        }

    def analyze_single_email(self, msg_data):
        """Analyze single email using all your existing systems"""
        subject = GetData.get_email_subject(msg_data)
        body = GetData.get_email_body(msg_data)
        sender = GetData.get_email_sender(msg_data)
        
        # Use your existing keyword detection system
        subject_matches = self.keyword_detector.find_keywords_in_text(subject, is_subject=True)
        body_matches = self.keyword_detector.find_keywords_in_text(body, is_subject=False)
        all_matches = subject_matches + body_matches
        
        email_length = len(subject) + len(body)
        scoring_result = self.position_scorer.calculate_comprehensive_score(all_matches, email_length)
        
        # Use your existing domain/URL analysis
        domain_url_analysis = analyze_email_domain_and_urls(sender, body, subject)

        # Use your existing attachment analysis
        raw_attachments = GetData.get_gmail_attachments(msg_data)
        parsed_attachments = self.attachment_analyzer.parse_gmail_attachment_data(
            self.service, msg_data["id"], raw_attachments
        )
        attachment_results = self.attachment_analyzer.analyze_attachments(
            parsed_attachments, subject, body
        )
        
        # Calculate risks
        attachment_risk = self.calculate_attachment_risk_score(attachment_results)
        link_risk = self.calculate_link_risk_score(domain_url_analysis)
        
        # Store the keyword score separately before calculating total
        keyword_score = scoring_result['total_score']
        
        # Calculate total risk score
        total_score = keyword_score + attachment_risk['attachment_risk_score'] + link_risk['link_risk_score']
        
        # Determine overall risk level
        if total_score >= 60:
            overall_risk_level = 'HIGH'
        elif total_score >= 30:
            overall_risk_level = 'MEDIUM'
        elif total_score >= 10:
            overall_risk_level = 'LOW'
        else:
            overall_risk_level = 'MINIMAL'
        
        # Combine all results
        return {
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
            'keyword_score': keyword_score,  # Store keyword score separately
            'total_score': total_score,
            'overall_risk_level': overall_risk_level,
            **scoring_result  # Include all existing scoring results
        }
    
    def print_email_analysis(self, analysis, email_number):
        """Print analysis results"""
        print(f"{'='*60}")
        print(f"EMAIL {email_number} ANALYSIS")
        print(f"{'='*60}")
        
        print(f"From: {analysis['sender']}")
        print(f"Subject: {analysis['subject']}")
        print(f"Body Length: {analysis['body_length']} characters")
        
        # Show risk assessment
        print(f"\nRISK ASSESSMENT:")
        print(f"  Overall Risk Level: {analysis.get('overall_risk_level', 'UNKNOWN')}")
        print(f"  Total Risk Score: {analysis.get('total_score', 0)}")
        
        print(f"\nSCORE BREAKDOWN:")
        print(f"  Keyword Score: {analysis.get('keyword_score', 0)}")
        print(f"  Attachment Score: {analysis.get('attachment_risk', {}).get('attachment_risk_score', 0)}")
        print(f"  Link/Domain Score: {analysis.get('link_risk', {}).get('link_risk_score', 0)}")
        
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
        """Get summary statistics"""
        if not analyses:
            return {}
        
        total_emails = len(analyses)
        high_risk = sum(1 for a in analyses if a.get('overall_risk_level') == 'HIGH')
        medium_risk = sum(1 for a in analyses if a.get('overall_risk_level') == 'MEDIUM')
        
        domain_high_risk = sum(1 for a in analyses 
                             if a.get('domain_url_analysis', {}).get('risk_level') == 'HIGH')
        total_suspicious_urls = sum(a.get('domain_url_analysis', {}).get('suspicious_url_count', 0) 
                                  for a in analyses)
        
        avg_score = sum(a.get('total_score', 0) for a in analyses) / total_emails if total_emails > 0 else 0
        avg_keyword_score = sum(a.get('keyword_score', 0) for a in analyses) / total_emails if total_emails > 0 else 0
        
        return {
            'total_emails_analyzed': total_emails,
            'high_risk_emails': high_risk,
            'medium_risk_emails': medium_risk,
            'suspicious_emails': sum(1 for a in analyses if a.get('total_score', 0) >= 10),
            'domain_high_risk_emails': domain_high_risk,
            'total_suspicious_urls': total_suspicious_urls,
            'average_score': round(avg_score, 2),
            'average_keyword_score': round(avg_keyword_score, 2),
            'highest_score': max((a.get('total_score', 0) for a in analyses), default=0),
            'most_suspicious_email': max(analyses, key=lambda x: x.get('total_score', 0)) if analyses else None
        }