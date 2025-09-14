"""
Complete Gmail API Integration with Keyword Detection System
"""

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import base64

# Import data from email
from get_data import GetData
from get_data_manual import GetDataManual

# Import keyword detection components
from keyword_detector import KeywordDetector
from position_scorer import PositionScorer

# Import domain/URL detection - ADD THIS LINE
from distancechecker import analyze_email_domain_and_urls

# Gmail API scopes required
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

class PhishingEmailAnalyzer:
    """
    Complete phishing email analyzer integrating Gmail API with keyword detection
    """
    
    def __init__(self):
        """Initialize Gmail service and keyword detection components"""
        self.service = GetData.gmail_service()
        self.keyword_detector = KeywordDetector()
        self.position_scorer = PositionScorer()
        # Remove the distance_checker line since we're using the function directly

    def analyze_manual_email(self):
        """
        Analyze a manually inputted email for phishing

        Args:
            manual_data: inputted data
            
        Returns:
            dict: Complete analysis results
        """        
        # In the future, this will be done on the web server itself, not in the console
        # Get data from text
        print("Paste your raw email and end with a single line 'EOF'\n")
        lines = []
        while True:
            line = input()
            if line.strip().upper() == "EOF":
                break
            lines.append(line)
        manual_data = "\n".join(lines)

        # Extract data from the manually inputted email
        email = GetDataManual.extract_email_info_from_txt(manual_data)

        ## Analysis of email
        # Perform keyword detection using updated method
        subject_matches = self.keyword_detector.find_keywords_in_text(email["Subject"], is_subject=True)
        body_matches = self.keyword_detector.find_keywords_in_text(email["Body"], is_subject=False)
        all_matches = subject_matches + body_matches
        
        # Calculate position-based scores
        email_length = len(email["Subject"]) + len(email["Body"])
        scoring_result = self.position_scorer.calculate_comprehensive_score(all_matches, email_length)
        
        # ADD DOMAIN/URL ANALYSIS
        domain_url_analysis = analyze_email_domain_and_urls(
            sender_email=email["From"],
            email_body=email["Body"],
            email_subject=email["Subject"]
        )
        
        # Combine results
        analysis = {
            'sender': email["From"],
            'subject': email["Subject"],
            'body_length': len(email["Body"]),
            'subject_length': len(email["Subject"]),
            'total_matches': len(all_matches),
            'subject_matches': len(subject_matches),
            'body_matches': len(body_matches),
            'domain_url_analysis': domain_url_analysis,  # ADD THIS
            **scoring_result  # Include all scoring results
        }
        
        return analysis

    def analyze_single_email(self, msg_data):
        """
        Analyze a single email for phishing indicators
        
        Args:
            msg_data: Gmail API message data
            
        Returns:
            dict: Complete analysis results
        """
        
        # Extract email components
        subject = GetData.get_email_subject(msg_data)
        body = GetData.get_email_body(msg_data)
        sender = GetData.get_email_sender(msg_data)
        
        # Perform keyword detection using updated method
        subject_matches = self.keyword_detector.find_keywords_in_text(subject, is_subject=True)
        body_matches = self.keyword_detector.find_keywords_in_text(body, is_subject=False)
        all_matches = subject_matches + body_matches
        
        # Calculate position-based scores
        email_length = len(subject) + len(body)
        scoring_result = self.position_scorer.calculate_comprehensive_score(all_matches, email_length)
        
        # ADD DOMAIN/URL ANALYSIS
        domain_url_analysis = analyze_email_domain_and_urls(
            sender_email=sender,
            email_body=body,
            email_subject=subject
        )
        
        # Combine results
        analysis = {
            'sender': sender,
            'subject': subject,
            'body_length': len(body),
            'subject_length': len(subject),
            'total_matches': len(all_matches),
            'subject_matches': len(subject_matches),
            'body_matches': len(body_matches),
            'domain_url_analysis': domain_url_analysis,  # ADD THIS
            **scoring_result  # Include all scoring results
        }
        
        return analysis
    
    def analyze_recent_emails(self, max_results=10):
        """
        Analyze recent emails for phishing indicators
        
        Args:
            max_results (int): Maximum number of emails to analyze
            
        Returns:
            list: Analysis results for each email
        """
        # Get recent emails
        results = self.service.users().messages().list(
            userId="me", 
            maxResults=max_results
        ).execute()
        messages = results.get("messages", [])
        
        analyses = []
        
        print(f"Analyzing {len(messages)} recent emails...\n")
        
        for i, msg in enumerate(messages, 1):
            try:
                # Get full message data
                msg_data = self.service.users().messages().get(
                    userId="me", 
                    id=msg["id"], 
                    format="full"
                ).execute()
                
                # Analyze email
                analysis = self.analyze_single_email(msg_data)
                analyses.append(analysis)
                
                # Print results
                self.print_email_analysis(analysis, i)
                
            except Exception as e:
                print(f"Error analyzing email {i}: {str(e)}")
        
        return analyses
    
    def print_email_analysis(self, analysis, email_number):
        """
        Print formatted analysis results for a single email
        
        Args:
            analysis (dict): Email analysis results
            email_number (int): Email sequence number
        """
        print(f"{'='*60}")
        print(f"EMAIL {email_number} ANALYSIS")
        print(f"{'='*60}")
        
        print(f"From: {analysis['sender']}")
        print(f"Subject: {analysis['subject']}")
        print(f"Body Length: {analysis['body_length']} characters")
        print()
        
        print(f"RISK ASSESSMENT:")
        print(f"  Risk Level: {analysis['risk_level']}")
        print(f"  Total Score: {analysis['total_score']}")
        print(f"  Keywords Found: {analysis['total_matches']}")
        print(f"  Subject Matches: {analysis['subject_matches']}")
        print(f"  Body Matches: {analysis['body_matches']}")
        print()
        
        # ADD DOMAIN/URL ANALYSIS DISPLAY
        domain_analysis = analysis.get('domain_url_analysis', {})
        if domain_analysis:
            print(f"DOMAIN/URL SECURITY:")
            print(f"  Domain Risk: {domain_analysis.get('risk_level', 'UNKNOWN')}")
            print(f"  Domain Score: {domain_analysis.get('risk_score', 0)}")
            print(f"  URLs Found: {domain_analysis.get('total_urls_analyzed', 0)}")
            print(f"  Suspicious URLs: {domain_analysis.get('suspicious_url_count', 0)}")
            
            if domain_analysis.get('risk_factors'):
                print(f"  Risk Factors: {', '.join(domain_analysis['risk_factors'])}")
            print()
        
        if analysis['category_scores']:
            print("SUSPICIOUS CATEGORIES:")
            sorted_categories = sorted(
                analysis['category_scores'].items(), 
                key=lambda x: x[1], 
                reverse=True
            )
            for category, score in sorted_categories:
                print(f"  {category}: {score:.1f}")
            print()
        
        if analysis['match_details']:
            print("TOP SUSPICIOUS KEYWORDS:")
            sorted_matches = sorted(
                analysis['match_details'], 
                key=lambda x: x['final_score'], 
                reverse=True
            )
            for match in sorted_matches[:3]:  # Show top 3
                location = "SUBJECT" if match['zone'] == 'subject' else "BODY"
                print(f"  '{match['keyword']}' ({match['category']}) in {location} - Score: {match['final_score']}")
        
        print(f"\n{'='*60}\n")
    
    def get_integration_summary(self, analyses):
        """
        Get summary statistics for integration with other detection methods
        
        Args:
            analyses (list): List of email analyses
            
        Returns:
            dict: Summary statistics
        """
        if not analyses:
            return {}
        
        total_emails = len(analyses)
        high_risk = sum(1 for a in analyses if a['risk_level'] == 'HIGH')
        medium_risk = sum(1 for a in analyses if a['risk_level'] == 'MEDIUM')
        suspicious_emails = sum(1 for a in analyses if a['total_score'] >= 10)
        
        # ADD DOMAIN/URL STATISTICS
        domain_high_risk = sum(1 for a in analyses 
                             if a.get('domain_url_analysis', {}).get('risk_level') == 'HIGH')
        total_suspicious_urls = sum(a.get('domain_url_analysis', {}).get('suspicious_url_count', 0) 
                                  for a in analyses)
        
        avg_score = sum(a['total_score'] for a in analyses) / total_emails
        
        return {
            'total_emails_analyzed': total_emails,
            'high_risk_emails': high_risk,
            'medium_risk_emails': medium_risk,
            'suspicious_emails': suspicious_emails,
            'domain_high_risk_emails': domain_high_risk,  # ADD THIS
            'total_suspicious_urls': total_suspicious_urls,  # ADD THIS
            'average_keyword_score': round(avg_score, 2),
            'highest_score': max(a['total_score'] for a in analyses),
            'most_suspicious_email': max(analyses, key=lambda x: x['total_score'])
        }

# Example usage
if __name__ == "__main__":
    # Initialize analyzer
    analyzer = PhishingEmailAnalyzer()
    
    # Analyze manually inputted emails
    # analyses = analyzer.analyze_manual_email()

    # Analyze recent emails
    analyses = analyzer.analyze_recent_emails(max_results=5)
    
    # Print summary
    summary = analyzer.get_integration_summary(analyses)
    
    print("="*60)
    print("ANALYSIS SUMMARY")
    print("="*60)
    print(f"Total Emails Analyzed: {summary.get('total_emails_analyzed', 0)}")
    print(f"High Risk Emails: {summary.get('high_risk_emails', 0)}")
    print(f"Medium Risk Emails: {summary.get('medium_risk_emails', 0)}")
    print(f"Suspicious Emails: {summary.get('suspicious_emails', 0)}")
    print(f"Domain High Risk Emails: {summary.get('domain_high_risk_emails', 0)}")  # ADD THIS
    print(f"Total Suspicious URLs Found: {summary.get('total_suspicious_urls', 0)}")  # ADD THIS
    print(f"Average Keyword Score: {summary.get('average_keyword_score', 0)}")
    print(f"Highest Score: {summary.get('highest_score', 0)}")
    
    if 'most_suspicious_email' in summary:
        most_suspicious = summary['most_suspicious_email']
        print(f"\nMost Suspicious Email:")
        print(f"  Subject: {most_suspicious['subject']}")
        print(f"  Score: {most_suspicious['total_score']}")
        print(f"  Risk Level: {most_suspicious['risk_level']}")