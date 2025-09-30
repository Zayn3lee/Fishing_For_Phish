# Import utilities and detection modules
from get_data import GetData
from keyword_detector import KeywordDetector
from position_scorer import PositionScorer
from distance_checker import analyze_email_domain_and_urls
from attachment_analyzer import AttachmentRiskAnalyzer

class PhishingEmailAnalyzer:
    """
    Phishing email analyzer using multiple detection components.

    Integrates:
    - Keyword detection
    - Position scoring
    - Domain/URL analysis
    - Attachment risk analysis
    """

    def __init__(self, service=None):
        """
        Initializes the phishing analyzer with detection systems.
        """
        self.service = None  # Will be initialized later "initialize_service()"
        self.keyword_detector = KeywordDetector()
        self.position_scorer = PositionScorer()
        self.attachment_analyzer = AttachmentRiskAnalyzer()

    def initialize_service(self):
        """
        Initialize the Gmail API service.
        Only needed once (e.g., at Flask app startup).
        """
        if not self.service:
            self.service = GetData.gmail_service()

    def analyze_emails(self, max_results=10):
        """
        Analyze a specified number of recent Gmail emails.
        Returns a list of detailed analysis results.
        """
        if not self.service:
            raise Exception("Gmail service not initialized. Call initialize_service() first.")
        
        # Fetch recent emails
        results = self.service.users().messages().list(
            userId="me", 
            maxResults=max_results
        ).execute()
        messages = results.get("messages", [])

        analyses = []
        print(f"Analyzing {len(messages)} recent emails...\n")
        
        for i, msg in enumerate(messages, 1):
            try:
                # Get full email content
                msg_data = self.service.users().messages().get(
                    userId="me", 
                    id=msg["id"], 
                    format="full"
                ).execute()
                
                # Run phishing analysis
                analysis = self.analyze_single_email(msg_data)
                analyses.append(analysis)

                # Print summary of the analysis
                self.print_email_analysis(analysis, i)
                
            except Exception as e:
                print(f"Error analyzing email {i}: {str(e)}")
        
        return analyses

    def calculate_attachment_risk_score(self, attachment_results):
        """
        Calculate a risk score for email attachments.
        Based on:
        - Suspicious flags
        - Risk factors like macros, archives, file type mismatches
        """
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

                # Add points for each risk factor
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

        # Determine risk level based on score
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
        """
        Calculate risk score from domain/URL analysis.
        Extracts suspicious URLs and sender analysis from `distance_checker`.
        """
        if not domain_url_analysis:
            return {
                'link_risk_score': 0,
                'link_risk_level': 'NONE',
                'has_links': False,
                'suspicious_link_count': 0
            }

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
        """
        Analyze one email:
        - Extract sender, subject, body
        - Run keyword, link, and attachment analysis
        - Calculate risk scores and assign risk level
        """
        subject = GetData.get_email_subject(msg_data)
        body = GetData.get_email_body(msg_data)
        sender = GetData.get_email_sender(msg_data)

        # Keyword matching
        subject_matches = self.keyword_detector.find_keywords_in_text(subject, is_subject=True)
        body_matches = self.keyword_detector.find_keywords_in_text(body, is_subject=False)
        all_matches = subject_matches + body_matches

        # Position and density-based keyword scoring
        email_length = len(subject) + len(body)
        scoring_result = self.position_scorer.calculate_comprehensive_score(all_matches, email_length)

        # Domain and URL analysis
        domain_url_analysis = analyze_email_domain_and_urls(sender, body, subject)

        # Attachment extraction and analysis
        raw_attachments = GetData.get_gmail_attachments(msg_data)
        parsed_attachments = self.attachment_analyzer.parse_gmail_attachment_data(
            self.service, msg_data["id"], raw_attachments
        )
        attachment_results = self.attachment_analyzer.analyze_attachments(
            parsed_attachments, subject, body
        )

        # Risk evaluations
        attachment_risk = self.calculate_attachment_risk_score(attachment_results)
        link_risk = self.calculate_link_risk_score(domain_url_analysis)
        keyword_score = scoring_result['total_score']

        # Total risk score aggregation
        total_score = keyword_score + attachment_risk['attachment_risk_score'] + link_risk['link_risk_score']

        # Assign risk level
        if total_score >= 60:
            overall_risk_level = 'HIGH'
        elif total_score >= 30:
            overall_risk_level = 'MEDIUM'
        elif total_score >= 10:
            overall_risk_level = 'LOW'
        else:
            overall_risk_level = 'MINIMAL'

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
            'keyword_score': keyword_score,
            'total_score': total_score,
            'overall_risk_level': overall_risk_level,
            **scoring_result
        }

    def print_email_analysis(self, analysis, email_number):
        """
        Nicely prints a formatted breakdown of analysis results to console.
        Includes sender, subject, score breakdown, and risk indicators.
        """
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
        """
        Generate summary statistics across all analyzed emails.

        Returns:
            dict: Aggregated metrics and top offender email
        """
        if not analyses:
            return {}

        total_emails = len(analyses)
        high_risk = sum(1 for a in analyses if a.get('overall_risk_level') == 'HIGH')
        medium_risk = sum(1 for a in analyses if a.get('overall_risk_level') == 'MEDIUM')
        suspicious = sum(1 for a in analyses if a.get('total_score', 0) >= 10)
        domain_high_risk = sum(1 for a in analyses if a.get('domain_url_analysis', {}).get('risk_level') == 'HIGH')
        total_suspicious_urls = sum(a.get('domain_url_analysis', {}).get('suspicious_url_count', 0) for a in analyses)

        avg_score = sum(a.get('total_score', 0) for a in analyses) / total_emails
        avg_keyword_score = sum(a.get('keyword_score', 0) for a in analyses) / total_emails
        highest_score = max((a.get('total_score', 0) for a in analyses), default=0)

        most_suspicious_email = max(analyses, key=lambda x: x.get('total_score', 0), default=None)

        return {
            'total_emails_analyzed': total_emails,
            'high_risk_emails': high_risk,
            'medium_risk_emails': medium_risk,
            'suspicious_emails': suspicious,
            'domain_high_risk_emails': domain_high_risk,
            'total_suspicious_urls': total_suspicious_urls,
            'average_score': round(avg_score, 2),
            'average_keyword_score': round(avg_keyword_score, 2),
            'highest_score': highest_score,
            'most_suspicious_email': most_suspicious_email
        }
