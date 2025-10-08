# Import utilities and detection modules
from get_data import GetData
from keyword_detector import KeywordDetector
from position_scorer import PositionScorer
from distance_checker import analyze_email_domain_and_urls
from attachment_analyzer import AttachmentRiskAnalyzer

class RiskAssessmentEngine:
    """
    General-purpose risk assessment that prioritizes signals correctly
    """
    
    def __init__(self):
        self.risk_weights = {
            'sender_legitimacy': 0.35,      # Most important
            'domain_url_risk': 0.30,        # Second most important
            'attachment_risk': 0.20,        # Third
            'keyword_risk': 0.15            # Least important (context-dependent)
        }
    
    def assess_risk(self, analysis: dict) -> dict:
        """
        General risk assessment using weighted scoring
        """
        # 1. Check sender legitimacy FIRST
        sender_analysis = analysis.get('domain_url_analysis', {}).get('sender_analysis', {})
        sender_legitimate = not sender_analysis.get('is_suspicious', True)
        
        # 2. Calculate component scores
        sender_score = self._calculate_sender_score(sender_analysis, sender_legitimate)
        url_score = self._calculate_url_score(analysis.get('domain_url_analysis', {}))
        attachment_score = analysis.get('attachment_risk', {}).get('attachment_risk_score', 0)
        keyword_score = self._calculate_keyword_score(
            analysis.get('keyword_score', 0),
            sender_legitimate,
            analysis
        )
        
        # 3. Apply weights
        weighted_score = (
            sender_score * self.risk_weights['sender_legitimacy'] +
            url_score * self.risk_weights['domain_url_risk'] +
            attachment_score * self.risk_weights['attachment_risk'] +
            keyword_score * self.risk_weights['keyword_risk']
        )
        
        # 4. Apply override rules
        final_score, risk_level = self._apply_override_rules(
            weighted_score,
            sender_legitimate,
            url_score,
            attachment_score,
            analysis
        )
        
        return {
            'final_score': final_score,
            'risk_level': risk_level,
            'component_scores': {
                'sender': sender_score,
                'urls': url_score,
                'attachments': attachment_score,
                'keywords': keyword_score
            },
            'sender_legitimate': sender_legitimate
        }
    
    def _calculate_sender_score(self, sender_analysis: dict, is_legitimate: bool) -> float:
        """Calculate sender risk score"""
        if is_legitimate:
            return 0  # Legitimate sender = no sender risk
        
        # Unknown or suspicious sender
        base_score = 30
        risk_score = sender_analysis.get('risk_score', 0)
        
        return min(base_score + (risk_score * 5), 100)
    
    def _calculate_url_score(self, domain_analysis: dict) -> float:
        """Calculate URL risk score"""
        risk_score = domain_analysis.get('risk_score', 0)
        suspicious_url_count = domain_analysis.get('suspicious_url_count', 0)
        
        # IP addresses, URL shorteners = automatic high score
        for url_analysis in domain_analysis.get('url_analyses', []):
            if any('IP address' in reason for reason in url_analysis.get('reasons', [])):
                return 80  # Very high risk
            if any('shortener' in reason.lower() for reason in url_analysis.get('reasons', [])):
                return 60  # High risk
        
        return min(risk_score * 8 + suspicious_url_count * 15, 100)
    
    def _calculate_keyword_score(self, raw_keyword_score: float, 
                                  sender_legitimate: bool, 
                                  analysis: dict) -> float:
        """
        Context-aware keyword scoring
        Keywords mean different things from legitimate vs unknown senders
        """
        # If sender is legitimate, keywords are less suspicious
        if sender_legitimate:
            # Check if keywords match expected context
            subject = analysis.get('subject', '').lower()
            
            # Expected security-related keywords from legitimate senders
            expected_keywords = ['security', 'alert', 'notification', 'update', 'access']
            has_expected = any(kw in subject for kw in expected_keywords)
            
            if has_expected:
                return raw_keyword_score * 0.2  # Reduce by 80%
            else:
                return raw_keyword_score * 0.5  # Reduce by 50%
        
        # Unknown sender - keywords are more suspicious
        return raw_keyword_score * 1.5  # Increase by 50%
    
    def _apply_override_rules(self, weighted_score: float,
                               sender_legitimate: bool,
                               url_score: float,
                               attachment_score: float,
                               analysis: dict) -> tuple:
        """
        Apply override rules that trump normal scoring
        """
        final_score = weighted_score
        
        # RULE 1: Legitimate sender with suspicious URLs = RED FLAG
        if sender_legitimate and url_score > 60:
            final_score = max(final_score, 50)  # Force MEDIUM at minimum
        
        # RULE 2: Malicious attachment = immediate HIGH risk
        if attachment_score > 40:
            final_score = max(final_score, 60)  # Force HIGH
        
        # RULE 3: IP address in URL = automatic HIGH risk
        domain_analysis = analysis.get('domain_url_analysis', {})
        for url_analysis in domain_analysis.get('url_analyses', []):
            if any('IP address' in reason for reason in url_analysis.get('reasons', [])):
                final_score = max(final_score, 65)  # Force HIGH
        
        # RULE 4: "Free money" type scams = HIGH risk regardless of sender
        subject = analysis.get('subject', '').lower()
        body = analysis.get('body', '').lower()
        combined = subject + ' ' + body
        
        scam_phrases = ['free money', 'you won', 'claim prize', 'lottery winner', 
                       'million dollars', 'inheritance', 'free cash', 'easy money']
        if any(phrase in combined for phrase in scam_phrases):
            if not sender_legitimate:
                final_score = max(final_score, 70)  # Force HIGH
        
        # RULE 5: All signals weak = LOW risk
        if url_score < 10 and attachment_score < 10 and weighted_score < 20:
            final_score = min(final_score, 15)
        
        # Determine risk level
        if final_score >= 60:
            risk_level = 'HIGH'
        elif final_score >= 35:
            risk_level = 'MEDIUM'
        elif final_score >= 15:
            risk_level = 'LOW'
        else:
            risk_level = 'MINIMAL'
        
        return final_score, risk_level


class PhishingEmailAnalyzer:
    """
    Phishing email analyzer using multiple detection components.

    Integrates:
    - Keyword detection
    - Position scoring
    - Domain/URL analysis
    - Attachment risk analysis
    - General risk assessment engine
    """

    def __init__(self, service=None):
        """
        Initializes the phishing analyzer with detection systems.
        """
        self.service = None  # Will be initialized later "initialize_service()"
        self.keyword_detector = KeywordDetector()
        self.position_scorer = PositionScorer()
        self.attachment_analyzer = AttachmentRiskAnalyzer()
        self.risk_engine = RiskAssessmentEngine()  # NEW: General risk engine

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
        - Calculate risk scores using general risk engine
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

        # Create analysis dict
        analysis = {
            'sender': sender,
            'subject': subject,
            'body': body if body != "No data found" else "",
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
            **scoring_result
        }

        # USE THE GENERAL RISK ENGINE
        risk_assessment = self.risk_engine.assess_risk(analysis)
        
        # Add risk assessment to analysis
        analysis['total_score'] = risk_assessment['final_score']
        analysis['overall_risk_level'] = risk_assessment['risk_level']
        analysis['risk_level'] = risk_assessment['risk_level']  # For backward compatibility
        analysis['component_scores_breakdown'] = risk_assessment['component_scores']
        analysis['sender_legitimate'] = risk_assessment['sender_legitimate']

        return analysis

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
        print(f"Sender Legitimate: {analysis.get('sender_legitimate', False)}")
        
        # Show risk assessment
        print(f"\nRISK ASSESSMENT:")
        print(f"  Overall Risk Level: {analysis.get('overall_risk_level', 'UNKNOWN')}")
        print(f"  Total Risk Score: {analysis.get('total_score', 0):.2f}")

        print(f"\nCOMPONENT SCORES:")
        component_scores = analysis.get('component_scores_breakdown', {})
        print(f"  Sender Score: {component_scores.get('sender', 0):.2f}")
        print(f"  URL Score: {component_scores.get('urls', 0):.2f}")
        print(f"  Attachment Score: {component_scores.get('attachments', 0):.2f}")
        print(f"  Keyword Score: {component_scores.get('keywords', 0):.2f}")

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
        suspicious = sum(1 for a in analyses if a.get('total_score', 0) >= 15)
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