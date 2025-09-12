"""
Main Integration File - Complete Keyword Detection and Scoring System
This file demonstrates how all components work together
"""

from keyword_detector import KeywordDetector
from position_scorer import PositionScorer
from keyword_lists import SuspiciousKeywords
from typing import Dict

class PhishingKeywordAnalyzer:
    """
    Complete phishing email keyword analysis system
    Integrates detection and scoring components
    """
    
    def __init__(self):
        """Initialize all components"""
        self.detector = KeywordDetector()
        self.scorer = PositionScorer()
    
    def analyze_email(self, email_content: str) -> Dict:
        """
        Complete email analysis pipeline
        
        Args:
            email_content (str): Raw email content from Gmail API
            
        Returns:
            Dict: Complete analysis results
        """
        # Step 1: Detect keywords
        detection_result = self.detector.analyze_email_content(email_content)
        
        # Step 2: Calculate position-based scores
        email_length = detection_result['subject_length'] + detection_result['body_length']
        scoring_result = self.scorer.calculate_comprehensive_score(
            detection_result['matches'], 
            email_length
        )
        
        # Step 3: Combine results
        complete_analysis = {
            # Email content info
            'subject': detection_result['subject'],
            'body_length': detection_result['body_length'],
            'subject_length': detection_result['subject_length'],
            
            # Detection results
            'total_matches': detection_result['total_matches'],
            'subject_matches': detection_result['subject_matches'],
            'body_matches': detection_result['body_matches'],
            'category_counts': detection_result['category_counts'],
            
            # Scoring results
            'total_score': scoring_result['total_score'],
            'risk_level': scoring_result['risk_level'],
            'category_scores': scoring_result['category_scores'],
            'position_scores': scoring_result['position_scores'],
            'match_details': scoring_result['match_details'],
            
            # Summary for integration
            'is_suspicious': scoring_result['total_score'] >= 10,
            'confidence': self._calculate_confidence(scoring_result['total_score']),
        }
        
        return complete_analysis
    
    def _calculate_confidence(self, score: float) -> str:
        """
        Calculate confidence level based on score
        
        Args:
            score (float): Total keyword score
            
        Returns:
            str: Confidence level
        """
        if score >= 50:
            return 'VERY_HIGH'
        elif score >= 25:
            return 'HIGH'
        elif score >= 10:
            return 'MEDIUM'
        elif score >= 5:
            return 'LOW'
        else:
            return 'VERY_LOW'
    
    def get_summary_for_integration(self, analysis_result: Dict) -> Dict:
        """
        Get simplified summary for integration with other detection methods
        
        Args:
            analysis_result (Dict): Complete analysis result
            
        Returns:
            Dict: Simplified summary for integration
        """
        return {
            'keyword_score': analysis_result['total_score'],
            'risk_level': analysis_result['risk_level'],
            'is_suspicious': analysis_result['is_suspicious'],
            'confidence': analysis_result['confidence'],
            'keyword_count': analysis_result['total_matches'],
            'top_categories': list(analysis_result['category_scores'].keys())
        }
    
    def print_analysis_report(self, analysis_result: Dict) -> None:
        """
        Print formatted analysis report
        
        Args:
            analysis_result (Dict): Complete analysis result
        """
        print("=" * 60)
        print("PHISHING EMAIL KEYWORD ANALYSIS REPORT")
        print("=" * 60)
        
        print(f"Subject: {analysis_result['subject']}")
        print(f"Email Length: {analysis_result['subject_length'] + analysis_result['body_length']} chars")
        print()
        
        print("RISK ASSESSMENT:")
        print(f"  Overall Risk Level: {analysis_result['risk_level']}")
        print(f"  Keyword Score: {analysis_result['total_score']}/100")
        print(f"  Confidence: {analysis_result['confidence']}")
        print(f"  Is Suspicious: {'YES' if analysis_result['is_suspicious'] else 'NO'}")
        print()
        
        print("KEYWORD ANALYSIS:")
        print(f"  Total Keywords Found: {analysis_result['total_matches']}")
        print(f"  Subject Line Matches: {analysis_result['subject_matches']}")
        print(f"  Body Matches: {analysis_result['body_matches']}")
        print()
        
        if analysis_result['category_scores']:
            print("CATEGORY BREAKDOWN:")
            sorted_categories = sorted(
                analysis_result['category_scores'].items(), 
                key=lambda x: x[1], 
                reverse=True)