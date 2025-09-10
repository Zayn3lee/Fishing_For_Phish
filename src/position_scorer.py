"""
Position-Based Scoring System for Phishing Email Detection
Calculates risk scores based on keyword positions and applies scoring logic
"""

from typing import Dict, List, Tuple
from collections import defaultdict
from keyword_detector import KeywordMatch
from keyword_lists import SuspiciousKeywords

class PositionScorer:
    """
    Handles position-based scoring for suspicious keywords in emails
    """
    
    def __init__(self):
        """Initialize scorer with position multipliers and category weights"""
        self.category_weights = SuspiciousKeywords.get_category_weights()
        
        # Position-based multipliers
        self.position_multipliers = {
            'subject': 3.0,         # Subject line gets highest weight
            'first_paragraph': 2.0,  # First paragraph is second priority
            'rest_of_email': 1.0     # Rest of email gets base weight
        }
        
        # Diminishing returns factors for repeated keywords
        self.diminishing_returns = [1.0, 0.7, 0.5, 0.3, 0.2, 0.1]
    
    def determine_position_zone(self, match: KeywordMatch, email_length: int) -> str:
        """
        Determine which zone of the email the keyword appears in
        
        Args:
            match (KeywordMatch): The keyword match to analyze
            email_length (int): Total length of email content
            
        Returns:
            str: Position zone ('subject', 'first_paragraph', 'rest_of_email')
        """
        if match.in_subject:
            return 'subject'
        
        # Consider first 200 characters of body as first paragraph
        if match.position <= 200:
            return 'first_paragraph'
        else:
            return 'rest_of_email'
    
    def calculate_base_score(self, category: str) -> float:
        """
        Get base score for a keyword category
        
        Args:
            category (str): Keyword category name
            
        Returns:
            float: Base score for the category
        """
        return float(self.category_weights.get(category, 5))
    
    def apply_diminishing_returns(self, occurrence_index: int) -> float:
        """
        Apply diminishing returns for repeated keywords in same category
        
        Args:
            occurrence_index (int): 0-based index of this occurrence
            
        Returns:
            float: Diminishing returns multiplier
        """
        if occurrence_index < len(self.diminishing_returns):
            return self.diminishing_returns[occurrence_index]
        else:
            # For very high counts, use minimum factor
            return self.diminishing_returns[-1]
    
    def apply_position_multiplier(self, zone: str) -> float:
        """
        Get position multiplier for a specific zone
        
        Args:
            zone (str): Position zone name
            
        Returns:
            float: Position multiplier
        """
        return self.position_multipliers.get(zone, 1.0)
    
    def calculate_match_score(self, match: KeywordMatch, occurrence_index: int, email_length: int) -> Dict:
        """
        Calculate comprehensive score for a single keyword match
        
        Args:
            match (KeywordMatch): The keyword match
            occurrence_index (int): Which occurrence this is for this category
            email_length (int): Total email length
            
        Returns:
            Dict: Detailed scoring information
        """
        # Determine position zone
        zone = self.determine_position_zone(match, email_length)
        
        # Get base score for category
        base_score = self.calculate_base_score(match.category)
        
        # Apply diminishing returns
        diminishing_factor = self.apply_diminishing_returns(occurrence_index)
        
        # Apply position multiplier
        position_multiplier = self.apply_position_multiplier(zone)
        
        # Calculate final score
        final_score = base_score * diminishing_factor * position_multiplier
        
        return {
            'keyword': match.keyword,
            'category': match.category,
            'zone': zone,
            'base_score': base_score,
            'diminishing_factor': diminishing_factor,
            'position_multiplier': position_multiplier,
            'final_score': round(final_score, 2),
            'position': match.position,
            'context': match.context
        }
    
    def calculate_comprehensive_score(self, matches: List[KeywordMatch], email_length: int) -> Dict:
        """
        Calculate comprehensive scoring for all keyword matches
        
        Args:
            matches (List[KeywordMatch]): All keyword matches found
            email_length (int): Total email length
            
        Returns:
            Dict: Complete scoring analysis
        """
        if not matches:
            return {
                'total_score': 0,
                'category_scores': {},
                'position_scores': {},
                'keyword_count': 0,
                'match_details': [],
                'risk_level': 'MINIMAL'
            }
        
        # Group matches by category for diminishing returns
        category_matches = defaultdict(list)
        for match in matches:
            category_matches[match.category].append(match)
        
        # Calculate scores for each match
        match_details = []
        category_scores = defaultdict(float)
        position_scores = defaultdict(float)
        
        for category, cat_matches in category_matches.items():
            # Sort matches within category by position for consistent diminishing returns
            cat_matches.sort(key=lambda x: x.position)
            
            for i, match in enumerate(cat_matches):
                # Calculate individual match score
                match_score_info = self.calculate_match_score(match, i, email_length)
                match_details.append(match_score_info)
                
                # Add to category and position totals
                score = match_score_info['final_score']
                category_scores[category] += score
                position_scores[match_score_info['zone']] += score
        
        # Calculate total score
        total_score = sum(category_scores.values())
        
        # Determine risk level
        risk_level = self.determine_risk_level(total_score)
        
        return {
            'total_score': round(total_score, 2),
            'category_scores': dict(category_scores),
            'position_scores': dict(position_scores),
            'keyword_count': len(matches),
            'match_details': match_details,
            'risk_level': risk_level
        }
    
    def determine_risk_level(self, total_score: float) -> str:
        """
        Determine risk level based on total score
        
        Args:
            total_score (float): Total calculated score
            
        Returns:
            str: Risk level classification
        """
        if total_score >= 50:
            return 'HIGH'
        elif total_score >= 25:
            return 'MEDIUM'
        elif total_score >= 10:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def get_scoring_breakdown(self, scoring_result: Dict) -> str:
        """
        Generate human-readable scoring breakdown
        
        Args:
            scoring_result (Dict): Result from calculate_comprehensive_score
            
        Returns:
            str: Formatted scoring breakdown
        """
        breakdown = []
        breakdown.append(f"Total Score: {scoring_result['total_score']}")
        breakdown.append(f"Risk Level: {scoring_result['risk_level']}")
        breakdown.append(f"Keywords Found: {scoring_result['keyword_count']}")
        
        breakdown.append("\nCategory Scores:")
        for category, score in scoring_result['category_scores'].items():
            breakdown.append(f"  {category}: {score:.1f}")
        
        breakdown.append("\nPosition Scores:")
        for position, score in scoring_result['position_scores'].items():
            breakdown.append(f"  {position}: {score:.1f}")
        
        breakdown.append("\nTop Keyword Matches:")
        # Sort matches by score and show top 5
        sorted_matches = sorted(
            scoring_result['match_details'], 
            key=lambda x: x['final_score'], 
            reverse=True
        )
        
        for match in sorted_matches[:5]:
            breakdown.append(
                f"  '{match['keyword']}' ({match['category']}) in {match['zone']} - Score: {match['final_score']}"
            )
        
        return '\n'.join(breakdown)

# Example usage and testing
if __name__ == "__main__":
    from keyword_detector import KeywordDetector
    
    # Initialize components
    detector = KeywordDetector()
    scorer = PositionScorer()
    
    # Test email with keywords in different positions
    test_email = """URGENT: Verify Your Account Now
    
This is the body [image: Bank]
URGENT: Your account will be suspended if you don't act immediately.
Click here to verify your account: http://fake-bank.com/verify
Your payment method has been declined and needs immediate attention.
Don't delay - this is your final notice before account termination.
Act now to prevent losing access to your funds permanently."""
    
    print("=== POSITION SCORING TEST ===")
    
    # Detect keywords
    analysis = detector.analyze_email_content(test_email)
    matches = analysis['matches']
    email_length = analysis['subject_length'] + analysis['body_length']
    
    # Calculate scores
    scoring_result = scorer.calculate_comprehensive_score(matches, email_length)
    
    # Display results
    print(scorer.get_scoring_breakdown(scoring_result))
    
    print("\n=== DETAILED MATCH ANALYSIS ===")
    for match in scoring_result['match_details']:
        print(f"Keyword: '{match['keyword']}'")
        print(f"  Category: {match['category']} (base score: {match['base_score']})")
        print(f"  Zone: {match['zone']} (multiplier: {match['position_multiplier']}x)")
        print(f"  Diminishing factor: {match['diminishing_factor']}x")
        print(f"  Final score: {match['final_score']}")
        print(f"  Context: ...{match['context']}...")
        print()