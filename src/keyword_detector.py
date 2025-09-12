"""
Keyword Detection Engine for Phishing Email Analysis
Handles finding and extracting suspicious keywords from email content
"""

import re
from typing import Dict, List, Tuple, Set
from dataclasses import dataclass
from keyword_lists import SuspiciousKeywords

@dataclass
class KeywordMatch:
    """Represents a keyword match with its position and context"""
    keyword: str
    category: str
    position: int
    context: str
    in_subject: bool

class KeywordDetector:
    """
    Main keyword detection engine for identifying suspicious content in emails
    """
    
    def __init__(self):
        """Initialize the detector with keyword categories"""
        self.keyword_categories = SuspiciousKeywords.get_keyword_categories()
        self.category_weights = SuspiciousKeywords.get_category_weights()
    
    def extract_email_parts(self, email_content: str, subject: str = "") -> Tuple[str, str]:
        """
        Extract subject and body from email content
        Handles the format from Gmail API integration
        
        Args:
            email_content (str): Email body content from get_email_body()
            subject (str): Email subject (to be passed separately from Gmail API)
            
        Returns:
            Tuple[str, str]: (subject, body) extracted from email
        """
        # Since get_email_body() returns the body directly, we use it as-is
        body = email_content.strip()
        
        # Subject needs to be passed separately from Gmail API
        # If no subject provided, try to extract from first line if it looks like a subject
        if not subject:
            lines = body.split('\n')
            if lines and len(lines[0]) < 100 and not lines[0].startswith(('http', 'www', '<')):
                # First line might be subject if it's short and doesn't look like body content
                subject = lines[0].strip()
                body = '\n'.join(lines[1:]).strip()
        
        return subject, body
    
    def find_keywords_in_text(self, text: str, is_subject: bool = False) -> List[KeywordMatch]:
        """
        Find all suspicious keywords in given text with their positions
        
        Args:
            text (str): Text to analyze
            is_subject (bool): Whether this text is from subject line
            
        Returns:
            List[KeywordMatch]: All keyword matches found
        """
        matches = []
        text_lower = text.lower()
        
        for category, keywords in self.keyword_categories.items():
            for keyword in keywords:
                # Create word boundary pattern to avoid partial matches
                pattern = r'\b' + re.escape(keyword.lower()) + r'\b'
                
                # Find all occurrences of this keyword
                for match in re.finditer(pattern, text_lower):
                    start_pos = match.start()
                    
                    # Extract context around the keyword (20 chars before and after)
                    context_start = max(0, start_pos - 20)
                    context_end = min(len(text), start_pos + len(keyword) + 20)
                    context = text[context_start:context_end].strip()
                    
                    # Create keyword match object
                    matches.append(KeywordMatch(
                        keyword=keyword,
                        category=category,
                        position=start_pos,
                        context=context,
                        in_subject=is_subject
                    ))
        
        return matches
    
    def analyze_email_content(self, email_content: str) -> Dict:
        """
        Analyze email content and extract all keyword matches
        
        Args:
            email_content (str): Raw email content
            
        Returns:
            Dict: Analysis results including matches and basic stats
        """
        # Extract email parts
        subject, body = self.extract_email_parts(email_content)
        
        # Find keywords in both subject and body
        subject_matches = self.find_keywords_in_text(subject, is_subject=True)
        body_matches = self.find_keywords_in_text(body, is_subject=False)
        
        # Combine all matches
        all_matches = subject_matches + body_matches
        
        # Create analysis summary
        analysis = {
            'subject': subject,
            'body': body,
            'subject_length': len(subject),
            'body_length': len(body),
            'total_matches': len(all_matches),
            'subject_matches': len(subject_matches),
            'body_matches': len(body_matches),
            'matches': all_matches
        }
        
        # Add category breakdown
        category_counts = {}
        for match in all_matches:
            category_counts[match.category] = category_counts.get(match.category, 0) + 1
        
        analysis['category_counts'] = category_counts
        
        return analysis
    
    def get_unique_keywords(self, matches: List[KeywordMatch]) -> Set[str]:
        """
        Extract unique keywords from matches
        
        Args:
            matches (List[KeywordMatch]): Keyword matches
            
        Returns:
            Set[str]: Unique keywords found
        """
        return set(match.keyword for match in matches)
    
    def get_matches_by_category(self, matches: List[KeywordMatch]) -> Dict[str, List[KeywordMatch]]:
        """
        Group matches by their category
        
        Args:
            matches (List[KeywordMatch]): All keyword matches
            
        Returns:
            Dict[str, List[KeywordMatch]]: Matches grouped by category
        """
        category_matches = {}
        for match in matches:
            if match.category not in category_matches:
                category_matches[match.category] = []
            category_matches[match.category].append(match)
        
        return category_matches
    
    def get_high_risk_matches(self, matches: List[KeywordMatch], min_category_weight: int = 8) -> List[KeywordMatch]:
        """
        Filter matches to only include high-risk categories
        
        Args:
            matches (List[KeywordMatch]): All matches
            min_category_weight (int): Minimum category weight to be considered high-risk
            
        Returns:
            List[KeywordMatch]: High-risk matches only
        """
        return [
            match for match in matches 
            if self.category_weights.get(match.category, 0) >= min_category_weight
        ]

# Example usage and testing
if __name__ == "__main__":
    detector = KeywordDetector()
    
    # Test with sample email
    sample_email = """URGENT: Account Verification Required
    
This is the body [image: Bank]
Your account has been temporarily suspended due to suspicious activity.
You must verify your account immediately to avoid permanent closure.
Click here to verify: http://fake-bank.com/verify
Act now before your access is terminated permanently.
Final notice - expires today!"""
    
    print("=== KEYWORD DETECTION TEST ===")
    analysis = detector.analyze_email_content(sample_email)
    
    print(f"Subject: {analysis['subject']}")
    print(f"Total matches found: {analysis['total_matches']}")
    print(f"Subject matches: {analysis['subject_matches']}")
    print(f"Body matches: {analysis['body_matches']}")
    
    print("\nCategory breakdown:")
    for category, count in analysis['category_counts'].items():
        weight = detector.category_weights.get(category, 0)
        print(f"  {category}: {count} matches (weight: {weight})")
    
    print("\nAll matches:")
    for i, match in enumerate(analysis['matches'], 1):
        location = "SUBJECT" if match.in_subject else "BODY"
        print(f"  {i}. '{match.keyword}' ({match.category}) in {location}")
        print(f"     Context: ...{match.context}...")
    
    # Test grouping functionality
    print("\n=== MATCH GROUPING TEST ===")
    matches_by_category = detector.get_matches_by_category(analysis['matches'])
    
    for category, matches in matches_by_category.items():
        print(f"\n{category.upper()}:")
        for match in matches:
            location = "subject" if match.in_subject else "body"
            print(f"  - '{match.keyword}' in {location}")
    
    # Test high-risk filtering
    high_risk = detector.get_high_risk_matches(analysis['matches'])
    print(f"\nHigh-risk matches (weight >= 8): {len(high_risk)}")
    for match in high_risk:
        print(f"  - '{match.keyword}' ({match.category}, weight: {detector.category_weights[match.category]})")