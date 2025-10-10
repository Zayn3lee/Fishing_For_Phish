import re
from typing import Dict, List, Tuple, Set
from dataclasses import dataclass
from keyword_lists import SuspiciousKeywords

@dataclass
class KeywordMatch:
    """
    Represents a keyword match within email text.

    Attributes:
        keyword (str): The matched keyword.
        category (str): Category of the keyword (e.g., threat, urgency).
        position (int): Index in the text where keyword was found.
        context (str): 40-character window of surrounding text.
        in_subject (bool): Whether keyword was found in subject.
    """
    keyword: str
    category: str
    position: int
    context: str
    in_subject: bool


class KeywordDetector:
    """
    Core class for detecting suspicious keywords in email content.
    """

    def __init__(self):
        """Initialize the detector with keyword categories and their risk weights."""
        self.keyword_categories = SuspiciousKeywords.get_keyword_categories()
        self.category_weights = SuspiciousKeywords.get_category_weights()

    def extract_email_parts(self, email_content: str, subject: str = "") -> Tuple[str, str]:
        """
        Extracts subject and body from raw email content.
        If subject is not provided, attempts to infer it from the first line.

        Args:
            email_content (str): Raw email body content.
            subject (str): Subject line from Gmail API (if available).

        Returns:
            Tuple[str, str]: A tuple of (subject, body)
        """
        body = email_content.strip()

        # Attempt to infer subject if not provided
        if not subject:
            lines = body.split('\n')
            if lines and len(lines[0]) < 100 and not lines[0].startswith(('http', 'www', '<')):
                subject = lines[0].strip()
                body = '\n'.join(lines[1:]).strip()

        return subject, body

    def find_keywords_in_text(self, text: str, is_subject: bool = False) -> List[KeywordMatch]:
        """
        Finds all suspicious keywords in the provided text.

        Args:
            text (str): The text to search within (subject or body).
            is_subject (bool): Whether the text is a subject line.

        Returns:
            List[KeywordMatch]: List of keyword match objects.
        """
        matches = []
        text_lower = text.lower()

        for category, keywords in self.keyword_categories.items():
            for keyword in keywords:
                # Use word boundaries to match exact words
                pattern = r'\b' + re.escape(keyword.lower()) + r'\b'

                for match in re.finditer(pattern, text_lower):
                    start_pos = match.start()

                    # Get 20 characters before and after the keyword for context
                    context_start = max(0, start_pos - 20)
                    context_end = min(len(text), start_pos + len(keyword) + 20)
                    context = text[context_start:context_end].strip()

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
        Analyzes the full email content and detects keywords.

        Args:
            email_content (str): Full raw content of an email.

        Returns:
            Dict: A dictionary of results, including:
                - subject, body
                - total_matches
                - subject/body keyword matches
                - category breakdown
                - all matches list
        """
        subject, body = self.extract_email_parts(email_content)

        subject_matches = self.find_keywords_in_text(subject, is_subject=True)
        body_matches = self.find_keywords_in_text(body, is_subject=False)
        all_matches = subject_matches + body_matches

        # Count matches by category
        category_counts = {}
        for match in all_matches:
            category_counts[match.category] = category_counts.get(match.category, 0) + 1

        return {
            'subject': subject,
            'body': body,
            'subject_length': len(subject),
            'body_length': len(body),
            'total_matches': len(all_matches),
            'subject_matches': len(subject_matches),
            'body_matches': len(body_matches),
            'matches': all_matches
        }
    
    def get_unique_keywords(self, matches: List[KeywordMatch]) -> Set[str]:
        """
        Extracts unique keywords from a list of matches.

        Args:
            matches (List[KeywordMatch]): List of detected matches.

        Returns:
            Set[str]: Unique keyword strings.
        """
        return set(match.keyword for match in matches)
    
    def get_matches_by_category(self, matches: List[KeywordMatch]) -> Dict[str, List[KeywordMatch]]:
        """
        Organizes matches by keyword category.

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
        Filters for matches in high-risk keyword categories.

        Args:
            matches (List[KeywordMatch]): All keyword matches.
            min_category_weight (int): Threshold weight to be considered high-risk.

        Returns:
            List[KeywordMatch]: High-risk keyword matches.
        """
        return [
            match for match in matches
            if self.category_weights.get(match.category, 0) >= min_category_weight
        ]
    

# =========================
# Example usage and testing
# =========================
if __name__ == "__main__":
    detector = KeywordDetector()

    sample_email = """
    URGENT: Account Verification Required
    This is the body [image: Bank]
    Your account has been temporarily suspended due to suspicious activity.
    You must verify your account immediately to avoid permanent closure.
    Click here to verify: http://fake-bank.com/verify
    Act now before your access is terminated permanently.
    Final notice - expires today!
    """

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
    print(f"High-risk matches (weight >= 8): {len(high_risk)}")
    for match in high_risk:
        print(f"  - '{match.keyword}' ({match.category}, weight: {detector.category_weights[match.category]})")
