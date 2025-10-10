"""
Suspicious Keywords Database for Phishing Email Detection
Contains categorized lists of keywords commonly found in phishing emails
"""

from typing import Dict, List

class SuspiciousKeywords:
    """
    Centralized database of suspicious keywords organized by category
    """
    
    @staticmethod
    def get_keyword_categories() -> Dict[str, List[str]]:
        """
        Returns comprehensive keyword database organized by category
        
        Returns:
            Dict[str, List[str]]: Dictionary mapping category names to keyword lists
        """
        return {
            'urgency': [
                'urgent', 'immediate', 'act now', 'expires today', 'limited time',
                'hurry', "don't delay", 'time sensitive', 'expires soon',
                'deadline', 'asap', 'right away', 'immediately', 'expire',
                'last chance', 'final notice', 'act fast', 'time running out',
                'expires in', 'limited offer', 'act quickly', 'don\'t wait'
            ],
            
            'financial_security': [
                'verify account', 'confirm identity', 'suspended account',
                'update payment', 'billing problem', 'security alert',
                'unauthorized access', 'locked account', 'frozen account',
                'payment failed', 'card declined', 'account compromised',
                'security breach', 'suspicious activity', 'verify identity',
                'confirm account', 'account verification', 'payment issue',
                'billing error', 'account locked', 'security notice',
                'unusual activity', 'verify payment', 'update billing'
            ],
            
            'action_oriented': [
                'click here', 'download now', 'call immediately',
                'respond now', 'confirm now', 'update now',
                'click below', 'tap here', 'press here', 'follow this link',
                'visit this link', 'go to', 'access here', 'login here',
                'sign in', 'verify here', 'confirm here', 'click to verify',
                'click to confirm', 'click to update', 'download attachment'
            ],
            
            'legitimacy_claims': [
                'winner', 'congratulations', 'prize', 'lottery',
                'inheritance', 'beneficiary', 'claim now', 'you won',
                'selected', 'chosen', 'reward', 'bonus', 'gift',
                'free money', 'cash prize', 'million dollars', 'lucky',
                'jackpot', 'sweepstakes', 'contest winner', 'grand prize',
                'you\'ve won', 'claim your prize', 'lucky winner'
            ],
            
            'personal_info': [
                'social security', 'ssn', 'credit card', 'password',
                'pin number', 'personal information', 'bank details',
                'account number', 'routing number', 'date of birth',
                'mother maiden name', 'security question', 'passport',
                'driver license', 'tax id', 'personal data', 'confidential',
                'provide information', 'send details', 'full name'
            ],
            
            'threats': [
                'account will be closed', 'legal action', 'suspended',
                'terminated', 'penalty', 'fine', 'court', 'lawsuit',
                'arrest', 'criminal', 'police', 'investigation',
                'consequences', 'action will be taken', 'permanently closed',
                'lose access', 'account closure', 'legal consequences',
                'criminal charges', 'prosecution', 'authorities'
            ]
        }
    
    @staticmethod
    def get_category_weights() -> Dict[str, int]:
        """
        Returns base weight scores for each keyword category
        Higher weights indicate more suspicious categories
        
        Returns:
            Dict[str, int]: Category name to weight mapping
        """
        return {
            'urgency': 8,
            'financial_security': 10,
            'action_oriented': 6,
            'legitimacy_claims': 9,
            'personal_info': 7,
            'threats': 12
        }
    
    @staticmethod
    def get_all_keywords() -> List[str]:
        """
        Returns a flat list of all suspicious keywords
        
        Returns:
            List[str]: All keywords combined
        """
        all_keywords = []
        categories = SuspiciousKeywords.get_keyword_categories()
        for keyword_list in categories.values():
            all_keywords.extend(keyword_list)
        return list(set(all_keywords))  # Remove duplicates
    
    @staticmethod
    def get_keywords_by_category(category: str) -> List[str]:
        """
        Get keywords for a specific category
        
        Args:
            category (str): Category name
            
        Returns:
            List[str]: Keywords in the specified category
        """
        categories = SuspiciousKeywords.get_keyword_categories()
        return categories.get(category, [])
    
    @staticmethod
    def add_custom_keywords(category: str, keywords: List[str]) -> Dict[str, List[str]]:
        """
        Add custom keywords to an existing category
        
        Args:
            category (str): Category to add keywords to
            keywords (List[str]): New keywords to add
            
        Returns:
            Dict[str, List[str]]: Updated keyword categories
        """
        categories = SuspiciousKeywords.get_keyword_categories()
        if category in categories:
            # Add new keywords while avoiding duplicates
            existing_keywords = set(categories[category])
            new_keywords = [kw for kw in keywords if kw.lower() not in existing_keywords]
            categories[category].extend(new_keywords)
        else:
            # Create new category
            categories[category] = keywords
        
        return categories

# Example usage and testing
if __name__ == "__main__":
    keywords = SuspiciousKeywords()
    
    print("=== KEYWORD CATEGORIES ===")
    categories = keywords.get_keyword_categories()
    
    for category, word_list in categories.items():
        print(f"\n{category.upper()} ({len(word_list)} keywords):")
        print(f"  Weight: {keywords.get_category_weights()[category]}")
        print(f"  Examples: {', '.join(word_list[:5])}...")
    
    print(f"\nTotal unique keywords: {len(keywords.get_all_keywords())}")
    
    # Test specific category lookup
    print(f"\nUrgency keywords: {keywords.get_keywords_by_category('urgency')[:3]}...")