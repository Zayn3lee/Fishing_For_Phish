from typing import Dict, List

class SuspiciousKeywords:
    """
    Centralized database of suspicious keywords organized by category.
    Provides utility methods to retrieve and manipulate phishing-related keyword sets.
    """

    def get_keyword_categories() -> Dict[str, List[str]]:
        """
        Returns a dictionary mapping category names to lists of suspicious keywords.

        Returns:
            Dict[str, List[str]]: Keyword categories and their corresponding keywords.
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

    def get_category_weights() -> Dict[str, int]:
        """
        Returns predefined weight scores for each category
        Used to prioritize or rank the threat level of keyword matches

        Returns:
            Dict[str, int]: Mapping of category to weight score
        """
        return {
            'urgency': 8,
            'financial_security': 10,
            'action_oriented': 6,
            'legitimacy_claims': 9,
            'personal_info': 7,
            'threats': 12
        }

    def get_all_keywords() -> List[str]:
        """
        Compiles all keywords from all categories into a single flat list, removing duplicates

        Returns:
            List[str]: List of unique suspicious keywords
        """
        all_keywords = []
        categories = SuspiciousKeywords.get_keyword_categories()

        # Combine all keywords across categories
        for keyword_list in categories.values():
            all_keywords.extend(keyword_list)

        return list(set(all_keywords))  # Deduplicate

    def get_keywords_by_category(category: str) -> List[str]:
        """
        Retrieves all keywords for a specific category

        Args:
            category (str): The category name.

        Returns:
            List[str]: List of keywords in that category (empty if not found)
        """
        categories = SuspiciousKeywords.get_keyword_categories()
        return categories.get(category, [])

    def add_custom_keywords(category: str, keywords: List[str]) -> Dict[str, List[str]]:
        """
        Adds user-defined keywords to an existing or new category.

        Args:
            category (str): Category name to update.
            keywords (List[str]): List of new keywords to add.

        Returns:
            Dict[str, List[str]]: The updated dictionary of keyword categories.
        """
        categories = SuspiciousKeywords.get_keyword_categories()

        if category in categories:
            existing_keywords = set(categories[category])
            # Only add non-duplicate, case-insensitive keywords
            new_keywords = [kw for kw in keywords if kw.lower() not in (k.lower() for k in existing_keywords)]
            categories[category].extend(new_keywords)
        else:
            # Create new category if it doesn't exist
            categories[category] = keywords

        return categories


# =======================
# Example usage and test
# =======================
if __name__ == "__main__":
    keywords = SuspiciousKeywords()

    print("=== KEYWORD CATEGORIES ===")
    categories = keywords.get_keyword_categories()

    for category, word_list in categories.items():
        print(f"\n{category.upper()} ({len(word_list)} keywords):")
        print(f"  Weight: {keywords.get_category_weights()[category]}")
        print(f"  Examples: {', '.join(word_list[:5])}...")

    print(f"\nTotal unique keywords: {len(keywords.get_all_keywords())}")

    # Lookup test
    print(f"\nUrgency keywords: {keywords.get_keywords_by_category('urgency')[:3]}...")
