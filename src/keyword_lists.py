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
                'you\'ve won', 'claim your prize', 'lucky winner',
                'free cash', 'easy money', 'make money fast', 'quick cash',
                'get rich', 'financial freedom', 'no investment', 'freemoney'
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
            'legitimacy_claims': 15,
            'personal_info': 7,
            'threats': 12
        }

    # NEW: Domain and URL specific keywords
    def get_phishing_domain_keywords() -> List[str]:
        """
        Keywords frequently used in phishing domain names
        
        Returns:
            List[str]: Keywords that appear in malicious domains
        """
        return [
            'secure', 'verify', 'update', 'confirm', 'urgent', 'suspended',
            'blocked', 'limited', 'restricted', 'temporary', 'alert',
            'warning', 'notice', 'action', 'required', 'immediate',
            'banking', 'payment', 'billing', 'invoice'
        ]
    
    def get_suspicious_url_path_keywords() -> List[str]:
        """
        Keywords that are suspicious when found in URL paths
        
        Returns:
            List[str]: Keywords that indicate phishing in URL paths
        """
        return [
            'verify', 'confirm', 'secure', 'update', 'login', 
            'suspended', 'locked', 'urgent', 'account', 'validation',
            'authentication', 'security', 'billing', 'payment'
        ]
    
    def get_legitimate_domains() -> set:
        """
        Known legitimate domains to whitelist
        
        Returns:
            set: Set of legitimate domain names
        """
        return {
            # Banking and Financial
            'paypal.com', 'citibank.com', 'americanexpress.com',

            # Government and Education
            'gov.sg', 'sit.singaporetech.edu.sg', 'nus.edu.sg', 'ntu.edu.sg',

            # Email Providers
            'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
            'icloud.com', 'mail.com',

            # Tech Companies
            'google.com', 'accounts.google.com', 'gmail.google.com',
            'googlemail.com', 'youtube.com', 'googlemessages.com',
            'android.com',
            'microsoft.com', 'live.com',
            'apple.com', 'icloud.com', 'me.com',
            'amazon.com', 'amazonses.com',
            'facebook.com', 'meta.com', 'instagram.com',
            'twitter.com', 'x.com', 'tiktok.com',
            'github.com', 'stackoverflow.com', 'reddit.com',
        }
    
    def get_suspicious_tlds() -> List[str]:
        """
        Top-level domains often abused in phishing attacks
        
        Returns:
            List[str]: Suspicious TLD extensions
        """
        return [
            '.tk', '.ml', '.ga', '.cf', '.click', '.download',
            '.top', '.win', '.bid', '.loan', '.work', '.date',
            '.racing', '.accountant', '.science', '.party'
        ]
    
    def get_url_shortener_domains() -> List[str]:
        """
        Common URL shortening services
        
        Returns:
            List[str]: URL shortener domain names
        """
        return [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 
            'short.link', 'tiny.cc', 'is.gd', 'buff.ly'
        ]
    
    def get_brand_names() -> List[str]:
        """
        Common brand names to check for abuse in domains/paths
        
        Returns:
            List[str]: Brand names that are often spoofed
        """
        return [
            'paypal', 'google', 'microsoft', 'amazon', 'apple', 
            'facebook', 'meta', 'instagram', 'twitter', 'netflix',
            'linkedin', 'dropbox', 'adobe', 'yahoo', 'ebay',
            'citibank', 'chase', 'wellsfargo', 'bankofamerica'
        ]

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

        return list(set(all_keywords))

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

    # Test new domain/URL methods
    print("\n=== URL/DOMAIN KEYWORDS ===")
    print(f"Phishing domain keywords: {len(keywords.get_phishing_domain_keywords())}")
    print(f"Suspicious URL path keywords: {len(keywords.get_suspicious_url_path_keywords())}")
    print(f"Legitimate domains: {len(keywords.get_legitimate_domains())}")
    print(f"Suspicious TLDs: {len(keywords.get_suspicious_tlds())}")
    print(f"URL shorteners: {len(keywords.get_url_shortener_domains())}")
    print(f"Brand names: {len(keywords.get_brand_names())}")