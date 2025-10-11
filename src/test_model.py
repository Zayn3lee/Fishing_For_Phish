"""
Test Decision Tree model
"""
from ml_classifier import MLPhishingDetector
from keyword_detector import KeywordDetector
from position_scorer import PositionScorer
from distance_checker import analyze_email_domain_and_urls

print("=" * 80)
print("TESTING DECISION TREE MODEL")
print("=" * 80)

# Load model
detector = MLPhishingDetector()
if not detector.load_model():
    print("❌ No model found! Run: python train_model.py")
    exit(1)

# Initialize analyzers
keyword_detector = KeywordDetector()
position_scorer = PositionScorer()

def analyze_email(subject, body, sender="unknown@example.com"):
    """Analyze email"""
    subject_matches = keyword_detector.find_keywords_in_text(subject, is_subject=True)
    body_matches = keyword_detector.find_keywords_in_text(body, is_subject=False)
    all_matches = subject_matches + body_matches
    
    score_result = position_scorer.calculate_comprehensive_score(all_matches, len(subject) + len(body))
    domain_analysis = analyze_email_domain_and_urls(sender, body, subject)
    
    return {
        'subject': subject,
        'body': body,
        'body_length': len(body),
        'subject_length': len(subject),
        'total_matches': len(all_matches),
        'subject_matches': len(subject_matches),
        'body_matches': len(body_matches),
        'keyword_score': score_result['total_score'],
        'total_score': score_result['total_score'] + domain_analysis.get('risk_score', 0),
        'category_scores': score_result.get('category_scores', {}),
        'position_scores': score_result.get('position_scores', {}),
        'domain_url_analysis': domain_analysis,
        'attachment_risk': {'has_attachments': False, 'attachment_risk_score': 0},
        'link_risk': {
            'has_links': len(domain_analysis.get('urls_found', [])) > 0,
            'link_risk_score': domain_analysis.get('risk_score', 0),
            'suspicious_link_count': len(domain_analysis.get('suspicious_urls', []))
        }
    }

# Test cases
tests = [
    {
        "name": "PHISHING - Urgent Account",
        "subject": "URGENT: Your account will be suspended",
        "body": "Click here immediately to verify: http://192.168.1.1/verify",
        "expected": "PHISHING"
    },
    {
        "name": "LEGITIMATE - Google Security",
        "subject": "Security alert",
        "body": "New sign-in detected. If this was you, no action needed.\nhttps://myaccount.google.com/security",
        "sender": "no-reply@accounts.google.com",
        "expected": "LEGITIMATE"
    },
    {
        "name": "PHISHING - Bank Scam",
        "subject": "Action Required: Verify Account",
        "body": "Your account has been limited. Verify now or lose access forever! http://fake-bank.com/verify",
        "expected": "PHISHING"
    },
    {
        "name": "LEGITIMATE - Newsletter",
        "subject": "Weekly Tech Digest",
        "body": "Here's your weekly tech news roundup. Read more at technews.com. Unsubscribe anytime.",
        "expected": "LEGITIMATE"
    }
]

# Run tests
print("\n" + "=" * 80)
print("TEST RESULTS")
print("=" * 80)

correct = 0

for test in tests:
    print(f"\n{'='*80}")
    print(f"TEST: {test['name']}")
    print(f"{'='*80}")
    
    analysis = analyze_email(test['subject'], test['body'], test.get('sender', 'unknown@example.com'))
    prediction = detector.predict(analysis)
    
    print(f"Subject: {test['subject']}")
    print(f"Expected: {test['expected']}")
    print(f"\n🤖 ML Prediction:")
    print(f"   Result: {prediction['prediction'].upper()}")
    print(f"   Probability: {prediction['probability']:.2%}")
    print(f"   Confidence: {prediction['confidence']}")
    
    is_correct = (prediction['prediction'].upper() == "PHISHING") == (test['expected'] == "PHISHING")
    correct += is_correct
    
    status = "✅ CORRECT" if is_correct else "❌ WRONG"
    print(f"\n{status}")

# Summary
print("\n" + "=" * 80)
print("SUMMARY")
print("=" * 80)
print(f"Accuracy: {correct}/{len(tests)} ({correct/len(tests)*100:.0f}%)")

if correct == len(tests):
    print("\n🎉 Perfect! Model working correctly!")
else:
    print(f"\n⚠️  {len(tests)-correct} test(s) failed")

print("\n" + "=" * 80)
print("Ready to use in Flask app!")
print("=" * 80)