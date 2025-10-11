"""
Extract features using real analyzers
"""
import pandas as pd
from keyword_detector import KeywordDetector
from position_scorer import PositionScorer
from distance_checker import analyze_email_domain_and_urls

print("=" * 80)
print("FEATURE EXTRACTION")
print("=" * 80)

# Load labeled emails
print("\n📂 Loading emails...")
df = pd.read_csv("emails_labeled.csv")
print(f"✅ Loaded {len(df)} emails")

# Initialize analyzers
print("\n🔧 Initializing analyzers...")
keyword_detector = KeywordDetector()
position_scorer = PositionScorer()

# Extract features
print("\n🔍 Extracting features (this may take a few minutes)...")

features_list = []
labels = []

for idx, row in df.iterrows():
    if idx % 500 == 0:
        print(f"   Processing {idx}/{len(df)}...")
    
    subject = str(row['subject']) if pd.notna(row['subject']) else ""
    body = str(row['body']) if pd.notna(row['body']) else ""
    label = int(row['label'])
    
    try:
        # Keyword detection
        subject_matches = keyword_detector.find_keywords_in_text(subject, is_subject=True)
        body_matches = keyword_detector.find_keywords_in_text(body, is_subject=False)
        all_matches = subject_matches + body_matches
        
        # Position scoring
        email_length = len(subject) + len(body)
        score_result = position_scorer.calculate_comprehensive_score(all_matches, email_length)
        
        # Domain/URL analysis
        domain_analysis = analyze_email_domain_and_urls("unknown@example.com", body, subject)
        
        # Build feature dict
        features = {
            'body_length': len(body),
            'subject_length': len(subject),
            'total_score': score_result['total_score'] + domain_analysis.get('risk_score', 0),
            'keyword_score': score_result['total_score'],
            'total_matches': len(all_matches),
            'subject_matches': len(subject_matches),
            'body_matches': len(body_matches),
            
            # Category scores
            'urgency_score': score_result.get('category_scores', {}).get('urgency', 0),
            'financial_score': score_result.get('category_scores', {}).get('financial_security', 0),
            'action_score': score_result.get('category_scores', {}).get('action_oriented', 0),
            'threat_score': score_result.get('category_scores', {}).get('threats', 0),
            'personal_info_score': score_result.get('category_scores', {}).get('personal_info', 0),
            
            # Domain/URL features
            'domain_risk': domain_analysis.get('risk_score', 0),
            'suspicious_urls': len(domain_analysis.get('suspicious_urls', [])),
            'total_urls': len(domain_analysis.get('urls_found', [])),
            
            # Text features
            'exclamation_count': (subject + body).count('!'),
            'question_count': (subject + body).count('?'),
            'http_count': body.lower().count('http'),
            'click_count': body.lower().count('click'),
        }
        
        features_list.append(features)
        labels.append(label)
        
    except Exception as e:
        print(f"   ⚠️ Error at row {idx}: {e}")
        continue

print(f"\n✅ Extracted features from {len(features_list)} emails")

# Convert to DataFrame
features_df = pd.DataFrame(features_list)
features_df['label'] = labels

# Show stats
print(f"\n📊 FEATURE STATISTICS:")
print("-" * 80)

key_features = ['total_score', 'keyword_score', 'domain_risk', 'suspicious_urls', 'urgency_score']

for feature in key_features:
    if feature in features_df.columns:
        phish_mean = features_df[features_df['label'] == 1][feature].mean()
        legit_mean = features_df[features_df['label'] == 0][feature].mean()
        diff = abs(phish_mean - legit_mean)
        print(f"{feature:20} Phishing: {phish_mean:6.2f} | Legit: {legit_mean:6.2f} | Diff: {diff:6.2f}")

# Save
output_file = "features.csv"
features_df.to_csv(output_file, index=False)
print(f"\n💾 Saved to: {output_file}")

print("\n" + "=" * 80)
print("NEXT STEP: python train_model.py")
print("=" * 80)