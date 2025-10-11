import pandas as pd
import joblib
import os

class MLPhishingDetector:
    """
    Decision Tree phishing detector
    """

    def __init__(self):
        self.model = None
        self.is_trained = False
        self.feature_names = []
        self.model_path = "phishing_model.pkl"

    def extract_features_from_analysis(self, analysis: dict) -> dict:
        """Extract features from analysis"""
        features = {}

        # Basic features
        features['body_length'] = analysis.get('body_length', 0)
        features['subject_length'] = len(analysis.get('subject', ''))
        features['total_score'] = analysis.get('total_score', 0)
        features['keyword_score'] = analysis.get('keyword_score', 0)
        features['total_matches'] = analysis.get('total_matches', 0)
        features['subject_matches'] = analysis.get('subject_matches', 0)
        features['body_matches'] = analysis.get('body_matches', 0)

        # Category scores
        cat = analysis.get('category_scores', {})
        features['urgency_score'] = cat.get('urgency', 0)
        features['financial_score'] = cat.get('financial_security', 0)
        features['action_score'] = cat.get('action_oriented', 0)
        features['threat_score'] = cat.get('threats', 0)
        features['personal_info_score'] = cat.get('personal_info', 0)

        # Domain/URL features
        domain = analysis.get('domain_url_analysis', {})
        features['domain_risk'] = domain.get('risk_score', 0)
        features['suspicious_urls'] = len(domain.get('suspicious_urls', []))
        features['total_urls'] = len(domain.get('urls_found', []))

        # Text features
        text = f"{analysis.get('subject', '')} {analysis.get('body', '')}"
        features['exclamation_count'] = text.count('!')
        features['question_count'] = text.count('?')
        features['http_count'] = text.lower().count('http')
        features['click_count'] = text.lower().count('click')

        return features

    def predict_probability(self, analysis: dict) -> float:
        """Predict probability of phishing"""
        if not self.is_trained:
            raise ValueError("Model not trained")
        
        features = self.extract_features_from_analysis(analysis)
        df = pd.DataFrame([features])
        
        # Ensure all features present
        for f in self.feature_names:
            if f not in df.columns:
                df[f] = 0
        df = df[self.feature_names]
        
        # Get probability
        prob = self.model.predict_proba(df)[0][1]
        return prob
    
    def predict(self, analysis: dict) -> dict:
        """Predict with detailed results"""
        prob = self.predict_probability(analysis)
        
        is_phishing = prob > 0.5
        confidence_score = abs(prob - 0.5) * 200
        
        if confidence_score > 60:
            confidence_level = "high"
        elif confidence_score > 30:
            confidence_level = "medium"
        else:
            confidence_level = "low"
        
        return {
            "probability": prob,
            "prediction": "phishing" if is_phishing else "legitimate",
            "confidence": confidence_level,
            "confidence_score": confidence_score,
            "interpretation": (
                f"Phishing detected ({prob*100:.0f}% confidence)" if is_phishing
                else f"Appears legitimate ({(1-prob)*100:.0f}% confidence)"
            )
        }

    def load_model(self):
        """Load trained model"""
        if os.path.exists(self.model_path):
            data = joblib.load(self.model_path)
            self.model = data['model']
            self.feature_names = data['feature_names']
            self.is_trained = True
            print(f"Model loaded from {self.model_path}")
            return True
        print("No saved model found.")
        return False