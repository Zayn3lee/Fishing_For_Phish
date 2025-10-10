import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.pipeline import Pipeline
import joblib
import os
import zipfile
import email
from email.parser import Parser
import re
from typing import Dict, List, Tuple, Optional
import warnings
warnings.filterwarnings('ignore')

class MLPhishingDetector:
    """
    Machine Learning-based phishing email detector that works with your existing rule-based system
    """
    
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.is_trained = False
        self.feature_names = []
        self.model_path = "phishing_model.pkl"
        
    def extract_features_from_analysis(self, analysis: Dict) -> Dict:
        """
        Extract ML features from your existing analysis results
        """
        features = {}
        
        # Basic email features
        features['subject_length'] = len(analysis.get('subject', ''))
        features['body_length'] = analysis.get('body_length', 0)
        features['total_score'] = analysis.get('total_score', 0)
        features['keyword_score'] = analysis.get('keyword_score', 0)
        
        # Keyword-based features
        features['total_matches'] = analysis.get('total_matches', 0)
        features['subject_matches'] = analysis.get('subject_matches', 0)
        features['body_matches'] = analysis.get('body_matches', 0)
        
        # Category scores from your position scorer
        category_scores = analysis.get('category_scores', {})
        features['urgency_score'] = category_scores.get('urgency', 0)
        features['financial_security_score'] = category_scores.get('financial_security', 0)
        features['action_oriented_score'] = category_scores.get('action_oriented', 0)
        features['legitimacy_claims_score'] = category_scores.get('legitimacy_claims', 0)
        features['personal_info_score'] = category_scores.get('personal_info', 0)
        features['threats_score'] = category_scores.get('threats', 0)
        
        # Position scores
        position_scores = analysis.get('position_scores', {})
        features['subject_position_score'] = position_scores.get('subject', 0)
        features['first_paragraph_score'] = position_scores.get('first_paragraph', 0)
        features['rest_of_email_score'] = position_scores.get('rest_of_email', 0)
        
        # Domain and URL features
        domain_analysis = analysis.get('domain_url_analysis', {})
        features['domain_risk_score'] = domain_analysis.get('risk_score', 0)
        features['suspicious_url_count'] = domain_analysis.get('suspicious_url_count', 0)
        features['total_urls'] = len(domain_analysis.get('urls_found', []))
        features['sender_suspicious'] = 1 if domain_analysis.get('sender_analysis', {}).get('is_suspicious', False) else 0
        
        # Attachment features
        attachment_risk = analysis.get('attachment_risk', {})
        features['has_attachments'] = 1 if attachment_risk.get('has_attachments', False) else 0
        features['attachment_risk_score'] = attachment_risk.get('attachment_risk_score', 0)
        features['suspicious_attachment_count'] = attachment_risk.get('suspicious_attachment_count', 0)
        
        # Link features
        link_risk = analysis.get('link_risk', {})
        features['has_links'] = 1 if link_risk.get('has_links', False) else 0
        features['link_risk_score'] = link_risk.get('link_risk_score', 0)
        features['suspicious_link_count'] = link_risk.get('suspicious_link_count', 0)
        
        # Text-based features
        subject_text = analysis.get('subject', '')
        body_text = analysis.get('body', '')
        combined_text = f"{subject_text} {body_text}"
        
        # Basic text statistics
        features['exclamation_count'] = combined_text.count('!')
        features['question_count'] = combined_text.count('?')
        features['caps_ratio'] = sum(1 for c in combined_text if c.isupper()) / max(len(combined_text), 1)
        features['digit_ratio'] = sum(1 for c in combined_text if c.isdigit()) / max(len(combined_text), 1)
        
        # URL-related text features
        features['http_count'] = combined_text.lower().count('http')
        features['click_here_count'] = combined_text.lower().count('click here')
        
        return features
    
    def prepare_training_data(self, email_analyses: List[Dict], labels: List[int]) -> Tuple[pd.DataFrame, np.array]:
        """
        Prepare training data from email analyses and labels
        """
        feature_list = []
        
        for analysis in email_analyses:
            features = self.extract_features_from_analysis(analysis)
            feature_list.append(features)
        
        # Convert to DataFrame
        df = pd.DataFrame(feature_list)
        
        # Fill any missing values with 0
        df = df.fillna(0)
        
        # Store feature names for later use
        self.feature_names = df.columns.tolist()
        
        return df, np.array(labels)
    
    def train_model(self, X: pd.DataFrame, y: np.array) -> Dict:
        """
        Train the machine learning model
        """
        # Split the data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Create and train model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        )
        
        self.model.fit(X_train, y_train)
        
        # Make predictions
        y_pred = self.model.predict(X_test)
        y_pred_proba = self.model.predict_proba(X_test)
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        
        # Get feature importance
        feature_importance = list(zip(self.feature_names, self.model.feature_importances_))
        feature_importance.sort(key=lambda x: x[1], reverse=True)
        
        self.is_trained = True
        
        return {
            'accuracy': accuracy,
            'classification_report': classification_report(y_test, y_pred),
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
            'feature_importance': feature_importance[:10],  # Top 10 features
            'train_size': len(X_train),
            'test_size': len(X_test),
            'phishing_samples': sum(y_train),
            'legitimate_samples': len(y_train) - sum(y_train)
        }
    
    def predict_probability(self, analysis: Dict) -> float:
        """
        Predict probability that an email is phishing based on analysis
        """
        if not self.is_trained or self.model is None:
            raise ValueError("Model not trained yet")
        
        # Extract features
        features = self.extract_features_from_analysis(analysis)
        
        # Convert to DataFrame with same columns as training data
        feature_df = pd.DataFrame([features])
        
        # Ensure all training features are present
        for feature_name in self.feature_names:
            if feature_name not in feature_df.columns:
                feature_df[feature_name] = 0
        
        # Reorder columns to match training data
        feature_df = feature_df[self.feature_names]
        
        # Make prediction
        probability = self.model.predict_proba(feature_df)[0][1]  # Probability of phishing (class 1)
        
        return probability
    
    def train_from_csv(self, csv_path: str) -> Dict:
        """
        Train model from a CSV file with columns: subject, body, label
        """
        try:
            # Load CSV
            df = pd.read_csv(csv_path)
            
            # Check required columns
            required_cols = ['subject', 'body', 'label']
            if not all(col in df.columns for col in required_cols):
                raise ValueError(f"CSV must contain columns: {required_cols}")
            
            # Process each email through your existing analysis pipeline
            from keyword_detector import KeywordDetector
            from position_scorer import PositionScorer
            
            email_analyses = []
            labels = []
            
            print(f"Processing {len(df)} emails...")
            
            for idx, row in df.iterrows():
                try:
                    # Create mock email analysis using your existing systems
                    subject = str(row['subject']) if pd.notna(row['subject']) else ""
                    body = str(row['body']) if pd.notna(row['body']) else ""
                    label = int(row['label'])  # 0 = legitimate, 1 = phishing
                    
                    # Create a mock analysis structure
                    analysis = self._create_mock_analysis(subject, body)
                    
                    email_analyses.append(analysis)
                    labels.append(label)
                    
                    if (idx + 1) % 100 == 0:
                        print(f"Processed {idx + 1}/{len(df)} emails...")
                        
                except Exception as e:
                    print(f"Error processing email {idx}: {e}")
                    continue
            
            if len(email_analyses) == 0:
                raise ValueError("No valid emails processed from CSV")
            
            # Prepare training data
            X, y = self.prepare_training_data(email_analyses, labels)
            
            # Train model
            results = self.train_model(X, y)
            
            return results  # This should be a dictionary
            
        except Exception as e:
            raise Exception(f"Error training from CSV: {str(e)}")
    
    def _create_mock_analysis(self, subject: str, body: str) -> Dict:
        """
        Create a mock analysis structure for training purposes
        """
        from keyword_detector import KeywordDetector
        from position_scorer import PositionScorer
        from distance_checker import analyze_email_domain_and_urls
        
        # Initialize components
        detector = KeywordDetector()
        scorer = PositionScorer()
        
        # Analyze keywords
        subject_matches = detector.find_keywords_in_text(subject, is_subject=True)
        body_matches = detector.find_keywords_in_text(body, is_subject=False)
        all_matches = subject_matches + body_matches
        
        # Calculate scores
        email_length = len(subject) + len(body)
        scoring_result = scorer.calculate_comprehensive_score(all_matches, email_length)
        
        # Analyze domain/URLs (using a dummy sender for training)
        domain_analysis = analyze_email_domain_and_urls("unknown@example.com", body, subject)
        
        # Create analysis structure
        analysis = {
            'subject': subject,
            'body': body,
            'body_length': len(body),
            'subject_length': len(subject),
            'total_matches': len(all_matches),
            'subject_matches': len(subject_matches),
            'body_matches': len(body_matches),
            'keyword_score': scoring_result['total_score'],
            'total_score': scoring_result['total_score'] + domain_analysis.get('risk_score', 0),
            'category_scores': scoring_result.get('category_scores', {}),
            'position_scores': scoring_result.get('position_scores', {}),
            'domain_url_analysis': domain_analysis,
            'attachment_risk': {'has_attachments': False, 'attachment_risk_score': 0, 'suspicious_attachment_count': 0},
            'link_risk': {
                'has_links': len(domain_analysis.get('urls_found', [])) > 0,
                'link_risk_score': domain_analysis.get('risk_score', 0),
                'suspicious_link_count': len(domain_analysis.get('suspicious_urls', []))
            }
        }
        
        return analysis
    
    def train_from_zip(self, zip_path: str) -> Dict:
        """
        Train model from a ZIP file containing raw email files
        Supports multiple folder structures:
        - phishing/ and legitimate/ folders
        - spam/ and ham/ folders  
        - or files with labels in filename
        """
        try:
            email_analyses = []
            labels = []
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                file_list = zip_ref.namelist()
                
                print(f"Found {len(file_list)} files in ZIP")
                
                for file_path in file_list:
                    if file_path.endswith('/'):  # Skip directories
                        continue
                    
                    try:
                        # Determine label from folder structure or filename
                        label = self._determine_email_label(file_path)
                        if label is None:
                            continue  # Skip if can't determine label
                        
                        # Read email content
                        with zip_ref.open(file_path) as email_file:
                            email_content = email_file.read().decode('utf-8', errors='ignore')
                        
                        # Parse email
                        subject, body = self._parse_email_content(email_content)
                        
                        # Skip if no meaningful content
                        if len(subject) + len(body) < 10:
                            continue
                        
                        # Create analysis
                        analysis = self._create_mock_analysis(subject, body)
                        
                        email_analyses.append(analysis)
                        labels.append(label)
                        
                        if len(email_analyses) % 50 == 0:
                            print(f"Processed {len(email_analyses)} emails...")
                            
                    except Exception as e:
                        print(f"Error processing {file_path}: {e}")
                        continue
            
            if len(email_analyses) == 0:
                raise ValueError("No valid emails found in ZIP file. Please check folder structure.")
            
            print(f"Successfully processed {len(email_analyses)} emails")
            print(f"Phishing emails: {sum(labels)}")
            print(f"Legitimate emails: {len(labels) - sum(labels)}")
            
            # Prepare training data
            X, y = self.prepare_training_data(email_analyses, labels)
            
            # Train model
            results = self.train_model(X, y)
            
            return results
            
        except Exception as e:
            raise Exception(f"Error training from ZIP: {str(e)}")
    
    def _determine_email_label(self, file_path: str) -> Optional[int]:
        """
        Determine if email is phishing (1) or legitimate (0) from file path
        """
        file_path_lower = file_path.lower()
        
        # Check folder structure
        if any(folder in file_path_lower for folder in ['phishing', 'spam', 'malicious', 'bad']):
            return 1
        elif any(folder in file_path_lower for folder in ['legitimate', 'ham', 'good', 'safe']):
            return 0
        
        # Check filename patterns
        if any(pattern in file_path_lower for pattern in ['phish', 'spam', 'malware']):
            return 1
        elif any(pattern in file_path_lower for pattern in ['legit', 'ham', 'safe']):
            return 0
        
        return None  # Can't determine label
    
    def train_from_folder(self, folder_path: str) -> Dict:
        """
        Train model from a folder containing email files
        Expects subfolders named 'phishing' and 'legitimate' or similar
        """
        try:
            import glob
            
            email_analyses = []
            labels = []
            
            # Look for common email file extensions
            extensions = ['*.txt', '*.eml', '*.msg', '*.email']
            
            # Search all subfolders
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, folder_path)
                    
                    try:
                        # Determine label
                        label = self._determine_email_label(relative_path)
                        if label is None:
                            continue
                        
                        # Read email content
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            email_content = f.read()
                        
                        # Parse email
                        subject, body = self._parse_email_content(email_content)
                        
                        # Skip if no meaningful content
                        if len(subject) + len(body) < 10:
                            continue
                        
                        # Create analysis
                        analysis = self._create_mock_analysis(subject, body)
                        
                        email_analyses.append(analysis)
                        labels.append(label)
                        
                        if len(email_analyses) % 50 == 0:
                            print(f"Processed {len(email_analyses)} emails...")
                            
                    except Exception as e:
                        print(f"Error processing {file_path}: {e}")
                        continue
            
            if len(email_analyses) == 0:
                raise ValueError("No valid emails found in folder. Please check folder structure.")
            
            print(f"Successfully processed {len(email_analyses)} emails")
            print(f"Phishing emails: {sum(labels)}")
            print(f"Legitimate emails: {len(labels) - sum(labels)}")
            
            # Prepare training data
            X, y = self.prepare_training_data(email_analyses, labels)
            
            # Train model
            results = self.train_model(X, y)
            
            return results
            
        except Exception as e:
            raise Exception(f"Error training from folder: {str(e)}")
    
    def _parse_email_content(self, content: str) -> Tuple[str, str]:
        """
        Parse email content to extract subject and body
        """
        try:
            parser = Parser()
            email_obj = parser.parsestr(content)
            
            subject = email_obj.get('Subject', '')
            
            # Extract body
            if email_obj.is_multipart():
                body = ""
                for part in email_obj.walk():
                    if part.get_content_type() == "text/plain":
                        try:
                            payload = part.get_payload(decode=True)
                            if isinstance(payload, bytes):
                                body += payload.decode('utf-8', errors='ignore')
                            else:
                                body += str(payload)
                        except:
                            pass
            else:
                try:
                    payload = email_obj.get_payload(decode=True)
                    if isinstance(payload, bytes):
                        body = payload.decode('utf-8', errors='ignore')
                    else:
                        body = str(payload) if payload else ""
                except:
                    body = str(email_obj.get_payload()) if email_obj.get_payload() else ""
            
            return subject, body
            
        except Exception as e:
            # Fallback: try to extract subject from first line
            lines = content.split('\n')
            subject = ""
            body = content
            
            for i, line in enumerate(lines):
                if line.startswith('Subject:'):
                    subject = line[8:].strip()
                    body = '\n'.join(lines[i+1:])
                    break
            
            return subject, body
    
    def save_model(self):
        """Save trained model to disk"""
        if self.is_trained and self.model is not None:
            model_data = {
                'model': self.model,
                'feature_names': self.feature_names,
                'is_trained': True
            }
            joblib.dump(model_data, self.model_path)
            print(f"Model saved to {self.model_path}")
    
    def load_model(self):
        """Load trained model from disk"""
        try:
            if os.path.exists(self.model_path):
                model_data = joblib.load(self.model_path)
                self.model = model_data['model']
                self.feature_names = model_data['feature_names']
                self.is_trained = model_data['is_trained']
                print(f"Model loaded from {self.model_path}")
                return True
            else:
                print("No saved model found")
                return False
        except Exception as e:
            print(f"Error loading model: {e}")
            return False