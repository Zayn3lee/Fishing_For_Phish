from flask import Flask, render_template, request, redirect, url_for, flash
from email_integration import PhishingEmailAnalyzer
from ml_classifier import MLPhishingDetector  # Import the actual ML class
import os
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"csv", "txt", "zip"}  # Added zip for ML training

app = Flask(__name__)
app.secret_key = "super_secret_key"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
analyzer = PhishingEmailAnalyzer()
ml_detector = MLPhishingDetector()

# Try to load existing ML model on startup
ml_detector.load_model()

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/")
def home():
    return render_template("home.html", ml_trained=ml_detector.is_trained)

@app.route("/gmail_login")
def gmail_login():
    try:
        analyzer.initialize_service()
        analyses = analyzer.analyze_emails(max_results=10)

        summary = analyzer.get_integration_summary(analyses)
        summary.update(calculate_attachment_summary(analyses))
        summary.update(calculate_link_summary(analyses))
        
        # Add ML predictions if available
        if ml_detector.is_trained:
            for analysis in analyses:
                try:
                    ml_prob = ml_detector.predict_probability(analysis)
                    analysis["ml_prediction"] = {
                        "probability": ml_prob,
                        "prediction": "phishing" if ml_prob > 0.5 else "legitimate",
                        "confidence": "high" if abs(ml_prob - 0.5) > 0.3 else "medium"
                    }
                    
                    # Combine rule-based and ML scores for enhanced decision
                    rule_based_score = analysis.get('total_score', 0)
                    ml_score = ml_prob * 100
                    combined_score = (rule_based_score * 0.6) + (ml_score * 0.4)
                    
                    analysis["combined_score"] = combined_score
                    analysis["enhanced_risk_level"] = "HIGH" if combined_score > 50 else "MEDIUM" if combined_score > 25 else "LOW"
                    
                except Exception as e:
                    analysis["ml_prediction"] = {"error": str(e)}
        
        summary["ml_model_active"] = ml_detector.is_trained

        return render_template("results.html", analyses=analyses, summary=summary, results=analyses)
    except Exception as e:
        flash(f"Error during Gmail analysis: {str(e)}")
        return redirect(url_for("home"))

@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        flash("No file part")
        return redirect(url_for("home"))

    file = request.files["file"]
    if file.filename == "":
        flash("No selected file")
        return redirect(url_for("home"))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
        file.save(filepath)

        from email_checker_manual import SimpleEmailAnalyzer  
        rule_analyzer = SimpleEmailAnalyzer()
        
        results = rule_analyzer.analyze_files([filepath])

        analyses = []
        for result in results:
            analysis = {
                "sender": result.sender_domain,
                "subject": "",  
                "body_length": len(result.extracted_urls),
                "risk_level": "HIGH" if result.is_suspicious else "LOW",
                "total_score": result.spam_score,
                "total_matches": len(result.suspicious_domains),
                "subject_matches": 0,
                "body_matches": 0,
                "link_risk": {
                    "has_links": bool(result.extracted_urls),
                    "total_links": len(result.extracted_urls),
                    "suspicious_link_count": len(result.suspicious_urls),
                    "link_risk_level": "HIGH" if result.suspicious_urls else "LOW",
                    "link_details": [
                        {
                            "type": "url",
                            "url": u["url"],
                            "risk_level": "HIGH",
                            "description": ", ".join(u["suspicious_reasons"])
                        } for u in result.suspicious_urls
                    ] if result.suspicious_urls else []
                },
                "attachment_risk": {"has_attachments": False, "attachment_risk_score": 0, "suspicious_attachment_count": 0},
                "attachment_results": [],
                "category_scores": {}
            }
            
            # Add ML prediction if model is trained
            if ml_detector.is_trained:
                try:
                    # Create analysis for ML using your mock analysis function
                    mock_analysis = {
                        'subject': '',
                        'body': '',
                        'body_length': 0,
                        'subject_length': 0,
                        'total_score': result.spam_score,
                        'keyword_score': result.spam_score * 0.5,  # Estimate keyword portion
                        'total_matches': len(result.suspicious_domains),
                        'subject_matches': 0,
                        'body_matches': 0,
                        'category_scores': {},
                        'position_scores': {},
                        'domain_url_analysis': {
                            'risk_score': 5 if result.is_suspicious else 1,
                            'urls_found': result.extracted_urls,
                            'suspicious_urls': result.suspicious_urls,
                            'suspicious_url_count': len(result.suspicious_urls),
                            'sender_analysis': {'is_suspicious': result.is_suspicious}
                        },
                        'attachment_risk': {'has_attachments': False, 'attachment_risk_score': 0, 'suspicious_attachment_count': 0},
                        'link_risk': {
                            'has_links': bool(result.extracted_urls),
                            'link_risk_score': 5 if result.suspicious_urls else 0,
                            'suspicious_link_count': len(result.suspicious_urls)
                        }
                    }
                    
                    ml_probability = ml_detector.predict_probability(mock_analysis)
                    
                    analysis["ml_prediction"] = {
                        "probability": ml_probability,
                        "prediction": "phishing" if ml_probability > 0.5 else "legitimate",
                        "confidence": "high" if abs(ml_probability - 0.5) > 0.3 else "medium"
                    }
                    
                    # Combine rule-based and ML for final decision
                    combined_score = (result.spam_score * 0.6) + (ml_probability * 100 * 0.4)
                    analysis["combined_score"] = combined_score
                    analysis["enhanced_risk_level"] = "HIGH" if combined_score > 50 else "MEDIUM" if combined_score > 25 else "LOW"
                    
                except Exception as e:
                    analysis["ml_prediction"] = {"error": str(e)}
            
            analyses.append(analysis)

        summary = {
            "total_emails_analyzed": len(analyses),
            "high_risk_emails": sum(1 for a in analyses if a["risk_level"] == "HIGH"),
            "medium_risk_emails": 0,
            "average_keyword_score": round(sum(a["total_score"] for a in analyses)/max(1,len(analyses)),2),
            "ml_model_active": ml_detector.is_trained
        }
        
        # Add ML summary if available
        if ml_detector.is_trained:
            ml_high_risk = sum(1 for a in analyses 
                             if a.get("ml_prediction", {}).get("prediction") == "phishing")
            summary["ml_high_risk_emails"] = ml_high_risk
            
            # Add enhanced risk summary
            enhanced_high_risk = sum(1 for a in analyses 
                                   if a.get("enhanced_risk_level") == "HIGH")
            summary["enhanced_high_risk_emails"] = enhanced_high_risk

        return render_template("results.html", analyses=analyses, summary=summary)

    flash("Invalid file type. Only CSV/TXT/ZIP allowed.")
    return redirect(url_for("home"))

@app.route("/ml_train")
def ml_train_page():
    """ML training page"""
    return render_template("ml_train.html")

@app.route("/ml_train", methods=["POST"])
def ml_train():
    """Train ML model from raw email files"""
    training_type = request.form.get('training_type', 'file')
    
    if training_type == 'file':
        # Handle file upload
        if "file" not in request.files:
            flash("No file selected")
            return redirect(url_for("ml_train_page"))
        
        file = request.files["file"]
        if file.filename == "":
            flash("No file selected")
            return redirect(url_for("ml_train_page"))
        
        # Accept CSV and ZIP files for training
        if not (file.filename.endswith('.csv') or file.filename.endswith('.zip')):
            flash("Please upload a CSV file (structured data) or ZIP file (raw email folders)")
            return redirect(url_for("ml_train_page"))
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
        file.save(filepath)
        
        try:
            # Train model based on file type
            if filename.endswith('.csv'):
                print("Training from CSV file...")
                results = ml_detector.train_from_csv(filepath)
            else:  # ZIP file with raw emails
                print("Training from ZIP file containing raw email folders...")
                results = ml_detector.train_from_zip(filepath)
            
            # Debug: Check what type results is
            print(f"Results type: {type(results)}")
            print(f"Results content: {results}")
            
            # If results is a list, take the first element
            if isinstance(results, list):
                results = results[0]
            
            ml_detector.save_model()
            
            flash(f"Model trained successfully! Accuracy: {results['accuracy']:.3f}")
            return render_template("ml_results.html", results=results)
            
        except Exception as e:
            flash(f"Training failed: {str(e)}")
            print(f"Detailed error: {e}")
            return redirect(url_for("ml_train_page"))
    
    else:
        flash("Invalid training type selected")
        return redirect(url_for("ml_train_page"))

@app.route("/ml_status")
def ml_status():
    """Check ML model status"""
    return {
        "is_trained": ml_detector.is_trained,
        "model_path": ml_detector.model_path,
        "model_exists": os.path.exists(ml_detector.model_path)
    }

def calculate_attachment_summary(analyses):
    total_attachments = 0
    total_suspicious_attachments = 0
    emails_with_attachments = 0
    high_risk_attachment_emails = 0
    for analysis in analyses:
        attachment_risk = analysis.get("attachment_risk", {})
        if attachment_risk.get("has_attachments"):
            emails_with_attachments += 1
            total_attachments += attachment_risk.get("total_attachments", 0)
            total_suspicious_attachments += attachment_risk.get("suspicious_attachment_count", 0)
            if attachment_risk.get("attachment_risk_level") == "HIGH":
                high_risk_attachment_emails += 1
    return {
        "emails_with_attachments": emails_with_attachments,
        "total_attachments": total_attachments,
        "total_suspicious_attachments": total_suspicious_attachments,
        "high_risk_attachment_emails": high_risk_attachment_emails,
    }

def calculate_link_summary(analyses):
    total_links = 0
    total_suspicious_links = 0
    emails_with_links = 0
    high_risk_link_emails = 0
    for analysis in analyses:
        link_risk = analysis.get("link_risk", {})
        if link_risk.get("has_links"):
            emails_with_links += 1
            total_links += link_risk.get("total_links", 0)
            total_suspicious_links += link_risk.get("suspicious_link_count", 0)
            if link_risk.get("link_risk_level") == "HIGH":
                high_risk_link_emails += 1
    return {
        "emails_with_links": emails_with_links,
        "total_links_analyzed": total_links,
        "total_suspicious_links_found": total_suspicious_links,
        "high_risk_link_emails": high_risk_link_emails,
    }

if __name__ == "__main__":
    app.run(debug=True, port=8081)