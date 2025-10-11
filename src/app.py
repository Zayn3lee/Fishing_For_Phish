# Import necessary Flask modules and utilities
from flask import Flask, render_template, request, redirect, url_for, flash
from email_integration import PhishingEmailAnalyzer                 # Rule-based Gmail analyzer
from email_checker_manual import SimpleEmailAnalyzer                # Local rule-based file analyzer
from ml_classifier import MLPhishingDetector                        # Machine learning classifier
import os
from werkzeug.utils import secure_filename                          # For safely handling uploaded file names

# Configuration for allowed upload types
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"csv", "txt"}

# Initialize Flask app and configuration
app = Flask(__name__)
app.secret_key = "super_secret_key"                                # Secret key for session/flash
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Initialize analyzers
analyzer = PhishingEmailAnalyzer()                                 # Rule-based analyzer
ml_detector = MLPhishingDetector()                                 # ML-based analyzer

# Load ML model on startup
ml_detector.load_model()

# Helper function to validate uploaded file types
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ------------------ ROUTES ------------------

# Home page route
@app.route("/")
def home():
    return render_template("home.html")

# Gmail login route to trigger Gmail integration and analyze recent emails
@app.route("/gmail_login")
def gmail_login():
    '''
    Integrate with Gmail, fetch and analyze recent emails using both rule-based and ML methods.
    '''
    try:
        analyzer.initialize_service()  # Connect to Gmail API
        analyses = analyzer.analyze_emails(max_results=10)  # Analyze latest 10 emails

        # Generate summary statistics
        summary = analyzer.get_integration_summary(analyses)
        summary.update(calculate_attachment_summary(analyses))
        summary.update(calculate_link_summary(analyses))
        
        # Add ML predictions if model is trained
        if ml_detector.is_trained:
            ml_high_risk_count = 0  # Initialize counter
            
            for analysis in analyses:
                try:
                    # Predict using ML model
                    ml_prob = ml_detector.predict_probability(analysis)
                    analysis["ml_prediction"] = {
                        "probability": ml_prob,
                        "prediction": "phishing" if ml_prob > 0.5 else "legitimate",
                        "confidence": "high" if abs(ml_prob - 0.5) > 0.3 else "medium"
                    }

                    # Combine rule-based and ML score into a unified score
                    rule_based_score = analysis.get('total_score', 0)
                    ml_score = ml_prob * 100
                    combined_score = (rule_based_score * 0.6) + (ml_score * 0.4)

                    analysis["combined_score"] = combined_score
                    analysis["enhanced_risk_level"] = (
                        "HIGH" if combined_score > 50 else
                        "MEDIUM" if combined_score > 25 else
                        "LOW"
                    )

                    # ATTACHMENT OVERRIDE - Force HIGH if critical attachment detected
                    attachment_risk = analysis.get('attachment_risk', {})
                    if attachment_risk.get('attachment_risk_score', 0) > 40:
                        analysis["combined_score"] = 70
                        analysis["enhanced_risk_level"] = "HIGH"

                    # Count ML high risk
                    if ml_prob > 0.5:
                        ml_high_risk_count += 1

                except Exception as e:
                    analysis["ml_prediction"] = {"error": str(e)}

            # Add ML summary stats
            summary["ml_model_active"] = True
            summary["ml_high_risk_emails"] = ml_high_risk_count
            summary["enhanced_high_risk_emails"] = sum(
                1 for a in analyses if a.get("enhanced_risk_level") == "HIGH"
            )
        else:
            summary["ml_model_active"] = False

        # Render the results
        return render_template("results.html", analyses=analyses, summary=summary, results=analyses)

    except Exception as e:
        flash(f"Error during Gmail analysis: {str(e)}")
        return redirect(url_for("home"))

# Route to handle uploaded files (TXT/CSV) for manual analysis
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

        # Parse email
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                email_content = f.read()
            
            from email.parser import Parser
            parser = Parser()
            email_obj = parser.parsestr(email_content)
            subject = email_obj.get('Subject', '')
            sender = email_obj.get('From', 'unknown@example.com')
            
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
        except:
            subject = ""
            body = ""
            sender = "unknown@example.com"
        
        # USE THE SAME ANALYZERS AS GMAIL (this is the key fix!)
        from keyword_detector import KeywordDetector
        from position_scorer import PositionScorer
        from distance_checker import analyze_email_domain_and_urls
        
        keyword_detector = KeywordDetector()
        position_scorer = PositionScorer()
        
        # Keyword detection
        subject_matches = keyword_detector.find_keywords_in_text(subject, is_subject=True)
        body_matches = keyword_detector.find_keywords_in_text(body, is_subject=False)
        all_matches = subject_matches + body_matches
        
        # Position scoring
        score_result = position_scorer.calculate_comprehensive_score(all_matches, len(subject) + len(body))
        
        # Domain/URL analysis
        domain_analysis = analyze_email_domain_and_urls(sender, body, subject)
        
        # Build analysis
        analysis = {
            "sender": sender,
            "subject": subject,  # ← Add this
            "body": body,  # ← Add this
            "body_length": len(body),
            "subject_length": len(subject),
            "total_score": score_result['total_score'] + domain_analysis.get('risk_score', 0),
            "keyword_score": score_result['total_score'],
            "total_matches": len(all_matches),
            "subject_matches": len(subject_matches),
            "body_matches": len(body_matches),
            "category_scores": score_result.get('category_scores', {}),
            "position_scores": score_result.get('position_scores', {}),  # ← Add this
            "domain_url_analysis": domain_analysis,  # ← Make sure this is complete
            "link_risk": {
                "has_links": len(domain_analysis.get('urls_found', [])) > 0,
                "total_links": len(domain_analysis.get('urls_found', [])),
                "suspicious_link_count": len(domain_analysis.get('suspicious_urls', [])),
                "link_risk_level": "HIGH" if len(domain_analysis.get('suspicious_urls', [])) > 2 else "LOW",
                "link_risk_score": domain_analysis.get('risk_score', 0),  # ← Add this
                "link_details": [
                    {
                        "type": "url",
                        "url": u.get('analyzed_url', ''),
                        "risk_level": "HIGH",
                        "description": ", ".join(u.get('reasons', []))
                    } for u in domain_analysis.get('suspicious_urls', [])
                ]
            },
            "attachment_risk": {
                "has_attachments": False,
                "attachment_risk_score": 0,
                "suspicious_attachment_count": 0
            },
        "attachment_results": [],
        "risk_level": "HIGH" if score_result['total_score'] + domain_analysis.get('risk_score', 0) > 50 else "MEDIUM" if score_result['total_score'] + domain_analysis.get('risk_score', 0) > 25 else "LOW",
    }
        
        analyses = [analysis]
        
        # Summary
        summary = {
            "total_emails_analyzed": 1,
            "high_risk_emails": 1 if analysis["risk_level"] == "HIGH" else 0,
            "medium_risk_emails": 1 if analysis["risk_level"] == "MEDIUM" else 0,
            "average_keyword_score": analysis["keyword_score"],
        }
        
        # Add ML prediction if available
        if ml_detector.is_trained:
            try:
                ml_prob = ml_detector.predict_probability(analysis)
                analysis["ml_prediction"] = {
                    "probability": ml_prob,
                    "prediction": "phishing" if ml_prob > 0.5 else "legitimate",
                    "confidence": "high" if abs(ml_prob - 0.5) > 0.3 else "medium"
                }
                
                rule_based_score = analysis["total_score"]
                ml_score = ml_prob * 100
                combined_score = (rule_based_score * 0.6) + (ml_score * 0.4)
                analysis["combined_score"] = combined_score
                analysis["enhanced_risk_level"] = (
                    "HIGH" if combined_score > 50 else
                    "MEDIUM" if combined_score > 25 else
                    "LOW"
                )
            except:
                pass

        return render_template("results.html", analyses=analyses, summary=summary)

    flash("Invalid file type. Only CSV/TXT allowed.")
    return redirect(url_for("home"))


# ------------------ SUMMARY FUNCTIONS ------------------

# Summarize attachment risks across all emails
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

# Summarize link risks across all emails
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

# Run the Flask app
if __name__ == "__main__":
    app.run(debug=True, port=8081)