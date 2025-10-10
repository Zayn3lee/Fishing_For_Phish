# Import necessary Flask modules and utilities
from flask import Flask, render_template, request, redirect, url_for, flash
from email_integration import PhishingEmailAnalyzer                 # Rule-based Gmail analyzer
from email_checker_manual import SimpleEmailAnalyzer                # Local rule-based file analyzer
from ml_classifier import MLPhishingDetector                        # Machine learning classifier
import os
from werkzeug.utils import secure_filename                          # For safely handling uploaded file names

# Configuration for allowed upload types
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"csv", "txt", "zip"}  # zip for ML training data

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
    return render_template("home.html", ml_trained=ml_detector.is_trained)

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

                    # Count ML high risk
                    if ml_prob > 0.5:
                        ml_high_risk_count += 1

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

# Route to handle uploaded files (TXT/CSV/ZIP) for manual analysis
@app.route("/upload", methods=["POST"])
def upload():
    # Check for file
    if "file" not in request.files:
        flash("No file part")
        return redirect(url_for("home"))

    # Check if file name is empty
    file = request.files["file"]
    if file.filename == "":
        flash("No selected file")
        return redirect(url_for("home"))

    # If file and file name exists
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
        file.save(filepath)

        # Call class for functions
        rule_analyzer = SimpleEmailAnalyzer()

        # Analyze uploaded file(s)
        results = rule_analyzer.analyze_files([filepath])

        # Set analysis objects 
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
                "attachment_risk": {
                    "has_attachments": False,
                    "attachment_risk_score": 0,
                    "suspicious_attachment_count": 0
                },
                "attachment_results": [],
                "category_scores": {}
            }

            # If ML model is trained, add ML prediction
            if ml_detector.is_trained:
                try:
                    # Construct mock analysis input for ML model
                    mock_analysis = {
                        'subject': '',
                        'body': '',
                        'body_length': 0,
                        'subject_length': 0,
                        'total_score': result.spam_score,
                        'keyword_score': result.spam_score * 0.5,
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

                    # Combine rule-based and ML predictions
                    combined_score = (result.spam_score * 0.6) + (ml_probability * 100 * 0.4)
                    analysis["combined_score"] = combined_score
                    analysis["enhanced_risk_level"] = (
                        "HIGH" if combined_score > 50 else
                        "MEDIUM" if combined_score > 25 else
                        "LOW"
                    )

                except Exception as e:
                    analysis["ml_prediction"] = {"error": str(e)}

            analyses.append(analysis)

        # Summary generation
        summary = {
            "total_emails_analyzed": len(analyses),
            "high_risk_emails": sum(1 for a in analyses if a["risk_level"] == "HIGH"),
            "medium_risk_emails": 0,
            "average_keyword_score": round(sum(a["total_score"] for a in analyses) / max(1, len(analyses)), 2),
            "ml_model_active": ml_detector.is_trained
        }

        if ml_detector.is_trained:
            summary["ml_high_risk_emails"] = sum(1 for a in analyses if a.get("ml_prediction", {}).get("prediction") == "phishing")
            summary["enhanced_high_risk_emails"] = sum(1 for a in analyses if a.get("enhanced_risk_level") == "HIGH")

        # Render ML model results to HTMl
        return render_template("results.html", analyses=analyses, summary=summary)

    flash("Invalid file type. Only CSV/TXT/ZIP allowed.")
    return redirect(url_for("home"))

# Route to display ML training UI
# Route to display ML training UI
@app.route("/ml_train")  # GET route
def ml_train_page():
    ''' ML training HTML page'''
    return render_template("ml_train.html")

# Route to handle ML model training
@app.route("/ml_train", methods=["POST"])  # POST route
def ml_train():
    ''' Training ML model '''
    training_type = request.form.get('training_type', 'file')

    if training_type == 'file':
        if "file" not in request.files:
            flash("No file selected")
            return redirect(url_for("ml_train_page"))

        files = request.files.getlist("file")  # Get multiple files
        
        if not files or files[0].filename == "":
            flash("No selected file")
            return redirect(url_for("ml_train_page"))

        # Check all files are CSV
        for file in files:
            if not file.filename.endswith('.csv'):
                flash(f"Invalid file: {file.filename}. Only CSV files are allowed.")
                return redirect(url_for("ml_train_page"))

        # Save and train on all files
        try:
            all_data = []
            for file in files:
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
                file.save(filepath)
                
                print(f"Training from CSV file: {filename}")
            
            # Train on the first file (or merge all files if you want)
            first_file = os.path.join(app.config["UPLOAD_FOLDER"], secure_filename(files[0].filename))
            results = ml_detector.train_from_csv(first_file)
            
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

# Route to get ML model status (for frontend AJAX or debug)
@app.route("/ml_status")
def ml_status():
    """Check ML model status"""
    return {
        "is_trained": ml_detector.is_trained,
        "model_path": ml_detector.model_path,
        "model_exists": os.path.exists(ml_detector.model_path)
    }


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