from flask import Flask, render_template, request, redirect, url_for, flash
from email_integration import PhishingEmailAnalyzer
import os
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"csv", "txt"}

app = Flask(__name__)
app.secret_key = "super_secret_key"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
analyzer = PhishingEmailAnalyzer()

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/gmail_login")
def gmail_login():
    try:
        analyzer.initialize_service()
        analyses = analyzer.analyze_emails(max_results=5)

        summary = analyzer.get_integration_summary(analyses)
        summary.update(calculate_attachment_summary(analyses))
        summary.update(calculate_link_summary(analyses))

        return render_template("results.html", analyses=analyses, summary=summary)
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

        analyses = []  
        summary = {"message": f"File '{filename}' uploaded successfully."}

        return render_template("results.html", analyses=analyses, summary=summary)

    flash("Invalid file type. Only CSV/TXT allowed.")
    return redirect(url_for("home"))

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
