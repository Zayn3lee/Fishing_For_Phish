from flask import Flask, render_template
from email_integration import PhishingEmailAnalyzer

app = Flask(__name__)
analyzer = PhishingEmailAnalyzer()

@app.route("/")
def analyze_emails():
    try:
        analyzer.initialize_service()

        analyses = analyzer.analyze_emails(max_results=5)

        summary = analyzer.get_integration_summary(analyses)
        
        return render_template("results.html", analyses=analyses, summary=summary)

    except Exception as e:
        return f"Error: {str(e)}" 


if __name__ == "__main__":
    app.run(debug=True)
