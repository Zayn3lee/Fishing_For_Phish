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
        
        # Add attachment statistics to summary
        attachment_stats = calculate_attachment_summary(analyses)
        summary.update(attachment_stats)
        
        # NEW: Add link statistics to summary
        link_stats = calculate_link_summary(analyses)
        summary.update(link_stats)
        
        return render_template("results.html", analyses=analyses, summary=summary)

    except Exception as e:
        return f"Error: {str(e)}" 

def calculate_attachment_summary(analyses):
    """Calculate attachment-related statistics for the summary"""
    total_attachments = 0
    total_suspicious_attachments = 0
    emails_with_attachments = 0
    high_risk_attachment_emails = 0
    
    for analysis in analyses:
        attachment_risk = analysis.get('attachment_risk', {})
        if attachment_risk.get('has_attachments'):
            emails_with_attachments += 1
            total_attachments += attachment_risk.get('total_attachments', 0)
            total_suspicious_attachments += attachment_risk.get('suspicious_attachment_count', 0)
            
            if attachment_risk.get('attachment_risk_level') == 'HIGH':
                high_risk_attachment_emails += 1
    
    return {
        'emails_with_attachments': emails_with_attachments,
        'total_attachments': total_attachments,
        'total_suspicious_attachments': total_suspicious_attachments,
        'high_risk_attachment_emails': high_risk_attachment_emails
    }

def calculate_link_summary(analyses):
    """NEW: Calculate link-related statistics for the summary"""
    total_links = 0
    total_suspicious_links = 0
    emails_with_links = 0
    high_risk_link_emails = 0
    sender_domain_issues = 0
    url_shortener_count = 0
    typosquatting_count = 0
    
    for analysis in analyses:
        link_risk = analysis.get('link_risk', {})
        if link_risk.get('has_links'):
            emails_with_links += 1
            total_links += link_risk.get('total_links', 0)
            total_suspicious_links += link_risk.get('suspicious_link_count', 0)
            
            if link_risk.get('link_risk_level') == 'HIGH':
                high_risk_link_emails += 1
            
            if link_risk.get('sender_suspicious'):
                sender_domain_issues += 1
            
            # Analyze specific threat types
            for detail in link_risk.get('link_details', []):
                description = detail.get('description', '').lower()
                if 'shortener' in description:
                    url_shortener_count += 1
                elif 'similar to' in description:
                    typosquatting_count += 1
    
    return {
        'emails_with_links': emails_with_links,
        'total_links_analyzed': total_links,
        'total_suspicious_links_found': total_suspicious_links,
        'high_risk_link_emails': high_risk_link_emails,
        'sender_domain_issues': sender_domain_issues,
        'url_shortener_detections': url_shortener_count,
        'typosquatting_detections': typosquatting_count
    }

if __name__ == "__main__":
    app.run(debug=True, port=8081)