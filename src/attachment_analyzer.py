import os
import io
import zipfile
import base64
import re
from typing import List, Dict

class AttachmentRiskAnalyzer:
    def __init__(self):
        self.high_risk_ext = {".exe", ".scr", ".bat", ".js", ".vbs", ".com", ".pif", ".cmd"}
        self.archive_ext = {".zip", ".rar", ".7z", ".tar", ".gz"}
        self.office_ext = {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".docm", ".xlsm", ".pptm"}
        
        # Enhanced: Patterns for obviously malicious filenames
        self.malicious_patterns = [
            r'malware', r'virus', r'trojan', r'keylogger', r'ransomware',
            r'payload', r'exploit', r'backdoor', r'rootkit', r'spyware',
            r'test.*malware', r'fake.*', r'phish.*', r'scam.*',
            r'crack', r'keygen', r'serial', r'loader', r'injector',
            r'bypass', r'hack.*tool', r'password.*steal', r'data.*steal'
        ]
        
        # Suspicious filename patterns
        self.suspicious_patterns = [
            r'urgent.*invoice', r'payment.*due', r'account.*suspended',
            r'security.*update', r'important.*document', r'confidential.*file',
            r'[0-9]{10,}\.exe',  # Random number executable
            r'document\d*\.exe',  # Document.exe type files
            r'photo\d*\.exe',     # Photo.exe type files
            r'\.pdf\.exe$',       # Double extension
            r'\.jpg\.exe$',       # Double extension
            r'\.doc\.exe$'        # Double extension
        ]

    def analyze_attachment(self, filename: str, content: bytes, email_subject: str = "", email_body: str = "") -> Dict:
        ext = os.path.splitext(filename)[1].lower()
        risk_factors = []
        filename_lower = filename.lower()
        
        # Check for obviously malicious filenames FIRST
        is_obviously_malicious = False
        for pattern in self.malicious_patterns:
            if re.search(pattern, filename_lower):
                risk_factors.append(f"CRITICAL: Filename contains malware indicators: '{filename}'")
                is_obviously_malicious = True
                break
        
        # Check for suspicious filename patterns
        if not is_obviously_malicious:
            for pattern in self.suspicious_patterns:
                if re.search(pattern, filename_lower):
                    risk_factors.append(f"Suspicious filename pattern: {filename}")
                    break
        
        # Check file extension risks
        if ext in self.high_risk_ext:
            if is_obviously_malicious:
                risk_factors.append(f"CRITICAL: High-risk executable extension with malicious name")
            else:
                risk_factors.append(f"High-risk extension: {ext}")

        # Context mismatch analysis (enhanced)
        subject_body = (email_subject or "") + " " + (email_body or "")
        subject_body_lower = subject_body.lower()
        
        # More sophisticated context analysis
        financial_keywords = ["bank", "paypal", "payment", "invoice", "receipt", "account"]
        security_keywords = ["security", "urgent", "suspended", "verify", "confirm"]
        
        has_financial_context = any(keyword in subject_body_lower for keyword in financial_keywords)
        has_security_context = any(keyword in subject_body_lower for keyword in security_keywords)
        
        if (has_financial_context or has_security_context) and ext in self.high_risk_ext:
            risk_factors.append("CRITICAL: Context mismatch - financial/security email with executable attachment")

        # Archive analysis
        if ext in self.archive_ext:
            try:
                if ext == ".zip":
                    with zipfile.ZipFile(io.BytesIO(content)) as z:
                        for name in z.namelist():
                            nested_ext = os.path.splitext(name)[1].lower()
                            nested_name = name.lower()
                            
                            # Check for malicious files inside archive
                            if any(re.search(pattern, nested_name) for pattern in self.malicious_patterns):
                                risk_factors.append(f"CRITICAL: Malicious file inside archive: {name}")
                            elif nested_ext in self.high_risk_ext:
                                risk_factors.append(f"High-risk executable inside archive: {name}")
                            elif any(re.search(pattern, nested_name) for pattern in self.suspicious_patterns):
                                risk_factors.append(f"Suspicious file inside archive: {name}")
            except Exception:
                risk_factors.append("Could not inspect archive contents - potentially corrupted or protected")

        # Office document macro detection (enhanced)
        if ext in self.office_ext:
            try:
                text = content.decode(errors="ignore")
                macro_indicators = [
                    "vba", "vbproject", "sub autoopen", "auto_open", "workbook_open",
                    "document_open", "shell", "createobject", "wscript", "powershell"
                ]
                
                found_indicators = [indicator for indicator in macro_indicators if indicator in text.lower()]
                if found_indicators:
                    risk_factors.append(f"Possible macro detected: {', '.join(found_indicators[:3])}")
            except Exception:
                pass
        
        # Enhanced suspicious scoring
        is_suspicious = len(risk_factors) > 0 or is_obviously_malicious
        
        # Override for obvious malware - always mark as suspicious
        if is_obviously_malicious:
            is_suspicious = True

        return {
            "filename": filename,
            "extension": ext,
            "is_suspicious": is_suspicious,
            "risk_factors": risk_factors,
            "is_obviously_malicious": is_obviously_malicious
        }

    def analyze_attachments(self, attachments: List[Dict], email_subject: str = "", email_body: str = "") -> List[Dict]:
        results = []
        for att in attachments:
            res = self.analyze_attachment(
                att.get("filename", ""), 
                att.get("content", b""), 
                email_subject, 
                email_body
            )
            results.append(res)
        return results

    # Recursive function to get all attachments (handles nested multiparts)
    def extract_gmail_attachments(self, msg_data) -> List[Dict]:
        attachments = []

        def parse_parts(parts):
            for part in parts:
                filename = part.get("filename")
                body = part.get("body", {})
                if filename:
                    attachments.append({
                        "filename": filename,
                        "attachment_id": body.get("attachmentId"),
                        "data": body.get("data")  # inline small files
                    })
                if "parts" in part:
                    parse_parts(part["parts"])

        payload = msg_data.get("payload", {})
        if "parts" in payload:
            parse_parts(payload["parts"])
        return attachments

    def parse_gmail_attachment_data(self, service, msg_id: str, attachments: List[Dict]) -> List[Dict]:
        parsed = []
        for att in attachments:
            try:
                if att.get("data"):  # inline content
                    file_data = base64.urlsafe_b64decode(att["data"].encode("UTF-8"))
                elif att.get("attachment_id"):  # must fetch from Gmail API
                    att_data = service.users().messages().attachments().get(
                        userId="me",
                        messageId=msg_id,
                        id=att["attachment_id"]
                    ).execute()
                    file_data = base64.urlsafe_b64decode(att_data["data"].encode("UTF-8"))
                else:
                    continue  # skip if no data
                parsed.append({"filename": att["filename"], "content": file_data})
            except Exception as e:
                print(f"Error parsing attachment {att.get('filename')}: {e}")
        return parsed