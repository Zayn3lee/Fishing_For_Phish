import os
import io
import zipfile
import base64
import re
from typing import List, Dict
from get_data import GetData

class AttachmentRiskAnalyzer:
    """
    A class for analyzing the risk level of email attachments based on their filename,
    extension, content, and context within the email (subject and body).
    """

    def __init__(self):
        # Define sets of file extensions considered risky
        self.high_risk_ext = {".exe", ".scr", ".bat", ".js", ".vbs", ".com", ".pif", ".cmd"}
        self.archive_ext = {".zip", ".rar", ".7z", ".tar", ".gz"}
        self.office_ext = {
            ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
            ".docm", ".xlsm", ".pptm"
        }

        # Regex patterns for filenames that may indicate malicious intent
        self.malicious_patterns = [
            r'malware', r'virus', r'trojan', r'keylogger', r'ransomware',
            r'payload', r'exploit', r'backdoor', r'rootkit', r'spyware',
            r'test.*malware', r'fake.*', r'phish.*', r'scam.*',
            r'crack', r'keygen', r'serial', r'loader', r'injector',
            r'bypass', r'hack.*tool', r'password.*steal', r'data.*steal'
        ]

        # Regex patterns for suspicious filenames (e.g., social engineering)
        self.suspicious_patterns = [
            r'urgent.*invoice', r'payment.*due', r'account.*suspended',
            r'security.*update', r'important.*document', r'confidential.*file',
            r'[0-9]{10,}\.exe',       # long random numbers + .exe
            r'document\d*\.exe',      # document1.exe
            r'photo\d*\.exe',         # photo123.exe
            r'\.pdf\.exe$',           # double extension
            r'\.jpg\.exe$',
            r'\.doc\.exe$'
        ]

    def analyze_attachment(self, filename: str, content: bytes, email_subject: str = "", email_body: str = "") -> Dict:
        """
        Analyze a single attachment's risk level.

        Args:
            filename (str): The name of the attachment file.
            content (bytes): The binary content of the file.
            email_subject (str): The subject of the email.
            email_body (str): The body text of the email.

        Returns:
            Dict: A dictionary containing risk assessment details.
        """
        ext = os.path.splitext(filename)[1].lower()
        risk_factors = []
        filename_lower = filename.lower()

        # Flag if file name has obvious malware keywords
        is_obviously_malicious = False
        for pattern in self.malicious_patterns:
            if re.search(pattern, filename_lower):
                risk_factors.append(f"CRITICAL: Filename contains malware indicators: '{filename}'")
                is_obviously_malicious = True
                break

        # Flag suspicious patterns if not already deemed malicious
        if not is_obviously_malicious:
            for pattern in self.suspicious_patterns:
                if re.search(pattern, filename_lower):
                    risk_factors.append(f"Suspicious filename pattern: {filename}")
                    break

        # Check for risky extensions
        if ext in self.high_risk_ext:
            if is_obviously_malicious:
                risk_factors.append("CRITICAL: High-risk executable extension with malicious name")
            else:
                risk_factors.append(f"High-risk extension: {ext}")

        # Analyze context (email subject + body) to detect mismatches
        subject_body = (email_subject or "") + " " + (email_body or "")
        subject_body_lower = subject_body.lower()

        financial_keywords = ["bank", "paypal", "payment", "invoice", "receipt", "account"]
        security_keywords = ["security", "urgent", "suspended", "verify", "confirm"]

        has_financial_context = any(kw in subject_body_lower for kw in financial_keywords)
        has_security_context = any(kw in subject_body_lower for kw in security_keywords)

        if (has_financial_context or has_security_context) and ext in self.high_risk_ext:
            risk_factors.append("CRITICAL: Context mismatch - financial/security email with executable attachment")

        # Analyze ZIP archives for malicious content
        if ext in self.archive_ext:
            try:
                if ext == ".zip":
                    with zipfile.ZipFile(io.BytesIO(content)) as z:
                        for name in z.namelist():
                            nested_ext = os.path.splitext(name)[1].lower()
                            nested_name = name.lower()

                            # Apply same analysis to files within archive
                            if any(re.search(pattern, nested_name) for pattern in self.malicious_patterns):
                                risk_factors.append(f"CRITICAL: Malicious file inside archive: {name}")
                            elif nested_ext in self.high_risk_ext:
                                risk_factors.append(f"High-risk executable inside archive: {name}")
                            elif any(re.search(pattern, nested_name) for pattern in self.suspicious_patterns):
                                risk_factors.append(f"Suspicious file inside archive: {name}")
            except Exception:
                risk_factors.append("Could not inspect archive contents - potentially corrupted or protected")

        # Basic macro detection in Office documents
        if ext in self.office_ext:
            try:
                text = content.decode(errors="ignore")
                macro_indicators = [
                    "vba", "vbproject", "sub autoopen", "auto_open", "workbook_open",
                    "document_open", "shell", "createobject", "wscript", "powershell"
                ]
                found_indicators = [i for i in macro_indicators if i in text.lower()]
                if found_indicators:
                    risk_factors.append(f"Possible macro detected: {', '.join(found_indicators[:3])}")
            except Exception:
                pass  # Do not crash on decoding issues

        # Final suspicion decision
        is_suspicious = len(risk_factors) > 0 or is_obviously_malicious

        return {
            "filename": filename,
            "extension": ext,
            "is_suspicious": is_suspicious,
            "risk_factors": risk_factors,
            "is_obviously_malicious": is_obviously_malicious
        }

    def analyze_attachments(self, attachments: List[Dict], email_subject: str = "", email_body: str = "") -> List[Dict]:
        """
        Analyze a list of attachments.

        Args:
            attachments (List[Dict]): List of attachment dictionaries with 'filename' and 'content'.
            email_subject (str): The email subject (for context).
            email_body (str): The email body (for context).

        Returns:
            List[Dict]: List of analysis results per attachment.
        """
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

    def parse_gmail_attachment_data(self, service, msg_id: str, attachments: List[Dict]) -> List[Dict]:
        """
        Download and decode Gmail attachments using Gmail API.

        Args:
            service: Authenticated Gmail API service instance.
            msg_id (str): ID of the Gmail message.
            attachments (List[Dict]): List of attachment metadata (from extract_gmail_attachments).

        Returns:
            List[Dict]: List of attachments with raw binary content.
        """
        parsed = []

        for att in attachments:
            try:
                if att.get("data"):
                    # Inline data (base64 encoded)
                    file_data = base64.urlsafe_b64decode(att["data"].encode("UTF-8"))
                elif att.get("attachment_id"):
                    # Fetch large file data via Gmail API
                    att_data = service.users().messages().attachments().get(
                        userId="me",
                        messageId=msg_id,
                        id=att["attachment_id"]
                    ).execute()
                    file_data = base64.urlsafe_b64decode(att_data["data"].encode("UTF-8"))
                else:
                    continue  # Skip if no data available
                parsed.append({
                    "filename": att["filename"],
                    "content": file_data
                })
            except Exception as e:
                print(f"Error parsing attachment {att.get('filename')}: {e}")

        return parsed
