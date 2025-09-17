import os
import io
import zipfile
import base64
from typing import List, Dict

class AttachmentRiskAnalyzer:
    def __init__(self):
        self.high_risk_ext = {".exe", ".scr", ".bat", ".js", ".vbs"}
        self.archive_ext = {".zip"}
        self.office_ext = {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".docm", ".xlsm", ".pptm"}

    def analyze_attachment(self, filename: str, content: bytes, email_subject: str = "", email_body: str = "") -> Dict:
        ext = os.path.splitext(filename)[1].lower()
        risk_factors = []

        if ext in self.high_risk_ext:
            risk_factors.append(f"High-risk extension: {ext}")

        subject_body = (email_subject or "") + " " + (email_body or "")
        subject_body_lower = subject_body.lower()
        if any(b in subject_body_lower for b in ["bank", "paypal", "account"]) and ext in self.high_risk_ext:
            risk_factors.append("Context mismatch: sensitive sender/context with risky attachment")

        if ext in self.archive_ext:
            try:
                with zipfile.ZipFile(io.BytesIO(content)) as z:
                    for n in z.namelist():
                        ne = os.path.splitext(n)[1].lower()
                        if ne in self.high_risk_ext:
                            risk_factors.append(f"Dangerous file inside archive: {n}")
            except Exception:
                risk_factors.append("Could not inspect ZIP contents")

        if ext in self.office_ext:
            try:
                text = content.decode(errors="ignore")
                if "vba" in text.lower() or "vbproject" in text.lower() or "sub autoopen" in text.lower():
                    risk_factors.append("Possible macro detected in Office document")
            except Exception:
                pass

        return {
            "filename": filename,
            "extension": ext,
            "is_suspicious": len(risk_factors) > 0,
            "risk_factors": risk_factors
        }

    def analyze_attachments(self, attachments: List[Dict], email_subject: str = "", email_body: str = "") -> List[Dict]:
        results = []
        for att in attachments:
            res = self.analyze_attachment(att.get("filename", ""), att.get("content", b""), email_subject, email_body)
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
