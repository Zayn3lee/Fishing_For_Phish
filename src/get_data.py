from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import base64

# Gmail API scopes required
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

class GetData:
    # Function to login user into their email via localhost:8080
    def gmail_service():
        flow = InstalledAppFlow.from_client_secrets_file("client_secrets.json", SCOPES)
        creds = flow.run_local_server(port=8080)
        service = build("gmail", "v1", credentials=creds)
        return service

    def get_email_body(msg_data):
        """
        Extract and decode email body (recursive for multipart emails)
        Skips attachments.
        """
        def get_parts_text(parts):
            for part in parts:
                mime_type = part.get("mimeType", "")
                filename = part.get("filename", "")
                body = part.get("body", {})

                # Skip attachments
                if filename:
                    continue

                # If data exists, decode it
                data = body.get("data")
                if data:
                    try:
                        decoded = base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")
                        return decoded
                    except Exception:
                        continue

                # Recurse if there are nested parts
                if "parts" in part:
                    nested = get_parts_text(part["parts"])
                    if nested:
                        return nested
            return None

        payload = msg_data.get("payload", {})

        # Case 1: simple body at top-level
        if "body" in payload and "data" in payload["body"]:
            try:
                return base64.urlsafe_b64decode(payload["body"]["data"]).decode("utf-8", errors="ignore")
            except Exception:
                pass

        # Case 2: multipart
        if "parts" in payload:
            body_text = get_parts_text(payload["parts"])
            if body_text:
                return body_text

        return "No data found"

    def get_email_subject(msg_data):
        """
        Extract email subject from Gmail API message data
        
        Args:
            msg_data: Gmail API message data
            
        Returns:
            str: Email subject line
        """
        headers = msg_data["payload"].get("headers", [])
        for header in headers:
            if header["name"].lower() == "subject":
                return header["value"]
        
        # No subject found
        return "No subject found"  

    def get_email_sender(msg_data):
        """
        Extract sender information from Gmail API message data
        
        Args:
            msg_data: Gmail API message data
            
        Returns:
            str: Sender email address
        """
        headers = msg_data["payload"].get("headers", [])
        for header in headers:
            if header["name"].lower() == "from":
                return header["value"]
            
        # Return if no header is found
        return "No header found"
