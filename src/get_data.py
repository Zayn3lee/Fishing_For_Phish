from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from typing import List, Dict, Union
import base64

# Gmail API scopes required
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

class GetData:
    """
    Utility class to interact with Gmail API and extract email data.
    """

    def gmail_service():
        """
        Authenticates the user using OAuth and returns a Gmail API service object.
        
        Returns:
            googleapiclient.discovery.Resource: Authenticated Gmail service instance
        """
        flow = InstalledAppFlow.from_client_secrets_file("client_secrets.json", SCOPES)
        creds = flow.run_local_server(port=8080)
        service = build("gmail", "v1", credentials=creds)
        return service

    def get_email_body(msg_data: Dict) -> str:
        """
        Extracts and decodes the email body text, skipping attachments.
        Handles both plain and multipart MIME types.
        
        Args:
            msg_data (dict): Gmail message payload
        
        Returns:
            str: The plain text content of the email body
        """
        def get_parts_text(parts: List[Dict]) -> Union[str, None]:
            """
            Recursively extract the text content from nested MIME parts.

            Args:
                parts (list): List of MIME parts

            Returns:
                str or None: Decoded text if found, otherwise None
            """
            for part in parts:
                filename = part.get("filename", "")
                body = part.get("body", {})

                # Skip attachments (they have filenames)
                if filename:
                    continue

                # Decode base64 data if present
                data = body.get("data")
                if data:
                    try:
                        decoded = base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")
                        return decoded
                    except Exception:
                        continue

                # Recurse into nested parts
                if "parts" in part:
                    nested = get_parts_text(part["parts"])
                    if nested:
                        return nested
            return None

        payload = msg_data.get("payload", {})

        # Case 1: Simple body text (not multipart)
        if "body" in payload and "data" in payload["body"]:
            try:
                return base64.urlsafe_b64decode(payload["body"]["data"]).decode("utf-8", errors="ignore")
            except Exception:
                pass

        # Case 2: Multipart email body
        if "parts" in payload:
            body_text = get_parts_text(payload["parts"])
            if body_text:
                return body_text

        return "No data found"

    def get_email_subject(msg_data: Dict) -> str:
        """
        Extract email subject from Gmail API message data
        
        Args:
            msg_data (dict): Gmail API message data

        Returns:
            str: Email subject or fallback message
        """
        headers = msg_data["payload"].get("headers", [])
        for header in headers:
            if header["name"].lower() == "subject":
                return header["value"]
        return "No subject found"

    def get_email_sender(msg_data: Dict) -> str:
        """
        Extract sender information from Gmail API message data
        
        Args:
            msg_data (dict): Gmail API message data

        Returns:
            str: Sender email address or fallback message
        """
        headers = msg_data["payload"].get("headers", [])
        for header in headers:
            if header["name"].lower() == "from":
                return header["value"]
            
        # Return if no header is found
        return "No header found"

    def get_gmail_attachments(msg_data: Dict) -> Union[List[Dict], str]:
        """
        Extract attachment metadata from a Gmail API message payload.

        Args:
            msg_data (dict): Gmail message dictionary (as returned by Gmail API).

        Returns:
            List[Dict]: List of attachment metadata dicts with filename, ID, and base64 inline data.
        """
        attachments = []

        def parse_parts(parts: List[Dict]):
            """
            Recursively searches for attachments in MIME parts.

            Args:
                parts (list): List of MIME parts
            """
            for part in parts:
                filename = part.get("filename")
                body = part.get("body", {})
                if filename:
                    attachments.append({
                        "filename": filename,
                        "attachment_id": body.get("attachmentId"),
                        "data": body.get("data")  # Inline small attachments
                    })
                # Recursively handle nested multiparts
                if "parts" in part:
                    parse_parts(part["parts"])

        payload = msg_data.get("payload", {})
        if "parts" in payload:
            parse_parts(payload["parts"])
            return attachments
        
        # Return if no attachments found
        return "No attachments found"