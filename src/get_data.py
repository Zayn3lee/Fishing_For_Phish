from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import base64

# Gmail API scopes required
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

class GetData:
    # Function to login user into their email via localhost:8080
    def gmail_service():
        creds = None
        flow = InstalledAppFlow.from_client_secrets_file("client_secrets.json", SCOPES)
        creds = flow.run_local_server(port=8080)
        service = build("gmail", "v1", credentials=creds)
        return service

    # Extracts and decodes email
    def get_email_body(msg_data):
        """
        Extract and decode email body
        
        Args:
            msg_data: Gmail API message data
            
        Returns:
            str: Decoded email body
        """
        payload = msg_data["payload"]
        
        # Case 1: Simple email (text/plain utf-8 directly in body)
        if "body" in payload and "data" in payload["body"]:
            data = payload["body"]["data"]
            decoded = base64.urlsafe_b64decode(data).decode("utf-8")
            return decoded
        
        # Case 2: Multipart email (text/plain + HTML parts)
        parts = payload.get("parts", [])
        for part in parts:
            if part["mimeType"] in ["text/plain", "text/html"]:
                data = part["body"]["data"]
                decoded = base64.urlsafe_b64decode(data).decode("utf-8")
                return decoded
        
        # return if no data found
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