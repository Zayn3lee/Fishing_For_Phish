from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import base64

# Gmail API scopes required
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

# Global variables that can be imported
service = None
messages = []
email_bodies = []

class GetData:
    # Function to login user into their email via localhost:8080
    def gmail_service():
        creds = None
        flow = InstalledAppFlow.from_client_secrets_file("client_secrets.json", SCOPES)
        creds = flow.run_local_server(port=8080)
        service = build("gmail", "v1", credentials=creds)
        return service

service = gmail_service()
results = service.users().messages().list(userId="me", maxResults=3).execute()
messages = results.get("messages", [])


# Extracts and decodes email
def get_email_body(msg_data):
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
    
    # return nothing if somehow email has neither cases
    return "Somehow neither cases has matched??"


# Iterate through all emails extracted
for msg in messages:
    msg_data = service.users().messages().get(userId="me", id=msg["id"], format="full").execute()
    
    body = get_email_body(msg_data)
    print("This is the body", body)