'''
This file extracts data from manually inserted emails into our program isntead of from the Gmail service
'''

from email import policy
from email.parser import BytesParser

class GetDataManual:
    # For now, function will get raw email from console.
    # Future, function will get email from the web server where the user can manually input the email
    def get_multiline_input():
        print("Paste your raw email and end with a single line 'EOF'\n")
        lines = []
        while True:
            line = input()
            if line.strip().upper() == "EOF":
                break
            lines.append(line)
        return "\n".join(lines)

    def extract_email_info_from_txt(raw_email:str):
        # Convert raw email string to bytes
        raw_bytes = raw_email.encode('utf-8')

        # Parse the email using the email default policy
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

        # Extract Key fields
        email_info = {
            "From": msg["From"],
            "To": msg["To"],
            "Subject": msg["Subject"],
            "Date": msg["Date"],
            "Message-ID": msg ["Message-ID"],
            "In-Reply-To": msg["In-Reply-To"],
            "References": msg["References"],
            "Content-Type": msg.get_content_type(),
            "Body": msg.get_content()
        }

        # Extract body depending if it's HTML or plain text
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    email_info["Body"] = part.get_content()
                    break

        return email_info