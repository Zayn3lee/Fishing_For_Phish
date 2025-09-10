import sys
import os

# Add the path where get_data.py is located
sys.path.append(r'c:\Users\Admin\Documents\GitHub\Fishing_For_Phish\src')

# ===== METHOD 1: Import and call function to get data =====
print("=== METHOD 1: Import function and call it ===")
from get_data import fetch_emails 
bodies = fetch_emails()
for body in bodies:
    print("This is the body", body)  

# ===== METHOD 9: Conditional import and usage =====
print("\n=== METHOD 9: Conditional usage ===")
import get_data

def get_email_summary():
    try:
        # Try to get fresh data
        bodies = get_data.fetch_emails()
        
        if bodies:
            return f"Successfully fetched {len(bodies)} emails"
        else:
            return "No emails found"
            
    except Exception as e:
        return f"Error: {str(e)}"

summary = get_email_summary()
print(f"Summary: {summary}")