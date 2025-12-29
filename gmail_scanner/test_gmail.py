# FOR TESTING PURPOSE DURING DEVELOPMENT

from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials

# Load token.json for authentication
creds = Credentials.from_authorized_user_file("gmail_scanner/token.json", ["https://mail.google.com/"])

# Build Gmail service
service = build("gmail", "v1", credentials=creds)

# Fetch your profile (just a safe test)
profile = service.users().getProfile(userId="me").execute()
print("Gmail access successful!")
print("Email address:", profile["emailAddress"])
