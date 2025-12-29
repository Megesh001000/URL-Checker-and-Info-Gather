from __future__ import print_function
from pathlib import Path
import json
import logging
import smtplib 
import base64
import os
from email.message import EmailMessage

import environ
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from email.mime.text import MIMEText


from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
logger=logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# initialize environment

BASE_DIR=Path(__file__).resolve().parent.parent
env=environ.Env()
environ.Env.read_env(str(BASE_DIR / ".env"))


# environ.Env.read_env(os.path.join(BASE_DIR, ".env"))

TOKEN_PATH = os.path.join(BASE_DIR, "token.json")
CREDS_PATH = os.path.join(BASE_DIR, "credentials.json")
# Environment variable keys

GOOGLE_CLIENT_ID=env("GOOGLE_CLIENT_ID",default=None)
GOOGLE_CLIENT_SECRET=env("GOOGLE_CLIENT_SECRET",default=None)
GOOGLE_REFRESH_TOKEN=env("GOOGLE_REFRESH_TOKEN",default=None)
GOOGLE_OAUTH_USER=env("GOOGLE_OAUTH_USER",default=None)

EMAIL_HOST=env("EMAIL_HOST",default="smtp.gmail.com")
EMAIL_PORT=env.int("EMAIL_PORT",default=587)
EMAIL_USE_TLS=env.bool("EMAIL_USE_TLS",default=True)
EMAIL_HOST_USER=env("EMAIL_HOST_USER",default=None)
EMAIL_HOST_PASSWORD=env("EMAIL_HOST_PASSWORD",default=None)

TOKEN_JSON = BASE_DIR / "token.json"
GMAIL_SCOPES = ['https://mail.google.com/',
                'https://www.googleapis.com/auth/gmail.readonly', 
                'https://www.googleapis.com/auth/gmail.send',
                'https://www.googleapis.com/auth/gmail.modify']
# def get_email_service():
#     creds = None
#     if os.path.exists(TOKEN_PATH):
#         creds = Credentials.from_authorized_user_file(TOKEN_PATH,GMAIL_SCOPES)
#     else:
#         raise FileNotFoundError("token.json not found. Please generate it first using get_refresh_token.py")

#     # Refresh token if expired
#     if creds and creds.expired and creds.refresh_token:
#         creds.refresh(Request())

#     service = build("gmail", "v1", credentials=creds)
#     return service

# creating credential using token.json or refresh token
def _build_creds_from_token_or_env(scopes=None):
    scopes=scopes or GMAIL_SCOPES
    creds=None
    if TOKEN_JSON.exists():
        try:
            with open(TOKEN_JSON,'r') as f:
                info=json.load(f)
            creds=Credentials.from_authorized_user_info(info,scopes=GMAIL_SCOPES)
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
                with open(TOKEN_JSON,"w")as f:
                    f.write(creds.to_json())
            return creds
        except Exception as e:
            logger.warning("Failed to load/refresh creds from token.json: %s", e)

    # using  GOOGLE REFRESH TOKEN & GOG CLIENT ID & GOG CLENT SECRET
    if GOOGLE_REFRESH_TOKEN and GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
        try:
            creds=Credentials(
                token=None,
                refresh_token=GOOGLE_REFRESH_TOKEN,
                client_id=GOOGLE_CLIENT_ID,
                client_secret=GOOGLE_CLIENT_SECRET,
                token_uri="https://oauth2.googleapis.com/token",
                scopes=scopes,
            )
            creds.refresh(Request())

            with open(TOKEN_JSON, "w") as f:
                f.write(creds.to_json())
                logger.info("Created token.json from environment refresh token")
                return creds
        except Exception as e:
            logger.exception("Failed to create credentials from environment refresh token: %s", e)

    # 3) Nothing worked
    raise RuntimeError("No valid credentials available. Create token.json or set refresh token in .env.")


# SMTP XOAUTH2 for sending Mail
def generate_xoauth_token(username:str,access_token:str) -> str:
    """Generate base64 XOAUTH2 token for Gmail SMTP."""
    auth_string=f"user={username}\x01auth=Bearer {access_token}\x01\x01"
    return base64.b64encode(auth_string.encode("utf-8")).decode("utf-8")

def get_smtp_connection_oauth(timeout:int=60):
    creds=None
    try:
        creds=_build_creds_from_token_or_env(scopes=["https://mail.google.com/"])
    except Exception as e:
        logger.error("Unable to obtain creds for SMTP OAuth: %s", e)
        raise
    if not creds or not creds.token:
        raise RuntimeError("No access token available for SMTP OAuth.")

    

    access_token=creds.token
    username=GOOGLE_OAUTH_USER  or EMAIL_HOST_USER
    if not access_token:
         raise RuntimeError("Failed to obtain access token via refresh token.")

    # Connect to SMTP server
    smtp_conn=smtplib.SMTP(EMAIL_HOST,EMAIL_PORT,timeout=timeout)
    smtp_conn.ehlo()
    if EMAIL_USE_TLS:
        smtp_conn.starttls()
        smtp_conn.ehlo()
    try:
        # Build XOAUTH2 base64 string
        xoauth2_base64=generate_xoauth_token(username,access_token)

        # Send AUTH command
        auth_cmd="AUTH XOAUTH2 " +xoauth2_base64
        code,resp=smtp_conn.docmd(auth_cmd)

        if code!=235: # 235 means Authentication successful
            smtp_conn.quit()
            raise RuntimeError(f"XOAUTH2 authentication failed (code={code}, resp={resp})")
        
        logger.debug("Authenticated to SMTP with OAuth2 for %s", GOOGLE_OAUTH_USER)
        return smtp_conn
    except Exception:
        smtp_conn.quit()
        raise

def get_smtp_connection_smtp(timeout:int=60):
    """
    Create and return an authenticated smtplib.SMTP connection using username/password.
    Raises RuntimeError if SMTP credentials not configured or login fails.
    """
    if not (EMAIL_HOST_USER and EMAIL_HOST_PASSWORD):
        raise RuntimeError("Missing SMTP username/password environment variables.")
    smtp_conn=smtplib.SMTP(EMAIL_HOST,EMAIL_PORT,timeout=timeout)
    smtp_conn.ehlo()
    if EMAIL_USE_TLS:
        smtp_conn.starttls()
        smtp_conn.ehlo()

    try:
        smtp_conn.login(EMAIL_HOST_USER,EMAIL_HOST_PASSWORD)
      
    except Exception as e:
        smtp_conn.quit()
        logger.exception(f"SMTP login failed: {e}")
        raise
    logger.debug(f"Authenticstion  to SMTP  with usernname {EMAIL_HOST_USER}")
    return smtp_conn

# def send_email_via_smtp_conn(smtp_conn: smtplib.SMTP, subject: str, body: str, to_list, from_email=None):
#     """
#     Send an email using an already-authenticated smtplib.SMTP connection.
#     `to_list` should be a list of recipient emails.
#     """
#     if isinstance(to_list,str):
#         to_list=[to_list]

#     if not from_email:
#         # Prefer GOOGLE_OAUTH_USER then EMAIL_HOST_USER
#         from_email=GOOGLE_OAUTH_USER or EMAIL_HOST_USER


#     msg=EmailMessage()
#     msg["Subject"]=subject
#     msg["From"]=from_email or EMAIL_HOST_USER
#     msg["To"]=','.join(to_list)
#     msg.set_content(body)

#     smtp_conn.send_message(msg)
#     logger.debug(f"Email sent: subject={subject} from={from_email} to={to_list}")


def send_email_via_smtp_conn(
    smtp_conn: smtplib.SMTP,
    subject: str,
    body: str,
    to_list,
    from_email=None,
    html_body=None
):
    if isinstance(to_list, str):
        to_list = [to_list]

    if not from_email:
        from_email = GOOGLE_OAUTH_USER or EMAIL_HOST_USER

    # Correct MIME email (multipart alternative)
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = ", ".join(to_list)

    # Plain text part
    msg.attach(MIMEText(body, "plain"))

    # HTML part (this is the part Gmail requires!)
    if html_body:
        msg.attach(MIMEText(html_body, "html"))

    smtp_conn.sendmail(from_email, to_list, msg.as_string())
    logger.debug(f"Email sent: subject={subject} from={from_email} to={to_list}")


def send_email(subject:str,body:str,to_list,from_email:str=None,html_body=None,prefer_oauth:bool=True):
    """
    High-level helper that will:
    - try OAuth2 first (if prefer_oauth True and OAuth config present),
    - otherwise fallback to SMTP username/password.
    It opens the connection, sends the email, and quits the connection.
    """

    # Try OAuth path if credentials present and allowed
    last_exception = None

    oauth_configured=all([GOOGLE_CLIENT_ID,GOOGLE_CLIENT_SECRET,GOOGLE_REFRESH_TOKEN,GOOGLE_OAUTH_USER])
    smtp_configured=all([EMAIL_HOST_USER,EMAIL_HOST_PASSWORD])

    
    if prefer_oauth and oauth_configured:
        try:
            smtp_conn=get_smtp_connection_oauth()
            try:
                send_email_via_smtp_conn(smtp_conn,subject,body,to_list,from_email,html_body=html_body)
                return
            finally:
                smtp_conn.quit()
            
        except Exception as e:
            last_exception = e
            logger.warning(f"OAuth2 email send failed, will try SMTP fallback if available: {e}")
          

     # Fallback to SMTP username/passwor
    
    if smtp_configured:
        try:
            smtp_conn=get_smtp_connection_smtp()
            try:
                send_email_via_smtp_conn(smtp_conn,subject,body,to_list,from_email,html_body=html_body)
                return
            finally:
                smtp_conn.quit()
            
        except Exception as e:
            logger.exception(f"SMTP fallback failed:{e}")
            last_exception=last_exception or e


     # If we reach here, no method worked
    raise RuntimeError("Failed to send email (no valid authentication method succeeded).") from last_exception

# CLI test helpe

if __name__=="__main__":
    import sys


    if len(sys.argv) <3:
        print("Usage: python gmail_auth.py recipient@example.com \"Subject here\"")
        sys.exit(1)
    recipient = sys.argv[1]
    subject = sys.argv[2]
    body = "Test email from gmail_scanner.gmail_auth.py"

    try:
        send_email(subject, body, [recipient])
        print("Email sent successfully.")
    except Exception as exc:
        print("Failed to send email:", exc)