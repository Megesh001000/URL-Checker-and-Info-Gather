import os
import logging
import base64
import email
from email.header import  decode_header
from email.message import EmailMessage
from pathlib import Path
import re 
import environ
import imaplib
import asyncio
import aiohttp
import ssl
import django
import sys
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from .gmail_auth import send_email,get_smtp_connection_oauth,get_smtp_connection_smtp,generate_xoauth_token
from detection.ml.ml_utils import predict_email_urls
import sys
import os

import pickle 
from dotenv import load_dotenv
load_dotenv()

# Add project root to Python path so imports work

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# # Set Django settings module
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "url_checker.settings")
django.setup()
from django.conf import settings
print(" Django initialized with settings:", settings.INSTALLED_APPS)
from detection.models import ProcessedEmail




token_path = os.getenv("GOOGLE_TOKEN_PATH", os.path.join(os.path.dirname(__file__), "token.json"))

BASE_DIR=Path(__file__).resolve().parent.parent
env=environ.Env()
env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
environ.Env.read_env(env_path) 





# Gmail OAuth/IMAP settings

GOOGLE_CLIENT_ID = env("GOOGLE_CLIENT_ID", default=None)
GOOGLE_CLIENT_SECRET = env("GOOGLE_CLIENT_SECRET", default=None)
GOOGLE_REFRESH_TOKEN = env("GOOGLE_REFRESH_TOKEN", default=None)
GOOGLE_OAUTH_USER = env("GOOGLE_OAUTH_USER", default=None)
TOKEN_PATH = env("GOOGLE_TOKEN_PATH", default="token.json") 
IMAP_HOST = env("IMAP_HOST", default="imap.gmail.com")
IMAP_PORT = env.int("IMAP_PORT", default=993)


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

handler = logging.StreamHandler()  # or logging.FileHandler('yourfile.log')
handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
logger.addHandler(handler)

SCOPES = ['https://mail.google.com/']
def load_credentials():
    """Load credentials from token.json and refresh if expired."""
    if not os.path.exists(TOKEN_PATH):
        raise RuntimeError(f"Token file not found at {TOKEN_PATH}. Run OAuth flow first.")

    creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)
    if creds.expired and creds.refresh_token:
        logger.info("Access token expired. Attempting to refresh")
        creds.refresh(Request())
        # Save refreshed token back to token.json
        creds_dict = {
            "token": creds.token,
            "refresh_token": creds.refresh_token,
            "token_uri": creds.token_uri,
            "client_id": creds.client_id,
            "client_secret": creds.client_secret,
            "scopes": creds.scopes,
        }
        import json
        with open(TOKEN_PATH, "w") as f:
            json.dump(creds_dict, f)
        logger.info(" Access token refreshed and saved to token.json")
    return creds
def get_oauth2_credentials():
    """Return a current Gmail OAuth access token for IMAP clients."""
    creds = load_credentials()
    if not creds.token:
        raise RuntimeError("No Gmail OAuth access token is available.")
    return creds.token
# def get_oauth2_credentials():
#     if not all([GOOGLE_CLIENT_ID,GOOGLE_CLIENT_SECRET,GOOGLE_OAUTH_USER,GOOGLE_REFRESH_TOKEN]):
#         raise RuntimeError("Missing OAuth2 environment variables for Gmail.")

#     creds=Credentials(
#         token=None,
#         refresh_token=GOOGLE_REFRESH_TOKEN,
#         client_id=GOOGLE_CLIENT_ID,
#         client_secret=GOOGLE_CLIENT_SECRET,
#         token_uri="https://oauth2.googleapis.com/token",
#     )

#     creds.refresh(Request())
#     return creds.token

def generate_xoauth2_string(username: str, access_token: str) -> str:
    # username must be your email address (string)
    auth_string = f"user={username}\x01auth=Bearer {access_token}\x01\x01"
    return auth_string.encode("utf-8")
    # return base64.b64encode(auth_string.encode()).decode()

   


def connect_imap():
    """Connect to Gmail IMAP using OAuth2."""
    try:
        creds = load_credentials()
        access_token = creds.token
        auth_string = generate_xoauth2_string(GOOGLE_OAUTH_USER, access_token)

        context = ssl.create_default_context()
        mail = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, ssl_context=context)
        typ,data=mail.authenticate("XOAUTH2", lambda x: auth_string)
        if typ != 'OK':
            raise Exception(f"Authentication failed: {data}")

        logger.info(" Connected to Gmail IMAP using OAuth2 successfully.")
        return mail

    except imaplib.IMAP4.error as e:
        logger.error(f"IMAP authentication failed: {e}")
        raise

    except ssl.SSLError as e:
        logger.error(f"SSL connection failed: {e}")
        raise

    except Exception as e:
        logger.exception(f"Unexpected error during IMAP connection: {e}")
        raise


# Fetching Emails

def  fetch_email(mail,folder='INBOX',limit=3,unseen_only=False):
    mail.select(folder)
    search_criteria = "UNSEEN" if unseen_only else "ALL"
    result,data=mail.search(None, search_criteria)
    print("Email Fetched")
    print(result)

    if result != "OK":
        raise RuntimeError(f"Failed to fetch emails from {folder}")
    email_ids=data[0].split()
    latest_ids=email_ids[-limit:]  # Get latest emails
    messages=[]

    for eid in latest_ids:
        eid_str=eid.decode()
        if ProcessedEmail.objects.filter(email_id=eid_str).exists():
            logger.debug(f"Skipping already processed email ID: {eid_str}")
            continue
        result,msg_data=mail.fetch(eid, "(RFC822)")

        if result != "OK":
            logger.warning(f"Failed to fetch email id {eid}")
            continue
        msg=email.message_from_bytes(msg_data[
            0][1])
        messages.append((eid_str,msg))

    return messages

async def fetch_email_async(mail, folder='INBOX', limit=3, unseen_only=False):
    return await asyncio.to_thread(fetch_email, mail, folder, limit, unseen_only)

# Parse Email Content

def parse_email(msg):
    subject,encoding=decode_header(msg.get("Subject") or "")[0]
    if  isinstance(subject,bytes):
        subject=subject.decode(encoding or "utf-8",errors="ignore")
    from_=msg.get("From")
    plain_body=""
    html_body=""
    if msg.is_multipart():
        for part in msg.walk():
            ctype=part.get_content_type()
            if ctype=="text/plain":    # checking for any plain text
                try:
                    plain_body+=part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="ignore")
                except:
                    plain_body+=part.get_payload(decode=True).decode(errors="ignore")
            elif ctype=="text/html":
                try:
                    html_body+=part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="ignore")
                except:
                    html_body+=part.get_payload(decode=True).decode(errors="ignore")
    else:
        body=(msg.get_payload(decode=True) or b"").decode(errors="ignore")
        if msg.get_content_type() == "text/html":
            html_body = body
        else:
            plain_body = body
    print("email parsed")
    return {"subject": subject, "from": from_, "html_body": html_body,"plain_body":plain_body}
        

# Extract URLs

# def extract_urls_from_email_body(parsed_data:str):
#     all_urls=set()    
#     plain_url_pattern=re.compile(r"https?://[^\s>\]\"']+"r"https?://[^[^\s)>\]]]+")
#     all_urls.update(plain_url_pattern.findall(parsed_data["plain_body"]))

#     html_link_pattern=html_link_pattern = re.compile(r'href=["\'](https?://[^"\']+)["\']', re.IGNORECASE)
#     all_urls.update(html_link_pattern.findall(parsed_data["html_body"]))
#     return list(all_urls)
def extract_urls_from_email_body(parsed_data: dict):
    all_urls = set()

    # Plain text URLs 
    plain_body = parsed_data.get("plain_body", "")
    plain_url_pattern = re.compile(
        r"https?://[^\s<>\]\)\"']+",
        re.IGNORECASE
    )
    all_urls.update(plain_url_pattern.findall(plain_body))

    # --- HTML URLs ---
    html_body = parsed_data.get("html_body", "")
    html_link_pattern = re.compile(
        r'href=["\'](https?://[^"\']+)["\']',
        re.IGNORECASE
    )
    all_urls.update(html_link_pattern.findall(html_body))
    print("url extracted")
    return list(all_urls)



# Process Emails & Send Notifications

# def process_and_notify(limit=5):
#     mail=connect_imap()
#     try:
#         logger.info(f"Fetching up to {limit} unseen emails...")
#         emails=fetch_email(mail,limit=limit)
#         if not emails:
#             logger.info("No new unseen emails found to process.")
#             return
#         for eid,msg in emails:
#             parsed=parse_email(msg)
#             urls=extract_urls_from_email_body(parsed)
#             logger.info(f"Processing email ID {eid}: '{parsed['subject']}'. Found {len(urls)} potential URL(s).")

#             is_phishing_detected = False


#             if urls:
#                 scan_result=predict_email_urls(urls,use_tool=True)
#                 if scan_result and any(isinstance(url_result,dict)and url_result.get('is_malicious',False) for url_result in scan_result):
#                         is_phishing_detected=True
#                 if is_phishing_detected:
#                     subject = f" PHISHING ALERT: URLs detected in email: {parsed['subject']}"
#                     body = f"From: {parsed['from']}\n\nThe following URL(s) were flagged as potentially malicious:\n" + "\n".join(urls)
#                 # subject = f"Phishing URLs detected in email: {parsed['subject']}"
#                 # body = f"From: {parsed['from']}\n\nURLs:\n" + "\n".join(urls)

#                    # Send email using your gmail_auth.py logic
#                 try:
#                     send_email(subject,body,to_list=[GOOGLE_OAUTH_USER])
                    
#                     logger.info(f"Notification sent for email: {parsed['subject']}")
#                 except Exception as e:
#                     logger.exception(f"Failed to send notification email: {e}")
                    
#             # Mark as processed
#             ProcessedEmail.objects.create(
#                 email_id=eid,
#                 subject=parsed["subject"],
#                 sender=parsed["from"],
#                 has_urls=bool(urls),
#                 is_phishing=is_phishing_detected
#             )
#             logger.info(f"Email ID {eid} marked as processed.")
#     finally:
#         try:
#             mail.logout()
#         except:
#              pass
        
def  process_and_notify(limit=1):
    mail=connect_imap()
    try:
        logger.info(f"Fetching up to {limit} unseen emails...")
        emails=fetch_email(mail,limit=limit)
        if not emails:
            logger.info("No new unseen emails found to process.")
            return
        

        for eid,msg in emails:
            parsed=parse_email(msg)
            urls=extract_urls_from_email_body(parsed)
            logger.info(f"Processing email ID {eid}: '{parsed['subject']}'. Found {len(urls)} potential URL(s).")
            is_phishing_detected=False
            detailed_url_info=[]

            if urls:
                scan_response=predict_email_urls(urls,use_tool=True)
                scan_result=scan_response.get("results", []) if isinstance(scan_response, dict) else []
                for idx,url_result in enumerate(scan_result):
                    url_info = {"url": urls[idx]}
                    if isinstance(url_result,dict):
                        url_info.update(url_result)
                    detailed_url_info.append(url_info)
                
                if any(url_result.get('is_malicious', False) for url_result in detailed_url_info):
                    is_phishing_detected = True
                
                if is_phishing_detected:
                    subject = f"PHISHING ALERT: URLs detected in email: {parsed['subject']}"


                    body_lines=[
                        f"From: {parsed['from']}",
                        f"Subject: {parsed['subject']}",
                        "",
                        "The following URL(s) were flagged as potentially malicious:\n"
                    ]
                    
                    for info in detailed_url_info:
                        if info.get('is_malicious',False):
                            ip=info.get("ip_address","N/A")
                            location = info.get('ip_geolocation', {})
                            country = location.get('country', 'Unknown')
                            region = location.get('region', 'Unknown')
                            city = location.get('city', 'Unknown')
                            org = location.get('org', 'Unknown')
                            ssl_issuer = info.get('ssl_issuer', 'Unknown')
                            entropy = info.get('entropy', 'N/A')

                            body_lines.append(
                                f"URL: {info['url']}\n"
                                f"IP: {ip}\n"
                                f"Location: {city}, {region}, {country}, Org: {org}\n"
                                f"SSL Issuer: {ssl_issuer}\n"
                                f"Entropy: {entropy}\n"
                               
                            )
                    
                    body = "\n".join(body_lines)

                    try:
                        send_email(subject, body, to_list=[GOOGLE_OAUTH_USER])
                        logger.info(f"Notification sent for email: {parsed['subject']}")
                    except Exception as e:
                        logger.exception(f"Failed to send notification email: {e}")

        ProcessedEmail.objects.create(
                    email_id=eid,
                    subject=parsed["subject"],
                    sender=parsed["from"],
                    has_urls=bool(urls),
                    is_phishing=is_phishing_detected
                )
        logger.info(f"Email ID {eid} marked as processed.")

    finally:
        try:
            mail.logout()
        except Exception:
            pass




# Async version of process_and_notify
# async def process_and_notify_async(limit=5):
#     mail = connect_imap()
#     try:
#         emails = await fetch_email_async(mail, limit=limit)
#         logger.info(f"Fetching up to {limit} unseen emails (Async)...")
#         if not emails:
#             logger.info("No new unseen emails found to process (Async).")
#             return
#         processing_tasks=[]
#         for eid, msg in emails:
#             processing_tasks.append(process_and_notify_async(eid,msg))
#         await asyncio.gather(*processing_tasks)

#             parsed = parse_email(msg)
#             urls = extract_urls_from_email_body(parsed["body"])
#             if urls:
#                 subject = f"Phishing URLs detected in email: {parsed['subject']}"
#                 body = f"From: {parsed['from']}\n\nURLs:\n" + "\n".join(urls)
#                 await asyncio.to_thread(send_email, subject, body, [GOOGLE_OAUTH_USER])
#                 logger.info(f"Notification sent for email: {parsed['subject']}")
#             await asyncio.to_thread(
#                 ProcessedEmail.objects.create,
#                 email_id=eid,
#                 subject=["subject"],
#                 sender=parsed["from"]
#             )
        
#     finally:
#         try:
#             mail.logout()
#         except:
#             pass

# async def process_single_email_async(eid,msg):
#     parsed=parse_email(msg)
#     urls=extract_urls_from_email_body(parsed)
#     logger.info(f"Processing email ID {eid}: '{parsed['subject']}'. Found {len(urls)} potential URL(s).")
#     is_phishing_detected=False
#     if urls:
#         scan_results=await asyncio.to_thread(predict_email_urls,urls,use_tool=True)
#         if scan_results and any(isinstance(url_result,dict)and url_result.get("is_mmalicious",False) for url_result in scan_results):
#             is_phishing_detected=True 
#         if is_phishing_detected:
#             subject = f" PHISHING ALERT: URLs detected in email: {parsed['subject']}"
#             body = f"From: {parsed['from']}\n\nThe following URL(s) were flagged as potentially malicious:\n" + "\n".join(urls)

#         try:
#             await asyncio.to_thread(send_email,subject,body,[GOOGLE_OAUTH_USER])
#             logger.warning(f"PHISHING ALERT Notification sent for email: {parsed['subject']}")
#         except Exception as e:
#                 logger.exception(f"Failed to send notification email: {e}")
#         else:
#             logger.info(f"No phishing URLs detected in email: {parsed['subject']}")
#     await asyncio.to_thread(
#         ProcessedEmail.objects.create,
#         email_id=eid,
#         subject=parsed["subject"],
#         sender=parsed["from"],
#         has_urls=bool(urls),
#         is_phishing=is_phishing_detected
#     )
#     logger.info(f"Email ID {eid} marked as processed.")
async def process_and_notify_async(limit=3):
    mail = connect_imap()
    try:
        logger.info(f"Fetching up to {limit} unseen emails (Async)...")
        emails = await fetch_email_async(mail, limit=limit)
        if not emails:
            logger.info("No new unseen emails found to process (Async).")
            return

        processing_tasks = []
        for eid, msg in emails:
            processing_tasks.append(process_single_email_async(eid, msg))  # call the single email async processor

        # Run all email processing concurrently
        await asyncio.gather(*processing_tasks)

    finally:
        try:
            mail.logout()
        except Exception:
            pass


async def process_single_email_async(eid, msg):
    parsed = parse_email(msg)
    urls = extract_urls_from_email_body(parsed)
    logger.info(f"Processing email ID {eid}: '{parsed['subject']}'. Found {len(urls)} potential URL(s).")
    
    is_phishing_detected = False
    detailed_url_info = []

    if urls:
        logger.info(f"URLs found: {urls}")
        logger.info("Starting predict_email_urls...")
        # Predict URLs using async-safe to_thread
        scan_results = await asyncio.to_thread(predict_email_urls, urls, use_tool=True)

        # Collect detailed info per URL
        for idx, url_result in enumerate(scan_results):
            url_info = {"url": urls[idx]}
            if isinstance(url_result, dict):
                url_info.update(url_result)
            detailed_url_info.append(url_info)

        # Check if any URL is malicious
        if any(url_result.get("is_malicious", False) for url_result in detailed_url_info):
            is_phishing_detected = True

        if is_phishing_detected:
            subject = f"PHISHING ALERT: URLs detected in email: {parsed['subject']}"

            # Build detailed body with IP, location, SSL, entropy
            body_lines = [
                f"From: {parsed['from']}",
                f"Subject: {parsed['subject']}",
                "",
                "The following URL(s) were flagged as potentially malicious:\n"
            ]

            for info in detailed_url_info:
                if info.get("is_malicious", False):
                    ip = info.get("ip_address", "N/A")
                    location = info.get("ip_geolocation", {})
                    country = location.get("country", "Unknown")
                    region = location.get("region", "Unknown")
                    city = location.get("city", "Unknown")
                    org = location.get("org", "Unknown")
                    ssl_issuer = info.get("ssl_issuer", "Unknown")
                    entropy = info.get("entropy", "N/A")

                    body_lines.append(
                        f"URL: {info['url']}\n"
                        f"IP: {ip}\n"
                        f"Location: {city}, {region}, {country}, Org: {org}\n"
                        f"SSL Issuer: {ssl_issuer}\n"
                        f"Entropy: {entropy}\n"
                        "-------------------------------"
                    )

            body = "\n".join(body_lines)

            # Send email alert asynchronously
            try:
                await asyncio.to_thread(send_email, subject, body, [GOOGLE_OAUTH_USER])
                logger.warning(f"PHISHING ALERT Notification sent for email: {parsed['subject']}")
            except Exception as e:
                logger.exception(f"Failed to send notification email: {e}")
        else:
            logger.info(f"No phishing URLs detected in email: {parsed['subject']}")

    # Mark email as processed in DB asynchronously
    await asyncio.to_thread(
        ProcessedEmail.objects.create,
        email_id=eid,
        subject=parsed["subject"],
        sender=parsed["from"],
        has_urls=bool(urls),
        is_phishing=is_phishing_detected
    )
    logger.info(f"Email ID {eid} marked as processed.")


if __name__ == "__main__":
    process_and_notify(limit=5)
    process_single_email_async(limit=5)
    print("Email Sentt successfully")

