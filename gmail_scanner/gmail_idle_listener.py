import logging
import time
from imapclient import IMAPClient
from pathlib import Path
import environ


from gmail_scanner.gmail_parser import process_and_notify
from gmail_scanner.gmail_parser import get_oauth2_credentials, generate_xoauth2_string



logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)




# Load environment
BASE_DIR=Path(__file__).resolve().parent.parent
env=environ.Env()
environ.Env.read_env(BASE_DIR,'.env')

HOST = env("EMAIL_HOST", "imap.gmail.com")
PORT = env.int("EMAIL_PORT", 993)
USER = env("GOOGLE_OAUTH_USER")

# Connect to IMAP using OAuth2

def imap_connect_oauth():
    access_token=get_oauth2_credentials()
    auth_string=generate_xoauth2_string(USER, access_token)
    client=IMAPClient(HOST, port=PORT, ssl=True, timeout=30)
    client._raw_command('AUTHENTICATE XOAUTH2', auth_string)
    return client

# IMAP IDLE listener

def listen_idle():
    while True:
        client=None
        try:
            client=imap_connect_oauth()
            client.select_folder("INBOX")
            logger.info("Connected and selected INBOX, entering IDLE")

            # Enter IMAP IDLE
            with client.idle() as idle:
                for response in idle.wait(60*29):  # ~29 minutes max per IDLE
                       if response:
                        logger.info("New email detected via IMAP IDLE: %s", response)
                        # Fetch and process new emails
                        process_and_notify(limit=5)
                    # Continue idle loop


        except Exception as e:
            logger.exception("IMAP IDLE error, reconnecting: %s", e)
        finally:
            try:
                if client:
                    client.logout()
            except Exception:
                pass
        # Short sleep before reconnecting
        time.sleep(5)


if __name__ == "__main__":
    listen_idle()
