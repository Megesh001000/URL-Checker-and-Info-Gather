# FOR TESTING PURPOSE DURING DEVELOPMENT

import asyncio
import logging
import os
import sys
import django


# Set up Python path for imports

# Add project root (outer 'url_checker') to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


# Set Django settings and setup

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "url_checker.url_checker.settings")
django.setup()


# Imports after Django setup

from gmail_scanner.gmail_parser import connect_imap, fetch_email_async, parse_email, extract_urls_from_email_body
from gmail_scanner.gmail_scanner import analyze_email
from gmail_scanner.gmail_classifier import classify_email
from gmail_scanner.gmail_auth import send_email
from detection.models import ProcessedEmail
from django.conf import settings
from asgiref.sync import sync_to_async
from detection.ml.features_extraction import FeatureExtractor
from django.conf import settings


# Logging setup

logger = logging.getLogger(__name__)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)


# Email processing function

async def process_single_email(eid, msg):
    parsed = parse_email(msg)
    urls = extract_urls_from_email_body(parsed)
    logger.info(f"Processing email ID {eid}: '{parsed['subject']}'. Found {len(urls)} URL(s).")

    all_url_features = []
    is_phishing_detected = False

    for url in urls:
        # Extract features for each URL
        feature_extractor = FeatureExtractor(url)
        features = feature_extractor.run_all()
        feature_extractor = FeatureExtractor(url)

        # Basic 25 features
        features = feature_extractor.run_all()

        # IP & Location
        ip_address = feature_extractor.resolve_ip()
        ip_location = feature_extractor.get_ip_geolocation()

        print(f"URL: {url}\n")
        print("Extracted Features:")
        for key, value in features.items():
            print(f"  {key}: {value}")

        print("IP Address:", ip_address)
        print("Location:", ip_location)

        print(f"URL: {url}\n")
        print("Extracted Features:")
        for key, value in features.items():
            print(f"  {key}: {value}")
        all_url_features.append({"url": url, "features": features})

        # Check blacklist flag for phishing detection
        if features.get("blacklist_flag", -1) == 1:
            is_phishing_detected = True

    # Prepare email dictionary for classifier
    email_dict = {
        "id": eid,
        "msg_from": parsed["from"],
        "msg_to": settings.GOOGLE_OAUTH_USER,
        "subject": parsed["subject"],
        "body": (parsed.get("plain_body") or "") + (parsed.get("html_body") or ""),
        "urls": [f["url"] for f in all_url_features],
        "url_features": all_url_features,
        "attachments": []  # Extend if you handle attachments
    }

    classification = classify_email(email_dict)

    # Send notification if phishing detected
    if is_phishing_detected or classification["label"] in ["High Risk", "Suspicious"]:
        subject = f"PHISHING ALERT: {parsed['subject']}"
        body = f"Email from {parsed['from']}\nDetected phishing URLs:\n" + "\n".join([f["url"] for f in all_url_features if f["features"].get("blacklist_flag") == 1])
        try:
            send_email(subject, body, [settings.GOOGLE_OAUTH_USER])
            logger.info(f"Notification sent for email ID {eid}")
        except Exception as e:
            logger.exception(f"Failed to send alert email: {e}")

    # Mark email as processed
    await sync_to_async(ProcessedEmail.objects.create)(
        email_id=eid,
        subject=parsed["subject"],
        sender=parsed["from"],
        has_urls=bool(urls),
        is_phishing=is_phishing_detected
    )
    logger.info(f"Email ID {eid} marked as processed.")


# Main function to fetch emails

async def main(limit=5):
    mail = connect_imap()
    try:
        emails = await fetch_email_async(mail, limit=limit)
        if not emails:
            logger.info("No new emails found.")
            return
        tasks = [process_single_email(eid, msg) for eid, msg in emails]
        await asyncio.gather(*tasks)
    finally:
        try:
            mail.logout()
        except Exception:
            pass


# Entry point

if __name__ == "__main__":
    asyncio.run(main(limit=10))
  