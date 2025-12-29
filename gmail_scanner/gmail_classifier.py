
# gmail_classifier.py TEMPORARY WITHOUT ML 
import logging

logger = logging.getLogger(__name__)

def classify_email(email_dict):
    """
    Rule-based classification until full ML pipeline is ready.
    
    email_dict = {
        "id": ...,
        "msg_from": ...,
        "msg_to": ...,
        "subject": ...,
        "body": ...,
        "urls": [...],
        "url_features": [{"url":..., "features": {...}}]
    }
    """

    url_features = email_dict.get("url_features", [])

    if not url_features:
        return {
            "label": "Safe",
            "confidence": 1.0,
            "reason": "No URLs found"
        }

    #  RULES -
    phishing_flags = 0

    for entry in url_features:
        features = entry.get("features", {})

        # Rule 1 — Blacklist
        if features.get("blacklist_flag", -1) == 1:
            phishing_flags += 1

        # Rule 2 — Domain age suspicious
        if features.get("domain_age", 9999) != -1 and features["domain_age"] < 30:
            phishing_flags += 1

        # Rule 3 — HTTPS missing
        if not features.get("https", False):
            phishing_flags += 1

        # Rule 4 — Entropy very high (random-looking URL)
        if features.get("entropy", 0) > 4.2:
            phishing_flags += 1

        # Rule 5 — DNS record missing
        if features.get("dns_record") is False:
            phishing_flags += 1

    #  LABEL DECISION -
    if phishing_flags >= 3:
        label = "High Risk"
    elif phishing_flags == 2:
        label = "Suspicious"
    else:
        label = "Safe"

    return {
        "label": label,
        "confidence": 1.0,
        "phishing_flags": phishing_flags,
        "reason": "Rule-based classification (temporary – ML disabled)"
    }
