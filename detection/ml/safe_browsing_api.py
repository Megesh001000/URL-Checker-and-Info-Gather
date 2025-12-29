# safe_browsing_api.py
import requests
import json
from django.conf import settings
from requests.exceptions import RequestException
from typing import Dict, Any, Optional

# IMPORTANT: Retrieve the necessary CLIENT_ID and CLIENT_VERSION!
API_KEY = getattr(settings, 'GOOGLE_SAFE_BROWSING_API_KEY', None)
CLIENT_ID = getattr(settings, 'SAFE_BROWSING_CLIENT_ID', 'DefaultMLApp') 
CLIENT_VERSION = getattr(settings, 'SAFE_BROWSING_CLIENT_VERSION', '1.0')

API_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
DEFAULT_THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]

def check_url_safety(url_to_check: str) -> Dict[str, Any] | None:
    """
    Checks a single URL against the Google Safe Browsing Lookup API (v4).
    """
    if not API_KEY:
        print("ERROR: GOOGLE_SAFE_BROWSING_API_KEY is not set.")
        return None

    full_url = f"{API_ENDPOINT}?key={API_KEY}"

    # THIS IS WHERE CLIENTINFO IS MANDATORY!
    payload = {
        "client": {
            "clientId": CLIENT_ID, 
            "clientVersion": CLIENT_VERSION
        },
        "threatInfo": {
            "threatTypes": DEFAULT_THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url_to_check}]
        }
    }

    headers = {'Content-Type': 'application/json'}

    try:
        response = requests.post(full_url, headers=headers, data=json.dumps(payload), timeout=5)
        response.raise_for_status() 
        data = response.json()
        
        # Returns the full response if matches are found, or an empty dict if safe.
        return data if data.get('matches') else {}

    except RequestException as e:
        print(f"Safe Browsing API Error for {url_to_check}: {e}")
        return None
    