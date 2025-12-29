import re
import json
from typing import Dict, Any, List

from detection.ml.features_extraction import FeatureExtractor



# URL extraction helper

def extract_urls_from_text(text: str) -> List[str]:
    """Extracts URLs from plaintext using regex."""
    url_regex = r'https?://[^\s)]+'
    return re.findall(url_regex, text)



# Main Gmail Scanning Function

def analyze_email(sender: str, subject: str, body: str) -> Dict[str, Any]:
    """
    Extract URLs from Gmail content and analyze each URL using FeatureExtractor.
    Returns a full JSON-like dictionary with URL-level and email-level details.
    """

    urls = extract_urls_from_text(body)

    # If no URLs found
    if not urls:
        return {
            "email_sender": sender,
            "email_subject": subject,
            "total_urls": 0,
            "url_results": [],
            "message": "No URLs found in the email body."
        }

    url_results = []

    for url in urls:
        try:
            features_obj = FeatureExtractor(url)
        except Exception as e:
            url_results.append({
                "url": url,
                "error": f"FeatureExtractor initialization failed: {str(e)}"
            })
            continue

        # Blacklist check
        blacklist_result = features_obj.check_blacklist()

        # Build final URL report dictionary
        result = {
            "url": url,
            "url_features": {
                "url_length": features_obj.get_url_length(),
                "domain_length": features_obj.get_domain_length(),
                "dots": features_obj.count_dots(),
                "hyphens": features_obj.count_hyphens(),
                "has_ip": features_obj.has_ip(),
                "suspicious_keywords": features_obj.count_suspicious_keywords(),
                "has_at": features_obj.has_at_symbol(),
                "https": features_obj.has_https(),
                "domain_age": features_obj.get_domain_age(),
                "domain_expiry": features_obj.get_domain_expiry(),
                "dns_record": features_obj.dns_records_exist(),
                "ip_geolocation": features_obj.get_ip_geolocation(),
                "iframe": features_obj.has_iframe(),
                "input_tags": features_obj.count_input_tags(),
                "favicon_check": features_obj.check_favicon(),
                "external_scripts_ratio": round(features_obj.external_scripts_ratio(), 4),
                "ssl": features_obj.has_ssl_certificate(),
                "ssl_issuer": features_obj.check_certificate_issuer(),
                "ssl_issuer_known": features_obj.ssl_issuer_known(),
                "entropy": round(features_obj.domain_entropy(), 4),
                "ttl": features_obj.ttl_value(),
                "title_mismatch": features_obj.title_mismatch(),
                # "new_special_chars": features_obj.num_special_chars(),
               
                
            },

            "blacklist_info": {
                "raw": blacklist_result,
                "blacklist_flag": blacklist_result.get("blacklisted", -1),
                "blacklist_message": blacklist_result.get("extra", "")
            }
        }

        # Add to list
        url_results.append(result)

    
    # Final JSON for the entire email
    
    email_report = {
        "email_sender": sender,
        "email_subject": subject,
        "total_urls": len(urls),
        "url_results": url_results
    }

    return email_report



# For direct testing

if __name__ == "__main__":
    sample_sender = "example@gmail.com"
    sample_subject = "Security update"
    sample_body = """
    Hello user, your account needs verification.
    Please click the link: https://suspicious-example.com/login?session=123
    """

    result = analyze_email(sample_sender, sample_subject, sample_body)
    print(json.dumps(result, indent=4))
