import re
import joblib
import math
import socket
import urllib.parse
from typing import  Dict,Any
from collections import Counter
from url_checker.detection.ml.features_extraction import extract_features,FeatureExtractor

import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "detection", "ml", "ml_models", "phiusiil_url_model.joblib")

try:
    model=joblib.load(MODEL_PATH)
    print("[INFO] ML model loaded successfully")
except Exception as e:
    model=None
    print(f"[WARNING] Could not load ML model: {e}")
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "bank", "account",
    "signin", "password", "confirm", "free", "bonus", "win"
]

SUSPICIOUS_TLDS = [".xyz", ".top", ".club", ".info", ".tk", ".ru", ".cn"]



def analyze_url(url:str,source:str='manual', attachment_name: str = None,attachment_type: str = None,attachment_size: int = None)->Dict[str,Any]:
    result = {"url": url, 
              "scan_source": source,
              "attachment_info":{
                  "attachment_name":attachment_name,
                  "attachment_type":attachment_type,
                  "attachment_size":attachment_size
            }if source=="attachment" else None
            }
    features_obj=FeatureExtractor(url)
    blacklist_result=features_obj.check_blacklist()
    features={
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
    "blacklist": blacklist_result,
    "raw_blacklist_result": blacklist_result,
    "blacklist_flag": blacklist_result.get("blacklisted", -1),
    "entropy": round(features_obj.domain_entropy(), 4),
    "ttl": features_obj.ttl_value(),
    "title_mismatch": features_obj.title_mismatch(),
    # "new_special_chars": features_obj.num_special_chars(),
    # "special_char_ratio": round(features_obj.special_char_ratio(), 4)
}
    result.update(features)
    # heuristic
    heuristic_score=(
        features["has_ip"]*10
        + (1 if features_obj.get_tld() in ["xyz", "tk", "top", "club", "info", "ru", "cn"] else 0) * 8        
        +features["suspicious_keywords"]*4
        +(0 if features["https"] else 5)
        +min(features["url_length"]/10,10)
    )
    # ml
    ml_score=0
    ml_label="Unknown"
    if model:
        try:
            ml_vectors=[
                features["url_length"],
                features["suspicious_keywords"],
                # features["special_chars"],
                features["dots"],
                features["has_ip"],
                1 if features["https"] else 0,
                features["entropy"],
                features["hyphens"],
                # features["special_char_ratio"]
            ]
            prediction=model.predict([ml_vectors])[0]
            prob=model.predict_proba([ml_vectors])[0][1]
            ml_score=prob*100
            ml_label="Phishing" if prediction==1 else "Legitimate"

        except Exception as e:
            print(f"[WARNING] ML prediction failed for {url}: {e}")
        
    combined_score=(heuristic_score+ml_score)/2
    if combined_score >= 75:
        label = "High Risk"
    elif combined_score >=40:
        label="Suspicious"
    else:
        label="Safe"
    
    result["ml_label"] = ml_label
    result["ml_score"] = round(ml_score, 2)
    result["heuristic_score"] = round(heuristic_score, 2)
    result["final_score"] = round(combined_score, 2)
    result["label"] = label

    return result
    
    
# Eg
if __name__ == "__main__":
    test_url = "https://secure-login-update.tk/bank"
    analysis = analyze_url(test_url, source="manual")
    print(analysis)