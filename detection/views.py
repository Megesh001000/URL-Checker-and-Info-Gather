# detection/views.py


import email

import hashlib
from html import escape
import json
import os
import re
import socket
import ssl
import time
import traceback
from django.core.cache import cache

from html import escape

from urllib.parse import urlparse
from typing import List, Dict, Any
from django.conf import settings
from django.db import IntegrityError
import requests
import whois
import datetime
import asyncio
import os
import logging
from google_auth_oauthlib.flow import Flow
from django.http import HttpResponse,JsonResponse,HttpRequest
from dotenv import load_dotenv
from django.utils.timezone import now

from django.http import JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.core.paginator import Paginator
from django.db.models import Count
from .models import URLHistory, URLScan, UploadFile, DatasetUpload, ProcessedEmail,UnifiedScan
from .forms import UploadFileForm
from django.views.decorators.csrf import csrf_exempt
# from gmail_scanner.gmail_parser import process_and_notify, extract_urls_from_email_body, parse_email, fetch_email, connect_imap
from gmail_scanner.gmail_auth import send_email

from detection.ml.features_extraction import FeatureExtractor

from django.views.decorators.http import require_http_methods
from gmail_scanner.gmail_parser import process_and_notify_async, fetch_email_async, parse_email, extract_urls_from_email_body, connect_imap

from detection.ml.ml_utils import predict_url, predict_batch,predict_email_urls
from detection.ml.features_extraction import  extract_features,FeatureExtractor
from django.shortcuts import render
from detection.ml.features_extraction import FeatureExtractor

from attachment_scanner.attachment_scanner import AttachmentScanner, extract_urls_from_attachment_bytes

logger=logging.getLogger(__name__)
# Home & URL Result Handling

VT_REQUEST_TIMEOUT = 10
VT_POLL_ATTEMPTS = 3
def home(request):
    return render(request, 'detection/home.html')




# Dashboard
def dashboard(request): 
    safe_count = URLScan.objects.filter(status="Safe").count() 
    phishing_count = URLScan.objects.filter(status="Phishing").count() 
    total_scans = URLScan.objects.count()
    # Daily Scans
    scan_days = URLScan.objects.extra({'date_only': "date(timestamp)"}).values('date_only').annotate(count=Count('id')).order_by('date_only')
    recent_scans = URLScan.objects.order_by('-timestamp')[:10] 
    context = { "safe_count": safe_count,
                "phishing_count": phishing_count,
                "total_scans": total_scans,
                "scan_days": scan_days,
                "recent_scans": recent_scans} 
    return render(request, 'detection/dashboard.html', context)

# URL Check History
def history(request):
    all_history = URLHistory.objects.order_by('-timestamp')
    paginator = Paginator(all_history, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'detection/history.html', {"history": page_obj})


# Recheck & Delete
# def recheck(request, entry_id):
#     entry = get_object_or_404(URLHistory, id=entry_id)
#     return redirect(request,'detection/home.html')  # Or implement recheck logic with threat recalculation
def recheck(request, entry_id):
    entry = get_object_or_404(URLHistory, pk=entry_id)
    return redirect(f"/?url={entry.url}")


def delete_entry(request, entry_id):
    entry = get_object_or_404(URLHistory, id=entry_id)
    entry.delete()
    return redirect('history')

    return render(request, 'detection/attachment.html', {"form": form, "result": result})




ML_THRESHOLD = 0.7

def dummy_ml_score(features: dict) -> float:
    """
    Fake ML model scoring.
    Output: 0.0 to 1.0
    """
    score = 0.0

    score += min(features.get("suspicious_keywords", 0) * 0.10, 0.40)

    if features.get("domain_age", 999) != -1 and features.get("domain_age") < 30:
        score += 0.25

    if features.get("blacklist", {}).get("blacklisted") == 1:
        return 0.95

    if not features.get("https", 1):
        score += 0.10

    if features.get("external_scripts_ratio", 0) > 0.50:
        score += 0.15

    return round(min(score, 1.0), 3)





def normalize_feature_output(raw: dict, default_url: str = "Unknown") -> dict:
    #  clean func
    def clean(v):
        if v in [None, "", "unknown", "Unknown", {}, []]:
            return "N/A"
        if v == -1:
            return "N/A"
        return v

    out = {}
    out["url"] = raw.get("url", default_url)

    #  lexxical
    out["url_length"] = clean(raw.get("url_length"))
    out["domain_length"] = clean(raw.get("domain_length"))
    out["dots"] = clean(raw.get("dots"))
    out["hyphens"] = clean(raw.get("hyphens"))
    out["has_ip"] = clean(raw.get("has_ip"))
    out["suspicious_keywords"] = clean(raw.get("suspicious_keywords"))
    out["entropy"] = clean(raw.get("entropy"))
    out["tld"] = clean(raw.get("tld"))
    out["https"] = bool(raw.get("https", 0))

    #  WHOIS / DNS 
    age = raw.get("domain_age")
    if isinstance(age, int) and age >= 0:
        out["domain_age"] = f"{age} days"
    else:
        out["domain_age"] = "N/A"

    exp = raw.get("domain_expiry")
    if exp is None or exp == -1:
        out["domain_expiry"] = "N/A"
    else:
        out["domain_expiry"] = exp

    out["dns_record"] = clean(raw.get("dns_record"))
    out["ttl"] = clean(raw.get("ttl"))

    #  Network
    ip = raw.get("ip_address") or raw.get("ip")
    out["ip_address"] = clean(ip)

    geo = raw.get("ip_geolocation", {}) or {}
    out["ip_geolocation"] = {
        "country": clean(geo.get("country")),
        "region": clean(geo.get("region")),
        "city": clean(geo.get("city")),
        "latitude": clean(geo.get("latitude")),
        "longitude": clean(geo.get("longitude")),
        "org": clean(geo.get("org")),
    }

    #  SSL 
    out["ssl_issuer"] = clean(raw.get("ssl_issuer"))
    out["ssl_valid"] = clean(raw.get("ssl"))
    out["ssl_expiry"] = clean(raw.get("ssl_expiry"))

    #  HTML 
    out["forms"] = clean(raw.get("input_tags"))
    out["iframes"] = clean(raw.get("iframe"))
    out["js_includes"] = clean(raw.get("external_scripts_ratio"))
    out["redirect_ratio"] = clean(raw.get("title_mismatch"))

    #  Blacklist
    bl = raw.get("blacklist", {}) or {}

    out["blacklist"] = {
        "blacklisted": bl.get("blacklisted", 0),
        "source": bl.get("source", "N/A"),
        "details": bl.get("details", "N/A"),
    }

    #  ML 
    score = raw.get("ml_score", 0)
    out["ml_score"] = score

    is_blacklisted = out["blacklist"]["blacklisted"] == 1
    is_ml = score is not None and score >= ML_THRESHOLD

    out["is_malicious"] = is_blacklisted or is_ml

    return out

def get_virustotal_url_report(url):
    headers = {"x-apikey": VT_API_KEY}
    encoded = requests.utils.quote(url, safe='')
    resp = requests.get(
        f"https://www.virustotal.com/api/v3/urls/{encoded}",
        headers=headers,
        timeout=10
    )
    if resp.status_code != 200:
        return {"vt_error": resp.text}

    data = resp.json().get("data", {}).get("attributes", {})
    return {
        "detected": data.get("last_analysis_stats", {}).get("malicious", 0),
        "suspicious": data.get("last_analysis_stats", {}).get("suspicious", 0),
        "harmless": data.get("last_analysis_stats", {}).get("harmless", 0),
        "undetected": data.get("last_analysis_stats", {}).get("undetected", 0),
        "reputation": data.get("reputation", 0),
        "final_url": data.get("last_final_url", url),
        "vendors": data.get("results", {})
    }

def result(request: HttpRequest) -> HttpResponse:
    url = request.GET.get("url", "").strip()

    if not url:
        return render(request, "detection/result.html", {"error": "No URL provided"})

    try:
        # Extract full features
        try:
            raw = FeatureExtractor(url).run_all()
        except Exception as e:
            raw = {"url": url, "error": str(e)}

        raw["url"] = url

        # Prefer the trained model; retain the heuristic only as a fallback.
        prediction = predict_url(url)
        raw["ml_score"] = prediction.get("final_score") if isinstance(prediction, dict) else None
        if raw["ml_score"] is None:
            raw["ml_score"] = dummy_ml_score(raw)

        #  Norm 
        norm = normalize_feature_output(raw, default_url=url)
        domain_age_days = "N/A"
        domain_expiry_date = "N/A"

        try:
            w = whois.whois(norm["url"])
            creation_date = w.creation_date

            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if isinstance(creation_date, datetime.datetime):
                domain_age_days = (datetime.datetime.now() - creation_date).days

            expiry = w.expiration_date
            if isinstance(expiry, list):
                expiry = expiry[0]
            if isinstance(expiry, datetime.datetime):
                domain_expiry_date = expiry.strftime("%Y-%m-%d")

        except Exception:
            pass

        norm["domain_age"] = f"{domain_age_days} days" if domain_age_days != "N/A" else "N/A"
        norm["domain_expiry"] = domain_expiry_date

        # VIRUSTOTAL URL SCAN
        VT_KEY = settings.VT_API_KEY
        vt_headers = {"x-apikey": VT_KEY} if VT_KEY else None

        vt_malicious = vt_suspicious = vt_harmless = 0
        reputation = 0
        last_final_url = url
        vendor_results = []
        vt_error = None

        try:
            if not vt_headers:
                raise RuntimeError("VirusTotal is not configured")
            # Submit URL
            submit = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=vt_headers,
                data={"url": url}, timeout=VT_REQUEST_TIMEOUT
            )

            if submit.status_code == 200:
                analysis_id = submit.json()["data"]["id"]

                # Poll until completed
                vt_report = None
                for _ in range(VT_POLL_ATTEMPTS):
                    poll = requests.get(
                        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                        headers=vt_headers, timeout=VT_REQUEST_TIMEOUT
                    )
                    js = poll.json()
                    if js["data"]["attributes"]["status"] == "completed":
                        vt_report = js
                        break
                    time.sleep(1)

                if vt_report:
                    stats = vt_report["data"]["attributes"]["stats"]
                    vt_malicious = stats.get("malicious", 0)
                    vt_suspicious = stats.get("suspicious", 0)
                    vt_harmless = stats.get("harmless", 0)

                    # Vendor results
                    vendors_raw = vt_report["data"]["attributes"].get("results", {})
                    vendor_results = [
                        {
                            "engine": eng,
                            "category": res.get("category", "Unknown"),
                            "method": res.get("method", "Unknown"),
                            "result": res.get("result", "None"),
                        }
                        for eng, res in vendors_raw.items()
                    ]

                    # Reputation & redirects
                    encoded = requests.utils.quote(url, safe="")
                    info = requests.get(
                        f"https://www.virustotal.com/api/v3/urls/{encoded}",
                        headers=vt_headers, timeout=VT_REQUEST_TIMEOUT
                    )

                    if info.status_code == 200:
                        info_data = info.json()["data"]["attributes"]
                        reputation = info_data.get("reputation", 0)
                        last_final_url = info_data.get("last_final_url", url)
            else:
                vt_error = f"Submission failed: {submit.status_code}"
        except Exception as e:
            vt_error = str(e)

        # Add VT outputs
        norm["vt_malicious"] = vt_malicious
        norm["vt_suspicious"] = vt_suspicious
        norm["vt_harmless"] = vt_harmless
        norm["vt_reputation"] = reputation
        norm["vt_final_url"] = last_final_url


        # FINAL DECISION
        is_mal = norm["is_malicious"]
        decision = "Phishing" if is_mal else "Safe"
        css_class = "text-danger" if is_mal else "text-success"

        context = {
            "url": url,
            "features": norm,
            "raw": raw,   # raw full JSON
            "decision": decision,
            "css_class": css_class,
            'vendors':vendor_results,
            'vt_results':vt_error
            
        }
        URLHistory.objects.create(
            url=url,
            result=decision,
        )
        URLScan.objects.create(
            url=url,
            status=decision,
            threat_scores=int(norm["ml_score"]*100)
        )
        # save unifiedscan 
        UnifiedScan.objects.create(
            module="URL",
            item=url,
            status=decision,
            detail_id=str(URLScan.objects.last().id) if URLScan.objects.exists() else "",
            scanned_url=url
        )

        return render(request, "detection/result.html", context)

    except Exception as e:
        traceback.print_exc()
        return render(request, "detection/result.html", {
            "error": str(e),
            "url": url
        })



# email scanner module  view
def predict_email_urls(url_list):
    results = []
    for url in url_list:
        try:
            raw = FeatureExtractor(url).run_all()
        except Exception as e:
            raw = {"url": url, "error": str(e)}

        raw["url"] = url

        score = dummy_ml_score(raw)
        raw["ml_score"] = score
        raw["prediction"] = 1 if score >= ML_THRESHOLD else 0

        results.append(raw)

    return results




# ALERT EMAIL SENDER


ALERT_RECIPIENT = "megwa@gmail.com"  
ALERT_TTL = 3600   # 1 hour per email alert

async def send_alert_email(eid, parsed, detailed):
    cache_key = f"alert_sent::{eid}"

    if cache.get(cache_key):
        return

    malicious = [d for d in detailed if d["is_malicious"]]
    if not malicious:
        return

    subject = f"⚠ PHISHING ALERT — {parsed.get('subject') or '(No subject)'}"

    plain_lines = [
        f"From: {parsed.get('from')}",
        f"Subject: {parsed.get('subject')}",
        "",
        "Detected malicious URLs:"
    ]

    html_rows = [
        "<table border='1' cellpadding='6' cellspacing='0' style='border-collapse:collapse;'>",
        "<tr><th>URL</th><th>Source</th><th>ML</th><th>IP</th><th>Location</th></tr>"
    ]

    for d in malicious:
        url = escape(d["url"])
        bl = d["blacklist"]
        geo = d["ip_geolocation"] or {}

        loc = f"{geo.get('city','')}, {geo.get('region','')}, {geo.get('country','')}"

        plain_lines.append(
            f"- {url} | blacklist={bl['blacklisted']} ({bl['source']}) | ml={d['ml_score']}"
        )

        html_rows.append(
            f"<tr>"
            f"<td>{url}</td>"
            f"<td>{bl['source']}</td>"
            f"<td>{d['ml_score']}</td>"
            f"<td>{d['ip_address']}</td>"
            f"<td>{loc}</td>"
            f"</tr>"
        )

    html_rows.append("</table>")

    plain_body = "\n".join(plain_lines)
    html_body = "<html><body>" + "<br>".join(plain_lines) + "<br>" + "".join(html_rows) + "</body></html>"

    try:
        await asyncio.to_thread(send_email, subject, plain_body, [ALERT_RECIPIENT], html_body=html_body)
        cache.set(cache_key, True, ALERT_TTL)
    except Exception as e:
        print("Alert email failed:", e)




# PROCESS SINGLE EMAIL (Async)


async def process_single_email(eid, msg):
    parsed = parse_email(msg)
    urls = extract_urls_from_email_body(parsed) or []

    detailed = []
    is_phish = False

    if urls:
        scan_response = await asyncio.to_thread(predict_email_urls, urls)
        scan_results = scan_response.get("results", []) if isinstance(scan_response, dict) else []

        for idx, url_text in enumerate(urls):
            raw = scan_results[idx] if idx < len(scan_results) else {}
            normalized = normalize_feature_output(raw, default_url=url_text)
            detailed.append(normalized)

        if any(d["is_malicious"] for d in detailed):
            is_phish = True

    # Save email to DB ONCE
    exists = await asyncio.to_thread(lambda: ProcessedEmail.objects.filter(email_id=eid).exists())

    if not exists:
        await asyncio.to_thread(
            ProcessedEmail.objects.create,
            email_id=eid,
            subject=parsed.get("subject", ""),
            sender=parsed.get("from", ""),
            has_urls=bool(urls),
            urls_data=json.dumps(detailed),
            is_phishing=is_phish
        )
    # await asyncio.to_thread(UnifiedScan.objects.create,
    #         module="EMAIL",
    #         item=parsed.get('subject','(No Subject)'),
    #         status="Phishing" if is_phish else 'Safe',
    #         detail_id=eid,
    #         scanned_url="; ".join(urls)


    #     )
    # exists = await asyncio.to_thread(lambda: ProcessedEmail.objects.filter(email_id=eid).exists())

    #  Send alert email
    if is_phish:
        await send_alert_email(eid, parsed, detailed)

    return {
        "subject": parsed.get("subject", "(No subject)"),
        "from": parsed.get("from", ""),
        "urls": detailed,
        "is_phishing": is_phish
    }




# FETCH & PROCESS ALL EMAILS (Async)


async def fetch_and_process_emails(limit=10):
    mail = connect_imap()
    try:
        emails = await fetch_email_async(mail, limit=limit)
        if not emails:
            return []

        tasks = [process_single_email(eid, msg) for eid, msg in emails]
        return await asyncio.gather(*tasks)
    finally:
        try:
            mail.logout()
        except:
            pass




#json


def scan_email_json(request):
    # try:
    #     results = asyncio.run(fetch_and_process_emails(limit=10))
    #     return JsonResponse({"ok": True, "emails": results})
    # except Exception as e:
    #     return JsonResponse({"ok": False, "error": str(e)}, status=500)
    
    try:
        

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(fetch_and_process_emails(limit=10))
        loop.close()



        return JsonResponse({"ok": True, "emails": results})

    except Exception as e:
        logger.exception("scan_email_json failed")
        return JsonResponse({"ok": False, "error": str(e)}, status=500)

    
    



def scan_email_view(request):
    # emails_display = []
    # for e in ProcessedEmail.objects.all().order_by('-id')[:30]:
    #     try:
    #         urls = json.loads(e.urls_data or "[]")
    #     except:
    #         urls = []

    #     emails_display.append({
    #         "subject": e.subject,
    #         "from": e.sender,
    #         "urls": urls,
    #         "is_phishing": e.is_phishing
    #     })
 
    return render(request, "detection/email_scan.html",{"emails":[]})




#  ML CONFIG -

ML_THRESHOLD = 0.70

def dummy_ml_score(features: dict) -> float:
    """
    Simple ML scoring simulation (0..1)
    """
    score = 0.0
    score += min(features.get("suspicious_keywords", 0) * 0.10, 0.40)

    age = features.get("domain_age", 1000)
    if isinstance(age, (int, float)) and 0 < age < 30:
        score += 0.25

    bl = features.get("blacklist", {}) or {}
    if isinstance(bl, dict) and bl.get("blacklisted") == 1:
        return 0.95

    if not features.get("https", True):
        score += 0.10

    if float(features.get("external_scripts_ratio", 0)) > 0.50:
        score += 0.15

    return round(min(score, 1.0), 3)


#  attachment page 

def attachment_scan_view(request: HttpRequest) -> HttpResponse:
    """
    Loads the attachment scanner HTML (upload form)
    """
    return render(request, "detection/attachment.html", {})

# json

@require_http_methods(["POST"])
def scan_attachment_json(request: HttpRequest) -> JsonResponse:
    try:
        uploaded = request.FILES.get("attachment")
        if not uploaded:
            return JsonResponse({"ok": False, "error": "No file uploaded"}, status=400)

        filename = uploaded.name
        if uploaded.size > settings.MAX_ATTACHMENT_UPLOAD_BYTES:
            return JsonResponse({"ok": False, "error": "Attachment exceeds the upload limit"}, status=413)
        content = uploaded.read()
        size = len(content)

        # File + internal URL extraction
        scanner = AttachmentScanner(enable_vt=True)   # VT file scan ON
        report = scanner.scan_file_from_bytes(content, filename, include_urls=True)

        #  URL FEATURE PROCESSING -

        urls_out = []
        extracted_urls = []
        any_phish = False

        for item in report.get("urls", []):
            url_text = item.get("url")

            raw_features = dict(item.get("features") or {})
            prediction = predict_url(url_text)
            model_score = prediction.get("final_score") if isinstance(prediction, dict) else None
            raw_features["url"] = url_text
            raw_features["ml_score"] = model_score if model_score is not None else dummy_ml_score(raw_features)

            # Normalize for UI
            norm = normalize_feature_output(raw_features, default_url=url_text)

            flat = norm.copy()
            flat["url"] = url_text
            flat["vt_url_report"] = item.get("vt_url_report")

            urls_out.append(flat)

            extracted_urls.append(url_text)

            if norm["is_malicious"]:
                any_phish = True
        # domain_age_days = "N/A"
        # domain_expiry_date = "N/A"
        # try:
        #     w = whois.whois(norm["url"])
        #     creation_date = w.creation_date

        #     if isinstance(creation_date, list):
        #         creation_date = creation_date[0]

        #     if isinstance(creation_date, datetime.datetime):
        #         domain_age_days = (datetime.datetime.now() - creation_date).days

        #     expiry = w.expiration_date
        #     if isinstance(expiry, list):
        #         expiry = expiry[0]
        #     if isinstance(expiry, datetime.datetime):
        #         domain_expiry_date = expiry.strftime("%Y-%m-%d")

        # except Exception:
        #     pass

        # norm["domain_age"] = f"{domain_age_days} days" if domain_age_days != "N/A" else "N/A"
        # norm["domain_expiry"] = domain_expiry_date

        #  SAVE TO DATABASE -

        file_info = report.get("file", {})
        file_sha = file_info.get("sha256", "")
        mime = file_info.get("mime", "application/octet-stream")

        saved = UploadFile.objects.create(
            file_name=filename,
            file_hash=file_sha,
            file_size=size,
            mime_type=mime,
            extracted_urls=extracted_urls,
            results={"file": file_info, "urls": urls_out},
            is_phishing=any_phish
        )   

        UnifiedScan.objects.create(
            module="ATTACHMENT",
            item=filename,
            scanned_url="; ".join(extracted_urls),
            status="Phishing" if  any_phish else "Safe",
            detail_id=str(saved.id),



        )


        #  json

        return JsonResponse({
            "ok": True,
            "file": {
                "file_name": filename,
                "sha256": file_sha,
                "mime": mime,
                "size": size,
            },
            "urls": urls_out,
            "is_phishing": any_phish,
            "saved_id": saved.id
        })

    except Exception as e:
        traceback.print_exc()
        return JsonResponse({"ok": False, "error": str(e)}, status=500)
