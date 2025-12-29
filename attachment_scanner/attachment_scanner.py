
import os
import re
import io
import zipfile
import joblib
import rarfile
import hashlib
import mimetypes
import magic
import json
import olefile
import logging
import math
import time
import requests
from PyPDF2 import PdfReader
from pdfminer.pdfparser import PDFParser
from pdfminer.pdfdocument import PDFDocument
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from detection.ml.features_extraction import FeatureExtractor

load_dotenv()
logger = logging.getLogger(__name__)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
    logger.addHandler(ch)
logger.setLevel(logging.INFO)

VT_API_KEY = os.getenv('VT_API_KEY')

# Use a named group "url" so group('url') works
URL_REGEX = re.compile(
    r'(?P<url>(?:https?://|http://|www\.)[A-Za-z0-9\-\._~:/?#\[\]@!$&\'()*+,;=%]+)',
    re.IGNORECASE
)

def _strip_trailing_punct(url: str) -> str:
    # remove trailing punctuation often attached to urls in plain text
    return url.rstrip('.,;:()[]{}<>\"\'') 

def extract_urls_from_text(text: str):
    """
    Extract URLs from a piece of text using the named-group regex.
    Returns a list (deduplicated, preserving first-seen order).
    """
    if not text:
        return []
    # normalize simple escaped newlines and CR
    text = text.replace("\\n", " ").replace("\r", " ")
    found = []
    seen = set()
    for m in URL_REGEX.finditer(text):
        try:
            url = m.group('url')
        except IndexError:
            # fallback to first group
            url = m.group(1)
        if not url:
            continue
        url = _strip_trailing_punct(url)
        if url.lower().startswith('www.'):
            url = "http://" + url
        # normalize simple double-encoded entities
        url = url.replace("&amp;", "&")
        if url not in seen:
            seen.add(url)
            found.append(url)
    logger.debug("extract_urls_from_text -> found %d urls", len(found))
    return found

# PDF extraction
def extract_url_from_pdf_bytes(data: bytes):
    urls = set()
    if PdfReader is None:
        try:
            txt = data.decode(errors='ignore')
            urls.update(extract_urls_from_text(txt))
        except Exception:
            pass
        return list(urls)

    try:
        reader = PdfReader(io.BytesIO(data))
        # page text
        for p in reader.pages:
            try:
                text = p.extract_text() or ""
                urls.update(extract_urls_from_text(text))
            except Exception:
                continue

        # annotations/URI extraction
        try:
            for p in reader.pages:
                ann = p.get('/Annots') or p.get('Annots')
                if not ann:
                    continue
                for a in ann:
                    try:
                        obj = a.get_object()
                        url = None
                        if '/A' in obj and isinstance(obj['/A'], dict) and '/URI' in obj['/A']:
                            url = obj['/A']['/URI']
                        elif "/URI" in obj:
                            url = obj['/URI']
                        if url:
                            urls.add(_strip_trailing_punct(url))
                    except Exception:
                        continue
        except Exception:
            pass
    except Exception:
        try:
            txt = data.decode(errors='ignore')
            urls.update(extract_urls_from_text(txt))
        except Exception:
            pass
    return list(urls)

# DOCX / PPTX / XLSX: open zip and scan internal xml
def extract_urls_from_docx_bytes(data: bytes):
    urls = set()
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        for name in z.namelist():
            if name.endswith('.rels') or name.endswith('.xml'):
                try:
                    raw = z.read(name).decode(errors='ignore')
                    urls.update(extract_urls_from_text(raw))
                except Exception:
                    continue
        # also check the document.xml if present
        try:
            doc_text = z.read('word/document.xml').decode(errors='ignore')
            urls.update(extract_urls_from_text(doc_text))
        except Exception:
            pass
    except Exception:
        try:
            txt = data.decode(errors='ignore')
            urls.update(extract_urls_from_text(txt))
        except Exception:
            pass
    return list(urls)

def extract_urls_from_pptx(data: bytes):
    urls = set()
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        for name in z.namelist():
            if name.endswith('.xml') or name.endswith('.rel'):
                try:
                    raw = z.read(name).decode(errors='ignore')
                    urls.update(extract_urls_from_text(raw))
                except Exception:
                    continue
    except Exception:
        try:
            txt = data.decode(errors='ignore')
            urls.update(extract_urls_from_text(txt))
        except Exception:
            pass
    return list(urls)

def extract_urls_from_xlsx_bytes(data: bytes):
    urls = set()
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        for name in z.namelist():
            if name.endswith(".xml") or name.endswith(".rels"):
                try:
                    raw = z.read(name).decode(errors="ignore")
                    urls.update(extract_urls_from_text(raw))
                except Exception:
                    continue
    except Exception:
        try:
            txt = data.decode(errors="ignore")
            urls.update(extract_urls_from_text(txt))
        except Exception:
            pass
    return list(urls)

def extract_urls_from_txt_bytes(data: bytes):
    try:
        text = data.decode("utf-8")
    except:
        try:
            text = data.decode("utf-16")
        except:
            text = data.decode(errors="ignore")
    
    return extract_urls_from_text(text)

def extract_urls_from_zip_bytes(data: bytes, recursive=True):
    urls = set()
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        for info in z.infolist():
            name = info.filename
            try:
                inner = z.read(name)
            except Exception:
                continue
            ext = os.path.splitext(name)[1].lower().lstrip(".")
            if ext == 'pdf':
                urls.update(extract_url_from_pdf_bytes(inner))
            elif ext in ('docx', 'doc'):
                urls.update(extract_urls_from_docx_bytes(inner))
            elif ext == 'pptx':
                urls.update(extract_urls_from_pptx(inner))
            elif ext in ("xlsx", "xls"):
                urls.update(extract_urls_from_xlsx_bytes(inner))
            elif ext in ("txt", "csv", "json", "html", "htm"):
                urls.update(extract_urls_from_txt_bytes(inner))
            elif ext in ("zip",) and recursive:
                urls.update(extract_urls_from_zip_bytes(inner, recursive=recursive))
            elif ext == "rar":
                try:
                    rf = rarfile.RarFile(io.BytesIO(inner))
                    # try reading inner entries
                    for rinfo in rf.namelist():
                        try:
                            inner_bytes = rf.read(rinfo)
                            urls.update(extract_urls_from_attachment_bytes(inner_bytes, rinfo, "" ))
                        except Exception:
                            continue
                except Exception:
                    pass
            else:
                try:
                    urls.update(extract_urls_from_text(inner.decode(errors="ignore")))
                except Exception:
                    pass
    except Exception:
        try:
            urls.update(extract_urls_from_text(data.decode(errors="ignore")))
        except Exception:
            pass
    return list(urls)

def extract_urls_from_attachment_bytes(data: bytes, filename: str, mime: str = ""):
    ext = os.path.splitext(filename)[1].lower().lstrip(".")
    if ext == "pdf":
        return extract_url_from_pdf_bytes(data)
    if ext == "docx":
        return extract_urls_from_docx_bytes(data)
    if ext in ("pptx",):
        return extract_urls_from_pptx(data)
    if ext in ("xlsx", "xls"):
        return extract_urls_from_xlsx_bytes(data)
    if ext in ("zip",):
        return extract_urls_from_zip_bytes(data)
    if ext in ("txt", "csv", "json", "html", "htm"):
        return extract_urls_from_txt_bytes(data)
    if not mime or mime == "application/octet-stream":
        try:
            return extract_urls_from_text(data.decode(errors="ignore"))
        except:
            pass

    if ext == "doc":
        try:
            if olefile.isOleFile(io.BytesIO(data)):
                ole = olefile.OleFileIO(io.BytesIO(data))
                if ole.exists("WordDocument"):
                    raw = ole.openstream("WordDocument").read().decode(errors="ignore")
                    return extract_urls_from_text(raw)
        except Exception:
            pass
    try:
        return extract_urls_from_text(data.decode(errors="ignore"))
    except Exception:
        return []

# File heuristics and helpers
BLACKLISTED_EXT = {
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".vbs", ".js", ".jar", ".msi", ".apk"
}
MACRO_EXT = {".docm", ".xlsm", ".pptm"}

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    occur = [0] * 256
    for x in data:
        occur[x] += 1
    entropy = 0.0
    for count in occur:
        if count == 0:
            continue
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy

def is_executable(filename: str) -> bool:
    evil_ext = ['.exe', '.dll', '.bat', '.sh', '.cmd', '.vbs', '.msi', '.js', '.apk', '.scr', '.jar']
    ext = os.path.splitext(filename)[1].lower()
    return ext in evil_ext

def suspicious_filenames_score(name: str):
    score = 0
    reasons = []
    if ".." in name:
        score += 10
        reasons.append("path traversal token in filename")
    if name.count(".") >= 2:
        score += 10
        reasons.append("double extension")
    lower = name.lower()
    for pat in ("password", "invoice", "urgent", "payment", "update"):
        if pat in lower:
            score += 15
            reasons.append(f"suspicious keyword in filename: {pat}")
    return score, reasons

# Main scanning class
class AttachmentScanner:
    def __init__(self, ml_model=None, enable_vt=True, vt_api_key=None):
        self.ml_model = ml_model
        self.enable_vt = enable_vt
        self.vt_api_key = vt_api_key or VT_API_KEY

    def _read_file(self, filepath: str):
        with open(filepath, 'rb') as f:
            data = f.read()
        return data

    def _file_basic(self, filepath: str):
        data = self._read_file(filepath)
        filename = os.path.basename(filepath)
        try:
            mime = magic.from_buffer(data, mime=True)
        except Exception:
            mime = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        sha256 = hashlib.sha256(data).hexdigest()
        size = len(data)
        return {"filename": filename, "content": data, "mime": mime, "sha256": sha256, "size": size}

    def _file_rules_scan(self, filename: str, data: bytes):
        ext = os.path.splitext(filename)[1].lower()
        entropy = calculate_entropy(data)
        score = 0
        reasons = []
        s, r = suspicious_filenames_score(filename)
        score += s
        reasons += r
        if ext in BLACKLISTED_EXT:
            score += 50
            reasons.append(f"blacklisted extension: {ext}")
        if ext in MACRO_EXT:
            score += 30
            reasons.append("macro-enabled office file")
        if ext == '.pdf':
            try:
                raw = data.decode(errors='ignore')
                for kw in ("/JS", "/JavaScript", "/Launch", "/OpenAction", "/AA"):
                    if kw in raw:
                        score += 25
                        reasons.append(f"PDF suspicious keyword: {kw}")
            except Exception:
                pass
        if ext == '.zip':
            try:
                z = zipfile.ZipFile(io.BytesIO(data))
                for n in z.namelist():
                    next_ext = os.path.splitext(n)[1].lower()
                    if next_ext in BLACKLISTED_EXT:
                        score += 40
                        reasons.append(f"zip contains dangerous file: {n}")
            except Exception:
                pass
        if entropy > 7.5:
            score += 20
            reasons.append("high entropy -> packed or encrypted")
        risk = 'SAFE'
        if score >= 40:
            risk = 'SUSPICIOUS'
        if score >= 80:
            risk = "MALICIOUS"
        return {"entropy": entropy, "score": score, "risk": risk, "reasons": reasons, "extension": ext}

    def vt_scan(self, data: bytes):
        if not self.enable_vt or not self.vt_api_key:
            return {"vt_enabled": False, "error": "NO_API_KEY"}
        headers = {"x-apikey": self.vt_api_key}
        try:
            files = {"file": ("attachment", data)}
            upload = requests.post("https://www.virustotal.com/api/v3/files", files=files, headers=headers, timeout=25)
            if upload.status_code not in (200, 201):
                return {"error": "VT_UPLOAD_FAILED", "status": upload.status_code}
            analysis_id = upload.json()["data"]["id"]
            report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            for _ in range(12):
                resp = requests.get(report_url, headers=headers, timeout=10)
                js = resp.json()
                status = js["data"]["attributes"]["status"]
                if status == "completed":
                    return js
                time.sleep(2.5)
            return {"error": "VT_TIMEOUT", "id": analysis_id}
        except Exception as e:
            return {"error": str(e), "vt_failed": True}

    def analyze_url(self, url: str):
        fe_result = {}
        try:
            fe = FeatureExtractor(url)
            fe_result = fe.run_all()
        except Exception as e:
            logger.exception("FeatureExtractor.run_all() failed for %s: %s", url, e)
            fe_result = {"error": "feature_extractor_failed", "error_msg": str(e), "url": url}
        # attach ML result if available
        if self.ml_model and isinstance(fe_result, dict):
            try:
                vals = [fe_result[k] for k in sorted(fe_result.keys())]
                if hasattr(self.ml_model, 'predict_proba'):
                    proba = self.ml_model.predict_proba([vals])[0][1]
                    fe_result['ml_score'] = float(proba)
                else:
                    pred = self.ml_model.predict([vals])[0]
                    fe_result['ml_result'] = float(pred)
            except Exception as e:
                logger.debug("URL ML prediction failed: %s", e)
                fe_result["ml_score"] = None
        return fe_result

    def scan_file(self, filepath: str, include_urls=True):
        if not os.path.isfile(filepath):
            raise FileNotFoundError(filepath)
        basic = self._file_basic(filepath)
        filename = basic['filename']
        data = basic['content']
        file_scan = self._file_rules_scan(filename, data)
        vt_report = {}
        if self.enable_vt and self.vt_api_key:
            vt_report = self.vt_scan(data)
            try:
                stats = vt_report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) or {}
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                if malicious >= 1:
                    file_scan["score"] += 40
                    file_scan["reasons"].append(f"VirusTotal detected {malicious} malicious engines")
                if suspicious >= 1:
                    file_scan["score"] += 20
                    file_scan["reasons"].append(f"VirusTotal suspicious detections: {suspicious}")
                if file_scan["score"] >= 80:
                    file_scan["risk"] = "MALICIOUS"
            except Exception:
                pass
        url_reports = []
        if include_urls:
            urls = extract_urls_from_attachment_bytes(data, filename, basic['mime'])
            print("DEBUG: Extracted URLs:", urls)



            urls = sorted(set(urls), key=lambda x: x)
            for url in urls:
                try:
                    feat = self.analyze_url(url)
                    url_reports.append({"url": url, "features": feat})
                except Exception as e:
                    url_reports.append({"url": url, "error": str(e)})
        report = {
            "file": {
                "filename": filename,
                "sha256": basic["sha256"],
                "mime": basic["mime"],
                "size": basic["size"],
                "scan": file_scan,
                "is_executable": is_executable(filename),
                "vt_report": vt_report
            },
            "urls_found_count": len(url_reports),
            "urls": url_reports
        }
        return report

    def scan_file_from_bytes(self, data: bytes, filename: str, include_urls=True):
        import hashlib
        import mimetypes
        import magic
        try:
            mime = magic.from_buffer(data, mime=True)
        except Exception:
            mime = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        basic = {"filename": filename, "content": data, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "mime": mime}
        file_scan = self._file_rules_scan(filename, data)
        vt_report = {}
        if self.enable_vt and self.vt_api_key:
            vt_report = self.vt_scan(data)
            try:
                stats = vt_report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) or {}
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                if malicious >= 1:
                    file_scan["score"] += 40
                    file_scan["reasons"].append(f"VirusTotal detected {malicious} malicious engines")
                if suspicious >= 1:
                    file_scan["score"] += 20
                    file_scan["reasons"].append(f"VirusTotal suspicious detections: {suspicious}")
                if file_scan["score"] >= 80:
                    file_scan["risk"] = "MALICIOUS"
            except Exception:
                pass
        url_reports = []
        if include_urls:
            urls = extract_urls_from_attachment_bytes(data, filename, basic['mime'])
            # preserve ordering and dedupe
            seen = set()
            ordered_urls = []
            for u in urls:
                if u not in seen:
                    seen.add(u)
                    ordered_urls.append(u)
            for url in ordered_urls:
                try:
                    feat = self.analyze_url(url)
                    url_reports.append({"url": url, "features": feat or {},"error": feat.get("error") if isinstance(feat, dict) else None})
                except Exception as e:
                    url_reports.append({"url": url, "error": str(e)})
        report = {
            "file": {"filename": filename, "sha256": basic["sha256"], "mime": basic["mime"], "size": basic["size"], "scan": file_scan, "is_executable": is_executable(filename), "vt_report": vt_report},
            "urls_found_count": len(url_reports),
            "urls": url_reports
        }
        return report

# quick CLI test
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Attachment scanner — file + URL analysis")
    p.add_argument("file", help="Path to file to scan")
    p.add_argument("--no-urls", dest="include_urls", action="store_false", help="Do not extract/analyze URLs")
    args = p.parse_args()
    scanner = AttachmentScanner()
    out = scanner.scan_file(args.file, include_urls=args.include_urls)
    print(json.dumps(out, indent=2))
