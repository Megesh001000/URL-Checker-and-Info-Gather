

from asyncio.log import logger
import json
import math
import re
import socket
import os 
import threading
import time
import socket
from urllib.parse import urlparse
import requests
import whois
import tldextract
import dns.resolver
import ssl
import datetime
from bs4 import BeautifulSoup
from functools import cache, lru_cache
from urllib.parse import quote
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from dotenv  import load_dotenv
from html import unescape
from dateutil.parser import parse as date_parse
import logging
logger=logging.getLogger(__name__)
if not logger.handlers:
    handler=logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

load_dotenv()




#  Global Constants 
HTTP_TIMEOUT = 5
WHOIS_TIMEOUT = 10
DNS_TIMEOUT = 15
SSL_TIMEOUT = 3

CACHE_TTL_SECONDS=6*60*60

MAX_RETRIES=3
BACKOFF_FACTOR=0.5
# PHISHTANK_CACHE_FILE = "phishtank_data.json" # Local filename for cache
# PHISHTANK_CACHE_LIFETIME_SECONDS = 24 * 60 * 60 # 24 hours
# simple whitelist of known CA tokens to mark issuer as "known" (expandable)
# KNOWN_CA_TOKENS = [
#     "let's encrypt", "letsencrypt", "let'sencrypt", "amazon", "comodossl", "digicert",
#     "globalsign", "sectigo", "godaddy", "google", "cloudflare", "ssl", "thawte", "buypass"
# ]
# Load API Key from environment variable (Security Fix)
# USAGE: Set the environment variable before running: export GOOGLE_SAFE_BROWSING_API_KEY="YOUR_KEY_HERE"
GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")
IPQS_API_KEY = os.environ.get("IPQS_API_KEY")

def _build_requests_session():
    session=requests.Session()
    retries=Retry(
        total=MAX_RETRIES,
        connect=MAX_RETRIES,
        read=MAX_RETRIES,
        backoff_factor=BACKOFF_FACTOR,
        status_forcelist=(429,500,502,503,504),
        allowed_methods=frozenset(['GET','POST','HEAD'])
    )
    adapter=HTTPAdapter(max_retries=retries,pool_maxsize=20)
    session.mount("https://",adapter)
    session.mount("http://",adapter)
    session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"})
    return session
REQUESTS_SESSION=_build_requests_session()
# Known safe whitelist (domains)
WHITELIST = {
    "google.com", "youtube.com", "linkedin.com", "github.com",
    "coursera.org", "facebook.com", "twitter.com", "instagram.com",
    "microsoft.com", "apple.com", "amazon.com"
}

# in memory domain cache  with ttl and lru
class TTLDomainCache:
    def __init__(self,maxsize=1000,ttl=CACHE_TTL_SECONDS):
        self.maxsize=maxsize
        self.ttl=ttl
        self.lock=threading.Lock()
        self.data={} # dict domain for timestampp and value
        self.order=[] # simple insertion order list for eviction 
    
    def get(self,key):
        with self.lock:
            rec=self.data.get(key)
            if not rec:
                return None
            ts,val=rec
            if(time.time() - ts) > self.ttl:
                del self.data[key] # expiresd
                try:
                    self.order.remove(key)
                except ValueError:
                    pass
                return None
            # refresh order to approx recent  use
            try:
                self.order.remove(key)
            except ValueError:
                pass
            self.order.append(key)
            return val

    def set(self,key,value):
        with self.lock:
            if key in self.data:
                try:
                    self.order.remove(key)
                except  ValueError:
                    pass
            
            # evict if needeed
            while len(self.order) >= self.maxsize:
                old=self.order.pop(0)
                try:
                    del self.data[old]
                except KeyError:
                    pass
            self.data[key]=(time.time(),value)
            self.order.append(key)

domain_cache=TTLDomainCache(maxsize=2000,ttl=CACHE_TTL_SECONDS)

def extract_domain_only(url:str):
    try:
        ext=tldextract.extract(url)
        domain=f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        return domain.lower()
    except Exception:
        return ""

def is_whitelisted(url:str):   #safe domain
    domain=extract_domain_only(url)
    return domain in WHITELIST

def safe_domain_extract(url: str):
    """Safely extracts domain, subdomain, and suffix using tldextract."""
    try:
        ext = tldextract.extract(url)
        # Use netloc for IP-based URLs to ensure the IP is handled properly
        if re.match(r"(\d{1,3}\.){3}\d{1,3}", ext.fqdn):
            domain = ext.fqdn
            subdomain = ""
        else:
            domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
            subdomain = ext.subdomain or ""
        suffix = ext.suffix or ""
        return domain, subdomain, suffix
    except Exception:
        return "", "", ""

#  FeatureExtractor Class 

class FeatureExtractor:
    def __init__(self, url: str, fetch_page: bool = True):
        self.url = unescape(url).strip() if isinstance(url, str) else ""
        self.domain, self.subdomain, self.suffix = safe_domain_extract(self.url)
        self.parsed_url = urlparse(self.url) # Store parsed URL
        self._html = None
        self._whois = None
        self._whois_attempted = False
        self.ip_match = re.match(r"(\d{1,3}\.){3}\d{1,3}", self.parsed_url.netloc) # Pre-calculate IP match
        self._dns_answer = None
        self._ssl_cert = None
        self._ssl_checked = False
        self.fetch_page = fetch_page
        # self._phishtank_data = None # Cache for PhishTank data (Efficiency Fix)


    # Network / IO helpers
    def _fetch_page_once(self):
        # Fetch HTML once per instance (cached). Returns text or None.
        if self._html is not None:
            return self._html
        if not self.fetch_page:
            return None
        # whitelist check
        if is_whitelisted(self.url):
            logger.debug(f"Skipping page fetch for whitelisted domain: {self.domain}")
            self._html = None
            return self._html

        try:
            head = REQUESTS_SESSION.head(self.url,timeout=min(HTTP_TIMEOUT,3), allow_redirects=True)
            if head.status_code in (403, 429, 503):
                logger.warning(f"HEAD blocked, attempting GET anyway: {self.url}")

            content_type=head.headers.get("Content-Type","")
            if head.status_code == 200 and ("text/html" in content_type or "application/xhtml+xml" in content_type):
                # GET  full content with retries/backoff
                for attempt in range(1,MAX_RETRIES+1):
                    try:
                        response=REQUESTS_SESSION.get(self.url,timeout=HTTP_TIMEOUT,allow_redirects=True)
                        if response.status_code == 200 and response.text:
                            ct=response.headers.get("Content-Type","")
                            if "html" in ct.lower() or "<html" in response.text.lower():

                                self._html = response.text
                                return self._html
                            else:
                                self._html=None
                        elif response.status_code in (403, 429, 503):
                            logger.warning(f"GET blocked ({response.status_code}) for {self.url}")
                            self._html = None
                            return self._html
                        else:
                            # non-200 fallback -> no html
                            self._html = None
                            return self._html
                    except requests.exceptions.RequestException as e:
                        sleep_time = BACKOFF_FACTOR * (2 ** (attempt - 1))
                        logger.debug(f"GET attempt {attempt} failed for {self.url}: {e}. Backoff {sleep_time}s")
                        time.sleep(sleep_time)
                logger.warning(f"All GET attempts failed for {self.url}")
                self._html = None
                return None   
            else:
                # HEAD did not return HTML or non-200
                try:
                    response=REQUESTS_SESSION.get(self.url,timeout=HTTP_TIMEOUT,allow_redirects=True)
                    if  response.status_code == 200 and response.text and ("text/html" in response.headers.get("Content-Type", "") or "<html" in response.text[:500].lower()):
                        self._html=response.text
                    else:
                        self._html=None
                except requests.exceptions.RequestException:
                    self._html = None
                return self._html
        except requests.exceptions.RequestException:
            # HEAD failed
            for attempt in range(1,MAX_RETRIES+1):
                try:
                    response = REQUESTS_SESSION.get(self.url, timeout=HTTP_TIMEOUT, allow_redirects=True)
                    if response.status_code == 200 and response.text and ("text/html" in response.headers.get("Content-Type", "") or "<html" in response.text[:500].lower()):
                        self._html = response.text
                    else:
                        self._html = None
                    return self._html
                except requests.exceptions.RequestException as e:
                    sleep_time = BACKOFF_FACTOR * (2 ** (attempt - 1))
                    logger.debug(f"Fallback GET attempt {attempt} failed for {self.url}: {e}. Backoff {sleep_time}s")
                    time.sleep(sleep_time)
            self._html = None
            return self._html
        except Exception as e:
            logger.exception(f"Unexpected error fetching {self.url}: {e}")
            self._html = None
            return self._html
    @staticmethod
    def parse_whois_date(d):
        if isinstance(d,list) and d:
            d=d[0]
        if not d: 
            return None
        if isinstance(d,datetime.datetime):
            return d
        try:
            return date_parse(str(d))
        except Exception:
            return None

    
        
    def _get_whois_once(self):
        if self._whois_attempted:
            return self._whois
        self._whois_attempted = True
        self._whois=None
        try:
            
            self._whois = whois.whois(self.domain,timeout=WHOIS_TIMEOUT) if self.domain and not self.ip_match else None
        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {self.domain}: {e},retrying once...")

            
            try:
                self._whois = whois.whois(self.domain, timeout=WHOIS_TIMEOUT)
            except Exception as e2:
                logger.debug(f"WHOIS lookup failed for {self.domain}: {e2}")
                self._whois = None
        return self._whois
    

    def get_domain_age(self):
        w = self._get_whois_once()
        if not w: 
            return -1
        creation = FeatureExtractor.parse_whois_date(w.creation_date)
        if not creation:
            return -1
        delta = datetime.datetime.now() - creation
        return max(0, delta.days)

    def get_domain_expiry(self):
        w = self._get_whois_once()
        if not w: 
            return -1
        expiry = FeatureExtractor.parse_whois_date(w.expiration_date)
        if not expiry:
            return -1
        delta = expiry - datetime.datetime.now()
        return int(delta.days) if delta.days > 0 else 0

    # def get_domain_age(self):
    #     w = self._get_whois_once()
    #     if not w: return -1
    #     try:
    #         creation = parse_whois_date(w.creation_date)
    #         # if isinstance(creation, list) and creation:
    #         #     creation = creation[0]
    #         if not creation: return -1 # Changed 1 to -1 for "unknown/missing"
            
    #         # Use dateutil.parser.parse for robust date handling if available, otherwise rely on fromisoformat
    #         if isinstance(creation, str):
    #             try:
    #                 # More robust parsing (though WHOIS dates vary widely)
    #                 creation = datetime.datetime.fromisoformat(creation.split('T')[0]) 
    #             except Exception:
    #                 return -1
                
    #         delta = datetime.datetime.now() - creation
    #         return max(0, delta.days)
    #     except Exception:
    #         return -1

    # def get_domain_expiry(self):
    #     w = self._get_whois_once()
    #     if not w: return -1
    #     try:
    #         expiry = parse_whois_date(w.expiration_date)
    #         if isinstance(expiry, list) and expiry:
    #             expiry = expiry[0]
    #         if not expiry: return -1
            
    #         if isinstance(expiry, str):
    #             try:
    #                 expiry = datetime.datetime.fromisoformat(expiry.split('T')[0])
    #             except Exception:
    #                 return -1
    #         if isinstance(expiry, datetime.datetime) or isinstance(expiry, datetime.date):
    #             if isinstance(expiry, datetime.date) and not isinstance(expiry, datetime.datetime):
    #                 expiry = datetime.datetime(expiry.year, expiry.month, expiry.day)
                
    #             delta = expiry - datetime.datetime.now()
    #             return int(delta.days) if delta.days > 0 else 0
    #         else:
    #             return -1
    #     except Exception as e:
    #         logger.debug(f"WHOIS Expiry check failed for {self.domain}: {e}")
            
    #         return -1

    def _dns_a_record(self):
        # Return DNS A answer object or None
        if self._dns_answer is not None:
            return self._dns_answer
        if not self.domain:
            return None
        try:
            res = dns.resolver.resolve(self.domain, "A", lifetime=DNS_TIMEOUT)
            self._dns_answer = res
            return res
        except Exception as e:
            logger.debug(f"DNS lookup failed for {self.domain}: {e}")
            
            self._dns_answer = None
            return None

    def _get_ssl_cert_once(self):
        # Attempt SSL connect and cache certificate dict
        if self._ssl_checked:
            return self._ssl_cert
        self._ssl_checked = True
        # Only attempt SSL connection if the scheme is HTTPS and have a host
        if self.parsed_url.scheme != "https" or not self.parsed_url.netloc:
            self._ssl_cert = None
            return None
            
        try:
            #  netloc for the connection, but domain for server_hostname
            host_to_connect = self.parsed_url.netloc.split(':')[0]
            server_name = self.domain or host_to_connect # SNI better with domain
            
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=server_name) as s:
                s.settimeout(SSL_TIMEOUT)
                s.connect((host_to_connect, 443))
                cert = s.getpeercert()
                self._ssl_cert = cert
                return cert
        except Exception as e:
            logger.debug(f"SSL check failed for {self.parsed_url.netloc}: {e}")
            self._ssl_cert = None
            return None

    # 1. Lexical Features
    def get_url_length(self):
        return len(self.url) if self.url else 0

    def get_domain_length(self):
        return len(self.domain) if self.domain else 0

    def count_dots(self):
        return self.url.count('.') if self.url else 0

    def count_hyphens(self):
        return self.url.count('-') if self.url else 0

    def has_ip(self):
        # Fixed: Check the entire netloc (hostname or IP) instead of just self.domain
        return 1 if self.ip_match else 0

    def count_suspicious_keywords(self):
        keywords = ["login", "secure", "update", "bank", "signin", "account"]
        return sum([self.url.lower().count(k) for k in keywords])
    def get_tld(self,url=None):
        try:
            
                target_url = url if url else self.url
                return tldextract.extract(target_url).suffix
    
        except:
            return ""
    def has_at_symbol(self):
        return 1 if "@" in self.url else 0

    def has_https(self):
        return 1 if self.parsed_url.scheme.lower() == "https" else 0
    # def is_valid_url(url):
    #     parsed = urlparse(url)
    #     return parsed.scheme in ("http", "https") and parsed.netloc != ""

    # Example usage
   
    # def num_special_chars(self):
    #     if not self.url or not self.parsed_url.netloc:
    #          return 0
    #     try:
    #         s = (self.parsed_url.netloc or "") + \
    #             (self.parsed_url.path or "") + \
    #             (self.parsed_url.query or "") + \
    #             (self.parsed_url.fragment or "") + \
    #             (self.parsed_url.params or "")
      
    #               # s=netloc+path+query+fragment
    #     except Exception:
    #         s=self.url
    #     allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~:/?#[]@!$&'()*+,;=%")
    #     try:
    #         count=sum(1 for ch in s if ch not in allowed )
    #         return int(count)
    #     except Exception as e:
    #         # This catches the specific type of error reported previously
    #         logger.warning(f"Error counting special chars for {self.url}: {e}")
    #         return -1 
    # def special_char_ratio(self):
    #     try:
    #         num_chars = self.num_special_chars()
    #         url_len = self.get_url_length() or 1
    #         return float(num_chars) / float(url_len)
    #     except Exception as e:
    #         logger.warning(f"Failed calculating special char ratio for URL {self.url}: {e}")
    #         return 0.0
        # url_len=self.get_url_length() or 1
        # return float(self.num_special_chars())/float(url_len)
    # 2. Host-Based Features
    # get_whois_info() is now just for internal use

  

    def dns_records_exist(self):
        ans = self._dns_a_record()
        return 1 if ans is not None else 0
    
    def ttl_value(self):
        try:
            ans = self._dns_a_record()
            if ans is None: 
                return -1
            ttl = getattr(ans.rrset, "ttl", None)
            return int(ttl) if ttl is not None else -1
        except Exception:
            return -1
    def resolve_ip(self):
        try:
            hostname = urlparse(self.url).hostname
            if hostname:
                return socket.gethostbyname(self.domain)
        except Exception as e:
            logger.debug(f"IP resolution failed for {self.url}: {e}")
            return None
    
    def get_ip_geolocation(self,ip: str = None):
        
        if not ip:
            ip = self.resolve_ip()
        if not ip:
            return {
                "country": "Unknown",
                "region": "Unknown",
                "city": "Unknown",
                "org": "Unknown",
                "latitude": -1,
                "longitude": -1
            }
        try:
            r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5).json()
            lat, lon = (r.get("loc", ",").split(",")) if "loc" in r else (-1, -1)
            return {
                "country": r.get("country", "Unknown"),
                "region": r.get("region", "Unknown"),
                "city": r.get("city", "Unknown"),
                "org": r.get("org", "Unknown"),
                "latitude": float(lat) if lat != "" else -1,
                "longitude": float(lon) if lon != "" else -1
            }
        except Exception as e:
            logger.debug(f"IP geolocation failed for {ip}: {e}")
            return {
                "country": "Unknown",
                "region": "Unknown",
                "city": "Unknown",
                "org": "Unknown",
                "latitude": -1,
                "longitude": -1
            }
    def encode_text(self, text):
        if not text or text == "Unknown":
            return -1
        return abs(hash(text)) % 10000
        
                

    # 3. Content-Based Features
    def fetch_page(self):
        return self._fetch_page_once()

    def has_iframe(self):
        html = self._fetch_page_once()
        return 1 if html and "<iframe" in html else 0
    # def iframe_flag(soup):
    #     iframes = soup.find_all("iframe")
    #     for f in iframes:
    #         style = f.get("style", "")
    #         if "display:none" in style or "visibility:hidden" in style:
    #             return 1
    #     return 0


    def count_input_tags(self):
        html = self._fetch_page_once()
        if not html: 
            return -1
        try:
            soup = BeautifulSoup(html, "html.parser")
            return len(soup.find_all("input"))
        except Exception:
            return -1

    def check_favicon(self):
        html = self._fetch_page_once()
        if not html:
            return -1
        try:
            soup = BeautifulSoup(html, "html.parser")
            icon = soup.find("link", rel=lambda x: x and 'icon' in x.lower())
            href = icon.get("href") if icon and icon.get("href") else None
            if href:
                # relative or same domain is okay; external is suspicious
                # Check if href is absolute (starts with http) and the domain is NOT in the href
                if href.lower().startswith(("http", "//")) and self.domain and self.domain not in href:
                    favicon_domain = urlparse(href).netloc
                    if self.domain and self.domain not in favicon_domain:
                        return 1
                return 0
                
            return 0
        except Exception:
            return -1
    

        
    
    def external_scripts_ratio(self):
        html = self._fetch_page_once()
        if not html: return 0.0
        try:
            soup = BeautifulSoup(html, "html.parser")
            scripts = [s for s in soup.find_all("script") if s.get("src")] 
            if not scripts: 
                return 0.0
            external = [s for s in scripts if self.domain not in s.get('src','')]
            return float(len(external)) / float(len(scripts))
        except Exception:
            return 0.0

    def title_mismatch(self):
        html = self._fetch_page_once()
        if not html: 
            return 0
        try:
            soup = BeautifulSoup(html, "html.parser")
            title = soup.title.string if soup.title else ""
            if not title: 
                return 0
            
            # Useing  main part of the domain (e.g., 'google' from 'google.com')
            main = (self.domain.split('.')[0] if self.domain else "").lower()
            
            # Checking if  main domain token is missing from the title
            if main and main not in str(title).lower():
                return 1
            return 0
        except Exception:
            return 0

    # 4. SSL/Network Features
    def has_ssl_certificate(self):
        cert = self._get_ssl_cert_once()
        return 1 if cert else 0
    def get_ssl_issuer(self):
        cert = self._get_ssl_cert_once()
        if not cert:
            return "Unknown"
        try:
            issuer = dict(x[0] for x in cert.get('issuer', []))
            return issuer.get('O', 'Unknown')
        except Exception:
            return "Unknown"

    
    def check_certificate_issuer(self):
        cert = self._get_ssl_cert_once()
        if not cert: 
            return "Unknown"
        issuer = cert.get("issuer")
        try:
            parts = []
            if isinstance(issuer, (list, tuple)):
                for item in issuer:
                    if isinstance(item,(list,tuple)):
                        for component in item:
                            if isinstance(component, (list, tuple)) and len(component) ==2:
                                # Look specifically for the Common Name (CN) or Organization (O)
                                attribute,value=component
                                if attribute.lower()=="commonname":
                                    parts.append((f"CN={value}"))
                                elif attribute=="OrganizationName":
                                    parts.append((f"O={value}"))
                                else:
                                    parts.append(f"{attribute}={value}")
                                                    
                            elif isinstance(component, str):
                                 parts.append(str(component))

                    elif isinstance(item, str):
                         parts.append(str(item))
                issuer_str=', '.join(parts)
                # Simplify to just the main CN/O if possible
                cn_match = re.search(r"CN=([^,]+)", issuer_str)
                org_match = re.search(r"O=([^,]+)", issuer_str)
                if cn_match:
                    return cn_match.group(1).strip()
                elif org_match:
                    return org_match.group(1).strip()
                return issuer_str.strip()
            return str(issuer).strip()
        except Exception:
            return "Unknown"
        
    def ssl_issuer_known(self):
        issuer = self.check_certificate_issuer().lower()
        if issuer == "unknown": 
            return 0
        for token in ["let's encrypt", "letsencrypt", "amazon", "comodossl", "digicert", "globalsign", "sectigo", "godaddy", "google", "cloudflare", "ssl", "thawte", "buypass"]:
            if token in issuer:
                return 1
        return 0

    def domain_entropy(self):
        if not self.domain: 
            return 0.0
        try:
            s = self.domain
            prob = [float(s.count(c)) / len(s) for c in set(s)]
            return -sum(p * math.log(p, 2) for p in prob) if prob else 0.0
        except Exception:
            return 0.0
    # def num_special_chars(self):
    #      return 0

    # def special_char_ratio(self):
    #     return 0.0

    # def _fetch_phishtank_data(self):
    #     """Fetches and caches PhishTank data for efficiency."""
    #     if self._phishtank_data is not None:
    #         return self._phishtank_data
        
    #     cache_path=PHISHTANK_CACHE_FILE
    #     try:
    #         if os.path.exists(cache_path):
    #             mtime=os.path.getmtime(cache_path)
    #             if (time.time()-mtime)<PHISHTANK_CACHE_LIFETIME_SECONDS:
    #                 with open(cache_path,"r",encoding="utf-8") as fh:
    #                     self._phishtank_data=json.load()
    #                     return self._phishtank_data
    #     except Exception:
    #         # if cache read fails, we'll attempt download
    #         pass


    #     phish_url = "https://data.phishtank.com/data/online-valid.json"
    #     try:
    #         # Increased timeout for large file download
    #         phish_resp = requests.get(phish_url, timeout=30) 
    #         if phish_resp.status_code == 200:
    #             self._phishtank_data = phish_resp.json()
    #             try:
    #                 with open(cache_path,"w",encoding="utf-8") as fh:
    #                     json.dump(self._phishtank_data,fh)
    #             except Exception:
    #                 pass
    #             print("PhishTank data fetched and cached.")
    #             return self._phishtank_data
    #         else:
    #             print(f"PhishTank returned status {phish_resp.status_code}")
    #             return None
    #     except Exception as e:
    #         print(f"PhishTank download failed: {str(e)}")
    #         return None

    def check_blacklist(self):
       
        """Checks Google Safe Browsing first, then falls back to PhishTank (if needed)."""
        
        # domain level cache check
        cached=domain_cache.get(self.domain)
        if  cached is not None:
            logger.debug(f"Using cached blacklist for domain: {self.domain}")
            return cached
        def _set_cache_and_return(result):
            if result.get("blacklisted") in (0, 1):
                domain_cache.set(self.domain, result)
            return result


        # 1 Google Safe Browsing Check (Primary) 
        if GOOGLE_SAFE_BROWSING_API_KEY:
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
            payload = {
                "client": {"clientId": "url-checker", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": self.url}]
                },

            }
            try:
                response = REQUESTS_SESSION.post(api_url, json=payload, timeout=6)
                if response.status_code == 200:
                    data = response.json()
                    if data.get("matches"):
                        out= {"blacklisted": 1, "source": "Google Safe Browsing", "details": "Listed as malicious."}
                        # domain_cache.set(self.domain,out)
                        return _set_cache_and_return(out)
                    else:
                        out = {"blacklisted": 0, "source": "Google Safe Browsing", "details": "Not listed."}
                        domain_cache.set(self.domain, out)
                        return _set_cache_and_return(out)
                elif response.status_code == 429:
                    print("Google API quota exceeded, falling back to PhishTank...")
                else:
                    print(f"Google Safe Browsing returned status {response.status_code}. Falling back.")
            except Exception as e:
                print("Google Safe Browsing check failed:", e, ". Falling back.")
        else:
            print("GOOGLE_SAFE_BROWSING_API_KEY not set. Checking PhishTank.")
        if IPQS_API_KEY:
            try:
                encoded_target = quote(self.url, safe='')
                ipqs_url = f"https://ipqualityscore.com/api/json/url/{IPQS_API_KEY}/{encoded_target}"
                # Optional tuning parameters
                params = {"strictness": 1, "fast": "false"}
                
                response = REQUESTS_SESSION.get(ipqs_url, params=params, timeout=8)
                if response.status_code != 200:
                    print(f"IPQS returned status {response.status_code}")
                    out = {"blacklisted": -1, "source": "IPQualityScore", "details": f"API request failed (status {response.status_code})."}
                    # domain_cache.set(self.domain, out)
                    return _set_cache_and_return(out)
                data = response.json()
                if not data.get("success", True):
                    out = {"blacklisted": -1, "source": "IPQualityScore", "details": data.get("message", "Invalid response")}
                    # domain_cache.set(self.domain, out)
                    return _set_cache_and_return(out)
                    
                # Extract results
                is_phishing = data.get("phishing", False)
                is_malware = data.get("malware", False)
                is_suspicious = data.get("suspicious", False)
                domain_risk = data.get("risk_score", 0)

                if is_phishing or is_malware or is_suspicious or domain_risk > 60:
                    out= {
                        "blacklisted": 1,
                        "source": "IPQualityScore",
                        "details": (
                            f"Detected: phishing={is_phishing}, malware={is_malware}, "
                            f"suspicious={is_suspicious}, risk_score={domain_risk}"
                        )
                    }
                    domain_cache.set(self.domain,out)
                    return out
                else:
                    out={
                        "blacklisted": 0,
                        "source": "IPQualityScore",
                        "details": f"Clean (risk_score={domain_risk})"
                    }
                    domain_cache.set(self.domain,out)
                    return out

            except requests.exceptions.RequestException as e:
                out = {"blacklisted": -1, "source": "IPQualityScore", "details": str(e)}
                domain_cache.set(self.domain, out)
                return out
        else:
            logger.debug("IPQS_API_KEY not set. Skipping IPQS check.")
        # Final structured fallback
        out = {"blacklisted": -1, "source": "unknown", "details": "Blacklist checks failed or were skipped."}
        domain_cache.set(self.domain, out)
        return out
        # 2. IPQualityScore Fallback
        # if IPQS_API_KEY:
        #     try:
        #         ipqs_url =f"https://ipqualityscore.com/api/json/url/{IPQS_API_KEY}/{self.url}"
        #         params={"strictness":1,"fast":"false","timeout":5}
        #         response=requests.get(ipqs_url,params=params,timeout=8)
        #         if response.status_code==200:
        #             data=response.json()
        #             if data.get("success") is False:
        #                 return {"blacklisted":-1,"source":"IPQS", "details": data.get("message", "Unknown error.")}
                        
        #             is_phishing=data.get("phishing",False)
        #             is_malware=data.get("malware",False)
        #             is_suspicious=data.get("suspicious",False)
        #             domain_risk=data.get("risk_score",0)


        #             if is_phishing or is_malware or is_suspicious or domain_risk > 60:
        #                 return {
        #                     "blacklisted": 1,
        #                     "source": "IPQualityScore",
        #                     "details": f"Detected: phishing={is_phishing}, malware={is_malware}, suspicious={is_suspicious}, risk_score={domain_risk}"
        #                 }
        #             else:
        #                 return {
        #                     "blacklisted": 0,
        #                     "source": "IPQualityScore",
        #                     "details": f"Clean (risk_score={domain_risk})"
        #                 }
        #         else:
        #             print(f"IPQS returned status {response.status_code}")
        #     except Exception as e:
        #         print("IPQS check failed:", str(e))
        # else:   
        #     print("IPQS_API_KEY not set. Skipping IPQS check.")
        #     return {"blacklisted": -1, "source": "IPQualityScore", "details": "Missing API key."}
          



        #  2. PhishTank Check (Fallback, using cached data) 
        # phish_data = self._fetch_phishtank_data()
        # if phish_data:
        #     url_to_check = self.url.lower().rstrip('/')
        #     for entry in phish_data:
        #         entry_url = entry.get("url", "").lower().rstrip('/')
        #         # Check for exact URL or domain match (more accurate than substring)
        #         if url_to_check == entry_url or (self.domain and self.domain.lower() in entry_url):
        #             return {"blacklisted": 1, "source": "PhishTank", "details": "URL or Domain found in PhishTank database"}
            
        #     return {"blacklisted": 0, "source": "safe", "details": "URL not found in blacklists."}
        
        #  3. Final Fallback (If no check succeeded) 
        return {"blacklisted": -1, "source": "unknown", "details": "Blacklist checks failed or were skipped (missing API key/data download failed)."}
    
    
    
    
    
  
    def run_all(self):
        """Collects and returns all features as a dictionary."""
        blacklist_result=self.check_blacklist()
        ip = self.resolve_ip()
        geo = self.get_ip_geolocation(ip)

        return {
            "url_length": self.get_url_length(),
            "domain_length": self.get_domain_length(),
            "dots": self.count_dots(),
            "hyphens": self.count_hyphens(),
            "has_ip":self.has_ip(),
            "ip_address": ip,

            "suspicious_keywords": self.count_suspicious_keywords(),
            "has_at": self.has_at_symbol(),
            "https": self.has_https(),

            "domain_age": self.get_domain_age(),
            "domain_expiry": self.get_domain_expiry(),
            "dns_record": self.dns_records_exist(),

            "ip_geolocation":geo,

            "iframe": self.has_iframe(),
            "input_tags": self.count_input_tags(),
            "favicon_check": self.check_favicon(),
            "external_scripts_ratio": round(self.external_scripts_ratio(), 4),

            "ssl": self.has_ssl_certificate(),
            "ssl_issuer": self.check_certificate_issuer(),
            "ssl_issuer_known": self.ssl_issuer_known(),

            "blacklist":blacklist_result,
            "raw_blacklist_result": blacklist_result,
            "blacklist_flag": blacklist_result.get("blacklisted",-1),

            "entropy": round(self.domain_entropy(), 4),
            "ttl": self.ttl_value(),
            "title_mismatch": self.title_mismatch(),

            "ip_latitude": geo["latitude"],
            "ip_longitude": geo["longitude"],
            "ip_country_code": self.encode_text(geo["country"]),
            "ip_region_code": self.encode_text(geo["region"]),
            "ip_city_code": self.encode_text(geo["city"]),
            "ip_org_code": self.encode_text(geo["org"]),


            'tld':self.get_tld(),

            # "special_chars": 0,
            # "special_char_ratio": 0.0,
            # "num_special_chars": 0,
            #     "specialchar_count": 0,
            #     "special_character_count": 0,
        }

#  Execution 

def extract_features(url: str, fetch_page: bool = True):
    """Instantiates and runs the FeatureExtractor class."""
    fe = FeatureExtractor(url, fetch_page=fetch_page)
    return fe.run_all()

if __name__ == "__main__":
    # Test cases to demonstrate fixes
    print("--- Testing Feature Extractor ---")
    
   
    
    test_url_safe = "https://www.google.com/search"
    print(f"\nTesting: {test_url_safe}")
    features_safe = extract_features(test_url_safe)
    print(f"Domain Age: {features_safe.get('domain_age')}") # Likely -1 if WHOIS blocks it
    print(f"Blacklist Flag: {features_safe.get('blacklist_flag')}")
   
    
    
