import re
import socket
import requests
import whois
import tldextract
import dns.resolver
import ssl
import datetime
from bs4 import BeautifulSoup

class FeatureExtractor:
    def __init__(self, url):
        self.url = url
        self.domain_info = tldextract.extract(url)
        self.domain = self.domain_info.registered_domain
        self.subdomain = self.domain_info.subdomain
        self.suffix = self.domain_info.suffix

    # 1. Lexical Features
    def get_url_length(self):
        return len(self.url)

    def get_domain_length(self):
        return len(self.domain)

    def count_dots(self):
        return self.url.count('.')

    def count_hyphens(self):
        return self.url.count('-')

    def has_ip(self):
        return 1 if re.match(r"(\d{1,3}\.){3}\d{1,3}", self.domain) else 0

    def count_suspicious_keywords(self):
        keywords = ["login", "secure", "update", "bank", "signin", "account"]
        return sum([self.url.lower().count(k) for k in keywords])

    # 2. Host-Based Features
    def get_whois_info(self):
        try:
            w = whois.whois(self.domain)
            return w
        except:
            return None

    def get_domain_age(self):
        w = self.get_whois_info()
        if w and w.creation_date:
            if isinstance(w.creation_date, list):
                creation_date = w.creation_date[0]
            else:
                creation_date = w.creation_date
            return (datetime.datetime.now() - creation_date).days
        return -1

    def get_domain_expiry(self):
        w = self.get_whois_info()
        if w and w.expiration_date:
            if isinstance(w.expiration_date, list):
                expiry_date = w.expiration_date[0]
            else:
                expiry_date = w.expiration_date
            return (expiry_date - datetime.datetime.now()).days
        return -1

    def dns_records_exist(self):
        try:
            dns.resolver.resolve(self.domain, 'A')
            return 1
        except:
            return 0

    def get_ip_geolocation(self):
        # Placeholder (use ipinfo or MaxMind API)
        return "Unknown"

    # 3. Content-Based Features
    def fetch_page(self):
        try:
            resp = requests.get(self.url, timeout=5)
            return resp.text
        except:
            return None

    def has_iframe(self):
        html = self.fetch_page()
        if html:
            return 1 if "<iframe" in html else 0
        return 0

    def count_input_tags(self):
        html = self.fetch_page()
        if html:
            soup = BeautifulSoup(html, "html.parser")
            return len(soup.find_all("input"))
        return -1

    def check_favicon(self):
        html = self.fetch_page()
        if html:
            soup = BeautifulSoup(html, "html.parser")
            icon = soup.find("link", rel="icon")
            if icon and self.domain not in str(icon.get("href", "")):
                return 1
        return 0

    def external_scripts_ratio(self):
        html = self.fetch_page()
        if html:
            soup = BeautifulSoup(html, "html.parser")
            scripts = soup.find_all("script", src=True)
            if not scripts: return 0
            external = [s for s in scripts if self.domain not in s['src']]
            return len(external) / len(scripts)
        return 0

    # 4. SSL/Network Features
    def has_ssl_certificate(self):
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=self.domain) as s:
                s.settimeout(3)
                s.connect((self.domain, 443))
                cert = s.getpeercert()
                return 1 if cert else 0
        except:
            return 0

    def check_certificate_issuer(self):
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=self.domain) as s:
                s.settimeout(3)
                s.connect((self.domain, 443))
                cert = s.getpeercert()
                return cert.get("issuer", "")
        except:
            return "Unknown"

    def alexa_rank(self):
        # Placeholder: needs API integration
        return -1

    def check_blacklist(self):
        # Placeholder: integrate Google Safe Browsing or PhishTank API
        return 0

    # 5. Advanced Features (Unique)
    def domain_entropy(self):
        import math
        prob = [self.domain.count(c)/len(self.domain) for c in set(self.domain)]
        return -sum([p*math.log(p, 2) for p in prob])

    def ttl_value(self):
        try:
            ans = dns.resolver.resolve(self.domain, 'A')
            return ans.rrset.ttl
        except:
            return -1

    def title_mismatch(self):
        html = self.fetch_page()
        if html:
            soup = BeautifulSoup(html, "html.parser")
            title = soup.title.string if soup.title else ""
            if self.domain.split('.')[0].lower() not in title.lower():
                return 1
        return 0
    # def get_features(url):
    
    #         features = {}
    #         features['url_length'] = len(url)
    #         features['has_https'] = 1 if url.startswith("https") else 0
    #         features['num_dots'] = url.count('.')
    #         # (Add more advanced features here like DNS, suspicious words, etc.)

    # return features
    





    def run_all(self):
        return {
            "url_length": self.get_url_length(),
            "domain_length": self.get_domain_length(),
            "dots": self.count_dots(),
            "hyphens": self.count_hyphens(),
            "has_ip": self.has_ip(),
            "suspicious_keywords": self.count_suspicious_keywords(),
            "domain_age": self.get_domain_age(),
            "domain_expiry": self.get_domain_expiry(),
            "dns_record": self.dns_records_exist(),
            "ip_geolocation": self.get_ip_geolocation(),
            "iframe": self.has_iframe(),
            "input_tags": self.count_input_tags(),
            "favicon_check": self.check_favicon(),
            "external_scripts_ratio": self.external_scripts_ratio(),
            "ssl": self.has_ssl_certificate(),
            "ssl_issuer": self.check_certificate_issuer(),
            "alexa_rank": self.alexa_rank(),
            "blacklist": self.check_blacklist(),
            "entropy": self.domain_entropy(),
            "ttl": self.ttl_value(),
            "title_mismatch": self.title_mismatch()
        }
   
