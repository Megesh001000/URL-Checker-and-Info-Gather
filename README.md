# 🛡️ CHECK URL --- URL Safety & Phishing Detection Platform

> A Django-based cybersecurity application for detecting suspicious and
> phishing URLs across web pages, emails, and file attachments.

## 📌 Overview

**CHECK URL** is a web-based URL safety and phishing-detection system
built with Python and Django.

The platform combines URL analysis, reputation intelligence, technical
inspection, and machine-learning-based prediction. It also extends URL
analysis to Gmail messages and uploaded attachments.

### Core modules

-   🔗 URL Scanner
-   📧 Email Scanner
-   📎 Attachment Scanner
-   📊 Dashboard
-   🕘 Scan History
-   🚨 Phishing Alerts
-   🧠 Machine-Learning URL Analysis

## ✨ Features

### 🔗 URL Scanner

The URL scanner can analyze:

-   IP address and IP geolocation
-   Country, region, city, and organization
-   Domain age and expiry
-   DNS records
-   HTTPS status
-   SSL issuer, validity, and expiry
-   Redirect behavior
-   HTML characteristics
-   Forms and iframes
-   JavaScript includes
-   Entropy-related features
-   Blacklist/reputation information
-   Google Safe Browsing information
-   VirusTotal results
-   Machine-learning prediction and score
-   Final Safe / Malicious classification

> Security providers can disagree, so an individual signal should not
> automatically be interpreted as proof that a website is malicious.

### 📧 Email Scanner

The email module connects to Gmail through OAuth 2.0 and IMAP.

Workflow:

``` text
Scan Emails
    ↓
Load Gmail OAuth credentials
    ↓
Refresh expired access token when possible
    ↓
Connect to Gmail IMAP
    ↓
Fetch unseen emails
    ↓
Parse email
    ↓
Extract URLs
    ↓
Run URL analysis
    ↓
Determine phishing status
    ↓
Store processed email
    ↓
Send alert when phishing is detected
```

URLs can be extracted from both plain-text email bodies and HTML `href`
attributes.

### 📎 Attachment Scanner

The attachment module accepts files such as:

-   PDF
-   DOCX
-   XLSX
-   TXT
-   ZIP
-   CSV
-   HTML
-   EML

The general workflow is:

``` text
Upload file
    ↓
Django attachment endpoint
    ↓
Process file
    ↓
Extract URLs
    ↓
Analyze URLs
    ↓
Display result
```

### 📊 Dashboard and History

The application provides pages for viewing scan activity and previously
processed information. Email processing stores information such as email
ID, subject, sender, URL presence, and phishing status.

### 🚨 Phishing Alerts

When phishing is detected in an email, the notification can include the
suspicious URL, IP address, location, organization, SSL issuer, and
entropy information.

## 🧠 Architecture

``` text
                     ┌────────────────────┐
                     │     CHECK URL      │
                     │    Django App      │
                     └─────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
              ▼                ▼                ▼
        URL Scanner       Email Scanner    Attachment Scanner
              │                │                │
              │                ▼                ▼
              │          Extract URLs      Extract URLs
              │                │                │
              └────────────────┼────────────────┘
                               ▼
                     ┌──────────────────┐
                     │ URL Analysis     │
                     │ Pipeline         │
                     └────────┬─────────┘
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
     Reputation          Technical           ML Analysis
       Checks             Analysis             / Score
          │                   │                   │
          └───────────────────┼───────────────────┘
                              ▼
                    ┌──────────────────┐
                    │ Final Decision   │
                    │ Safe / Malicious │
                    └────────┬─────────┘
                             │
                 ┌───────────┴───────────┐
                 ▼                       ▼
             Dashboard                Alerts
                 │
                 ▼
              History
```

## 🧩 Technology Stack

### Backend

-   Python
-   Django
-   Django ORM
-   `asyncio`
-   `asyncio.to_thread()` for blocking operations in async flows

### Frontend

-   HTML5
-   CSS3
-   JavaScript
-   Bootstrap 5
-   Font Awesome
-   Google Fonts

### Database

-   MySQL

### Email

-   Gmail IMAP
-   Gmail OAuth 2.0
-   SMTP/OAuth-based notification support

### Security Intelligence

-   VirusTotal
-   Google Safe Browsing
-   DNS information
-   SSL/TLS analysis
-   IP/network information
-   Domain information
-   Machine-learning URL prediction

## 📁 Suggested Project Structure

``` text
URL_SAFETY_CHECKER/
│
├── manage.py
├── requirements.txt
├── README.md
├── .env
├── .gitignore
│
├── url_checker/
│   ├── settings.py
│   ├── urls.py
│   ├── asgi.py
│   └── wsgi.py
│
├── detection/
│   ├── migrations/
│   ├── ml/
│   │   └── ml_utils.py
│   ├── templates/
│   │   └── detection/
│   ├── static/
│   │   └── detection/
│   │       ├── css/
│   │       └── js/
│   ├── models.py
│   ├── views.py
│   └── urls.py
│
└── gmail_scanner/
    ├── gmail_parser.py
    ├── gmail_auth.py
    └── ...
```

> Keep this section synchronized with your actual repository structure
> before publishing.

## ⚙️ Installation

### 1. Clone the repository

``` bash
git clone <your-repository-url>
cd URL_SAFETY_CHECKER
```

### 2. Create a virtual environment

Windows:

``` powershell
python -m venv venv
venv\Scripts\activate
```

Linux/macOS:

``` bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

``` bash
pip install -r requirements.txt
```

If you are creating `requirements.txt` for the first time, activate the
virtual environment and run:

``` bash
pip freeze > requirements.txt
```

### 4. Configure environment variables

Create `.env` in the project root.

Example:

``` env
SECRET_KEY=your-django-secret-key
DEBUG=True

DB_NAME=your_database
DB_USER=your_database_user
DB_PASSWORD=your_database_password
DB_HOST=127.0.0.1
DB_PORT=3306

GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REFRESH_TOKEN=your-refresh-token
GOOGLE_OAUTH_USER=your-email@gmail.com

GOOGLE_TOKEN_PATH=token.json

IMAP_HOST=imap.gmail.com
IMAP_PORT=993

VIRUSTOTAL_API_KEY=your-api-key
```

Only include variables actually used by your current implementation.

### 5. Database migration

``` bash
python manage.py makemigrations
python manage.py migrate
```

Create an administrator:

``` bash
python manage.py createsuperuser
```

### 6. Run the application

``` bash
python manage.py runserver
```

Open:

``` text
http://127.0.0.1:8000/
```

## 📧 Gmail OAuth Setup

The email scanner requires Gmail OAuth configuration.

General steps:

1.  Create a Google Cloud project.
2.  Configure the required Gmail OAuth/API settings.
3.  Create OAuth credentials.
4.  Authorize the Gmail account used by the scanner.
5.  Obtain the required refresh token.
6.  Configure the credentials through environment variables/token
    configuration.
7.  Never commit OAuth secrets or `token.json` to Git.

## 🔐 Security

Never commit secrets such as:

``` text
.env
token.json
client secrets
API keys
database passwords
private keys
```

Recommended `.gitignore` entries:

``` gitignore
.env
token.json
*.pem
*.key
__pycache__/
*.pyc
venv/
.venv/
media/
```

## 🧪 Testing Checklist

### URL scanner

-   Safe URLs
-   Suspicious URLs
-   HTTP and HTTPS
-   Redirecting URLs
-   Invalid URLs
-   Domains with missing WHOIS information
-   Domains with incomplete SSL information

### Email scanner

-   Email without URLs
-   Email with one URL
-   Email with multiple URLs
-   HTML links
-   Plain-text links
-   Safe URLs
-   Suspicious URLs
-   Expired OAuth access token

### Attachment scanner

-   TXT
-   PDF
-   DOCX
-   XLSX
-   CSV
-   HTML
-   EML
-   ZIP
-   Invalid files
-   Files containing multiple URLs

## ⚠️ Known Limitations

-   External APIs can time out or become unavailable.
-   Some websites block automated requests.
-   IP geolocation identifies infrastructure location, not necessarily
    the website operator's physical location.
-   Domain and WHOIS data may be unavailable.
-   SSL information may be incomplete.
-   Reputation providers can disagree.
-   Machine-learning models can produce false positives and false
    negatives.
-   CDNs, proxies, cloud hosting, and shared infrastructure can make
    IP-based conclusions less precise.
-   Email tracking links are not automatically phishing.
-   JavaScript-generated URLs may not be visible through basic HTML
    extraction.

## 🚀 Production Deployment

Do not use Django's development server as a production server.

A typical production architecture is:

``` text
Internet
   ↓
Nginx
   ↓
Gunicorn / Uvicorn
   ↓
Django
   ↓
MySQL
```

For production, configure at minimum:

-   `DEBUG=False`
-   Strong `SECRET_KEY`
-   Correct `ALLOWED_HOSTS`
-   HTTPS
-   Secure cookies
-   CSRF protection
-   Database credentials
-   API-key protection
-   Upload-size limits
-   Logging and monitoring
-   Static/media deployment

## 🔮 Future Improvements

-   [ ] Background scanning with Celery
-   [ ] Redis task queue
-   [ ] Improved ML model
-   [ ] URL reputation caching
-   [ ] Additional threat-intelligence providers
-   [ ] Attachment hash/malware analysis
-   [ ] YARA-based file analysis
-   [ ] Improved email classification
-   [ ] User authentication
-   [ ] Role-based access
-   [ ] Per-user scan history
-   [ ] REST API
-   [ ] API authentication
-   [ ] Rate limiting
-   [ ] Docker deployment
-   [ ] Automated tests
-   [ ] CI/CD
-   [ ] Production monitoring

## 🤝 Contributing

Create a feature branch:

``` bash
git checkout -b feature/new-detection
```

Then:

``` bash
git add .
git commit -m "Add new detection feature"
git push origin feature/new-detection
```

Open a pull request describing:

-   What changed
-   Why it changed
-   How it was tested
-   Screenshots when useful

## 📜 License

Choose a license before publishing the repository publicly.

For example:

``` text
MIT License
```

Do not claim a license unless you have intentionally selected one.

## 🛡️ Security Notice

This project is intended for defensive security research, education, and
authorized analysis. Only scan URLs, emails, files, and systems that you
are authorized to analyze.

------------------------------------------------------------------------

## ⭐ CHECK URL

**URL Safety & Phishing Detection Platform**

Built with Python, Django, machine learning, threat-intelligence
services, Gmail OAuth/IMAP, and web security analysis.
