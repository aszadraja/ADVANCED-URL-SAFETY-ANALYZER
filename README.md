# 🛡️ Advanced URL Safety Analyzer

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-2.3-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Status](https://img.shields.io/badge/Status-Active-brightgreen.svg)

> A comprehensive web security analysis tool that checks website safety across multiple dimensions — SSL certificates, hosting info, CDN detection, threat intelligence, and content security.

![Project Banner](screenshots/banner.png)

---

## 📖 Table of Contents

- [About the Project](#-about-the-project)
- [Features](#-features)
- [Screenshots](#-screenshots)
- [Tech Stack](#-tech-stack)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Usage](#-usage)
- [How It Works](#-how-it-works)
- [API Reference](#-api-reference)
- [Project Structure](#-project-structure)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)
- [Author](#-author)
- [Acknowledgments](#-acknowledgments)

---

## 🎯 About the Project

The **Advanced URL Safety Analyzer** is a full-stack web security tool that helps users verify whether a website is safe to visit before clicking on suspicious links.

### 💡 The Problem
Every day, millions of users fall victim to phishing attacks, malware sites, and fraudulent URLs. Traditional URL checkers only show basic SSL info — they miss critical security indicators like CDN detection, threat intelligence, and content analysis.

### ✅ Our Solution
Our analyzer performs **15+ security checks** in real-time, including:
- Advanced SSL/TLS certificate inspection
- Real IP resolution with **CDN detection** (Cloudflare, Akamai, AWS CloudFront)
- Threat intelligence integration
- JavaScript security analysis
- Privacy & tracking assessment
- Multi-factor risk scoring

### 🎯 Why It's Different
Unlike basic URL checkers, our tool **detects when websites hide behind CDNs** — a critical feature that reveals the true hosting infrastructure behind any website.

---

## ✨ Features

### 🔒 Security Analysis
- **SSL/TLS Certificate Verification** — Checks validity, expiry, and issuer
- **Real IP Resolution** — Gets actual server IPs, not just cached DNS
- **CDN Detection** — Identifies Cloudflare, Akamai, AWS CloudFront, Fastly, Google Cloud
- **DNS Analysis** — Multiple A records and load balancing detection

### 🕵️ Threat Intelligence
- **Phishing Pattern Detection** — Identifies suspicious domain keywords
- **Malware Indicator Scanning** — Detects suspicious TLDs and IP-based URLs
- **Reputation Scoring** — 0-100 reputation score based on multiple factors
- **Brand Impersonation Detection** — Catches fake versions of popular sites

### 📄 Content Analysis
- **Website Purpose Identification** — E-commerce, blog, corporate, etc.
- **Form Detection** — Login/payment form identification
- **Technology Stack** — Detects React, WordPress, Bootstrap, etc.
- **Metadata Extraction** — Title, description, keywords

### ⚠️ Risk Assessment
- **Multi-Factor Scoring** — Weighted risk calculation
- **Security Scorecard** — Category-wise security scores
- **Actionable Recommendations** — Specific fixes for each issue
- **Warning System** — Priority-based security alerts

### 🎨 User Experience
- **Clean Modern UI** — Professional design with smooth animations
- **Real-Time Analysis** — Instant results with progress tracking
- **Responsive Design** — Works on desktop, tablet, and mobile
- **Batch Processing** — Analyze multiple URLs at once

---

## 📸 Screenshots

### 🏠 Main Interface
![Main Interface](screenshots/main-interface.png)
*Clean, modern interface with intuitive URL input*

### 📊 Analysis Results
![Analysis Results](screenshots/results.png)
*Comprehensive security analysis with detailed cards*

### 🔍 CDN Detection
![CDN Detection](screenshots/cdn-detection.png)
*Intelligent CDN detection showing Cloudflare/Akamai infrastructure*

### ⚠️ Security Warnings
![Security Warnings](screenshots/warnings.png)
*Clear warning system with actionable recommendations*

### 📱 Mobile View
![Mobile View](screenshots/mobile.png)
*Fully responsive design for mobile devices*

---

## 🛠️ Tech Stack

### Backend
- **Python 3.8+** — Core language
- **Flask 2.3** — Web framework
- **Flask-CORS** — Cross-origin support

### Security Libraries
- **OpenSSL** — SSL/TLS certificate analysis
- **dnspython** — Advanced DNS resolution
- **python-whois** — Domain registration lookup
- **tldextract** — Domain parsing
- **BeautifulSoup4** — HTML content parsing

### Frontend
- **HTML5** — Modern semantic markup
- **CSS3** — Custom properties, flexbox, grid
- **Vanilla JavaScript** — No framework overhead
- **Font Awesome** — Professional icons

### External APIs
- **ipapi.co** — IP geolocation
- **ipinfo.io** — Backup IP intelligence
- **Google DNS API** — Reliable DNS resolution

---

## 🏗️ Architecture
┌─────────────────┐
│ User Input │
│ (URL) │
└────────┬────────┘
│
▼
┌─────────────────┐
│ Flask Backend │
│ (app.py) │
└────────┬────────┘
│
┌────┴────┬──────────┬──────────┐
▼ ▼ ▼ ▼
┌────────┐ ┌─────┐ ┌─────────┐ ┌────────┐
│ SSL │ │ IP │ │ Content │ │Threat │
│Analysis│ │ + │ │Analysis │ │Intel │
│ │ │ CDN │ │ │ │ │
└────────┘ └─────┘ └─────────┘ └────────┘
│
▼
┌─────────────────┐
│ Risk Scoring │
│ Algorithm │
└────────┬────────┘
│
▼
┌─────────────────┐
│ JSON Response │
│ + UI Display │
└─────────────────┘

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Git (for cloning)

### Steps

**1. Clone the repository**
```bash
git clone https://github.com/YOUR_USERNAME/url-safety-analyzer.git
cd url-safety-analyzer

2. Create a virtual environment
bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# Mac/Linux
python3 -m venv .venv
source .venv/bin/activate

3. Install dependencies
bash
pip install -r requirements.txt

4. Run the application
bash
python app.py

5. Open in browser
text
http://localhost:5000
🚀 Usage
Single URL Analysis
Open the app at http://localhost:5000
Enter a URL (e.g., https://google.com)
Click "Analyze URL"

View comprehensive results:
Security status (Safe/Unsafe/Warning)
SSL certificate details
Hosting & CDN information
Security warnings

Content analysis:
Example URLs to Test
URL	Expected Result
https://google.com	✅ Safe, Direct Server
https://tryhackme.com	✅ Safe, Behind Cloudflare
https://amazon.com	✅ Safe, Behind Akamai
https://github.com	✅ Safe, Direct Server
https://example.com	✅ Safe

🔬 How It Works
The Analysis Pipeline
text
1. URL Validation
   ↓
2. Website Accessibility Check
   ↓
3. SSL Certificate Analysis
   ↓
4. IP + CDN Detection
   ↓
5. Content Analysis
   ↓
6. Threat Intelligence Scan
   ↓
7. Risk Scoring
   ↓
8. Report Generation
Risk Scoring Algorithm
The tool uses a weighted scoring system across multiple security factors:

Factor	Weight	What It Checks
SSL/TLS	40%	Certificate validity, expiry, issuer trust
Domain Trust	20%	Domain age, suspicious patterns
Security Headers	20%	HSTS, X-Frame-Options, CSP
Content Risks	20%	Login forms, malicious scripts
Risk Levels:

0-29 points → ✅ SAFE (Low risk)

30-59 points → ⚠️ NEEDS CAUTION (Medium risk)

60+ points → ❌ UNSAFE (High risk)

CDN Detection
The tool identifies when a website uses a CDN by matching the IP against known CDN ranges:

python
cdn_ranges = {
    'Cloudflare': ['104.16.', '104.17.', '172.67.', ...],
    'Akamai': ['23.', '104.64.', ...],
    'AWS CloudFront': ['13.32.', '52.84.', ...],
    'Fastly': ['151.101.', '199.232.'],
    'Google Cloud CDN': ['34.', '35.', ...]
}
🔌 API Reference
Analyze URL
Endpoint: POST /api/analyze-url

Request:

json
{
  "url": "https://example.com"
}
Response:

json
{
  "url": "https://example.com",
  "is_safe": true,
  "risk_level": "low",
  "ssl_info": {
    "has_ssl": true,
    "valid_ssl": true,
    "days_until_expiry": 120,
    "issuer": "Let's Encrypt"
  },
  "hosting_info": {
    "ip_address": "93.184.216.34",
    "ip_addresses": ["93.184.216.34"],
    "country": "United States",
    "cdn_info": {
      "uses_cdn": false,
      "cdn_provider": "Direct Server"
    }
  },
  "security_analysis": {
    "has_https": true,
    "response_time": 245
  },
  "warnings": []
}
Health Check
Endpoint: GET /health

Response:

json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00"
}
📁 Project Structure
text
url-safety-analyzer/
│
├── app.py                     # Main Flask application
├── requirements.txt           # Python dependencies
├── .gitignore                # Git ignore rules
├── README.md                 # This file
├── LICENSE                   # MIT License
│
├── templates/                # HTML templates
│   └── index.html           # Main UI
│
├── static/                   # Static assets (optional)
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── app.js
│
└── screenshots/              # Documentation images
    ├── banner.png
    ├── main-interface.png
    ├── results.png
    └── cdn-detection.png
🗺️ Roadmap
✅ Completed
☑ SSL/TLS certificate analysis
☑ Real IP resolution
☑ CDN detection (Cloudflare, Akamai, AWS)
☑ Content analysis with forms detection
☑ Threat intelligence scanning
☑ Multi-factor risk scoring
☑ Modern responsive UI
🚧 In Progress
□ Google Safe Browsing API integration
□ VirusTotal API integration
□ Batch URL analysis (CSV upload)
□ Historical tracking dashboard
🔮 Future Plans
□ Machine learning for phishing detection
□ Browser extension for real-time protection
□ Mobile app (iOS/Android)
□ Public REST API with rate limiting
□ Blockchain-verified security certificates
□ Dark web monitoring
🤝 Contributing
Contributions are welcome! Here's how:
Fork the repository
Create a feature branch (git checkout -b feature/AmazingFeature)
Commit your changes (git commit -m 'Add some AmazingFeature')
Push to the branch (git push origin feature/AmazingFeature)
Open a Pull Request

Development Guidelines
Follow PEP 8 for Python code
Add comments for complex logic
Update README if adding features
Test locally before submitting PR

📄 License
This project is licensed under the MIT License — see the LICENSE file for details.

👨‍💻 Author
Aszad Raja
🎓 Student at [CGC UNIVERSITY]
💼 https://www.linkedin.com/in/aszad-raja-a7725b2b8
🐙 @aszadraja
📧 aszadraja039@gmail.com

🏆 Team Members:
Kunal Kumar — Lead Developer
Tanish — Frontend Developer
Aszad Raja — Security Analyst

🙏 Acknowledgments
Flask Documentation
OpenSSL Python Bindings
BeautifulSoup Documentation
ipapi.co — Free IP geolocation API
Font Awesome — Icons
Shields.io — README badges

📊 Project Stats
https://img.shields.io/github/stars/YOUR_USERNAME/url-safety-analyzer?style=social
https://img.shields.io/github/forks/YOUR_USERNAME/url-safety-analyzer?style=social
https://img.shields.io/github/issues/YOUR_USERNAME/url-safety-analyzer
https://img.shields.io/github/last-commit/YOUR_USERNAME/url-safety-analyzer

<div align="center">
⭐ Star this repository if you found it helpful!

Made with ❤️ for a safer internet

# 🛡️ Advanced URL Safety Analyzer
A comprehensive web security tool that analyzes websites for threats, SSL issues, and CDN infrastructure.

## ✨ Features

- 🔒 SSL/TLS certificate analysis
- 🌐 Real IP resolution + CDN detection (Cloudflare, Akamai, AWS)
- 🕵️ Threat intelligence & phishing detection
- 📄 Content & form analysis
- ⚠️ Multi-factor risk scoring

## 🛠️ Tech Stack

**Backend:** Python, Flask, OpenSSL, BeautifulSoup
**Frontend:** HTML5, CSS3, JavaScript
**APIs:** ipapi.co, Google DNS

## 📦 Installation
```bash

git clone https://github.com/YOUR_USERNAME/url-safety-analyzer.git
cd url-safety-analyzer
python -m venv .venv
.venv\Scripts\activate  # Windows
pip install -r requirements.txt
python app.py
Open http://localhost:5000

🔬 How It Works
Validates URL format
Checks website accessibility
Analyzes SSL certificate
Resolves real IP + detects CDN
Scans content for threats
Calculates risk score
Generates report

Risk Levels:
0-29 → ✅ Safe
30-59 → ⚠️ Caution
60+ → ❌ Unsafe

📁 Structure
text
url-safety-analyzer/
├── app.py
├── requirements.txt
├── templates/index.html
└── README.md
📄 License
MIT License — see LICENSE

👨‍💻 Author
Aszad Raja
GitHub: @aszadraja
LinkedIn:https://www.linkedin.com/in/aszad-raja-a7725b2b8

⭐ Star this repo if you find it useful!
