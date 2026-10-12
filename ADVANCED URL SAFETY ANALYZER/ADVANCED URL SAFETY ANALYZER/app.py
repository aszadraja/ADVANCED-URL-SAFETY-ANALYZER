from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import requests
import re
import urllib.parse
from datetime import datetime
import whois
import ssl
import socket
import OpenSSL
from urllib3.util.connection import create_connection
import dns.resolver
import time
from bs4 import BeautifulSoup
import tldextract
import ipaddress
import traceback

app = Flask(__name__)
CORS(app)


class AdvancedURLSafetyChecker:
    def __init__(self):
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

    # ============================================================
    # MAIN ANALYSIS METHOD (FIXED - has complete try/except)
    # ============================================================
    def analyze_url(self, url):
        """Comprehensive URL analysis with real-time checks"""
        try:
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc

            analysis_result = {
                'url': url,
                'domain': domain,
                'is_safe': True,
                'risk_level': 'low',
                'warnings': [],
                'ssl_info': {},
                'hosting_info': {},
                'security_analysis': {},
                'content_analysis': {},
                'timestamp': datetime.now().isoformat()
            }

            # Check if website actually exists and is accessible
            accessibility_check = self.check_website_accessibility(url)
            analysis_result['security_analysis'].update(accessibility_check)

            if not accessibility_check['exists']:
                analysis_result['is_safe'] = False
                analysis_result['risk_level'] = 'high'
                analysis_result['warnings'].append('Website does not exist or is not accessible')
                return analysis_result

            # Perform comprehensive SSL analysis
            ssl_analysis = self.comprehensive_ssl_analysis(domain)
            analysis_result['ssl_info'] = ssl_analysis

            # Analyze hosting information (now with CDN detection)
            hosting_analysis = self.analyze_hosting_info(domain)
            analysis_result['hosting_info'] = hosting_analysis

            # Analyze domain and URL structure
            domain_analysis = self.analyze_domain_structure(url, domain)
            analysis_result['security_analysis'].update(domain_analysis)

            # Fetch and analyze website content
            content_analysis = self.analyze_website_content(url)
            analysis_result['content_analysis'] = content_analysis

            # Determine overall safety
            analysis_result = self.calculate_risk_score(analysis_result)

            return analysis_result

        except Exception as e:
            print(f"❌ Error in analyze_url: {str(e)}")
            print(traceback.format_exc())
            return {
                'url': url,
                'is_safe': False,
                'risk_level': 'high',
                'warnings': [f'Analysis error: {str(e)}'],
                'error': str(e)
            }

    # ============================================================
    # IP + CDN DETECTION METHODS (NEW)
    # ============================================================
    def get_all_ips(self, domain):
        """Get ALL IP addresses for accurate analysis"""
        all_ips = []

        try:
            # Method 1: System DNS via socket
            try:
                addr_info = socket.getaddrinfo(domain, None)
                for info in addr_info:
                    ip = info[4][0]
                    # Filter out IPv6 for simplicity
                    if ':' not in ip and ip not in all_ips:
                        all_ips.append(ip)
            except Exception as e:
                print(f"⚠️ Socket lookup failed: {e}")

            # Method 2: Google DNS API (more reliable)
            try:
                response = requests.get(
                    f'https://dns.google/resolve?name={domain}&type=A',
                    timeout=5
                )
                if response.status_code == 200:
                    data = response.json()
                    if 'Answer' in data:
                        for answer in data['Answer']:
                            if answer['type'] == 1:  # A record
                                if answer['data'] not in all_ips:
                                    all_ips.append(answer['data'])
            except Exception as e:
                print(f"⚠️ Google DNS lookup failed: {e}")

            return all_ips

        except Exception as e:
            print(f"❌ Error getting IPs: {e}")
            return []

    def detect_cdn(self, domain, ip_address):
        """Detect if website uses CDN based on IP ranges"""
        result = {
            'uses_cdn': False,
            'cdn_provider': 'Direct Server',
            'origin_ip_hidden': False,
            'note': ''
        }

        cdn_ranges = {
            'Cloudflare': ['104.16.', '104.17.', '104.18.', '104.19.', '104.20.',
                           '104.21.', '172.67.', '188.114.', '162.159.'],
            'Akamai': ['23.', '104.64.', '184.24.', '184.25.', '184.26.', '184.27.'],
            'AWS CloudFront': ['13.32.', '13.33.', '13.35.', '52.84.', '54.230.', '54.239.'],
            'Fastly': ['151.101.', '199.232.'],
            'Google Cloud CDN': ['34.', '35.', '104.196.', '104.199.'],
            'Sucuri': ['192.124.249.'],
            'StackPath': ['151.139.']
        }

        for provider, prefixes in cdn_ranges.items():
            for prefix in prefixes:
                if ip_address.startswith(prefix):
                    result['uses_cdn'] = True
                    result['cdn_provider'] = provider
                    result['origin_ip_hidden'] = True
                    result['note'] = f'IP belongs to {provider}. Origin server IP is hidden.'
                    return result

        return result

    def detect_cdn_from_headers(self, url):
        """Detect CDN using HTTP response headers"""
        try:
            response = requests.head(url, timeout=5, allow_redirects=True,
                                     headers={'User-Agent': self.user_agent})
            headers = {k.lower(): v for k, v in response.headers.items()}

            if 'cf-ray' in headers or 'cloudflare' in headers.get('server', '').lower():
                return 'Cloudflare'
            if 'x-akamai-transformed' in headers:
                return 'Akamai'
            if 'x-amz-cf-id' in headers:
                return 'AWS CloudFront'
            if 'x-served-by' in headers and 'fastly' in str(headers).lower():
                return 'Fastly'
            if 'x-sucuri-id' in headers:
                return 'Sucuri'

        except Exception as e:
            print(f"⚠️ CDN header detection failed: {e}")

        return None

    def get_detailed_ip_info(self, ip_address):
        """Get geolocation info about an IP address"""
        try:
            # Try ipapi.co first
            response = requests.get(f'https://ipapi.co/{ip_address}/json/', timeout=8)
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country_name', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'region': data.get('region', 'Unknown'),
                    'organization': data.get('org', 'Unknown'),
                    'isp': data.get('org', 'Unknown'),
                    'hosting_provider': self.detect_hosting_provider(data.get('org', ''))
                }
        except Exception as e:
            print(f"⚠️ ipapi.co failed: {e}")

        # Fallback: ipinfo.io
        try:
            response = requests.get(f'https://ipinfo.io/{ip_address}/json', timeout=8)
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'region': data.get('region', 'Unknown'),
                    'organization': data.get('org', 'Unknown'),
                    'isp': data.get('org', 'Unknown'),
                    'hosting_provider': self.detect_hosting_provider(data.get('org', ''))
                }
        except Exception as e:
            print(f"⚠️ ipinfo.io failed: {e}")

        return None

    def detect_hosting_provider(self, org_string):
        """Detect hosting provider from organization string"""
        if not org_string:
            return 'Unknown'

        org_lower = org_string.lower()

        hosting_providers = {
            'amazon': 'Amazon AWS', 'aws': 'Amazon AWS',
            'google': 'Google Cloud', 'gcp': 'Google Cloud',
            'microsoft': 'Microsoft Azure', 'azure': 'Microsoft Azure',
            'cloudflare': 'Cloudflare',
            'digitalocean': 'DigitalOcean',
            'linode': 'Linode', 'akamai': 'Akamai',
            'ovh': 'OVH', 'godaddy': 'GoDaddy',
            'bluehost': 'Bluehost', 'hostgator': 'HostGator',
            'siteground': 'SiteGround', 'heroku': 'Heroku',
            'netlify': 'Netlify', 'vercel': 'Vercel',
            'alibaba': 'Alibaba Cloud', 'oracle': 'Oracle Cloud',
            'ibm': 'IBM Cloud'
        }

        for key, provider in hosting_providers.items():
            if key in org_lower:
                return provider

        return org_string  # Return raw org name if no match

    # ============================================================
    # WEBSITE ACCESSIBILITY
    # ============================================================
    def check_website_accessibility(self, url):
        """Check if website exists and is accessible"""
        result = {
            'exists': False,
            'response_time': None,
            'status_code': None,
            'has_https': url.startswith('https://'),
            'redirects_https': False,
            'final_url': url
        }

        try:
            start_time = time.time()
            response = requests.get(
                url,
                timeout=10,
                headers={'User-Agent': self.user_agent},
                allow_redirects=True,
                verify=True
            )
            end_time = time.time()

            result['response_time'] = round((end_time - start_time) * 1000, 2)
            result['status_code'] = response.status_code
            result['exists'] = 200 <= response.status_code < 400
            result['final_url'] = response.url

            if response.history:
                for resp in response.history:
                    if resp.url.startswith('https://'):
                        result['redirects_https'] = True
                        break

        except requests.exceptions.SSLError as e:
            result['warnings'] = [f'SSL certificate error: {str(e)}']
            result['exists'] = False
        except requests.exceptions.ConnectionError as e:
            result['warnings'] = [f'Connection error: {str(e)}']
            result['exists'] = False
        except requests.exceptions.Timeout:
            result['warnings'] = ['Request timeout: Website took too long to respond']
            result['exists'] = False
        except requests.exceptions.RequestException as e:
            result['warnings'] = [f'Request error: {str(e)}']
            result['exists'] = False
        except Exception as e:
            result['warnings'] = [f'Unexpected error: {str(e)}']
            result['exists'] = False

        return result

    # ============================================================
    # SSL ANALYSIS
    # ============================================================
    def comprehensive_ssl_analysis(self, domain):
        """Perform detailed SSL certificate analysis"""
        result = {
            'has_ssl': False,
            'valid_ssl': False,
            'days_until_expiry': None,
            'issuer': 'Unknown',
            'subject': 'Unknown',
            'certificate_chain': False,
            'error': None
        }

        try:
            domain = domain.split(':')[0]

            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_binary = ssock.getpeercert(binary_form=True)

                    if cert_binary:
                        x509 = OpenSSL.crypto.load_certificate(
                            OpenSSL.crypto.FILETYPE_ASN1, cert_binary
                        )

                        result['has_ssl'] = True

                        # Subject
                        subject = x509.get_subject()
                        subject_components = {}
                        for key, value in subject.get_components():
                            key_str = key.decode('utf-8') if isinstance(key, bytes) else str(key)
                            value_str = value.decode('utf-8') if isinstance(value, bytes) else str(value)
                            subject_components[key_str] = value_str
                        result['subject'] = subject_components.get('CN', 'Unknown')

                        # Issuer
                        issuer = x509.get_issuer()
                        issuer_components = {}
                        for key, value in issuer.get_components():
                            key_str = key.decode('utf-8') if isinstance(key, bytes) else str(key)
                            value_str = value.decode('utf-8') if isinstance(value, bytes) else str(value)
                            issuer_components[key_str] = value_str
                        result['issuer'] = issuer_components.get('CN', 'Unknown')

                        # Expiry
                        not_after = x509.get_notAfter()
                        if not_after:
                            not_after_str = not_after.decode('utf-8') if isinstance(not_after, bytes) else str(not_after)
                            expiry_date = datetime.strptime(not_after_str, '%Y%m%d%H%M%SZ')
                            days_until_expiry = (expiry_date - datetime.now()).days
                            result['days_until_expiry'] = days_until_expiry
                            result['valid_ssl'] = days_until_expiry > 0

                            if days_until_expiry < 30:
                                result['warnings'] = [f'SSL certificate expires in {days_until_expiry} days']

        except ssl.SSLCertVerificationError as e:
            result['error'] = f'SSL verification failed: {str(e)}'
            result['valid_ssl'] = False
        except socket.gaierror as e:
            result['error'] = f'Domain resolution failed: {str(e)}'
        except socket.timeout:
            result['error'] = 'SSL handshake timeout'
        except Exception as e:
            result['error'] = f'SSL analysis error: {str(e)}'

        return result

    # ============================================================
    # HOSTING INFO (NOW WITH CDN DETECTION)
    # ============================================================
    def analyze_hosting_info(self, domain):
        """Analyze hosting provider and server information with CDN detection"""
        result = {
            'ip_address': None,
            'ip_addresses': [],
            'country': 'Unknown',
            'organization': 'Unknown',
            'hosting_provider': 'Unknown',
            'exists': False,
            'error': None,
            'cdn_info': {},
            'origin_type': 'Unknown',
            'note': ''
        }

        try:
            clean_domain = domain.replace('www.', '').split(':')[0]

            # Get ALL IPs
            all_ips = self.get_all_ips(clean_domain)

            if not all_ips:
                result['error'] = 'Could not resolve domain to IP address'
                result['exists'] = False
                return result

            result['ip_addresses'] = all_ips
            result['ip_address'] = all_ips[0]
            result['exists'] = True

            # Detect CDN from IP
            cdn_info = self.detect_cdn(clean_domain, all_ips[0])
            result['cdn_info'] = cdn_info

            # Get geolocation details
            ip_details = self.get_detailed_ip_info(all_ips[0])
            if ip_details:
                result.update(ip_details)

            # Set origin type and note based on CDN detection
            if cdn_info['uses_cdn']:
                result['origin_type'] = f"Behind {cdn_info['cdn_provider']} CDN"
                result['hosting_provider'] = cdn_info['cdn_provider']
                result['note'] = f"⚠️ Real server IP is hidden by {cdn_info['cdn_provider']}"
            else:
                result['origin_type'] = 'Direct Server'
                result['note'] = '✅ Direct server IP (no CDN detected)'

            print(f"✅ IPs found: {all_ips}")
            print(f"📍 CDN: {cdn_info['cdn_provider']}")

        except socket.gaierror as e:
            result['error'] = f'Domain resolution failed: {str(e)}'
            result['exists'] = False
        except Exception as e:
            result['error'] = f'Hosting analysis error: {str(e)}'
            result['exists'] = False

        return result

    # ============================================================
    # DOMAIN STRUCTURE ANALYSIS
    # ============================================================
    def analyze_domain_structure(self, url, domain):
        """Analyze domain for suspicious patterns"""
        result = {
            'valid_domain': False,
            'suspicious_patterns': [],
            'domain_age': 'Unknown',
            'registrar': 'Unknown'
        }

        try:
            extracted = tldextract.extract(domain)
            result['valid_domain'] = bool(extracted.domain and extracted.suffix)

            # Suspicious keywords
            suspicious_keywords = ['login', 'verify', 'secure', 'account', 'banking',
                                   'paypal', 'amazon', 'microsoft', 'apple']
            for keyword in suspicious_keywords:
                if keyword in domain.lower():
                    result['suspicious_patterns'].append(f'Suspicious keyword in domain: {keyword}')

            # Multiple hyphens
            if domain.count('-') > 2:
                result['suspicious_patterns'].append('Multiple hyphens in domain (potential phishing)')

            # Long domain name
            if len(domain) > 50:
                result['suspicious_patterns'].append('Unusually long domain name')

            # WHOIS lookup
            try:
                domain_info = whois.whois(domain)
                if domain_info.creation_date:
                    if isinstance(domain_info.creation_date, list):
                        creation_date = domain_info.creation_date[0]
                    else:
                        creation_date = domain_info.creation_date

                    if creation_date:
                        domain_age = (datetime.now() - creation_date).days
                        result['domain_age'] = f"{domain_age} days"

                        if domain_age < 30:
                            result['suspicious_patterns'].append(f'Very new domain ({domain_age} days old)')

                if domain_info.registrar:
                    result['registrar'] = str(domain_info.registrar)

            except Exception as e:
                result['registrar'] = 'WHOIS lookup failed'

        except Exception as e:
            result['error'] = str(e)

        return result

    # ============================================================
    # CONTENT ANALYSIS
    # ============================================================
    def analyze_website_content(self, url):
        """Analyze website content and metadata"""
        result = {
            'title': 'Not available',
            'description': 'Not available',
            'content_type': 'Unknown',
            'content_length': 0,
            'meta_keywords': 'Not available',
            'has_forms': False,
            'has_login_fields': False
        }

        try:
            response = requests.get(url, timeout=10, headers={'User-Agent': self.user_agent})
            result['content_type'] = response.headers.get('content-type', '').split(';')[0]
            result['content_length'] = len(response.content)

            soup = BeautifulSoup(response.content, 'html.parser')

            title_tag = soup.find('title')
            if title_tag and title_tag.get_text().strip():
                result['title'] = title_tag.get_text().strip()[:100]

            meta_desc = soup.find('meta', attrs={'name': 'description'})
            if meta_desc and meta_desc.get('content'):
                result['description'] = meta_desc.get('content', '')[:200]

            meta_keywords = soup.find('meta', attrs={'name': 'keywords'})
            if meta_keywords and meta_keywords.get('content'):
                result['meta_keywords'] = meta_keywords.get('content', '')[:150]

            forms = soup.find_all('form')
            if forms:
                result['has_forms'] = True
                for form in forms:
                    inputs = form.find_all('input')
                    for input_field in inputs:
                        input_type = input_field.get('type', '').lower()
                        input_name = input_field.get('name', '').lower()
                        if input_type in ['password', 'email'] or 'password' in input_name or 'login' in input_name:
                            result['has_login_fields'] = True
                            break

        except Exception as e:
            result['error'] = f'Content analysis error: {str(e)}'

        return result

    # ============================================================
    # RISK SCORING
    # ============================================================
    def calculate_risk_score(self, analysis_result):
        """Calculate overall risk score based on various factors"""
        risk_score = 0
        warnings = analysis_result.get('warnings', [])

        # SSL factors
        ssl_info = analysis_result.get('ssl_info', {})
        if not ssl_info.get('has_ssl'):
            risk_score += 2
            warnings.append('No SSL certificate detected')
        elif not ssl_info.get('valid_ssl'):
            risk_score += 2
            warnings.append('Invalid or expired SSL certificate')

        if ssl_info.get('error'):
            risk_score += 1
            warnings.append(f'SSL issue: {ssl_info.get("error")}')

        # Hosting factors
        hosting_info = analysis_result.get('hosting_info', {})
        if not hosting_info.get('exists'):
            risk_score += 3

        # Security factors
        security_analysis = analysis_result.get('security_analysis', {})
        if not security_analysis.get('has_https') and not security_analysis.get('redirects_https'):
            risk_score += 1
            warnings.append('Website does not use HTTPS')

        suspicious_patterns = security_analysis.get('suspicious_patterns', [])
        if suspicious_patterns:
            risk_score += len(suspicious_patterns)
            warnings.extend(suspicious_patterns)

        # Content factors
        content_analysis = analysis_result.get('content_analysis', {})
        if content_analysis.get('has_login_fields'):
            risk_score += 1
            warnings.append('Website contains login/password fields - verify authenticity')

        # Determine risk level
        if risk_score >= 3:
            analysis_result['is_safe'] = False
            analysis_result['risk_level'] = 'high'
        elif risk_score >= 1:
            analysis_result['is_safe'] = True
            analysis_result['risk_level'] = 'medium'
        else:
            analysis_result['is_safe'] = True
            analysis_result['risk_level'] = 'low'

        analysis_result['warnings'] = warnings

        return analysis_result


# ============================================================
# FLASK ROUTES
# ============================================================
safety_checker = AdvancedURLSafetyChecker()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/analyze-url', methods=['POST'])
def analyze_url():
    """API endpoint to analyze URL safety"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400

        url = data.get('url', '').strip()

        if not url:
            return jsonify({'error': 'URL is required'}), 400

        try:
            parsed = urllib.parse.urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return jsonify({'error': 'Invalid URL format. Include http:// or https:// and domain'}), 400
        except Exception:
            return jsonify({'error': 'Invalid URL format'}), 400

        print(f"🚀 Analyzing URL: {url}")

        result = safety_checker.analyze_url(url)

        return jsonify(result)

    except Exception as e:
        print(f"❌ Error in analyze-url endpoint: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500


@app.route('/health')
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)