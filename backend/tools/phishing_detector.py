import re
import requests
from urllib.parse import urlparse
import tldextract
import ssl
import socket
from datetime import datetime
import whois
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
import os
try:
    from google.cloud import webrisk_v1
    SAFE_BROWSING_AVAILABLE = True
except ImportError:
    SAFE_BROWSING_AVAILABLE = False
import time
from requests.exceptions import HTTPError, ConnectionError, Timeout

class PhishingDetector:
    def __init__(self):
        self.features = {}
        # Expanded list with domain variations
        self.trusted_domains = {
            # Major tech companies
            'google', 'gmail', 'youtube', 'googleblog', 'googleusercontent',
            'microsoft', 'office365', 'outlook', 'live', 'azure', 'msn', 'bing',
            'facebook', 'fb', 'instagram', 'whatsapp', 'messenger',
            'apple', 'icloud', 'itunes',
            'amazon', 'aws', 'amazonwebservices',
            
            # Social media
            'twitter', 'linkedin', 'pinterest', 'reddit', 'tumblr',
            
            # Payment services
            'paypal', 'stripe', 'visa', 'mastercard', 'americanexpress',
            
            # Cloud services
            'dropbox', 'box', 'github', 'gitlab', 'bitbucket',
            'salesforce', 'adobe', 'zoom', 'slack', 'spotify',
            
            # Major banks (add more as needed)
            'chase', 'bankofamerica', 'wellsfargo', 'citibank', 'hsbc',
            
            # E-commerce
            'ebay', 'walmart', 'target', 'bestbuy', 'shopify'
        }
        
        # Add suspicious keywords
        self.suspicious_keywords = {
            'login': 5,
            'verify': 8,
            'account': 5,
            'secure': 5,
            'banking': 10,
            'update': 5,
            'confirm': 8,
            'password': 10,
            'credential': 10,
            'wallet': 8,
            'bitcoin': 8,
            'crypto': 8,
            'urgent': 10,
            'suspended': 10,
            'unusual': 8,
            'security': 5,
            'limited': 8,
            'expires': 8,
            'authenticate': 8
        }

        # Make Safe Browsing optional
        self.safe_browsing_client = None
        if SAFE_BROWSING_AVAILABLE:
            try:
                self.safe_browsing_client = webrisk_v1.WebRiskServiceClient()
            except Exception:
                pass
            
        # Setup Chrome options for screenshots
        self.chrome_options = Options()
        self.chrome_options.add_argument('--headless')
        self.chrome_options.add_argument('--no-sandbox')
        self.chrome_options.add_argument('--disable-dev-shm-usage')
        self.chrome_options.add_argument('--disable-gpu')
        self.chrome_options.add_argument('--disable-extensions')
        self.chrome_options.add_argument('--disable-logging')
        self.chrome_options.add_argument('--log-level=3')
        self.chrome_options.add_argument('--silent')
        self.chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])
        self.screenshots_dir = 'screenshots'
        if not os.path.exists(self.screenshots_dir):
            os.makedirs(self.screenshots_dir)
        
    def analyze_url(self, url):
        try:
            self.features = {}
            self._extract_features(url)
            self._check_redirects(url)
            self._check_safe_browsing(url)
            self._get_whois_info(url)
            self._capture_screenshot(url)
            
            risk_score = self._calculate_risk_score()
            
            return {
                'risk_score': risk_score,
                'risk_level': self._determine_risk_level(risk_score),
                'analysis': self.features,
                'screenshot_path': self.features.get('screenshot_path')
            }
        except Exception as e:
            raise Exception(f"Analysis failed: {str(e)}")

    def _extract_features(self, url):
        # Basic URL structure analysis
        self.features['uses_https'] = url.startswith('https://')
        self.features['has_suspicious_chars'] = bool(re.search(r'[<>{}|\^~\[\]`]', url))
        
        # Enhanced domain analysis
        parsed = urlparse(url)
        ext = tldextract.extract(url)
        self.features['domain'] = ext.domain
        
        # Enhanced domain trust check
        domain_parts = ext.domain.lower().split('.')
        base_domain = domain_parts[0]
        
        # Check exact domain match first
        self.features['is_trusted_domain'] = base_domain in self.trusted_domains
        
        # If not trusted, check for typosquatting
        if not self.features['is_trusted_domain']:
            for trusted in self.trusted_domains:
                similarity = self._calculate_similarity(base_domain, trusted)
                if similarity > 0.85:  # 85% similar
                    self.features['possible_typosquatting'] = True
                    self.features['similarity_score'] = similarity * 100
                    self.features['similar_to'] = trusted
                    break
            else:
                self.features['possible_typosquatting'] = False
                self.features['similarity_score'] = 0
                self.features['similar_to'] = None

        # Check for numeric confusing domains
        self.features['has_numeric_domain'] = bool(re.search(r'\d', ext.domain))
        
        # Check for excessive subdomains
        self.features['subdomain_count'] = len(ext.subdomain.split('.')) if ext.subdomain else 0
        self.features['excessive_subdomains'] = self.features['subdomain_count'] > 3

        # Domain age and registration
        try:
            domain_info = whois.whois(parsed.netloc)
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            domain_age = (datetime.now() - creation_date).days
            
            self.features['domain_age_days'] = domain_age
            self.features['domain_age'] = domain_age > 180  # 6 months threshold
            
            # Registration length check
            if domain_info.expiration_date:
                expiry_date = domain_info.expiration_date
                if isinstance(expiry_date, list):
                    expiry_date = expiry_date[0]
                registration_length = (expiry_date - creation_date).days
                self.features['short_registration'] = registration_length < 365
            else:
                self.features['short_registration'] = True
                
        except Exception:
            self.features['domain_age'] = False
            self.features['domain_age_days'] = 0
            self.features['short_registration'] = True

        # SSL Certificate check
        try:
            context = ssl.create_default_context()
            with socket.create_connection((parsed.netloc, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=parsed.netloc) as ssock:
                    cert = ssock.getpeercert()
                    self.features['valid_ssl'] = True
                    self.features['cert_issuer'] = dict(x[0] for x in cert['issuer'])['organizationName']
        except Exception:
            self.features['valid_ssl'] = False
            self.features['cert_issuer'] = None

        # Enhanced content analysis
        try:
            response = requests.get(url, timeout=5, verify=True)
            content = response.text.lower()
            
            # Check for login/password forms
            self.features['has_login_form'] = bool(re.search(r'<form.*login|password|signin', content))
            
            # Calculate suspicious keyword score
            keyword_score = 0
            for keyword, weight in self.suspicious_keywords.items():
                if keyword in content:
                    keyword_score += weight
            self.features['suspicious_keyword_score'] = keyword_score
            
            # Check for password input fields
            self.features['password_input_count'] = len(re.findall(r'type=["\']password["\']', content))
            
            # Check for external resources and scripts
            external_resources = set()
            external_scripts = set()
            for match in re.finditer(r'src=["\']https?://([^/"\'>]+)', content):
                domain = tldextract.extract(match.group(1)).registered_domain
                if domain != ext.registered_domain:
                    external_resources.add(domain)
                    if '.js' in match.group(1):
                        external_scripts.add(domain)
                        
            self.features['external_resources'] = len(external_resources)
            self.features['external_scripts'] = len(external_scripts)
            
            # Check for obfuscated JavaScript
            self.features['has_obfuscated_js'] = bool(re.search(r'eval\(|String\.fromCharCode|escape\(|unescape\(', content))
            
        except Exception:
            self.features['has_login_form'] = False
            self.features['suspicious_keyword_score'] = 0
            self.features['external_resources'] = 0
            self.features['external_scripts'] = 0
            self.features['has_obfuscated_js'] = False
            self.features['password_input_count'] = 0

    def _check_redirects(self, url):
        """Check for suspicious redirects"""
        try:
            response = requests.get(url, allow_redirects=False, timeout=5)
            redirects = []
            max_redirects = 5
            redirect_count = 0
            
            while response.is_redirect and redirect_count < max_redirects:
                redirect_count += 1
                next_url = response.headers['Location']
                redirects.append(next_url)
                response = requests.get(next_url, allow_redirects=False, timeout=5)
            
            self.features['redirect_count'] = redirect_count
            self.features['has_redirects'] = redirect_count > 0
            self.features['redirect_chain'] = redirects
            self.features['suspicious_redirects'] = any(
                not url.startswith('https') for url in redirects
            )
            
        except (HTTPError, ConnectionError, Timeout):
            self.features['redirect_error'] = True
            self.features['redirect_count'] = 0
            self.features['has_redirects'] = False

    def _check_safe_browsing(self, url):
        """Optional Google Safe Browsing check"""
        self.features['safe_browsing_threat'] = False
        
        if not self.safe_browsing_client:
            # Use alternative checks when API is not available
            suspicious_patterns = [
                r'login.*?secure',
                r'verify.*?account',
                r'password.*?reset',
                r'banking.*?login',
                r'update.*?billing',
                r'confirm.*?payment'
            ]
            
            try:
                response = requests.get(url, timeout=5, verify=True)
                content = response.text.lower()
                
                pattern_matches = sum(
                    1 for pattern in suspicious_patterns 
                    if re.search(pattern, content)
                )
                
                self.features['pattern_matches'] = pattern_matches
                self.features['high_risk_patterns'] = pattern_matches > 2
                
            except Exception:
                self.features['pattern_matches'] = 0
                self.features['high_risk_patterns'] = False
            
            return

        # Original Safe Browsing API check if available
        try:
            if self.safe_browsing_client:
                threat_types = [
                    webrisk_v1.ThreatType.MALWARE,
                    webrisk_v1.ThreatType.SOCIAL_ENGINEERING,
                    webrisk_v1.ThreatType.UNWANTED_SOFTWARE
                ]
                
                response = self.safe_browsing_client.search_uris(
                    request={
                        "uri": url,
                        "threat_types": threat_types
                    }
                )
                
                self.features['safe_browsing_threat'] = bool(response.threat)
                if response.threat:
                    self.features['threat_types'] = [
                        str(threat.threat_type) for threat in response.threat.threat_types
                    ]
            else:
                self.features['safe_browsing_threat'] = False
                self.features['safe_browsing_error'] = "API not configured"
                
        except Exception as e:
            self.features['safe_browsing_error'] = str(e)
            self.features['safe_browsing_threat'] = False

    def _get_whois_info(self, url):
        """Enhanced WHOIS information gathering"""
        try:
            parsed = urlparse(url)
            domain_info = whois.whois(parsed.netloc)
            
            self.features['whois_info'] = {
                'registrar': domain_info.registrar,
                'creation_date': str(domain_info.creation_date),
                'expiration_date': str(domain_info.expiration_date),
                'last_updated': str(domain_info.updated_date),
                'status': domain_info.status,
                'name_servers': domain_info.name_servers
            }
            
            # Check for privacy protection
            self.features['privacy_protected'] = (
                'privacy' in str(domain_info.registrar).lower() or
                'private' in str(domain_info.registrar).lower()
            )
            
        except Exception as e:
            self.features['whois_error'] = str(e)

    def _capture_screenshot(self, url):
        """Capture screenshot of the website with improved error handling"""
        try:
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(
                service=service,
                options=self.chrome_options
            )
            driver.set_page_load_timeout(10)  # Set page load timeout
            driver.set_window_size(1920, 1080)
            
            try:
                driver.get(url)
                time.sleep(2)  # Wait for page to load
                
                filename = f"screenshot_{int(time.time())}.png"
                filepath = os.path.join(self.screenshots_dir, filename)
                driver.save_screenshot(filepath)
                
                self.features['screenshot_path'] = filepath
                self.features['screenshot_captured'] = True
                
            except Exception as e:
                self.features['screenshot_error'] = f"Page load error: {str(e)}"
                self.features['screenshot_captured'] = False
                
        except Exception as e:
            self.features['screenshot_error'] = f"Driver error: {str(e)}"
            self.features['screenshot_captured'] = False
        finally:
            try:
                driver.quit()
            except:
                pass

    def _calculate_risk_score(self):
        # Base score starts at 0 instead of 50
        score = 0
        
        # Early return for confirmed trusted domains
        if self.features.get('is_trusted_domain', False):
            return 5  # Very low risk for trusted domains

        # Risk factors and their weights
        risk_factors = {
            'uses_https': (-20, bool),
            'has_suspicious_chars': (30, bool),
            'possible_typosquatting': (40, bool),
            'has_numeric_domain': (20, bool),
            'excessive_subdomains': (15, bool),
            'domain_age': (-25, bool),
            'short_registration': (25, bool),
            'valid_ssl': (-20, bool),
            'has_login_form': (15, bool),
            'has_obfuscated_js': (35, bool),
            'suspicious_keyword_score': (0.5, int),  # Multiplied by score
            'external_resources': (3, int),  # Multiplied by count
            'external_scripts': (5, int),  # Multiplied by count
            'password_input_count': (8, int),  # Multiplied by count,
            'safe_browsing_threat': (50, bool),
            'suspicious_redirects': (30, bool),
            'privacy_protected': (15, bool),
            'redirect_count': (5, int)  # Multiplied by count
        }

        # Calculate score based on risk factors
        for feature, (weight, value_type) in risk_factors.items():
            if feature in self.features:
                value = self.features[feature]
                if value_type == bool:
                    score += weight if value else 0
                elif value_type == int:
                    score += weight * value

        # Adjust score based on similarity to trusted domains
        if self.features.get('possible_typosquatting', False):
            similarity_penalty = self.features.get('similarity_score', 0) * 0.4
            score += similarity_penalty

        # Adjust scoring for sites without Safe Browsing API
        if not self.safe_browsing_client and self.features.get('high_risk_patterns', False):
            score += 30  # Add significant weight to pattern matches

        # Ensure score stays within 0-100 range
        return min(max(score, 0), 100)

    def _determine_risk_level(self, score):
        if score < 15:
            return 'low'
        elif score < 40:
            return 'medium'
        else:
            return 'high'

    def _calculate_similarity(self, str1, str2):
        """Calculate string similarity using Levenshtein distance"""
        from difflib import SequenceMatcher
        return SequenceMatcher(None, str1, str2).ratio()

    def generateRecommendations(self, analysis):
        recommendations = []

        # Modify the domain age recommendation
        if not analysis['domain_age'] and not analysis.get('is_trusted_domain', False):
            recommendations.append('Domain is relatively new. Verify the legitimacy of the website.')
        
        # ...rest of existing recommendations...

        return recommendations
