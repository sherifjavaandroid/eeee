import socket
import ssl
import requests
import logging
from typing import Dict, Any, Optional
from urllib.parse import urlparse

class NetworkHelper:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def check_ssl_configuration(self, url: str) -> Dict[str, Any]:
        """Check SSL/TLS configuration of a URL"""
        result = {
            'url': url,
            'ssl_enabled': False,
            'protocol': None,
            'cipher': None,
            'certificate': None,
            'vulnerabilities': []
        }

        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)

            if parsed_url.scheme != 'https':
                result['vulnerabilities'].append('Not using HTTPS')
                return result

            # Create SSL context
            context = ssl.create_default_context()

            # Test connection
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    result['ssl_enabled'] = True
                    result['protocol'] = ssock.version()
                    result['cipher'] = ssock.cipher()

                    # Get certificate
                    cert = ssock.getpeercert()
                    result['certificate'] = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'notBefore': cert['notBefore'],
                        'notAfter': cert['notAfter']
                    }

                    # Check for vulnerabilities
                    if ssock.version() in ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']:
                        result['vulnerabilities'].append(f'Weak protocol: {ssock.version()}')

                    cipher_suite = ssock.cipher()[0]
                    if any(weak in cipher_suite.lower() for weak in ['rc4', 'des', 'md5']):
                        result['vulnerabilities'].append(f'Weak cipher: {cipher_suite}')

        except Exception as e:
            self.logger.error(f"SSL check failed for {url}: {e}")
            result['error'] = str(e)

        return result

    def test_ssl_pinning(self, url: str) -> bool:
        """Test if SSL pinning is implemented"""
        try:
            # Try to connect with a custom certificate
            session = requests.Session()
            session.verify = False  # Disable certificate verification

            response = session.get(url, timeout=10)

            # If we can connect without proper certificate, pinning is not implemented
            if response.status_code == 200:
                return False
            else:
                return True
        except requests.exceptions.SSLError:
            # SSL error indicates pinning might be implemented
            return True
        except Exception as e:
            self.logger.error(f"SSL pinning test failed: {e}")
            return False

    def scan_ports(self, host: str, ports: list = None) -> Dict[int, bool]:
        """Scan specified ports on a host"""
        if ports is None:
            ports = [80, 443, 8080, 8443, 3000, 5000, 8000]

        open_ports = {}

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))

                if result == 0:
                    open_ports[port] = True
                    self.logger.info(f"Port {port} is open on {host}")
                else:
                    open_ports[port] = False

                sock.close()
            except Exception as e:
                self.logger.error(f"Error scanning port {port} on {host}: {e}")
                open_ports[port] = False

        return open_ports

    def analyze_headers(self, url: str) -> Dict[str, Any]:
        """Analyze HTTP headers for security issues"""
        result = {
            'url': url,
            'headers': {},
            'missing_headers': [],
            'vulnerable_headers': []
        }

        try:
            response = requests.get(url, timeout=10)
            result['headers'] = dict(response.headers)

            # Check for security headers
            security_headers = {
                'Strict-Transport-Security': 'HSTS not implemented',
                'X-Content-Type-Options': 'X-Content-Type-Options header missing',
                'X-Frame-Options': 'Clickjacking protection missing',
                'Content-Security-Policy': 'CSP not implemented',
                'X-XSS-Protection': 'XSS protection header missing',
                'Referrer-Policy': 'Referrer policy not set',
                'Permissions-Policy': 'Permissions policy not defined'
            }

            for header, message in security_headers.items():
                if header not in response.headers:
                    result['missing_headers'].append(message)

            # Check for vulnerable header values
            if 'Server' in response.headers:
                result['vulnerable_headers'].append(f"Server header exposes version: {response.headers['Server']}")

            if 'X-Powered-By' in response.headers:
                result['vulnerable_headers'].append(f"X-Powered-By header exposes technology: {response.headers['X-Powered-By']}")

            if 'Access-Control-Allow-Origin' in response.headers:
                if response.headers['Access-Control-Allow-Origin'] == '*':
                    result['vulnerable_headers'].append("CORS misconfiguration: Allow-Origin set to *")

        except Exception as e:
            self.logger.error(f"Header analysis failed for {url}: {e}")
            result['error'] = str(e)

        return result

    def check_http_methods(self, url: str) -> Dict[str, bool]:
        """Check allowed HTTP methods"""
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT']
        allowed_methods = {}

        for method in methods:
            try:
                response = requests.request(method, url, timeout=5)
                allowed_methods[method] = response.status_code != 405
            except Exception:
                allowed_methods[method] = False

        return allowed_methods