import asyncio
import logging
import json
import ssl
from typing import Dict, List, Any, Optional
from datetime import datetime
from mitmproxy import http, options
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.addons import core

class NetworkInterceptor:
    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.logger = logging.getLogger(__name__)
        self.host = host
        self.port = port
        self.captured_requests = []
        self.api_endpoints = set()
        self.sensitive_data = []
        self.vulnerabilities = []

    def start_proxy(self):
        """Start the mitmproxy instance"""
        opts = options.Options(
            listen_host=self.host,
            listen_port=self.port,
            ssl_insecure=True
        )

        master = DumpMaster(opts)
        master.addons.add(self)

        try:
            asyncio.run(master.run())
        except KeyboardInterrupt:
            master.shutdown()

    def request(self, flow: http.HTTPFlow) -> None:
        """Handle intercepted requests"""
        request_data = {
            'timestamp': datetime.now().isoformat(),
            'method': flow.request.method,
            'url': flow.request.pretty_url,
            'headers': dict(flow.request.headers),
            'body': flow.request.text or flow.request.content.decode('utf-8', errors='ignore')
        }

        self.captured_requests.append(request_data)
        self.api_endpoints.add(flow.request.pretty_url)

        # Check for security issues
        self.check_request_security(flow)

        # Look for sensitive data
        self.check_sensitive_data(flow)

    def response(self, flow: http.HTTPFlow) -> None:
        """Handle intercepted responses"""
        response_data = {
            'status_code': flow.response.status_code,
            'headers': dict(flow.response.headers),
            'body': flow.response.text or flow.response.content.decode('utf-8', errors='ignore')
        }

        # Update the captured request with response data
        if self.captured_requests:
            self.captured_requests[-1]['response'] = response_data

        # Check response for security issues
        self.check_response_security(flow)

    def check_request_security(self, flow: http.HTTPFlow):
        """Check request for security issues"""

        # Check for insecure HTTP
        if flow.request.scheme == "http":
            self.vulnerabilities.append({
                'type': 'insecure_communication',
                'severity': 'High',
                'description': f'Insecure HTTP communication to {flow.request.pretty_url}',
                'url': flow.request.pretty_url
            })

        # Check for missing security headers
        if 'Authorization' not in flow.request.headers and 'Cookie' not in flow.request.headers:
            if any(keyword in flow.request.pretty_url.lower() for keyword in ['api', 'auth', 'user', 'account']):
                self.vulnerabilities.append({
                    'type': 'missing_authentication',
                    'severity': 'Medium',
                    'description': f'No authentication headers found for sensitive endpoint: {flow.request.pretty_url}',
                    'url': flow.request.pretty_url
                })

        # Check for basic auth
        if 'Authorization' in flow.request.headers:
            auth_header = flow.request.headers['Authorization']
            if auth_header.startswith('Basic'):
                self.vulnerabilities.append({
                    'type': 'basic_authentication',
                    'severity': 'Medium',
                    'description': 'Basic authentication detected - consider using more secure methods',
                    'url': flow.request.pretty_url
                })

    def check_response_security(self, flow: http.HTTPFlow):
        """Check response for security issues"""

        # Check for missing security headers
        security_headers = {
            'Strict-Transport-Security': 'HSTS header missing',
            'X-Content-Type-Options': 'X-Content-Type-Options header missing',
            'X-Frame-Options': 'X-Frame-Options header missing',
            'Content-Security-Policy': 'CSP header missing',
            'X-XSS-Protection': 'XSS Protection header missing'
        }

        for header, message in security_headers.items():
            if header not in flow.response.headers:
                self.vulnerabilities.append({
                    'type': 'missing_security_header',
                    'severity': 'Low',
                    'description': message,
                    'url': flow.request.pretty_url
                })

        # Check for sensitive data in response
        if flow.response.text:
            self.check_response_for_sensitive_data(flow.response.text, flow.request.pretty_url)

    def check_sensitive_data(self, flow: http.HTTPFlow):
        """Check for sensitive data in requests"""
        text = flow.request.text or flow.request.content.decode('utf-8', errors='ignore')

        sensitive_patterns = {
            'password': r'password["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            'api_key': r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            'token': r'token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            'email': r'[\w\.-]+@[\w\.-]+\.\w+',
            'credit_card': r'\b(?:\d{4}[- ]?){3}\d{4}\b'
        }

        import re
        for data_type, pattern in sensitive_patterns.items():
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                self.sensitive_data.append({
                    'type': data_type,
                    'value': match.group(0)[:50] + '...' if len(match.group(0)) > 50 else match.group(0),
                    'url': flow.request.pretty_url,
                    'method': flow.request.method
                })

    def check_response_for_sensitive_data(self, text: str, url: str):
        """Check response for sensitive data"""
        sensitive_patterns = {
            'jwt': r'eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
            'private_key': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
            'password': r'password["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            'api_key': r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']'
        }

        import re
        for data_type, pattern in sensitive_patterns.items():
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                self.sensitive_data.append({
                    'type': data_type,
                    'value': match.group(0)[:50] + '...' if len(match.group(0)) > 50 else match.group(0),
                    'url': url,
                    'location': 'response'
                })

    def get_captured_data(self) -> Dict[str, Any]:
        """Get all captured data"""
        return {
            'requests': self.captured_requests,
            'api_endpoints': list(self.api_endpoints),
            'sensitive_data': self.sensitive_data,
            'vulnerabilities': self.vulnerabilities
        }

    def save_captured_data(self, output_file: str):
        """Save captured data to file"""
        data = self.get_captured_data()
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)