import logging
import json
from typing import Dict, List, Any
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from pathlib import Path

class BugBountyReporter:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.templates_dir = Path(__file__).parent.parent.parent / 'templates'
        self.env = Environment(loader=FileSystemLoader(str(self.templates_dir)))

    def generate_hackerone_report(self, vulnerabilities: List[Dict[str, Any]],
                                  app_info: Dict[str, Any]) -> str:
        """Generate HackerOne-style bug bounty report"""

        # Group vulnerabilities by severity
        critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'Critical']
        high_vulns = [v for v in vulnerabilities if v.get('severity') == 'High']

        # Select the most critical vulnerability for the main report
        main_vuln = critical_vulns[0] if critical_vulns else (high_vulns[0] if high_vulns else vulnerabilities[0])

        report_data = {
            'title': self._generate_title(main_vuln),
            'summary': self._generate_summary(main_vuln),
            'vulnerability_type': main_vuln.get('type', 'Security Vulnerability'),
            'severity': main_vuln.get('severity', 'Medium'),
            'description': main_vuln.get('description', ''),
            'steps_to_reproduce': self._generate_steps(main_vuln),
            'impact': self._generate_impact(main_vuln),
            'supporting_material': self._generate_supporting_material(main_vuln),
            'remediation': self._generate_remediation(main_vuln),
            'app_info': app_info,
            'additional_vulns': vulnerabilities[1:] if len(vulnerabilities) > 1 else []
        }

        template = self.env.get_template('bug_bounty_template.md')
        return template.render(**report_data)

    def _generate_title(self, vulnerability: Dict[str, Any]) -> str:
        """Generate report title"""
        vuln_type = vulnerability.get('type', 'Security Issue')
        package = vulnerability.get('package_name', 'Mobile App')

        titles = {
            'sql_injection': f"SQL Injection in {package} allows data extraction",
            'hardcoded_secret': f"Hardcoded API Keys/Secrets exposed in {package}",
            'insecure_storage': f"Sensitive data stored insecurely in {package}",
            'exported_component': f"Exported components allow unauthorized access in {package}",
            'webview_vulnerability': f"WebView misconfiguration leads to JavaScript execution in {package}",
            'weak_crypto': f"Weak cryptography implementation in {package}",
            'insecure_communication': f"Unencrypted network communication in {package}"
        }

        return titles.get(vuln_type.lower(), f"{vuln_type} vulnerability in {package}")

    def _generate_summary(self, vulnerability: Dict[str, Any]) -> str:
        """Generate executive summary"""
        summaries = {
            'sql_injection': "A SQL injection vulnerability was discovered that allows attackers to extract sensitive data from the application's database.",
            'hardcoded_secret': "Hardcoded secrets including API keys and credentials were found in the application code, potentially allowing unauthorized access to backend services.",
            'insecure_storage': "The application stores sensitive user data in an insecure manner, making it accessible to other applications or attackers with physical access to the device.",
            'exported_component': "Several application components are exported without proper protection, allowing malicious applications to interact with them and potentially bypass security controls.",
            'webview_vulnerability': "The application's WebView implementation contains security misconfigurations that could allow attackers to execute arbitrary JavaScript code.",
            'weak_crypto': "The application uses weak or deprecated cryptographic algorithms that can be easily broken by attackers.",
            'insecure_communication': "The application transmits sensitive data over unencrypted channels, making it vulnerable to man-in-the-middle attacks."
        }

        return summaries.get(vulnerability.get('type', '').lower(), vulnerability.get('description', ''))

    def _generate_steps(self, vulnerability: Dict[str, Any]) -> List[str]:
        """Generate steps to reproduce"""
        vuln_type = vulnerability.get('type', '').lower()

        if vuln_type == 'sql_injection':
            return [
                "Install the target application",
                f"Navigate to the vulnerable endpoint: {vulnerability.get('location', 'Unknown')}",
                "Intercept the request using a proxy tool",
                f"Modify the parameter '{vulnerability.get('parameter', 'input')}' with SQL injection payload",
                "Observe that the application returns database contents"
            ]
        elif vuln_type == 'hardcoded_secret':
            return [
                "Decompile the application using JADX or similar tool",
                f"Search for hardcoded secrets in {vulnerability.get('location', 'source code')}",
                f"Find the exposed secret: {vulnerability.get('value', 'REDACTED')[:20]}...",
                "Use the secret to access protected API endpoints"
            ]
        elif vuln_type == 'exported_component':
            return [
                "Install the target application",
                "Use ADB to interact with exported components",
                f"Execute: adb shell am start -n {vulnerability.get('component_name', 'com.app/.Activity')}",
                "Observe that the component launches without authentication"
            ]
        else:
            return [
                "Install and run the target application",
                f"Navigate to {vulnerability.get('location', 'affected feature')}",
                "Perform the attack as described",
                "Observe the security impact"
            ]

    def _generate_impact(self, vulnerability: Dict[str, Any]) -> str:
        """Generate impact statement"""
        impacts = {
            'sql_injection': "This vulnerability allows attackers to:\n- Extract sensitive user data including passwords and personal information\n- Modify or delete database contents\n- Potentially execute administrative operations\n- Compromise user privacy and data integrity",
            'hardcoded_secret': "This vulnerability allows attackers to:\n- Access protected API endpoints\n- Impersonate legitimate users\n- Access or modify sensitive data\n- Potentially compromise the entire backend infrastructure",
            'insecure_storage': "This vulnerability allows attackers to:\n- Access sensitive user data stored on the device\n- Extract authentication tokens and session data\n- Compromise user privacy\n- Potentially perform account takeover",
            'exported_component': "This vulnerability allows attackers to:\n- Bypass authentication mechanisms\n- Access restricted functionality\n- Extract sensitive information\n- Perform unauthorized actions on behalf of users",
            'webview_vulnerability': "This vulnerability allows attackers to:\n- Execute arbitrary JavaScript in the application context\n- Access local files and data\n- Steal sensitive information\n- Perform actions on behalf of the user",
            'weak_crypto': "This vulnerability allows attackers to:\n- Decrypt sensitive data\n- Forge authentication tokens\n- Compromise data confidentiality\n- Break secure communications",
            'insecure_communication': "This vulnerability allows attackers to:\n- Intercept sensitive data in transit\n- Perform man-in-the-middle attacks\n- Steal user credentials and session tokens\n- Modify data in transit"
        }

        return impacts.get(vulnerability.get('type', '').lower(),
                           "This vulnerability could lead to unauthorized access, data breach, or compromise of user privacy.")

    def _generate_supporting_material(self, vulnerability: Dict[str, Any]) -> List[str]:
        """Generate list of supporting materials"""
        materials = []

        if vulnerability.get('screenshot'):
            materials.append(f"Screenshot: {vulnerability['screenshot']}")

        if vulnerability.get('video_poc'):
            materials.append(f"Video PoC: {vulnerability['video_poc']}")

        if vulnerability.get('code_snippet'):
            materials.append("Code snippet demonstrating the vulnerability")

        if vulnerability.get('request_response'):
            materials.append("HTTP request/response demonstrating the issue")

        materials.append("Detailed technical analysis in the description above")

        return materials

    def _generate_remediation(self, vulnerability: Dict[str, Any]) -> str:
        """Generate remediation recommendations"""
        remediations = {
            'sql_injection': "1. Use parameterized queries instead of string concatenation\n2. Implement proper input validation and sanitization\n3. Use prepared statements for all database operations\n4. Apply the principle of least privilege for database access",
            'hardcoded_secret': "1. Remove all hardcoded secrets from the source code\n2. Use secure key management systems (Android Keystore, iOS Keychain)\n3. Implement proper secret rotation mechanisms\n4. Use environment variables or secure configuration files",
            'insecure_storage': "1. Use Android Keystore or iOS Keychain for sensitive data\n2. Encrypt data before storage using strong algorithms\n3. Avoid storing sensitive data in SharedPreferences or NSUserDefaults\n4. Implement proper file permissions",
            'exported_component': "1. Set android:exported=\"false\" for components that don't need external access\n2. Implement proper permission checks\n3. Use signature-level permissions for sensitive components\n4. Validate all input from external sources",
            'webview_vulnerability': "1. Disable JavaScript if not required\n2. Implement proper input validation for WebView content\n3. Use @JavascriptInterface annotation carefully\n4. Disable file access unless absolutely necessary",
            'weak_crypto': "1. Replace weak algorithms (MD5, SHA1, DES) with strong alternatives\n2. Use AES-256 for symmetric encryption\n3. Implement proper key management\n4. Use authenticated encryption modes (GCM)",
            'insecure_communication': "1. Enforce HTTPS for all network communications\n2. Implement certificate pinning\n3. Use TLS 1.2 or higher\n4. Validate server certificates properly"
        }

        return remediations.get(vulnerability.get('type', '').lower(),
                                "Implement security best practices and follow secure coding guidelines.")