import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any
from jinja2 import Environment, FileSystemLoader

class ReportGenerator:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.templates_dir = Path('src/templates')
        self.env = Environment(loader=FileSystemLoader(str(self.templates_dir)))

    def generate_report(self, app_path: str, platform: str,
                        vulnerabilities: List[Dict[str, Any]],
                        exploits: List[Dict[str, Any]],
                        output_dir: str) -> Path:
        """Generate comprehensive security report"""

        # Prepare report data
        report_data = {
            'app_path': app_path,
            'platform': platform,
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'vulnerabilities': vulnerabilities,
            'exploits': exploits,
            'summary': self._generate_summary(vulnerabilities),
            'recommendations': self._generate_recommendations(vulnerabilities)
        }

        # Generate HTML report
        html_report = self._generate_html_report(report_data)

        # Generate Markdown report
        md_report = self._generate_markdown_report(report_data)

        # Generate JSON report
        json_report = self._generate_json_report(report_data)

        # Save reports
        output_path = Path(output_dir) / 'reports'
        output_path.mkdir(exist_ok=True)

        html_path = output_path / f'security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html'
        md_path = output_path / f'security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.md'
        json_path = output_path / f'security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'

        with open(html_path, 'w') as f:
            f.write(html_report)

        with open(md_path, 'w') as f:
            f.write(md_report)

        with open(json_path, 'w') as f:
            json.dump(json_report, f, indent=2)

        self.logger.info(f"Reports generated: {html_path}, {md_path}, {json_path}")
        return html_path

    def _generate_html_report(self, data: Dict[str, Any]) -> str:
        """Generate HTML report using template"""
        template = self.env.get_template('report_template.html')
        return template.render(**data)

    def _generate_markdown_report(self, data: Dict[str, Any]) -> str:
        """Generate Markdown report"""
        template = self.env.get_template('vulnerability_report.md')
        return template.render(**data)

    def _generate_json_report(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate JSON report"""
        return data

    def _generate_summary(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate vulnerability summary"""
        summary = {
            'total': len(vulnerabilities),
            'critical': len([v for v in vulnerabilities if v.get('severity') == 'Critical']),
            'high': len([v for v in vulnerabilities if v.get('severity') == 'High']),
            'medium': len([v for v in vulnerabilities if v.get('severity') == 'Medium']),
            'low': len([v for v in vulnerabilities if v.get('severity') == 'Low'])
        }

        # Group by type
        by_type = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            if vuln_type not in by_type:
                by_type[vuln_type] = 0
            by_type[vuln_type] += 1

        summary['by_type'] = by_type
        return summary

    def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Generate security recommendations based on vulnerabilities"""
        recommendations = []

        vuln_types = set(v.get('type') for v in vulnerabilities)

        recommendation_map = {
            'sql_injection': {
                'title': 'Fix SQL Injection Vulnerabilities',
                'description': 'Use parameterized queries instead of string concatenation. Implement proper input validation and sanitization.'
            },
            'weak_crypto': {
                'title': 'Update Cryptographic Algorithms',
                'description': 'Replace weak algorithms (MD5, SHA1, DES) with stronger alternatives (SHA-256, AES-256). Use proper key management.'
            },
            'hardcoded_secrets': {
                'title': 'Remove Hardcoded Secrets',
                'description': 'Use secure key management systems. Store secrets in encrypted configuration files or use environment variables.'
            },
            'insecure_storage': {
                'title': 'Secure Data Storage',
                'description': 'Use Android Keystore or iOS Keychain for sensitive data. Avoid world-readable/writable permissions.'
            },
            'webview_issues': {
                'title': 'Secure WebView Configuration',
                'description': 'Disable JavaScript if not needed. Be cautious with addJavascriptInterface. Implement proper input validation.'
            }
        }

        for vuln_type in vuln_types:
            if vuln_type in recommendation_map:
                recommendations.append(recommendation_map[vuln_type])

        return recommendations