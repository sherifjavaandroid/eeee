import logging
from typing import Dict, List, Any
from collections import defaultdict

class SecurityAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def analyze_results(self, static_results: Dict[str, Any],
                        dynamic_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze and combine static and dynamic analysis results"""
        vulnerabilities = []

        # Process static analysis results
        if static_results:
            vulnerabilities.extend(self._process_static_results(static_results))

        # Process dynamic analysis results
        if dynamic_results:
            vulnerabilities.extend(self._process_dynamic_results(dynamic_results))

        # Remove duplicates and assign IDs
        vulnerabilities = self._deduplicate_vulnerabilities(vulnerabilities)

        # Calculate risk scores
        for vuln in vulnerabilities:
            vuln['risk_score'] = self._calculate_risk_score(vuln)

        # Sort by risk score
        vulnerabilities.sort(key=lambda x: x['risk_score'], reverse=True)

        return vulnerabilities

    def _process_static_results(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process static analysis results"""
        vulnerabilities = []

        # Process manifest issues
        for issue in results.get('manifest_issues', []):
            vulnerabilities.append({
                'id': f"STATIC-{len(vulnerabilities) + 1}",
                'type': issue['type'],
                'severity': issue['severity'],
                'description': issue['description'],
                'location': issue.get('location', 'Unknown'),
                'source': 'static_analysis',
                'category': 'configuration'
            })

        # Process code vulnerabilities
        for vuln in results.get('vulnerabilities', []):
            vulnerabilities.append({
                'id': f"STATIC-{len(vulnerabilities) + 1}",
                'type': vuln['type'],
                'severity': vuln['severity'],
                'description': vuln['description'],
                'location': f"{vuln['file']}:{vuln['line']}",
                'code': vuln.get('code', ''),
                'source': 'static_analysis',
                'category': 'code'
            })

        # Process secrets
        for secret in results.get('secrets', []):
            vulnerabilities.append({
                'id': f"STATIC-{len(vulnerabilities) + 1}",
                'type': 'hardcoded_secret',
                'severity': 'High',
                'description': f"Hardcoded {secret['type']} found",
                'location': f"{secret['file']}:{secret['line']}",
                'value': secret['value'][:20] + '...',  # Truncate for security
                'source': 'static_analysis',
                'category': 'secret'
            })

        return vulnerabilities

    def _process_dynamic_results(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process dynamic analysis results"""
        vulnerabilities = []

        # Process runtime issues
        for issue in results.get('runtime_issues', []):
            vulnerabilities.append({
                'id': f"DYNAMIC-{len(vulnerabilities) + 1}",
                'type': issue['type'],
                'severity': issue['severity'],
                'description': issue['description'],
                'source': 'dynamic_analysis',
                'category': 'runtime'
            })

        # Process network issues
        for issue in results.get('network_issues', []):
            vulnerabilities.append({
                'id': f"DYNAMIC-{len(vulnerabilities) + 1}",
                'type': issue['type'],
                'severity': issue['severity'],
                'description': issue['description'],
                'source': 'dynamic_analysis',
                'category': 'network'
            })

        # Process storage issues
        for issue in results.get('storage_issues', []):
            vulnerabilities.append({
                'id': f"DYNAMIC-{len(vulnerabilities) + 1}",
                'type': issue['type'],
                'severity': issue['severity'],
                'description': issue['description'],
                'source': 'dynamic_analysis',
                'category': 'storage'
            })

        return vulnerabilities

    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate vulnerabilities"""
        unique_vulns = {}

        for vuln in vulnerabilities:
            # Create a unique key based on type, location, and description
            key = f"{vuln['type']}:{vuln.get('location', '')}:{vuln['description']}"

            if key not in unique_vulns:
                unique_vulns[key] = vuln
            else:
                # Merge information if duplicate
                existing = unique_vulns[key]
                if existing['severity'] != vuln['severity']:
                    # Keep the higher severity
                    if self._severity_to_number(vuln['severity']) > self._severity_to_number(existing['severity']):
                        existing['severity'] = vuln['severity']

        return list(unique_vulns.values())

    def _calculate_risk_score(self, vulnerability: Dict[str, Any]) -> float:
        """Calculate risk score for a vulnerability"""
        severity_scores = {
            'Critical': 10.0,
            'High': 8.0,
            'Medium': 5.0,
            'Low': 2.0
        }

        category_multipliers = {
            'code': 1.2,
            'configuration': 1.0,
            'secret': 1.5,
            'runtime': 1.3,
            'network': 1.4,
            'storage': 1.3
        }

        base_score = severity_scores.get(vulnerability.get('severity', 'Low'), 2.0)
        multiplier = category_multipliers.get(vulnerability.get('category', 'code'), 1.0)

        return base_score * multiplier

    def _severity_to_number(self, severity: str) -> int:
        """Convert severity to numeric value for comparison"""
        severity_map = {
            'Critical': 4,
            'High': 3,
            'Medium': 2,
            'Low': 1
        }
        return severity_map.get(severity, 0)