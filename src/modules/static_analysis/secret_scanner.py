import re
import logging
from pathlib import Path
from typing import Dict, List, Any

class SecretScanner:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.patterns = self._load_patterns()

    def _load_patterns(self) -> Dict[str, str]:
        """Load regex patterns for secret detection"""
        return {
            'aws_access_key': r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
            'aws_secret_key': r'(?i)aws(.{0,20})?(?-i)[\'"\s]?([0-9a-zA-Z/+]{40})[\'"\s]?',
            'azure_client_id': r'(?i)(?:azure|client).{0,20}id.{0,20}[\'"\s]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})[\'"\s]?',
            'azure_client_secret': r'(?i)(?:azure|client).{0,20}secret.{0,20}[\'"\s]?([0-9a-zA-Z\-_~]{34,})[\'"\s]?',
            'firebase_key': r'AIza[0-9A-Za-z_-]{35}',
            'firebase_domain': r'([\w.-]+\.firebaseio\.com|[\w.-]+\.firebaseapp\.com)',
            'gcp_api_key': r'AIza[0-9A-Za-z\\-_]{35}',
            'github_token': r'(?:ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{36,255}',
            'google_oauth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
            'heroku_api_key': r'(?i)heroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
            'jwt_token': r'ey[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
            'mailchimp_api_key': r'[0-9a-f]{32}-us[0-9]{1,2}',
            'mailgun_api_key': r'key-[0-9a-zA-Z]{32}',
            'password': r'(?i)(?:password|passwd|pwd)[\s]*[=:]+[\s]*[\'"]?([^\s\'"]{4,})[\'"]?',
            'private_key': r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
            'slack_token': r'xox[abpr]-[0-9a-zA-Z]{10,48}',
            'slack_webhook': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
            'stripe_api_key': r'(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}',
            'twilio_api_key': r'SK[0-9a-fA-F]{32}',
            'twitter_oauth': r'(?i)twitter.*[\'"\s][0-9a-zA-Z]{35,44}[\'"\s]',
            'generic_api_key': r'(?i)api[_\s-]?key[\s]*[=:]+[\s]*[\'"]?([^\s\'"]{20,})[\'"]?',
            'generic_secret': r'(?i)secret[\s]*[=:]+[\s]*[\'"]?([^\s\'"]{8,})[\'"]?'
        }

    def scan_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Scan a single file for secrets"""
        secrets = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Skip if file is too large
            if len(content) > 1_000_000:  # 1MB limit
                self.logger.warning(f"Skipping large file: {file_path}")
                return secrets

            for secret_type, pattern in self.patterns.items():
                matches = re.finditer(pattern, content)
                for match in matches:
                    # Get the matched value
                    value = match.group(0)
                    if match.groups():
                        value = match.group(1)

                    # Find line number
                    line_number = content[:match.start()].count('\n') + 1

                    # Get surrounding context
                    lines = content.splitlines()
                    context_start = max(0, line_number - 3)
                    context_end = min(len(lines), line_number + 2)
                    context = '\n'.join(lines[context_start:context_end])

                    secrets.append({
                        'type': secret_type,
                        'value': self._mask_secret(value),
                        'file': str(file_path),
                        'line': line_number,
                        'context': context,
                        'confidence': self._calculate_confidence(secret_type, value, context)
                    })

        except Exception as e:
            self.logger.error(f"Error scanning file {file_path}: {e}")

        return secrets

    def scan_directory(self, directory: Path) -> List[Dict[str, Any]]:
        """Scan directory recursively for secrets"""
        all_secrets = []

        # File extensions to scan
        target_extensions = {
            '.java', '.kt', '.xml', '.json', '.properties', '.yml', '.yaml',
            '.js', '.ts', '.jsx', '.tsx', '.vue', '.html', '.css',
            '.py', '.rb', '.php', '.go', '.swift', '.m', '.h',
            '.conf', '.config', '.ini', '.env', '.sh', '.bash'
        }

        # Files to ignore
        ignore_patterns = {
            'node_modules', 'build', 'dist', '.git', '__pycache__',
            'vendor', 'target', 'bin', 'obj', 'packages'
        }

        for file_path in directory.rglob('*'):
            # Skip ignored directories
            if any(ignored in file_path.parts for ignored in ignore_patterns):
                continue

            # Skip non-text files
            if file_path.is_file() and file_path.suffix.lower() in target_extensions:
                secrets = self.scan_file(file_path)
                all_secrets.extend(secrets)

        return all_secrets

    def _mask_secret(self, secret: str) -> str:
        """Mask secret value for security"""
        if len(secret) <= 8:
            return '*' * len(secret)

        visible_chars = 4
        return secret[:visible_chars] + '*' * (len(secret) - visible_chars * 2) + secret[-visible_chars:]

    def _calculate_confidence(self, secret_type: str, value: str, context: str) -> float:
        """Calculate confidence score for detected secret"""
        confidence = 0.5  # Base confidence

        # Increase confidence for certain patterns
        if secret_type in ['jwt_token', 'private_key', 'aws_access_key']:
            confidence += 0.3

        # Check context for keywords
        context_keywords = ['api', 'key', 'secret', 'token', 'password', 'credential', 'auth']
        context_lower = context.lower()
        if any(keyword in context_lower for keyword in context_keywords):
            confidence += 0.2

        # Check if it looks like a real value (not a placeholder)
        if not re.match(r'^[xX]+$|^[0-9]+$|^[a-zA-Z]+$|example|test|sample|placeholder', value):
            confidence += 0.1

        # Check length
        if len(value) > 20:
            confidence += 0.1

        return min(confidence, 1.0)