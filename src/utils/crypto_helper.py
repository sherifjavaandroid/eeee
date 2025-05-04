import hashlib
import base64
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from typing import Dict, Any, Optional

class CryptoHelper:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def identify_hash(self, hash_string: str) -> Dict[str, Any]:
        """Identify hash type based on characteristics"""
        result = {
            'hash': hash_string,
            'possible_types': [],
            'length': len(hash_string)
        }

        # Common hash lengths
        hash_patterns = {
            32: ['MD5', 'MD4', 'MD2', 'NTLM'],
            40: ['SHA1', 'RIPEMD160'],
            56: ['SHA224'],
            64: ['SHA256', 'SHA3-256', 'RIPEMD256', 'Keccak-256'],
            96: ['SHA384', 'SHA3-384'],
            128: ['SHA512', 'SHA3-512', 'Whirlpool', 'Keccak-512']
        }

        # Check if it's hex
        is_hex = all(c in '0123456789abcdefABCDEF' for c in hash_string)

        if is_hex and len(hash_string) in hash_patterns:
            result['possible_types'] = hash_patterns[len(hash_string)]

        # Check for specific patterns
        if hash_string.startswith('$2a$') or hash_string.startswith('$2b$'):
            result['possible_types'] = ['bcrypt']
        elif hash_string.startswith('$1$'):
            result['possible_types'] = ['MD5 Crypt']
        elif hash_string.startswith('$5$'):
            result['possible_types'] = ['SHA256 Crypt']
        elif hash_string.startswith('$6$'):
            result['possible_types'] = ['SHA512 Crypt']
        elif ':' in hash_string and len(hash_string.split(':')[0]) in [32, 40, 64]:
            result['possible_types'] = ['Salted hash']

        return result

    def crack_weak_hash(self, hash_string: str, wordlist: list = None) -> Optional[str]:
        """Attempt to crack weak hashes using a wordlist"""
        if wordlist is None:
            # Default common passwords
            wordlist = [
                'password', '123456', '12345678', 'qwerty', 'abc123',
                'password1', '12345', '1234567', 'letmein', 'welcome',
                'monkey', 'dragon', '1234567890', 'football', 'iloveyou',
                'admin', 'welcome1', 'admin123', 'password123', 'qwerty123'
            ]

        hash_info = self.identify_hash(hash_string)

        if not hash_info['possible_types']:
            return None

        # Try different hash algorithms
        algorithms = {
            'MD5': hashlib.md5,
            'SHA1': hashlib.sha1,
            'SHA256': hashlib.sha256,
            'SHA512': hashlib.sha512
        }

        for password in wordlist:
            for algo_name, algo_func in algorithms.items():
                if algo_name in hash_info['possible_types']:
                    test_hash = algo_func(password.encode()).hexdigest()
                    if test_hash == hash_string:
                        return password

        return None

    def analyze_encryption(self, data: bytes) -> Dict[str, Any]:
        """Analyze encrypted data to identify encryption type"""
        result = {
            'data_length': len(data),
            'entropy': self._calculate_entropy(data),
            'possible_types': []
        }

        # Check for common encryption patterns
        if data.startswith(b'Salted__'):
            result['possible_types'].append('OpenSSL encrypted data')

        # Check for base64 encoding
        try:
            decoded = base64.b64decode(data)
            if len(decoded) < len(data):
                result['possible_types'].append('Base64 encoded')
        except Exception:
            pass

        # Check entropy
        if result['entropy'] > 7.5:
            result['possible_types'].append('Likely encrypted or compressed data')

        return result

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0

        entropy = 0
        for i in range(256):
            char_count = data.count(bytes([i]))
            if char_count > 0:
                frequency = float(char_count) / len(data)
                entropy -= frequency * (frequency.bit_length() - 1)

        return entropy

    def detect_weak_crypto(self, algorithm: str) -> Dict[str, Any]:
        """Detect weak cryptographic algorithms"""
        weak_algorithms = {
            'MD5': {'severity': 'High', 'reason': 'Collision vulnerabilities'},
            'SHA1': {'severity': 'High', 'reason': 'Collision vulnerabilities'},
            'DES': {'severity': 'Critical', 'reason': 'Key size too small'},
            '3DES': {'severity': 'High', 'reason': 'Deprecated and slow'},
            'RC4': {'severity': 'Critical', 'reason': 'Multiple vulnerabilities'},
            'ECB': {'severity': 'High', 'reason': 'Reveals data patterns'},
            'MD4': {'severity': 'Critical', 'reason': 'Severely broken'},
            'MD2': {'severity': 'Critical', 'reason': 'Severely broken'}
        }

        result = {
            'algorithm': algorithm,
            'is_weak': False,
            'severity': None,
            'reason': None,
            'recommendation': None
        }

        for weak_algo, info in weak_algorithms.items():
            if weak_algo.lower() in algorithm.lower():
                result['is_weak'] = True
                result['severity'] = info['severity']
                result['reason'] = info['reason']
                result['recommendation'] = self._get_recommendation(weak_algo)
                break

        return result

    def _get_recommendation(self, weak_algorithm: str) -> str:
        """Get recommendation for replacing weak algorithm"""
        recommendations = {
            'MD5': 'Use SHA-256 or SHA-3',
            'SHA1': 'Use SHA-256 or SHA-3',
            'DES': 'Use AES-256',
            '3DES': 'Use AES-256',
            'RC4': 'Use AES-GCM or ChaCha20-Poly1305',
            'ECB': 'Use CBC, CTR, or GCM mode',
            'MD4': 'Use SHA-256 or SHA-3',
            'MD2': 'Use SHA-256 or SHA-3'
        }

        return recommendations.get(weak_algorithm, 'Use modern, secure algorithms')