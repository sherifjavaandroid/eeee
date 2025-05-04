import subprocess
import re
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional

class BinaryAnalyzer:
    def __init__(self, binary_path: str):
        self.binary_path = Path(binary_path)
        self.logger = logging.getLogger(__name__)
        self.results = {}

    def analyze(self) -> Dict[str, Any]:
        """Perform comprehensive binary analysis"""
        self.results = {
            'file_type': self.get_file_type(),
            'architecture': self.get_architecture(),
            'encryption': self.check_encryption(),
            'security_features': self.check_security_features(),
            'symbols': self.extract_symbols(),
            'strings': self.extract_strings(),
            'vulnerabilities': self.find_vulnerabilities()
        }

        return self.results

    def get_file_type(self) -> Dict[str, Any]:
        """Get binary file type information"""
        try:
            result = subprocess.run(['file', str(self.binary_path)],
                                    capture_output=True, text=True)

            file_info = result.stdout.strip()

            return {
                'full_info': file_info,
                'is_mach_o': 'Mach-O' in file_info,
                'is_universal': 'universal binary' in file_info,
                'is_executable': 'executable' in file_info
            }
        except Exception as e:
            self.logger.error(f"Failed to get file type: {e}")
            return {}

    def get_architecture(self) -> List[str]:
        """Get binary architectures"""
        try:
            result = subprocess.run(['lipo', '-info', str(self.binary_path)],
                                    capture_output=True, text=True)

            if 'Architectures in the fat file' in result.stdout:
                # Universal binary
                archs = result.stdout.split(':')[-1].strip().split()
                return archs
            else:
                # Single architecture
                arch = result.stdout.split(':')[-1].strip()
                return [arch]
        except Exception as e:
            self.logger.error(f"Failed to get architecture: {e}")
            return []

    def check_encryption(self) -> Dict[str, Any]:
        """Check if binary is encrypted"""
        try:
            result = subprocess.run(['otool', '-l', str(self.binary_path)],
                                    capture_output=True, text=True)

            encryption_info = {
                'is_encrypted': False,
                'cryptid': 0,
                'cryptoff': 0,
                'cryptsize': 0
            }

            lines = result.stdout.splitlines()
            for i, line in enumerate(lines):
                if 'LC_ENCRYPTION_INFO' in line or 'LC_ENCRYPTION_INFO_64' in line:
                    # Found encryption info, parse next few lines
                    for j in range(i + 1, min(i + 10, len(lines))):
                        if 'cryptid' in lines[j]:
                            cryptid = int(lines[j].split()[-1])
                            encryption_info['cryptid'] = cryptid
                            encryption_info['is_encrypted'] = cryptid != 0
                        elif 'cryptoff' in lines[j]:
                            encryption_info['cryptoff'] = int(lines[j].split()[-1])
                        elif 'cryptsize' in lines[j]:
                            encryption_info['cryptsize'] = int(lines[j].split()[-1])

            return encryption_info
        except Exception as e:
            self.logger.error(f"Failed to check encryption: {e}")
            return {}

    def check_security_features(self) -> Dict[str, bool]:
        """Check binary security features"""
        features = {
            'pie': False,
            'stack_canary': False,
            'arc': False,
            'stripped': False,
            'restricted': False
        }

        try:
            # Check for PIE
            result = subprocess.run(['otool', '-hv', str(self.binary_path)],
                                    capture_output=True, text=True)
            if 'PIE' in result.stdout:
                features['pie'] = True

            # Check for stack canary
            result = subprocess.run(['otool', '-Iv', str(self.binary_path)],
                                    capture_output=True, text=True)
            if '___stack_chk_fail' in result.stdout or '___stack_chk_guard' in result.stdout:
                features['stack_canary'] = True

            # Check for ARC
            if '_objc_release' in result.stdout:
                features['arc'] = True

            # Check if stripped
            result = subprocess.run(['nm', str(self.binary_path)],
                                    capture_output=True, text=True)
            if 'no symbols' in result.stderr:
                features['stripped'] = True

            # Check for restricted segment
            result = subprocess.run(['otool', '-l', str(self.binary_path)],
                                    capture_output=True, text=True)
            if '__RESTRICT' in result.stdout:
                features['restricted'] = True

        except Exception as e:
            self.logger.error(f"Failed to check security features: {e}")

        return features

    def extract_symbols(self) -> Dict[str, List[str]]:
        """Extract symbols from binary"""
        symbols = {
            'functions': [],
            'classes': [],
            'methods': [],
            'imports': []
        }

        try:
            # Extract all symbols
            result = subprocess.run(['nm', '-arch', 'arm64', str(self.binary_path)],
                                    capture_output=True, text=True)

            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    symbol_type = parts[1]
                    symbol_name = ' '.join(parts[2:])

                    # Categorize symbols
                    if symbol_type in ['T', 't']:  # Text (code) section
                        symbols['functions'].append(symbol_name)
                    elif symbol_type == 'U':  # Undefined (imported)
                        symbols['imports'].append(symbol_name)
                    elif '_OBJC_CLASS_$_' in symbol_name:
                        class_name = symbol_name.replace('_OBJC_CLASS_$_', '')
                        symbols['classes'].append(class_name)
                    elif '[' in symbol_name and ']' in symbol_name:
                        symbols['methods'].append(symbol_name)

        except Exception as e:
            self.logger.error(f"Failed to extract symbols: {e}")

        return symbols

    def extract_strings(self) -> Dict[str, List[str]]:
        """Extract strings from binary"""
        strings = {
            'urls': [],
            'api_keys': [],
            'sensitive_data': [],
            'file_paths': [],
            'interesting': []
        }

        try:
            # Extract strings
            result = subprocess.run(['strings', str(self.binary_path)],
                                    capture_output=True, text=True)

            for string in result.stdout.splitlines():
                # Categorize strings
                if re.match(r'https?://', string):
                    strings['urls'].append(string)
                elif re.match(r'^[A-Za-z0-9_-]{20,}$', string):
                    strings['api_keys'].append(string)
                elif any(keyword in string.lower() for keyword in
                         ['password', 'secret', 'key', 'token', 'auth']):
                    strings['sensitive_data'].append(string)
                elif string.startswith('/') and len(string) > 5:
                    strings['file_paths'].append(string)
                elif any(keyword in string.lower() for keyword in
                         ['debug', 'error', 'warning', 'jailbreak', 'root']):
                    strings['interesting'].append(string)

        except Exception as e:
            self.logger.error(f"Failed to extract strings: {e}")

        return strings

    def find_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Find potential vulnerabilities in binary"""
        vulnerabilities = []

        # Check for insecure functions
        insecure_functions = {
            '_strcpy': 'Buffer overflow risk',
            '_strcat': 'Buffer overflow risk',
            '_sprintf': 'Format string vulnerability',
            '_gets': 'Buffer overflow risk',
            '_scanf': 'Buffer overflow risk',
            '_system': 'Command injection risk'
        }

        symbols = self.extract_symbols()
        for func in symbols.get('imports', []):
            if func in insecure_functions:
                vulnerabilities.append({
                    'type': 'insecure_function',
                    'function': func,
                    'severity': 'High',
                    'description': insecure_functions[func]
                })

        # Check for weak crypto
        weak_crypto = {
            '_CC_MD5': 'MD5 hash function (weak)',
            '_CC_SHA1': 'SHA1 hash function (weak)',
            '_CCCrypt': 'Check for weak encryption modes'
        }

        for func in symbols.get('imports', []):
            if func in weak_crypto:
                vulnerabilities.append({
                    'type': 'weak_crypto',
                    'function': func,
                    'severity': 'Medium',
                    'description': weak_crypto[func]
                })

        # Check security features
        security_features = self.check_security_features()

        if not security_features.get('pie'):
            vulnerabilities.append({
                'type': 'missing_pie',
                'severity': 'Medium',
                'description': 'Binary not compiled with PIE'
            })

        if not security_features.get('stack_canary'):
            vulnerabilities.append({
                'type': 'missing_stack_canary',
                'severity': 'Medium',
                'description': 'Stack canaries not enabled'
            })

        # Check for debugging and logging functions
        debug_functions = ['NSLog', '_printf', '_NSAssert']
        for func in symbols.get('imports', []):
            if any(debug_func in func for debug_func in debug_functions):
                vulnerabilities.append({
                    'type': 'debug_logging',
                    'function': func,
                    'severity': 'Low',
                    'description': 'Debug logging function found'
                })

        return vulnerabilities

    def class_dump(self, output_dir: str) -> bool:
        """Dump Objective-C class information"""
        try:
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)

            subprocess.run([
                'class-dump',
                '-H',  # Generate header files
                '-o', str(output_path),
                str(self.binary_path)
            ], check=True)

            self.logger.info(f"Class dump completed to {output_dir}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Class dump failed: {e}")
            return False
        except FileNotFoundError:
            self.logger.error("class-dump tool not found")
            return False