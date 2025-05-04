import os
import subprocess
import tempfile
import zipfile
import plistlib
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional

class IPAAnalyzer:
    def __init__(self, ipa_path: str):
        self.ipa_path = Path(ipa_path)
        self.extracted_path = None
        self.logger = logging.getLogger(__name__)
        self.app_path = None
        self.info_plist = None
        self.bundle_id = None

    def extract(self) -> Path:
        """Extract IPA contents"""
        self.extracted_path = Path(tempfile.mkdtemp())

        try:
            # Extract IPA (which is a ZIP file)
            with zipfile.ZipFile(self.ipa_path, 'r') as zip_ref:
                zip_ref.extractall(self.extracted_path)

            # Find the .app directory
            payload_dir = self.extracted_path / 'Payload'
            if payload_dir.exists():
                app_dirs = [d for d in payload_dir.iterdir() if d.is_dir() and d.suffix == '.app']
                if app_dirs:
                    self.app_path = app_dirs[0]
                else:
                    raise Exception("No .app directory found in Payload")
            else:
                raise Exception("No Payload directory found in IPA")

            self.logger.info(f"IPA extracted to: {self.extracted_path}")
            return self.extracted_path

        except Exception as e:
            self.logger.error(f"Failed to extract IPA: {e}")
            raise

    def get_app_info(self) -> Dict[str, Any]:
        """Get basic app information from Info.plist"""
        if not self.app_path:
            self.extract()

        info = {}

        try:
            # Read Info.plist
            info_plist_path = self.app_path / 'Info.plist'
            if info_plist_path.exists():
                with open(info_plist_path, 'rb') as f:
                    self.info_plist = plistlib.load(f)

                # Extract basic information
                self.bundle_id = self.info_plist.get('CFBundleIdentifier', '')
                info['bundle_id'] = self.bundle_id
                info['display_name'] = self.info_plist.get('CFBundleDisplayName', '')
                info['version'] = self.info_plist.get('CFBundleShortVersionString', '')
                info['build'] = self.info_plist.get('CFBundleVersion', '')
                info['minimum_os'] = self.info_plist.get('MinimumOSVersion', '')

                # Extract permissions
                info['permissions'] = []
                permission_keys = [
                    'NSCameraUsageDescription',
                    'NSPhotoLibraryUsageDescription',
                    'NSLocationWhenInUseUsageDescription',
                    'NSLocationAlwaysUsageDescription',
                    'NSMicrophoneUsageDescription',
                    'NSContactsUsageDescription',
                    'NSCalendarsUsageDescription',
                    'NSHealthShareUsageDescription',
                    'NSHealthUpdateUsageDescription',
                    'NSMotionUsageDescription',
                    'NSBluetoothPeripheralUsageDescription'
                ]

                for key in permission_keys:
                    if key in self.info_plist:
                        info['permissions'].append({
                            'key': key,
                            'description': self.info_plist[key]
                        })

                # Check for URL schemes
                if 'CFBundleURLTypes' in self.info_plist:
                    info['url_schemes'] = []
                    for url_type in self.info_plist['CFBundleURLTypes']:
                        schemes = url_type.get('CFBundleURLSchemes', [])
                        info['url_schemes'].extend(schemes)

            return info

        except Exception as e:
            self.logger.error(f"Failed to get app info: {e}")
            return info

    def analyze_info_plist(self) -> List[Dict[str, Any]]:
        """Analyze Info.plist for security issues"""
        issues = []

        if not self.info_plist:
            self.get_app_info()

        if not self.info_plist:
            self.logger.error("Info.plist not found")
            return issues

        try:
            # Check for App Transport Security (ATS) settings
            ats = self.info_plist.get('NSAppTransportSecurity', {})
            if ats.get('NSAllowsArbitraryLoads', False):
                issues.append({
                    'type': 'Insecure Network Configuration',
                    'severity': 'High',
                    'description': 'App allows arbitrary network loads (ATS disabled)',
                    'location': 'Info.plist'
                })

            # Check for specific domain exceptions
            if 'NSExceptionDomains' in ats:
                for domain, settings in ats['NSExceptionDomains'].items():
                    if settings.get('NSExceptionAllowsInsecureHTTPLoads', False):
                        issues.append({
                            'type': 'Insecure Domain Exception',
                            'severity': 'Medium',
                            'description': f'Insecure HTTP allowed for domain: {domain}',
                            'location': 'Info.plist'
                        })

            # Check for background modes
            bg_modes = self.info_plist.get('UIBackgroundModes', [])
            if 'fetch' in bg_modes or 'remote-notification' in bg_modes:
                issues.append({
                    'type': 'Background Execution',
                    'severity': 'Low',
                    'description': 'App can execute in background',
                    'location': 'Info.plist',
                    'details': ', '.join(bg_modes)
                })

            # Check for URL schemes
            url_types = self.info_plist.get('CFBundleURLTypes', [])
            for url_type in url_types:
                schemes = url_type.get('CFBundleURLSchemes', [])
                for scheme in schemes:
                    issues.append({
                        'type': 'Custom URL Scheme',
                        'severity': 'Low',
                        'description': f'Custom URL scheme registered: {scheme}',
                        'location': 'Info.plist'
                    })

            # Check for exported file types
            if 'UTExportedTypeDeclarations' in self.info_plist:
                issues.append({
                    'type': 'Exported File Types',
                    'severity': 'Low',
                    'description': 'App exports custom file types',
                    'location': 'Info.plist'
                })

            # Check for debugging settings
            if self.info_plist.get('GCDebugEnabled', False):
                issues.append({
                    'type': 'Debug Mode Enabled',
                    'severity': 'Medium',
                    'description': 'Game Center debug mode is enabled',
                    'location': 'Info.plist'
                })

            return issues

        except Exception as e:
            self.logger.error(f"Failed to analyze Info.plist: {e}")
            return issues

    def analyze_binary(self) -> List[Dict[str, Any]]:
        """Analyze the binary for security features"""
        issues = []

        if not self.app_path:
            self.extract()

        try:
            # Find the main executable
            executable_name = self.info_plist.get('CFBundleExecutable', '')
            if not executable_name:
                return issues

            executable_path = self.app_path / executable_name
            if not executable_path.exists():
                return issues

            # Check for encryption
            result = subprocess.run(
                ['otool', '-l', str(executable_path)],
                capture_output=True,
                text=True
            )

            if 'LC_ENCRYPTION_INFO' in result.stdout:
                # Parse encryption info
                lines = result.stdout.splitlines()
                for i, line in enumerate(lines):
                    if 'LC_ENCRYPTION_INFO' in line:
                        # Check next few lines for cryptid
                        for j in range(i + 1, min(i + 5, len(lines))):
                            if 'cryptid' in lines[j]:
                                cryptid = int(lines[j].split()[-1])
                                if cryptid == 0:
                                    issues.append({
                                        'type': 'Binary Not Encrypted',
                                        'severity': 'High',
                                        'description': 'Binary is not encrypted',
                                        'location': executable_name
                                    })
                                break

            # Check for debugging symbols
            result = subprocess.run(
                ['nm', str(executable_path)],
                capture_output=True,
                text=True
            )

            if result.stdout:
                # Check for debugging symbols
                debug_symbols = ['_NSLog', '_printf', '_NSAssert']
                for symbol in debug_symbols:
                    if symbol in result.stdout:
                        issues.append({
                            'type': 'Debug Symbols Present',
                            'severity': 'Low',
                            'description': f'Debug symbol found: {symbol}',
                            'location': executable_name
                        })

            # Check for stack protection
            result = subprocess.run(
                ['otool', '-Iv', str(executable_path)],
                capture_output=True,
                text=True
            )

            if '__stack_chk_fail' not in result.stdout:
                issues.append({
                    'type': 'Stack Protection Missing',
                    'severity': 'Medium',
                    'description': 'Binary compiled without stack protection',
                    'location': executable_name
                })

            # Check for PIE (Position Independent Executable)
            result = subprocess.run(
                ['otool', '-hv', str(executable_path)],
                capture_output=True,
                text=True
            )

            if 'PIE' not in result.stdout:
                issues.append({
                    'type': 'PIE Not Enabled',
                    'severity': 'Medium',
                    'description': 'Binary not compiled as Position Independent Executable',
                    'location': executable_name
                })

            return issues

        except Exception as e:
            self.logger.error(f"Failed to analyze binary: {e}")
            return issues

    def get_extracted_path(self) -> Path:
        """Get the path to extracted IPA contents"""
        return self.extracted_path

    def get_bundle_id(self) -> str:
        """Get the bundle ID"""
        if not self.bundle_id:
            self.get_app_info()
        return self.bundle_id