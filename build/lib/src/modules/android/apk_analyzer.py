import os
import subprocess
import tempfile
import zipfile
import logging
from pathlib import Path
from typing import Dict, List, Any
import xml.etree.ElementTree as ET

class APKAnalyzer:
    def __init__(self, apk_path: str):
        self.apk_path = Path(apk_path)
        self.extracted_path = None
        self.logger = logging.getLogger(__name__)
        self.manifest_data = None
        self.package_name = None

    def extract(self) -> Path:
        """Extract APK contents"""
        self.extracted_path = Path(tempfile.mkdtemp())

        try:
            # Extract using apktool
            subprocess.run([
                'apktool', 'd', '-f', str(self.apk_path),
                '-o', str(self.extracted_path)
            ], check=True, capture_output=True)

            self.logger.info(f"APK extracted to: {self.extracted_path}")
            return self.extracted_path

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to extract APK: {e}")
            raise

    def get_app_info(self) -> Dict[str, Any]:
        """Get basic app information"""
        info = {}

        try:
            # Use aapt to get app info
            result = subprocess.run([
                'aapt', 'dump', 'badging', str(self.apk_path)
            ], capture_output=True, text=True)

            output = result.stdout

            # Parse package name
            if "package: name='" in output:
                self.package_name = output.split("package: name='")[1].split("'")[0]
                info['package_name'] = self.package_name

            # Parse version
            if "versionName='" in output:
                info['version'] = output.split("versionName='")[1].split("'")[0]

            # Parse permissions
            permissions = []
            for line in output.splitlines():
                if line.startswith('uses-permission:'):
                    perm = line.split("'")[1]
                    permissions.append(perm)
            info['permissions'] = permissions

            return info

        except Exception as e:
            self.logger.error(f"Failed to get app info: {e}")
            return info

    def analyze_manifest(self) -> List[Dict[str, Any]]:
        """Analyze AndroidManifest.xml for security issues"""
        issues = []
        manifest_path = self.extracted_path / 'AndroidManifest.xml'

        if not manifest_path.exists():
            self.logger.error("AndroidManifest.xml not found")
            return issues

        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()

            # Check for debuggable flag
            app_elem = root.find('.//application')
            if app_elem is not None:
                debuggable = app_elem.get('{http://schemas.android.com/apk/res/android}debuggable')
                if debuggable == 'true':
                    issues.append({
                        'type': 'Debuggable App',
                        'severity': 'High',
                        'description': 'Application is debuggable',
                        'location': 'AndroidManifest.xml'
                    })

                # Check allowBackup
                allow_backup = app_elem.get('{http://schemas.android.com/apk/res/android}allowBackup')
                if allow_backup == 'true':
                    issues.append({
                        'type': 'Backup Allowed',
                        'severity': 'Medium',
                        'description': 'Application allows backup',
                        'location': 'AndroidManifest.xml'
                    })

            # Check for exported components
            for component in ['activity', 'service', 'receiver', 'provider']:
                for elem in root.findall(f'.//{component}'):
                    exported = elem.get('{http://schemas.android.com/apk/res/android}exported')
                    if exported == 'true':
                        name = elem.get('{http://schemas.android.com/apk/res/android}name')
                        issues.append({
                            'type': 'Exported Component',
                            'severity': 'Medium',
                            'description': f'Exported {component}: {name}',
                            'location': 'AndroidManifest.xml'
                        })

            return issues

        except Exception as e:
            self.logger.error(f"Failed to analyze manifest: {e}")
            return issues

    def get_extracted_path(self) -> Path:
        """Get the path to extracted APK contents"""
        return self.extracted_path

    def get_package_name(self) -> str:
        """Get the package name"""
        if not self.package_name:
            self.get_app_info()
        return self.package_name