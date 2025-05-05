# src/modules/android/apk_analyzer.py
import os
import subprocess
import tempfile
import zipfile
import logging
from pathlib import Path
from typing import Dict, List, Any
import xml.etree.ElementTree as ET
import platform

class APKAnalyzer:
    def __init__(self, apk_path: str):
        self.apk_path = Path(apk_path)
        self.extracted_path = None
        self.logger = logging.getLogger(__name__)
        self.manifest_data = None
        self.package_name = None
        self.is_windows = platform.system() == "Windows"

        # Check if APK file exists
        if not self.apk_path.exists():
            raise FileNotFoundError(f"APK file not found: {apk_path}")

        self.logger.info(f"Initializing APKAnalyzer for: {apk_path}")

        # Skip tool check - we'll handle errors during actual usage
        self.logger.info("Skipping tool check - will verify during execution")

    def _run_tool(self, tool_name: str, args: List[str], timeout: int = 300) -> subprocess.CompletedProcess:
        """Run a tool with Windows compatibility"""
        if self.is_windows:
            # For Windows, use startupinfo to prevent console windows
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE

            # Try direct execution without checking version
            if tool_name == "apktool":
                # Method 1: Direct execution with full command
                cmd = f"apktool {' '.join(args)}"
                self.logger.debug(f"Running command: {cmd}")
                try:
                    # Use Popen instead of run for better control
                    process = subprocess.Popen(
                        cmd,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        startupinfo=startupinfo
                    )
                    stdout, stderr = process.communicate(timeout=timeout)
                    return subprocess.CompletedProcess(cmd, process.returncode, stdout, stderr)
                except subprocess.TimeoutExpired:
                    process.kill()
                    raise
            else:
                # For other tools like aapt
                cmd = [tool_name] + args
                return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, startupinfo=startupinfo)
        else:
            # Unix-like systems
            cmd = [tool_name] + args
            return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)



    def extract(self) -> Path:
        """Extract APK contents"""
        self.logger.info("Starting APK extraction...")
        self.extracted_path = Path(tempfile.mkdtemp())
        self.logger.info(f"Temporary extraction path: {self.extracted_path}")

        try:
            # Extract using apktool
            self.logger.info(f"Extracting APK using apktool...")
            result = self._run_tool(
                "apktool",
                ["d", "-f", str(self.apk_path), "-o", str(self.extracted_path)],
                timeout=300
            )

            if result.returncode != 0:
                self.logger.error(f"apktool failed with return code {result.returncode}")
                self.logger.error(f"stdout: {result.stdout}")
                self.logger.error(f"stderr: {result.stderr}")

                # Fallback to basic ZIP extraction if apktool fails
                self.logger.warning("Falling back to ZIP extraction...")
                return self._extract_as_zip()

            self.logger.info(f"APK extracted successfully to: {self.extracted_path}")
            return self.extracted_path

        except subprocess.TimeoutExpired:
            self.logger.error("APK extraction timed out")
            self.logger.warning("Falling back to ZIP extraction...")
            return self._extract_as_zip()
        except Exception as e:
            self.logger.error(f"Unexpected error during extraction: {e}")
            self.logger.warning("Falling back to ZIP extraction...")
            return self._extract_as_zip()




    def _extract_as_zip(self) -> Path:
        """Fallback extraction method using ZIP"""
        try:
            self.logger.info("Extracting APK as ZIP file...")
            with zipfile.ZipFile(self.apk_path, 'r') as zip_ref:
                zip_ref.extractall(self.extracted_path)
            self.logger.info(f"ZIP extraction completed to: {self.extracted_path}")
            return self.extracted_path
        except Exception as e:
            self.logger.error(f"ZIP extraction failed: {e}")
            raise RuntimeError(f"Failed to extract APK: {e}")

    def get_app_info(self) -> Dict[str, Any]:
        """Get basic app information"""
        self.logger.info("Getting app info...")
        info = {}

        try:
            # Use aapt to get app info
            self.logger.info("Getting app info using aapt...")
            result = self._run_tool(
                "aapt",
                ["dump", "badging", str(self.apk_path)],
                timeout=30
            )

            if result.returncode != 0:
                self.logger.error(f"aapt failed: {result.stderr}")
                # Fallback to basic info
                return self._get_basic_info()

            output = result.stdout
            self.logger.debug(f"aapt output length: {len(output)} characters")

            # Parse package name
            if "package: name='" in output:
                self.package_name = output.split("package: name='")[1].split("'")[0]
                info['package_name'] = self.package_name
                self.logger.info(f"Package name: {self.package_name}")

            # Parse version
            if "versionName='" in output:
                info['version'] = output.split("versionName='")[1].split("'")[0]
                self.logger.info(f"Version: {info['version']}")

            # Parse permissions
            permissions = []
            for line in output.splitlines():
                if line.startswith('uses-permission:'):
                    perm = line.split("'")[1]
                    permissions.append(perm)
            info['permissions'] = permissions
            self.logger.info(f"Found {len(permissions)} permissions")

            return info

        except Exception as e:
            self.logger.error(f"Failed to get app info: {e}")
            return self._get_basic_info()

    def _get_basic_info(self) -> Dict[str, Any]:
        """Get basic info when tools fail"""
        return {
            'package_name': 'unknown',
            'version': 'unknown',
            'permissions': []
        }

    def analyze_manifest(self) -> List[Dict[str, Any]]:
        """Analyze AndroidManifest.xml for security issues"""
        self.logger.info("Analyzing manifest...")

        if not self.extracted_path:
            self.logger.error("APK not extracted yet")
            return []

        issues = []

        # Try both possible manifest locations
        possible_paths = [
            self.extracted_path / 'AndroidManifest.xml',
            self.extracted_path / 'original' / 'AndroidManifest.xml'
        ]

        manifest_path = None
        for path in possible_paths:
            if path.exists():
                manifest_path = path
                break

        if not manifest_path:
            self.logger.warning("AndroidManifest.xml not found, trying to parse binary manifest...")
            # If extracted as ZIP, the manifest might be in binary format
            binary_manifest = self.extracted_path / 'AndroidManifest.xml'
            if binary_manifest.exists():
                self.logger.info("Found binary manifest, basic analysis only")
                # Basic analysis for binary manifest
                return [{
                    'type': 'Binary Manifest',
                    'severity': 'Info',
                    'description': 'Manifest is in binary format, detailed analysis limited',
                    'location': 'AndroidManifest.xml'
                }]
            return issues

        try:
            self.logger.info(f"Parsing manifest at: {manifest_path}")
            tree = ET.parse(manifest_path)
            root = tree.getroot()

            # Check for debuggable flag
            app_elem = root.find('.//application')
            if app_elem is not None:
                debuggable = app_elem.get('{http://schemas.android.com/apk/res/android}debuggable')
                if debuggable == 'true':
                    self.logger.warning("App is debuggable!")
                    issues.append({
                        'type': 'Debuggable App',
                        'severity': 'High',
                        'description': 'Application is debuggable',
                        'location': 'AndroidManifest.xml'
                    })

                # Check allowBackup
                allow_backup = app_elem.get('{http://schemas.android.com/apk/res/android}allowBackup')
                if allow_backup == 'true':
                    self.logger.warning("App allows backup!")
                    issues.append({
                        'type': 'Backup Allowed',
                        'severity': 'Medium',
                        'description': 'Application allows backup',
                        'location': 'AndroidManifest.xml'
                    })

            # Check for exported components
            for component in ['activity', 'service', 'receiver', 'provider']:
                component_count = 0
                for elem in root.findall(f'.//{component}'):
                    component_count += 1
                    exported = elem.get('{http://schemas.android.com/apk/res/android}exported')
                    if exported == 'true':
                        name = elem.get('{http://schemas.android.com/apk/res/android}name')
                        self.logger.warning(f"Found exported {component}: {name}")
                        issues.append({
                            'type': 'Exported Component',
                            'severity': 'Medium',
                            'description': f'Exported {component}: {name}',
                            'location': 'AndroidManifest.xml'
                        })
                self.logger.info(f"Found {component_count} {component}(s)")

            self.logger.info(f"Manifest analysis found {len(issues)} issues")
            return issues

        except ET.ParseError as e:
            self.logger.error(f"Failed to parse manifest XML: {e}")
            return [{
                'type': 'Manifest Parse Error',
                'severity': 'Info',
                'description': 'Could not parse manifest XML',
                'location': 'AndroidManifest.xml'
            }]
        except Exception as e:
            self.logger.error(f"Failed to analyze manifest: {e}")
            return []

    def get_extracted_path(self) -> Path:
        """Get the path to extracted APK contents"""
        return self.extracted_path

    def get_package_name(self) -> str:
        """Get the package name"""
        if not self.package_name:
            self.get_app_info()
        return self.package_name or 'unknown'