import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Any

from ..modules.android.apk_analyzer import APKAnalyzer
from ..modules.ios.ipa_analyzer import IPAAnalyzer
from ..modules.static_analysis.vulnerability_scanner import VulnerabilityScanner
from ..modules.dynamic_analysis.frida_manager import FridaManager

class MobileSecurityScanner:
    def __init__(self, app_path: str, platform: str):
        self.app_path = Path(app_path)
        self.platform = platform.lower()
        self.logger = logging.getLogger(__name__)

        # Initialize platform-specific analyzer
        if self.platform == 'android':
            self.analyzer = APKAnalyzer(app_path)
        elif self.platform == 'ios':
            self.analyzer = IPAAnalyzer(app_path)
        else:
            raise ValueError(f"Unsupported platform: {platform}")

        self.vulnerability_scanner = VulnerabilityScanner()
        self.frida_manager = FridaManager()

    def run_static_analysis(self) -> Dict[str, Any]:
        """Run static analysis on the application"""
        self.logger.info("Starting static analysis...")

        results = {
            'app_info': {},
            'manifest_issues': [],
            'code_issues': [],
            'secrets': [],
            'vulnerabilities': []
        }

        try:
            # Extract and analyze the app
            self.analyzer.extract()

            # Get basic app information
            results['app_info'] = self.analyzer.get_app_info()

            # Analyze manifest/plist
            results['manifest_issues'] = self.analyzer.analyze_manifest()

            # Scan for vulnerabilities
            results['vulnerabilities'] = self.vulnerability_scanner.scan(
                self.analyzer.get_extracted_path()
            )

            # Search for secrets
            results['secrets'] = self.vulnerability_scanner.find_secrets(
                self.analyzer.get_extracted_path()
            )

            return results

        except Exception as e:
            self.logger.error(f"Static analysis failed: {str(e)}")
            raise

    def run_dynamic_analysis(self) -> Dict[str, Any]:
        """Run dynamic analysis on the application"""
        self.logger.info("Starting dynamic analysis...")

        results = {
            'runtime_issues': [],
            'network_issues': [],
            'storage_issues': [],
            'api_endpoints': []
        }

        try:
            # Install the app
            if self.platform == 'android':
                self._install_android_app()
            else:
                self._install_ios_app()

            # Start Frida instrumentation
            package_name = self.analyzer.get_package_name()
            self.frida_manager.attach(package_name)

            # Run various tests
            results['runtime_issues'] = self._test_runtime_security()
            results['network_issues'] = self._test_network_security()
            results['storage_issues'] = self._test_data_storage()
            results['api_endpoints'] = self._discover_api_endpoints()

            return results

        except Exception as e:
            self.logger.error(f"Dynamic analysis failed: {str(e)}")
            raise
        finally:
            self.frida_manager.detach()

    def _install_android_app(self):
        """Install Android app using ADB"""
        try:
            subprocess.run(['adb', 'install', str(self.app_path)], check=True)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to install Android app: {e}")

    def _install_ios_app(self):
        """Install iOS app using ideviceinstaller"""
        try:
            subprocess.run(['ideviceinstaller', '-i', str(self.app_path)], check=True)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to install iOS app: {e}")

    def _test_runtime_security(self) -> List[Dict[str, Any]]:
        """Test runtime security features"""
        issues = []

        # Test root/jailbreak detection
        if self.frida_manager.run_script('root_detection_bypass.js'):
            issues.append({
                'type': 'Root/Jailbreak Detection',
                'severity': 'Medium',
                'description': 'App has weak root/jailbreak detection'
            })

        # Test SSL pinning
        if self.frida_manager.run_script('ssl_pinning_bypass.js'):
            issues.append({
                'type': 'SSL Pinning',
                'severity': 'High',
                'description': 'SSL pinning can be bypassed'
            })

        return issues

    def _test_network_security(self) -> List[Dict[str, Any]]:
        """Test network security"""
        # Implementation for network security testing
        return []

    def _test_data_storage(self) -> List[Dict[str, Any]]:
        """Test data storage security"""
        # Implementation for data storage testing
        return []

    def _discover_api_endpoints(self) -> List[str]:
        """Discover API endpoints"""
        # Implementation for API endpoint discovery
        return []