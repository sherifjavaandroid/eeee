# src/core/scanner.py
import logging
import subprocess
import time
import os
from pathlib import Path
from typing import Dict, List, Any, Optional

from ..modules.android.apk_analyzer import APKAnalyzer
from ..modules.ios.ipa_analyzer import IPAAnalyzer
from ..modules.static_analysis.vulnerability_scanner import VulnerabilityScanner
from ..modules.dynamic_analysis.frida_manager import FridaManager
from ..utils.adb_helper import ADBHelper

class MobileSecurityScanner:
    def __init__(self, app_path: str, platform: str):
        self.app_path = Path(app_path)
        self.platform = platform.lower()
        self.logger = logging.getLogger(__name__)
        self.adb = ADBHelper()

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
        start_time = time.time()

        results = {
            'app_info': {},
            'manifest_issues': [],
            'code_issues': [],
            'secrets': [],
            'vulnerabilities': []
        }

        try:
            # Extract and analyze the app
            extracted_path = self.analyzer.extract()

            # Check extraction results
            if not extracted_path:
                self.logger.error("Extraction failed")
                raise RuntimeError("Failed to extract application")

            # Check for expected files and directories
            manifest_path = extracted_path / "AndroidManifest.xml"
            if not manifest_path.exists():
                self.logger.warning("AndroidManifest.xml not found in extracted files")
                # Try to locate in subdirectories
                manifest_files = list(extracted_path.glob("**/AndroidManifest.xml"))
                if manifest_files:
                    self.logger.info(f"Found manifest at alternative location: {manifest_files[0]}")

            # Get basic app information
            results['app_info'] = self.analyzer.get_app_info()
            self.logger.info(f"App info: {results['app_info']}")

            # Analyze manifest/plist
            results['manifest_issues'] = self.analyzer.analyze_manifest()
            self.logger.info(f"Found {len(results['manifest_issues'])} manifest issues")

            # Log directories in extracted path for debugging
            self.logger.info("Extracted directory structure:")
            for root, dirs, files in os.walk(extracted_path):
                level = root.replace(str(extracted_path), '').count(os.sep)
                indent = ' ' * 4 * level
                self.logger.info(f"{indent}{os.path.basename(root)}/")
                if level <= 2:  # Only show files for first few levels to avoid log spam
                    for f in files[:5]:  # Limit to 5 files per directory
                        self.logger.info(f"{indent}    {f}")
                    if len(files) > 5:
                        self.logger.info(f"{indent}    ... and {len(files)-5} more files")

            # Scan for Java files
            java_file_patterns = [
                '**/*.java',
                '**/src/**/*.java',
                '**/sources/**/*.java',
                '**/decompiled/**/*.java',
                '**/java/**/*.java'
            ]

            java_files = []
            for pattern in java_file_patterns:
                found_files = list(extracted_path.glob(pattern))
                java_files.extend(found_files)
                self.logger.info(f"Found {len(found_files)} Java files with pattern: {pattern}")

            # Remove duplicates
            java_files = list(set(java_files))
            self.logger.info(f"Total unique Java files found: {len(java_files)}")

            # Sample of Java files found
            if java_files:
                self.logger.info("Sample Java files:")
                for java_file in java_files[:5]:
                    self.logger.info(f"  - {java_file}")
            else:
                self.logger.warning("No Java files found for vulnerability scanning")

                # Check for smali files
                smali_files = list(extracted_path.glob("**/*.smali"))
                self.logger.info(f"Found {len(smali_files)} Smali files")

                if smali_files:
                    self.logger.info("Sample Smali files:")
                    for smali_file in smali_files[:5]:
                        self.logger.info(f"  - {smali_file}")

                    # Try to decompile smali files to java if needed
                    if hasattr(self.analyzer, 'convert_smali_to_java'):
                        self.logger.info("Attempting to convert Smali to Java...")
                        self.analyzer.convert_smali_to_java()

                        # Check for Java files again
                        java_files = []
                        for pattern in java_file_patterns:
                            found_files = list(extracted_path.glob(pattern))
                            java_files.extend(found_files)
                        java_files = list(set(java_files))
                        self.logger.info(f"After conversion: {len(java_files)} Java files")

            # Run vulnerability scanner with detailed logging
            self.logger.info(f"Running vulnerability scanner on extracted path: {extracted_path}")
            vulnerabilities = self.vulnerability_scanner.scan(extracted_path)
            results['vulnerabilities'] = vulnerabilities
            self.logger.info(f"Found {len(vulnerabilities)} code vulnerabilities")

            # Log first few vulnerabilities for debugging
            if vulnerabilities:
                self.logger.info("Sample vulnerabilities found:")
                for vuln in vulnerabilities[:3]:
                    self.logger.info(f"  - {vuln.get('type', 'Unknown')}: {vuln.get('description', 'No description')}")

            # Search for secrets
            self.logger.info(f"Searching for secrets in: {extracted_path}")
            secrets = self.vulnerability_scanner.find_secrets(extracted_path)
            results['secrets'] = secrets
            self.logger.info(f"Found {len(secrets)} secrets")

            # Log first few secrets for debugging
            if secrets:
                self.logger.info("Sample secrets found:")
                for secret in secrets[:3]:
                    self.logger.info(f"  - {secret.get('type', 'Unknown')}: {secret.get('file', 'Unknown file')}")

            # Log completion time
            elapsed_time = time.time() - start_time
            self.logger.info(f"Static analysis completed in {elapsed_time:.2f} seconds")
            return results

        except Exception as e:
            self.logger.error(f"Static analysis failed: {str(e)}")
            # Log detailed exception
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            raise

    def run_dynamic_analysis(self) -> Dict[str, Any]:
        """Run dynamic analysis on the application"""
        self.logger.info("Starting dynamic analysis...")
        start_time = time.time()

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

            # Check if rooted before running Frida tests
            is_rooted = False
            if self.platform == 'android':
                is_rooted = self._is_device_rooted()
                self.logger.info(f"Device root status: {'Rooted' if is_rooted else 'Not rooted'}")
                if not is_rooted:
                    self.logger.warning("Device is not rooted - Frida-based tests will be limited")

            # Connect Frida manager to device
            connected = self.frida_manager.connect_device()
            if not connected:
                self.logger.error("Failed to connect Frida to device")
                return results

            # Try to get device information
            try:
                device_info = self.adb.get_device_info()
                self.logger.info(f"Device info: {device_info}")
            except Exception as e:
                self.logger.warning(f"Failed to get device info: {e}")

            # Start Frida instrumentation
            package_name = self.analyzer.get_package_name()
            self.logger.info(f"Attaching to package: {package_name}")
            frida_attached = self.frida_manager.attach(package_name)

            # Only run Frida-based tests if attachment was successful
            if frida_attached:
                self.logger.info("Frida attachment successful, running Frida-based tests")

                # Run various tests
                self.logger.info("Testing runtime security...")
                results['runtime_issues'] = self._test_runtime_security()

                self.logger.info("Testing network security...")
                results['network_issues'] = self._test_network_security()

                self.logger.info("Testing data storage...")
                results['storage_issues'] = self._test_data_storage()

                self.logger.info("Discovering API endpoints...")
                results['api_endpoints'] = self._discover_api_endpoints()
            else:
                self.logger.warning("Skipping Frida-based tests due to attachment failure")

                # Run alternative tests that don't require Frida
                self.logger.info("Running alternative runtime security tests...")
                results['runtime_issues'] = self._test_runtime_security_alternative()

                # Try to get basic app info via ADB
                try:
                    if self.platform == 'android':
                        package_info = self.adb.execute_shell_command(f"dumpsys package {package_name}")
                        if package_info:
                            self.logger.info(f"Got package info via ADB ({len(package_info)} chars)")

                            # Extract essential information
                            if "allowBackup=" in package_info:
                                backup_setting = package_info.split("allowBackup=")[1].split()[0]
                                self.logger.info(f"Backup setting: {backup_setting}")

                                if backup_setting.lower() == "true":
                                    results['storage_issues'].append({
                                        'type': 'Backup Allowed',
                                        'severity': 'Medium',
                                        'description': 'Application allows backup via ADB',
                                        'evidence': 'allowBackup=true in package info'
                                    })
                except Exception as e:
                    self.logger.warning(f"Failed to get package info via ADB: {e}")

            # Log completion time
            elapsed_time = time.time() - start_time
            self.logger.info(f"Dynamic analysis completed in {elapsed_time:.2f} seconds")
            return results

        except Exception as e:
            self.logger.error(f"Dynamic analysis failed: {str(e)}")
            # Log detailed exception
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            raise
        finally:
            # Always try to detach Frida gracefully
            try:
                self.frida_manager.detach()
            except Exception as e:
                self.logger.warning(f"Error during Frida detachment: {e}")

    def _is_device_rooted(self) -> bool:
        """Check if Android device is rooted using multiple methods"""
        # Method 1: Check via su command
        try:
            result = self.adb.execute_shell_command('su -c id')
            if result and 'uid=0' in result:
                self.logger.info("Device is rooted (su command successful)")
                return True
        except Exception as e:
            self.logger.debug(f"su command check failed: {e}")

        # Method 2: Check existence of su binary
        try:
            result = self.adb.execute_shell_command('which su')
            if result and len(result.strip()) > 0:
                self.logger.info("Device is rooted (su binary found)")
                return True
        except Exception as e:
            self.logger.debug(f"su binary check failed: {e}")

        # Method 3: Check for Magisk app
        try:
            result = self.adb.execute_shell_command('pm list packages | grep magisk')
            if result and 'magisk' in result.lower():
                self.logger.info("Device is rooted (Magisk found)")
                return True
        except Exception as e:
            self.logger.debug(f"Magisk check failed: {e}")

        # Method 4: Try to access a root-only file
        try:
            result = self.adb.execute_shell_command('ls -la /data')
            if result and not 'permission denied' in result.lower():
                self.logger.info("Device is rooted (can access /data)")
                return True
        except Exception as e:
            self.logger.debug(f"Root directory access check failed: {e}")

        self.logger.info("Device does not appear to be rooted")
        return False

    def _install_android_app(self):
        """Install Android app using ADB"""
        try:
            # First try to uninstall any existing app
            package_name = self.analyzer.get_package_name()
            if package_name:
                try:
                    self.logger.info(f"Attempting to uninstall existing app: {package_name}")
                    subprocess.run(['adb', 'uninstall', package_name], check=False, timeout=30)
                except Exception as e:
                    self.logger.warning(f"Failed to uninstall existing app: {e}")

            # Verify ADB is available
            try:
                adb_version = subprocess.run(['adb', 'version'],
                                             capture_output=True, text=True, check=True)
                self.logger.info(f"ADB version: {adb_version.stdout.strip()}")
            except Exception as e:
                self.logger.error(f"ADB not available: {e}")
                raise RuntimeError("ADB not available")

            # List connected devices
            try:
                devices = subprocess.run(['adb', 'devices'],
                                         capture_output=True, text=True, check=True)
                self.logger.info(f"Connected devices: {devices.stdout.strip()}")

                # Check if any device is connected
                device_lines = devices.stdout.strip().split('\n')
                if len(device_lines) <= 1:
                    self.logger.error("No devices connected")
                    raise RuntimeError("No devices connected to ADB")
            except Exception as e:
                self.logger.error(f"Failed to list devices: {e}")
                raise

            # Now install the app with verbose logging
            self.logger.info(f"Installing app: {self.app_path}")
            try:
                install_process = subprocess.run(['adb', 'install', str(self.app_path)],
                                                 capture_output=True, text=True, check=True)
                self.logger.info(f"Installation output: {install_process.stdout}")
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Installation failed: {e.stdout} {e.stderr}")

                # Try with -r flag (reinstall) as fallback
                self.logger.info("Trying with -r flag (reinstall)")
                install_process = subprocess.run(['adb', 'install', '-r', str(self.app_path)],
                                                 capture_output=True, text=True, check=True)
                self.logger.info(f"Reinstallation output: {install_process.stdout}")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to install Android app: {e}")
            self.logger.error(f"Error output: {e.stderr}")
            raise RuntimeError(f"Failed to install Android app: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error during installation: {e}")
            raise RuntimeError(f"Unexpected error during installation: {e}")

    def _install_ios_app(self):
        """Install iOS app using ideviceinstaller"""
        try:
            # Check if ideviceinstaller is available
            try:
                subprocess.run(['ideviceinstaller', '--version'],
                               capture_output=True, text=True, check=True)
            except Exception as e:
                self.logger.error(f"ideviceinstaller not available: {e}")
                raise RuntimeError("ideviceinstaller not available")

            # List connected devices
            try:
                devices = subprocess.run(['idevice_id', '-l'],
                                         capture_output=True, text=True, check=True)
                self.logger.info(f"Connected iOS devices: {devices.stdout.strip()}")

                # Check if any device is connected
                if not devices.stdout.strip():
                    self.logger.error("No iOS devices connected")
                    raise RuntimeError("No iOS devices connected")
            except Exception as e:
                self.logger.error(f"Failed to list iOS devices: {e}")
                raise

            # Try to uninstall first
            package_name = self.analyzer.get_package_name()
            if package_name:
                try:
                    self.logger.info(f"Attempting to uninstall existing app: {package_name}")
                    subprocess.run(['ideviceinstaller', '-U', package_name],
                                   check=False, timeout=30, capture_output=True)
                except Exception as e:
                    self.logger.warning(f"Failed to uninstall existing app: {e}")

            # Now install the app
            self.logger.info(f"Installing iOS app: {self.app_path}")
            install_process = subprocess.run(['ideviceinstaller', '-i', str(self.app_path)],
                                             capture_output=True, text=True, check=True)
            self.logger.info(f"Installation output: {install_process.stdout}")

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to install iOS app: {e}")
            self.logger.error(f"Error output: {e.stderr}")
            raise RuntimeError(f"Failed to install iOS app: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error during iOS installation: {e}")
            raise RuntimeError(f"Unexpected error during iOS installation: {e}")

    def _test_runtime_security(self) -> List[Dict[str, Any]]:
        """Test runtime security features using Frida"""
        self.logger.info("Testing runtime security with Frida")
        issues = []

        # Test root/jailbreak detection
        self.logger.info("Testing root/jailbreak detection...")
        try:
            root_result = self.frida_manager.run_script('root_detection_bypass.js')
            self.logger.info(f"Root detection test result: {root_result}")

            if root_result and root_result.get('success'):
                issues.append({
                    'type': 'Root/Jailbreak Detection',
                    'severity': 'Medium',
                    'description': 'App has root/jailbreak detection that can be bypassed',
                    'details': str(root_result.get('messages', []))
                })
        except Exception as e:
            self.logger.error(f"Error testing root detection: {e}")

        # Test SSL pinning
        self.logger.info("Testing SSL pinning...")
        try:
            ssl_result = self.frida_manager.run_script('ssl_bypass.js')
            self.logger.info(f"SSL pinning test result: {ssl_result}")

            if ssl_result and ssl_result.get('success'):
                issues.append({
                    'type': 'SSL Pinning',
                    'severity': 'High',
                    'description': 'SSL pinning can be bypassed',
                    'details': str(ssl_result.get('messages', []))
                })
        except Exception as e:
            self.logger.error(f"Error testing SSL pinning: {e}")

        # List loaded classes if possible
        try:
            package_name = self.analyzer.get_package_name()
            self.logger.info(f"Listing loaded classes for {package_name}...")
            classes = self.frida_manager.list_loaded_classes(package_name)

            if classes:
                self.logger.info(f"Found {len(classes)} loaded classes")

                # Look for interesting security-related classes
                security_keywords = ['crypto', 'security', 'ssl', 'tls', 'cert', 'auth', 'crypt',
                                     'key', 'trust', 'password', 'biometric', 'fingerprint']

                security_classes = []
                for cls in classes:
                    if any(keyword in cls.lower() for keyword in security_keywords):
                        security_classes.append(cls)

                self.logger.info(f"Found {len(security_classes)} security-related classes")
                if security_classes:
                    issues.append({
                        'type': 'Security Classes',
                        'severity': 'Info',
                        'description': 'Security-related classes found in the application',
                        'details': str(security_classes[:10])  # First 10 classes
                    })
        except Exception as e:
            self.logger.error(f"Error listing classes: {e}")

        # Check security features
        try:
            self.logger.info("Checking security features...")
            security_features = self.frida_manager.check_security_features()
            self.logger.info(f"Security features: {security_features}")

            if security_features:
                # Report enabled security features
                for feature, enabled in security_features.items():
                    if enabled:
                        issues.append({
                            'type': f'{feature.replace("_", " ").title()}',
                            'severity': 'Info',
                            'description': f'Security feature detected: {feature}',
                            'details': f'The application implements {feature}'
                        })
        except Exception as e:
            self.logger.error(f"Error checking security features: {e}")

        return issues

    def _test_runtime_security_alternative(self) -> List[Dict[str, Any]]:
        """Alternative runtime security tests that don't require Frida"""
        self.logger.info("Running alternative runtime security tests")
        issues = []

        # Use ADB commands to check for common security issues
        if self.platform == 'android':
            # Check for debug flags in app settings
            package_name = self.analyzer.get_package_name()
            if package_name:
                # Check if app is debuggable
                try:
                    self.logger.info(f"Checking if app is debuggable: {package_name}")
                    result = self.adb.execute_shell_command(f'run-as {package_name} id')
                    if result:
                        self.logger.info(f"App is debuggable: {result}")
                        issues.append({
                            'type': 'Debuggable App',
                            'severity': 'High',
                            'description': 'Application is debuggable',
                            'details': f'run-as command succeeded: {result}'
                        })
                except Exception as e:
                    self.logger.info(f"App is not debuggable or error occurred: {e}")

                # Check app backup settings
                try:
                    self.logger.info(f"Checking backup settings: {package_name}")
                    result = self.adb.execute_shell_command(
                        f'dumpsys package {package_name} | grep allowBackup'
                    )
                    self.logger.info(f"Backup settings result: {result}")

                    if result and 'allowBackup=true' in result:
                        issues.append({
                            'type': 'Backup Allowed',
                            'severity': 'Medium',
                            'description': 'Application allows backup',
                            'details': f'allowBackup=true in package settings'
                        })
                except Exception as e:
                    self.logger.warning(f"Failed to check backup settings: {e}")

                # Check if app is running
                try:
                    self.logger.info(f"Checking if app is running: {package_name}")
                    result = self.adb.execute_shell_command(f'ps | grep {package_name}')
                    if result:
                        self.logger.info(f"App is running: {result}")
                    else:
                        self.logger.info("App is not running, trying to launch it")
                        launch_result = self.adb.execute_shell_command(
                            f'am start -n {package_name}/.MainActivity'
                        )
                        self.logger.info(f"Launch result: {launch_result}")
                except Exception as e:
                    self.logger.warning(f"Failed to check or launch app: {e}")

                # Check app permissions
                try:
                    self.logger.info(f"Checking app permissions: {package_name}")
                    result = self.adb.execute_shell_command(
                        f'dumpsys package {package_name} | grep permission'
                    )

                    if result:
                        self.logger.info(f"Permission info found ({len(result)} chars)")

                        # Check for dangerous permissions
                        dangerous_permissions = [
                            'CAMERA', 'RECORD_AUDIO', 'ACCESS_FINE_LOCATION',
                            'ACCESS_BACKGROUND_LOCATION', 'READ_CONTACTS', 'WRITE_CONTACTS',
                            'READ_CALL_LOG', 'WRITE_CALL_LOG', 'READ_EXTERNAL_STORAGE',
                            'WRITE_EXTERNAL_STORAGE', 'READ_SMS', 'RECEIVE_SMS', 'SEND_SMS'
                        ]

                        found_dangerous = []
                        for perm in dangerous_permissions:
                            if perm in result:
                                found_dangerous.append(perm)

                        if found_dangerous:
                            self.logger.info(f"Found dangerous permissions: {found_dangerous}")
                            issues.append({
                                'type': 'Dangerous Permissions',
                                'severity': 'Medium',
                                'description': 'Application uses potentially dangerous permissions',
                                'details': f'Permissions: {", ".join(found_dangerous)}'
                            })
                except Exception as e:
                    self.logger.warning(f"Failed to check permissions: {e}")

        # For iOS
        elif self.platform == 'ios':
            # Run iOS-specific tests
            try:
                # Check if the device is jailbroken
                self.logger.info("Checking if iOS device is jailbroken")
                # Common files found on jailbroken devices
                jailbreak_files = [
                    '/Applications/Cydia.app',
                    '/Library/MobileSubstrate/MobileSubstrate.dylib',
                    '/bin/bash',
                    '/usr/sbin/sshd',
                    '/etc/apt'
                ]

                jailbroken = False
                for jb_file in jailbreak_files:
                    try:
                        result = subprocess.run(
                            ['idevicesyslog', '-p', f'ls {jb_file}'],
                            capture_output=True, text=True, timeout=2
                        )
                        if 'No such file or directory' not in result.stdout:
                            jailbroken = True
                            self.logger.info(f"Jailbreak indicator found: {jb_file}")
                            break
                    except:
                        pass

                if jailbroken:
                    issues.append({
                        'type': 'Jailbroken Device',
                        'severity': 'Info',
                        'description': 'Device appears to be jailbroken',
                        'details': 'Jailbreak indicators found on device'
                    })
            except Exception as e:
                self.logger.warning(f"iOS jailbreak check failed: {e}")

        return issues

    def _test_network_security(self) -> List[Dict[str, Any]]:
        """Test network security using Frida and other tools"""
        self.logger.info("Testing network security")
        issues = []

        try:
            # Run network monitoring script with Frida
            self.logger.info("Running network API monitor...")
            monitor_result = self.frida_manager.run_script('api_monitor.js')
            self.logger.info(f"Network monitor result: {monitor_result}")

            if monitor_result and monitor_result.get('success'):
                # Extract findings
                findings = monitor_result.get('findings', [])
                for finding in findings:
                    if finding.get('type') == 'network':
                        issues.append({
                            'type': 'Network Request',
                            'severity': 'Info',
                            'description': f'Network request detected to {finding.get("url", "unknown")}',
                            'details': str(finding)
                        })
        except Exception as e:
            self.logger.error(f"Error testing network security: {e}")

        # Check for cleartext traffic
        if self.platform == 'android':
            try:
                package_name = self.analyzer.get_package_name()
                result = self.adb.execute_shell_command(
                    f'dumpsys package {package_name} | grep -A 5 "Network security config"'
                )

                if result:
                    self.logger.info(f"Network security config: {result}")
                    if 'cleartextTrafficPermitted=true' in result:
                        issues.append({
                            'type': 'Cleartext Traffic',
                            'severity': 'Medium',
                            'description': 'Application allows cleartext HTTP traffic',
                            'details': 'cleartextTrafficPermitted=true in network security config'
                        })
            except Exception as e:
                self.logger.warning(f"Failed to check cleartext traffic: {e}")

        return issues

    def _test_data_storage(self) -> List[Dict[str, Any]]:
        """Test data storage security using Frida and ADB"""
        self.logger.info("Testing data storage security")
        issues = []

        if self.platform == 'android':
            package_name = self.analyzer.get_package_name()

            # Check shared preferences
            try:
                self.logger.info(f"Checking shared preferences: {package_name}")
                # On a rooted device, we can directly access the app's data
                result = self.adb.execute_shell_command(
                    f'ls -la /data/data/{package_name}/shared_prefs/'
                )

                if result and 'Permission denied' not in result:
                    self.logger.info(f"Found shared preferences: {result}")

                    # Try to read the content of some preference files
                    pref_files = []
                    for line in result.splitlines():
                        parts = line.split()
                        if len(parts) >= 8 and parts[-1].endswith('.xml'):
                            pref_files.append(parts[-1])

                    if pref_files:
                        self.logger.info(f"Found {len(pref_files)} preference files: {pref_files}")

                        # Try to read a sample file
                        for pref_file in pref_files[:2]:  # Limit to first two files
                            try:
                                pref_content = self.adb.execute_shell_command(
                                    f'cat /data/data/{package_name}/shared_prefs/{pref_file}'
                                )
                                if pref_content:
                                    self.logger.info(f"SharedPreference content sample ({len(pref_content)} chars)")

                                    # Check for sensitive data in shared preferences
                                    sensitive_patterns = ['password', 'token', 'key', 'secret', 'credential', 'auth']
                                    found_sensitive = False

                                    for pattern in sensitive_patterns:
                                        if pattern in pref_content.lower():
                                            found_sensitive = True
                                            self.logger.warning(f"Found sensitive data pattern '{pattern}' in preferences")

                                    if found_sensitive:
                                        issues.append({
                                            'type': 'Insecure Data Storage',
                                            'severity': 'High',
                                            'description': 'Sensitive data stored in SharedPreferences',
                                            'details': f'Found sensitive data patterns in {pref_file}'
                                        })
                            except Exception as e:
                                self.logger.warning(f"Failed to read preference file {pref_file}: {e}")
            except Exception as e:
                self.logger.warning(f"Failed to check shared preferences: {e}")

            # Check for databases
            try:
                self.logger.info(f"Checking databases: {package_name}")
                result = self.adb.execute_shell_command(
                    f'ls -la /data/data/{package_name}/databases/'
                )

                if result and 'Permission denied' not in result:
                    self.logger.info(f"Found databases: {result}")

                    # Get database files
                    db_files = []
                    for line in result.splitlines():
                        parts = line.split()
                        if len(parts) >= 8 and (parts[-1].endswith('.db') or parts[-1].endswith('.sqlite')):
                            db_files.append(parts[-1])

                    if db_files:
                        self.logger.info(f"Found {len(db_files)} database files: {db_files}")
                        issues.append({
                            'type': 'Database Storage',
                            'severity': 'Info',
                            'description': 'Application uses SQLite databases for storage',
                            'details': f'Found databases: {", ".join(db_files)}'
                        })

                        # Try to get schema for a sample database
                        if db_files:
                            try:
                                schema = self.adb.execute_shell_command(
                                    f'sqlite3 /data/data/{package_name}/databases/{db_files[0]} ".schema"'
                                )

                                if schema:
                                    self.logger.info(f"Database schema for {db_files[0]}: {schema}")

                                    # Look for sensitive table names
                                    sensitive_tables = ['user', 'account', 'password', 'credit', 'payment', 'secret']
                                    for table in sensitive_tables:
                                        if f"CREATE TABLE {table}" in schema:
                                            issues.append({
                                                'type': 'Sensitive Database',
                                                'severity': 'Medium',
                                                'description': f'Potentially sensitive data stored in "{table}" table',
                                                'details': f'Found sensitive table in {db_files[0]}'
                                            })
                            except Exception as e:
                                self.logger.warning(f"Failed to get database schema: {e}")
            except Exception as e:
                self.logger.warning(f"Failed to check databases: {e}")

            # Check for files directory
            try:
                self.logger.info(f"Checking files directory: {package_name}")
                result = self.adb.execute_shell_command(
                    f'ls -la /data/data/{package_name}/files/'
                )

                if result and 'Permission denied' not in result:
                    self.logger.info(f"Found files: {result}")

                    # Check for sensitive file types
                    sensitive_extensions = ['.json', '.xml', '.txt', '.key', '.pem', '.der', '.p12', '.pfx']
                    sensitive_files = []

                    for line in result.splitlines():
                        parts = line.split()
                        if len(parts) >= 8:
                            filename = parts[-1]
                            if any(filename.endswith(ext) for ext in sensitive_extensions):
                                sensitive_files.append(filename)

                    if sensitive_files:
                        self.logger.info(f"Found potentially sensitive files: {sensitive_files}")
                        issues.append({
                            'type': 'File Storage',
                            'severity': 'Medium',
                            'description': 'Application stores potentially sensitive files',
                            'details': f'Found files with sensitive extensions: {", ".join(sensitive_files)}'
                        })
            except Exception as e:
                self.logger.warning(f"Failed to check files directory: {e}")

        elif self.platform == 'ios':
            package_name = self.analyzer.get_package_name()

            # iOS storage checks would go here
            # This would typically require a jailbroken device
            self.logger.info(f"iOS data storage checks would require a jailbroken device")

            issues.append({
                'type': 'iOS Data Storage',
                'severity': 'Info',
                'description': 'Data storage security testing on iOS requires a jailbroken device',
                'details': 'Consider using tools like Frida or Objection on a jailbroken device'
            })

        return issues

    def _discover_api_endpoints(self) -> List[str]:
        """Discover API endpoints using Frida and traffic analysis"""
        self.logger.info("Discovering API endpoints")
        endpoints = []

        try:
            # Use Frida to monitor network requests
            self.logger.info("Running API monitor script...")
            monitor_result = self.frida_manager.run_script('api_monitor.js')

            if monitor_result and monitor_result.get('success'):
                # Extract endpoints from findings
                findings = monitor_result.get('findings', [])

                for finding in findings:
                    if finding.get('type') == 'network' and finding.get('url'):
                        url = finding.get('url')
                        if url not in endpoints:
                            endpoints.append(url)

            self.logger.info(f"Found {len(endpoints)} API endpoints")

            # Sample of endpoints found
            if endpoints:
                self.logger.info("Sample endpoints:")
                for endpoint in endpoints[:5]:  # Show first 5
                    self.logger.info(f"  - {endpoint}")

                if len(endpoints) > 5:
                    self.logger.info(f"  ... and {len(endpoints) - 5} more")
        except Exception as e:
            self.logger.error(f"Error discovering API endpoints: {e}")

        # Alternative method: static analysis of strings/code
        if not endpoints and self.platform == 'android':
            try:
                self.logger.info("Trying static analysis to find endpoints...")
                extracted_path = self.analyzer.get_extracted_path()

                # Look for URLs in strings.xml
                strings_xml_paths = list(extracted_path.glob("**/strings.xml"))
                for strings_path in strings_xml_paths:
                    try:
                        with open(strings_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                            # Simple regex for URLs
                            import re
                            url_pattern = r'https?://[^\s"\'<>)]+\.[^\s"\'<>)]*'
                            matches = re.findall(url_pattern, content)

                            for url in matches:
                                if url not in endpoints:
                                    endpoints.append(url)
                    except Exception as e:
                        self.logger.warning(f"Error parsing {strings_path}: {e}")

                # Look for URLs in Java files
                java_files = []
                java_patterns = ['**/*.java', '**/src/**/*.java', '**/sources/**/*.java']

                for pattern in java_patterns:
                    found_files = list(extracted_path.glob(pattern))
                    java_files.extend(found_files)

                for java_file in java_files[:20]:  # Limit to first 20 files
                    try:
                        with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                            # Look for URLs
                            url_pattern = r'https?://[^\s"\'<>)]+\.[^\s"\'<>)]*'
                            matches = re.findall(url_pattern, content)

                            for url in matches:
                                if url not in endpoints:
                                    endpoints.append(url)
                    except Exception as e:
                        self.logger.warning(f"Error parsing {java_file}: {e}")

                # Look for API patterns
                api_patterns = ['/api/v[0-9]+/', '/rest/', '/graphql']
                for java_file in java_files[:20]:
                    try:
                        with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                            for pattern in api_patterns:
                                if pattern in content:
                                    self.logger.info(f"Found API pattern {pattern} in {java_file}")
                                    endpoints.append(f"API pattern: {pattern}")
                    except Exception as e:
                        self.logger.warning(f"Error searching API patterns in {java_file}: {e}")

                self.logger.info(f"Found {len(endpoints)} API endpoints via static analysis")
            except Exception as e:
                self.logger.error(f"Error in static endpoint discovery: {e}")

        return endpoints