import subprocess
import time
import logging
from typing import Dict, List, Any, Optional
from src.utils.adb_helper import ADBHelper

class DynamicTester:
    def __init__(self, package_name: str):
        self.package_name = package_name
        self.logger = logging.getLogger(__name__)
        self.adb = ADBHelper()
        self.activities = []
        self.services = []
        self.receivers = []
        self.providers = []

    def setup(self) -> bool:
        """Setup device for testing"""
        if not self.adb.check_adb():
            self.logger.error("ADB not available")
            return False

        devices = self.adb.list_devices()
        if not devices:
            self.logger.error("No devices connected")
            return False

        self.adb.set_device(devices[0])
        return True

    def get_components(self) -> Dict[str, List[str]]:
        """Get all components of the app"""
        components = {
            'activities': [],
            'services': [],
            'receivers': [],
            'providers': []
        }

        try:
            # Get package info
            output = self.adb.execute_shell_command(f'dumpsys package {self.package_name}')
            if not output:
                return components

            current_section = None

            for line in output.splitlines():
                line = line.strip()

                if 'Activity Resolver Table:' in line:
                    current_section = 'activities'
                elif 'Service Resolver Table:' in line:
                    current_section = 'services'
                elif 'Receiver Resolver Table:' in line:
                    current_section = 'receivers'
                elif 'Provider Resolver Table:' in line:
                    current_section = 'providers'
                elif line.startswith(self.package_name) and current_section:
                    component_name = line.split(' ')[0]
                    components[current_section].append(component_name)

            self.activities = components['activities']
            self.services = components['services']
            self.receivers = components['receivers']
            self.providers = components['providers']

            return components

        except Exception as e:
            self.logger.error(f"Failed to get components: {e}")
            return components

    def test_exported_activities(self) -> List[Dict[str, Any]]:
        """Test exported activities"""
        vulnerabilities = []

        for activity in self.activities:
            try:
                # Try to start the activity
                result = self.adb.execute_shell_command(
                    f'am start -n {activity}'
                )

                if result and 'Error' not in result:
                    vulnerabilities.append({
                        'type': 'exported_activity',
                        'component': activity,
                        'severity': 'Medium',
                        'description': f'Activity {activity} can be launched externally',
                        'exploitation': f'adb shell am start -n {activity}'
                    })

            except Exception as e:
                self.logger.error(f"Error testing activity {activity}: {e}")

        return vulnerabilities

    def test_exported_services(self) -> List[Dict[str, Any]]:
        """Test exported services"""
        vulnerabilities = []

        for service in self.services:
            try:
                # Try to start the service
                result = self.adb.execute_shell_command(
                    f'am startservice -n {service}'
                )

                if result and 'Error' not in result:
                    vulnerabilities.append({
                        'type': 'exported_service',
                        'component': service,
                        'severity': 'High',
                        'description': f'Service {service} can be started externally',
                        'exploitation': f'adb shell am startservice -n {service}'
                    })

            except Exception as e:
                self.logger.error(f"Error testing service {service}: {e}")

        return vulnerabilities

    def test_content_providers(self) -> List[Dict[str, Any]]:
        """Test content providers"""
        vulnerabilities = []

        # Common content provider URIs
        common_paths = [
            '',
            'users',
            'accounts',
            'settings',
            'data',
            'files',
            'database'
        ]

        for provider in self.providers:
            # Extract provider authority
            authority = provider.split('/')[-1]

            for path in common_paths:
                uri = f"content://{authority}/{path}"

                try:
                    # Try to query the provider
                    result = self.adb.execute_shell_command(
                        f'content query --uri {uri}'
                    )

                    if result and 'Error' not in result and 'No result found' not in result:
                        vulnerabilities.append({
                            'type': 'exposed_content_provider',
                            'component': provider,
                            'uri': uri,
                            'severity': 'High',
                            'description': f'Content provider {authority} exposes data at {uri}',
                            'exploitation': f'adb shell content query --uri {uri}',
                            'data': result
                        })

                except Exception as e:
                    self.logger.error(f"Error testing provider {uri}: {e}")

                # Test for SQL injection
                injection_uri = f"{uri}' OR '1'='1"
                try:
                    result = self.adb.execute_shell_command(
                        f'content query --uri "{injection_uri}"'
                    )

                    if result and 'Error' not in result and len(result) > 0:
                        vulnerabilities.append({
                            'type': 'sql_injection',
                            'component': provider,
                            'uri': uri,
                            'severity': 'Critical',
                            'description': f'SQL injection in content provider {authority}',
                            'exploitation': f'adb shell content query --uri "{injection_uri}"'
                        })

                except Exception:
                    pass

        return vulnerabilities

    def test_broadcast_receivers(self) -> List[Dict[str, Any]]:
        """Test broadcast receivers"""
        vulnerabilities = []

        # Common broadcast actions
        common_actions = [
            'BOOT_COMPLETED',
            'SMS_RECEIVED',
            'PHONE_STATE',
            'NEW_OUTGOING_CALL',
            'PACKAGE_ADDED',
            'PACKAGE_REMOVED',
            'CONNECTIVITY_CHANGE'
        ]

        for receiver in self.receivers:
            # Try with custom action based on receiver name
            custom_action = f"{self.package_name}.{receiver.split('.')[-1].upper()}"

            try:
                result = self.adb.execute_shell_command(
                    f'am broadcast -a {custom_action}'
                )

                if result and 'Broadcast completed' in result:
                    vulnerabilities.append({
                        'type': 'exported_receiver',
                        'component': receiver,
                        'action': custom_action,
                        'severity': 'Medium',
                        'description': f'Broadcast receiver {receiver} responds to custom action',
                        'exploitation': f'adb shell am broadcast -a {custom_action}'
                    })

            except Exception as e:
                self.logger.error(f"Error testing receiver {receiver}: {e}")

        return vulnerabilities

    def test_debuggable(self) -> Optional[Dict[str, Any]]:
        """Test if app is debuggable"""
        try:
            # Check if app is debuggable
            result = self.adb.execute_shell_command(
                f'run-as {self.package_name} id'
            )

            if result and 'uid=' in result:
                return {
                    'type': 'debuggable_app',
                    'severity': 'High',
                    'description': 'Application is debuggable',
                    'exploitation': f'run-as {self.package_name}',
                    'impact': 'Attacker can run commands as the app user'
                }

        except Exception:
            pass

        return None

    def test_backup_flag(self) -> Optional[Dict[str, Any]]:
        """Test if app allows backup"""
        try:
            # Try to backup the app
            result = subprocess.run(
                ['adb', 'backup', '-f', 'backup.ab', '-noapk', self.package_name],
                capture_output=True,
                text=True
            )

            # Check if backup was successful
            import os
            if os.path.exists('backup.ab') and os.path.getsize('backup.ab') > 0:
                os.remove('backup.ab')  # Clean up

                return {
                    'type': 'backup_allowed',
                    'severity': 'Medium',
                    'description': 'Application allows backup',
                    'exploitation': f'adb backup -f backup.ab {self.package_name}',
                    'impact': 'App data can be extracted via backup'
                }

        except Exception:
            pass

        return None

    def run_all_tests(self) -> List[Dict[str, Any]]:
        """Run all dynamic tests"""
        if not self.setup():
            return []

        vulnerabilities = []

        # Get components
        self.get_components()

        # Run tests
        vulnerabilities.extend(self.test_exported_activities())
        vulnerabilities.extend(self.test_exported_services())
        vulnerabilities.extend(self.test_content_providers())
        vulnerabilities.extend(self.test_broadcast_receivers())

        # Test app flags
        debuggable = self.test_debuggable()
        if debuggable:
            vulnerabilities.append(debuggable)

        backup = self.test_backup_flag()
        if backup:
            vulnerabilities.append(backup)

        return vulnerabilities