import subprocess
import logging
from typing import List, Optional, Dict, Any
from pathlib import Path

class ADBHelper:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.device_id = None

    def check_adb(self) -> bool:
        """Check if ADB is available"""
        try:
            subprocess.run(['adb', 'version'], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.logger.error("ADB not found or not working")
            return False

    def list_devices(self) -> List[str]:
        """List connected devices"""
        try:
            result = subprocess.run(['adb', 'devices'], capture_output=True, text=True)
            devices = []
            for line in result.stdout.splitlines()[1:]:
                if '\tdevice' in line:
                    devices.append(line.split('\t')[0])
            return devices
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to list devices: {e}")
            return []

    def set_device(self, device_id: str = None):
        """Set target device"""
        if device_id:
            self.device_id = device_id
        else:
            devices = self.list_devices()
            if devices:
                self.device_id = devices[0]
                self.logger.info(f"Using device: {self.device_id}")
            else:
                self.logger.error("No devices connected")

    def _get_adb_command(self, command: List[str]) -> List[str]:
        """Get ADB command with device ID if set"""
        if self.device_id:
            return ['adb', '-s', self.device_id] + command
        else:
            return ['adb'] + command

    def install_app(self, apk_path: str) -> bool:
        """Install APK on device"""
        try:
            cmd = self._get_adb_command(['install', '-r', apk_path])
            subprocess.run(cmd, check=True)
            self.logger.info(f"Successfully installed {apk_path}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to install APK: {e}")
            return False

    def uninstall_app(self, package_name: str) -> bool:
        """Uninstall app from device"""
        try:
            cmd = self._get_adb_command(['uninstall', package_name])
            subprocess.run(cmd, check=True)
            self.logger.info(f"Successfully uninstalled {package_name}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to uninstall app: {e}")
            return False

    def start_app(self, package_name: str, activity: str = None) -> bool:
        """Start app on device"""
        try:
            if activity:
                cmd = self._get_adb_command(['shell', 'am', 'start', '-n', f"{package_name}/{activity}"])
            else:
                cmd = self._get_adb_command(['shell', 'monkey', '-p', package_name, '-c', 'android.intent.category.LAUNCHER', '1'])

            subprocess.run(cmd, check=True)
            self.logger.info(f"Successfully started {package_name}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to start app: {e}")
            return False

    def stop_app(self, package_name: str) -> bool:
        """Stop app on device"""
        try:
            cmd = self._get_adb_command(['shell', 'am', 'force-stop', package_name])
            subprocess.run(cmd, check=True)
            self.logger.info(f"Successfully stopped {package_name}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to stop app: {e}")
            return False

    def clear_app_data(self, package_name: str) -> bool:
        """Clear app data"""
        try:
            cmd = self._get_adb_command(['shell', 'pm', 'clear', package_name])
            subprocess.run(cmd, check=True)
            self.logger.info(f"Successfully cleared data for {package_name}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to clear app data: {e}")
            return False

    def pull_file(self, remote_path: str, local_path: str) -> bool:
        """Pull file from device"""
        try:
            cmd = self._get_adb_command(['pull', remote_path, local_path])
            subprocess.run(cmd, check=True)
            self.logger.info(f"Successfully pulled {remote_path} to {local_path}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to pull file: {e}")
            return False

    def push_file(self, local_path: str, remote_path: str) -> bool:
        """Push file to device"""
        try:
            cmd = self._get_adb_command(['push', local_path, remote_path])
            subprocess.run(cmd, check=True)
            self.logger.info(f"Successfully pushed {local_path} to {remote_path}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to push file: {e}")
            return False

    def execute_shell_command(self, command: str) -> Optional[str]:
        """Execute shell command on device"""
        try:
            cmd = self._get_adb_command(['shell', command])
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to execute shell command: {e}")
            return None

    def get_installed_packages(self) -> List[str]:
        """Get list of installed packages"""
        try:
            cmd = self._get_adb_command(['shell', 'pm', 'list', 'packages'])
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            packages = [line.replace('package:', '') for line in result.stdout.splitlines()]
            return packages
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to get installed packages: {e}")
            return []

    def get_device_info(self) -> Dict[str, str]:
        """Get device information"""
        info = {}
        try:
            # Get Android version
            version = self.execute_shell_command('getprop ro.build.version.release')
            if version:
                info['android_version'] = version.strip()

            # Get device model
            model = self.execute_shell_command('getprop ro.product.model')
            if model:
                info['device_model'] = model.strip()

            # Get manufacturer
            manufacturer = self.execute_shell_command('getprop ro.product.manufacturer')
            if manufacturer:
                info['manufacturer'] = manufacturer.strip()

            # Get SDK version
            sdk = self.execute_shell_command('getprop ro.build.version.sdk')
            if sdk:
                info['sdk_version'] = sdk.strip()

            return info
        except Exception as e:
            self.logger.error(f"Failed to get device info: {e}")
            return info

    def take_screenshot(self, output_path: str) -> bool:
        """Take screenshot from device"""
        try:
            # Take screenshot on device
            self.execute_shell_command('screencap -p /sdcard/screenshot.png')

            # Pull screenshot
            self.pull_file('/sdcard/screenshot.png', output_path)

            # Clean up
            self.execute_shell_command('rm /sdcard/screenshot.png')

            self.logger.info(f"Screenshot saved to {output_path}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to take screenshot: {e}")
            return False

    def start_logcat(self, package_name: str = None) -> subprocess.Popen:
        """Start logcat monitoring"""
        try:
            if package_name:
                cmd = self._get_adb_command(['logcat', f'--pid=$(pidof {package_name})'])
            else:
                cmd = self._get_adb_command(['logcat'])

            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.logger.info("Started logcat monitoring")
            return process
        except Exception as e:
            self.logger.error(f"Failed to start logcat: {e}")
            return None