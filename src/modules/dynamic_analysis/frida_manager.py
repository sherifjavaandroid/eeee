import frida
import logging
import time
from pathlib import Path
from typing import Optional, Dict, Any

class FridaManager:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.device = None
        self.session = None
        self.script = None
        self.scripts_dir = Path('src/scripts')

    def connect_device(self, device_type: str = 'usb') -> bool:
        """Connect to device"""
        try:
            if device_type == 'usb':
                self.device = frida.get_usb_device()
            elif device_type == 'remote':
                self.device = frida.get_remote_device()
            else:
                self.device = frida.get_local_device()

            self.logger.info(f"Connected to device: {self.device.name}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to connect to device: {e}")
            return False

    def attach(self, package_name: str) -> bool:
        """Attach to running application"""
        if not self.device:
            self.connect_device()

        try:
            # Try to spawn the app
            pid = self.device.spawn([package_name])
            self.session = self.device.attach(pid)
            self.device.resume(pid)

            self.logger.info(f"Attached to {package_name}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to attach to {package_name}: {e}")
            return False

    def detach(self):
        """Detach from application"""
        if self.session:
            try:
                self.session.detach()
                self.logger.info("Detached from application")
            except Exception as e:
                self.logger.error(f"Error detaching: {e}")

    def run_script(self, script_name: str) -> Optional[Dict[str, Any]]:
        """Run a Frida script"""
        if not self.session:
            self.logger.error("No active session")
            return None

        script_path = self.scripts_dir / script_name
        if not script_path.exists():
            self.logger.error(f"Script not found: {script_name}")
            return None

        try:
            with open(script_path, 'r') as f:
                script_content = f.read()

            self.script = self.session.create_script(script_content)
            self.script.on('message', self._on_message)
            self.script.load()

            # Wait for script to execute
            time.sleep(5)

            return self._get_script_results()

        except Exception as e:
            self.logger.error(f"Failed to run script {script_name}: {e}")
            return None

    def _on_message(self, message, data):
        """Handle messages from Frida script"""
        if message['type'] == 'send':
            self.logger.info(f"Frida message: {message['payload']}")
        elif message['type'] == 'error':
            self.logger.error(f"Frida error: {message['stack']}")

    def _get_script_results(self) -> Dict[str, Any]:
        """Get results from executed script"""
        # Implementation to collect and return script results
        return {}