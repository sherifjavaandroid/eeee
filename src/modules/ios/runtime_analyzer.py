import frida
import logging
import time
from typing import Dict, List, Any, Optional
from pathlib import Path

class RuntimeAnalyzer:
    def __init__(self, bundle_id: str):
        self.bundle_id = bundle_id
        self.logger = logging.getLogger(__name__)
        self.session = None
        self.script = None
        self.device = None

    def connect_device(self) -> bool:
        """Connect to iOS device"""
        try:
            self.device = frida.get_usb_device()
            self.logger.info(f"Connected to device: {self.device.name}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to connect to device: {e}")
            return False

    def spawn_app(self) -> bool:
        """Spawn the target application"""
        if not self.device:
            if not self.connect_device():
                return False

        try:
            # Spawn the app
            pid = self.device.spawn([self.bundle_id])
            self.session = self.device.attach(pid)
            self.device.resume(pid)

            self.logger.info(f"Spawned {self.bundle_id} with PID {pid}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to spawn app: {e}")
            return False

    def attach_to_app(self) -> bool:
        """Attach to running application"""
        if not self.device:
            if not self.connect_device():
                return False

        try:
            self.session = self.device.attach(self.bundle_id)
            self.logger.info(f"Attached to {self.bundle_id}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to attach to app: {e}")
            return False

    def load_script(self, script_content: str) -> bool:
        """Load Frida script"""
        if not self.session:
            self.logger.error("No active session")
            return False

        try:
            self.script = self.session.create_script(script_content)
            self.script.on('message', self._on_message)
            self.script.load()
            return True
        except Exception as e:
            self.logger.error(f"Failed to load script: {e}")
            return False

    def _on_message(self, message, data):
        """Handle messages from Frida script"""
        if message['type'] == 'send':
            self.logger.info(f"Script message: {message['payload']}")
        elif message['type'] == 'error':
            self.logger.error(f"Script error: {message['stack']}")

    def detect_jailbreak(self) -> Dict[str, Any]:
        """Detect jailbreak detection mechanisms"""
        script_content = """
        var jailbreakPaths = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/private/var/lib/apt/",
            "/usr/bin/ssh",
            "/usr/libexec/sftp-server"
        ];
        
        // Hook NSFileManager fileExistsAtPath:
        var NSFileManager = ObjC.classes.NSFileManager;
        Interceptor.attach(NSFileManager['- fileExistsAtPath:'].implementation, {
            onEnter: function(args) {
                var path = ObjC.Object(args[2]).toString();
                for (var i = 0; i < jailbreakPaths.length; i++) {
                    if (path.indexOf(jailbreakPaths[i]) !== -1) {
                        send({type: 'jailbreak_check', path: path});
                    }
                }
            }
        });
        
        // Hook common jailbreak detection methods
        if (ObjC.classes.UIDevice) {
            Interceptor.attach(ObjC.classes.UIDevice['- isJailbroken'].implementation, {
                onEnter: function() {
                    send({type: 'jailbreak_check', method: 'isJailbroken'});
                },
                onLeave: function(retval) {
                    retval.replace(0);
                }
            });
        }
        """

        results = {
            'jailbreak_checks': [],
            'bypassed': False
        }

        if self.load_script(script_content):
            # Wait for results
            time.sleep(5)
            results['bypassed'] = True

        return results

    def hook_crypto_functions(self) -> Dict[str, List[Dict[str, Any]]]:
        """Hook cryptographic functions"""
        script_content = """
        // Hook CommonCrypto functions
        var CCCrypt = Module.findExportByName(null, 'CCCrypt');
        if (CCCrypt) {
            Interceptor.attach(CCCrypt, {
                onEnter: function(args) {
                    var operation = args[0].toInt32();
                    var algorithm = args[1].toInt32();
                    var options = args[2].toInt32();
                    
                    send({
                        type: 'crypto',
                        function: 'CCCrypt',
                        operation: operation === 0 ? 'encrypt' : 'decrypt',
                        algorithm: algorithm,
                        options: options
                    });
                }
            });
        }
        
        // Hook hash functions
        var CC_MD5 = Module.findExportByName(null, 'CC_MD5');
        if (CC_MD5) {
            Interceptor.attach(CC_MD5, {
                onEnter: function(args) {
                    send({
                        type: 'crypto',
                        function: 'CC_MD5',
                        warning: 'Weak hash function used'
                    });
                }
            });
        }
        """

        crypto_usage = []

        if self.load_script(script_content):
            # Wait for results
            time.sleep(5)

        return crypto_usage

    def hook_network_functions(self) -> Dict[str, List[Dict[str, Any]]]:
        """Hook network functions"""
        script_content = """
        // Hook NSURLSession
        var NSURLSession = ObjC.classes.NSURLSession;
        Interceptor.attach(NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation, {
            onEnter: function(args) {
                var request = ObjC.Object(args[2]);
                var url = request.URL().absoluteString().toString();
                send({
                    type: 'network',
                    function: 'NSURLSession',
                    url: url,
                    method: request.HTTPMethod().toString()
                });
            }
        });
        
        // Hook NSURLConnection (legacy)
        if (ObjC.classes.NSURLConnection) {
            Interceptor.attach(ObjC.classes.NSURLConnection['+ sendSynchronousRequest:returningResponse:error:'].implementation, {
                onEnter: function(args) {
                    var request = ObjC.Object(args[2]);
                    send({
                        type: 'network',
                        function: 'NSURLConnection',
                        url: request.URL().absoluteString().toString()
                    });
                }
            });
        }
        """

        network_calls = []

        if self.load_script(script_content):
            # Wait for results
            time.sleep(5)

        return network_calls

    def hook_keychain_operations(self) -> Dict[str, List[Dict[str, Any]]]:
        """Hook keychain operations"""
        script_content = """
        // Hook SecItemAdd
        var SecItemAdd = Module.findExportByName('Security', 'SecItemAdd');
        if (SecItemAdd) {
            Interceptor.attach(SecItemAdd, {
                onEnter: function(args) {
                    var query = new ObjC.Object(args[0]);
                    send({
                        type: 'keychain',
                        function: 'SecItemAdd',
                        query: query.toString()
                    });
                }
            });
        }
        
        // Hook SecItemCopyMatching
        var SecItemCopyMatching = Module.findExportByName('Security', 'SecItemCopyMatching');
        if (SecItemCopyMatching) {
            Interceptor.attach(SecItemCopyMatching, {
                onEnter: function(args) {
                    var query = new ObjC.Object(args[0]);
                    send({
                        type: 'keychain',
                        function: 'SecItemCopyMatching',
                        query: query.toString()
                    });
                }
            });
        }
        """

        keychain_operations = []

        if self.load_script(script_content):
            # Wait for results
            time.sleep(5)

        return keychain_operations

    def dump_classes(self) -> List[str]:
        """Dump all Objective-C classes"""
        script_content = """
        for (var className in ObjC.classes) {
            if (ObjC.classes.hasOwnProperty(className)) {
                send({type: 'class', name: className});
            }
        }
        """

        classes = []

        def message_handler(message, data):
            if message['type'] == 'send' and message['payload']['type'] == 'class':
                classes.append(message['payload']['name'])

        if self.load_script(script_content):
            time.sleep(5)

        return classes

    def find_methods(self, class_name: str) -> List[str]:
        """Find all methods of a class"""
        script_content = f"""
        var className = '{class_name}';
        if (ObjC.classes[className]) {{
            var methods = ObjC.classes[className].$ownMethods;
            for (var i = 0; i < methods.length; i++) {{
                send({{type: 'method', name: methods[i]}});
            }}
        }}
        """

        methods = []

        def message_handler(message, data):
            if message['type'] == 'send' and message['payload']['type'] == 'method':
                methods.append(message['payload']['name'])

        if self.load_script(script_content):
            time.sleep(5)

        return methods

    def run_comprehensive_analysis(self) -> Dict[str, Any]:
        """Run comprehensive runtime analysis"""
        results = {
            'jailbreak_detection': self.detect_jailbreak(),
            'crypto_usage': self.hook_crypto_functions(),
            'network_calls': self.hook_network_functions(),
            'keychain_operations': self.hook_keychain_operations(),
            'classes': self.dump_classes()[:100]  # Limit to first 100 classes
        }

        return results