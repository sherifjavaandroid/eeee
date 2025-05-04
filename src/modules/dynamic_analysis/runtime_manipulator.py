import frida
import logging
import time
from typing import Dict, List, Any, Optional
from pathlib import Path

class RuntimeManipulator:
    def __init__(self, package_name: str):
        self.package_name = package_name
        self.logger = logging.getLogger(__name__)
        self.device = None
        self.session = None
        self.script = None
        self.hooks = {}

    def connect(self) -> bool:
        """Connect to device"""
        try:
            self.device = frida.get_usb_device()
            self.logger.info(f"Connected to device: {self.device.name}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to connect: {e}")
            return False

    def attach_to_process(self) -> bool:
        """Attach to running process"""
        if not self.device:
            if not self.connect():
                return False

        try:
            self.session = self.device.attach(self.package_name)
            self.logger.info(f"Attached to {self.package_name}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to attach: {e}")
            return False

    def spawn_and_attach(self) -> bool:
        """Spawn process and attach"""
        if not self.device:
            if not self.connect():
                return False

        try:
            pid = self.device.spawn([self.package_name])
            self.session = self.device.attach(pid)
            self.device.resume(pid)
            self.logger.info(f"Spawned and attached to {self.package_name}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to spawn: {e}")
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
        """Handle messages from script"""
        if message['type'] == 'send':
            payload = message['payload']
            if isinstance(payload, dict) and 'type' in payload:
                msg_type = payload['type']
                if msg_type in self.hooks:
                    self.hooks[msg_type].append(payload)
                else:
                    self.hooks[msg_type] = [payload]
            self.logger.info(f"Message: {payload}")
        elif message['type'] == 'error':
            self.logger.error(f"Error: {message['stack']}")

    def hook_method(self, class_name: str, method_name: str,
                    on_enter: Optional[str] = None, on_leave: Optional[str] = None) -> bool:
        """Hook a specific method"""
        script_content = f"""
        Java.perform(function() {{
            var targetClass = Java.use('{class_name}');
            targetClass.{method_name}.implementation = function() {{
                var args = Array.prototype.slice.call(arguments);
                
                send({{
                    type: 'method_call',
                    class: '{class_name}',
                    method: '{method_name}',
                    args: args.map(function(arg) {{ return arg ? arg.toString() : 'null'; }})
                }});
                
                {on_enter if on_enter else ''}
                
                var result = this.{method_name}.apply(this, arguments);
                
                send({{
                    type: 'method_result',
                    class: '{class_name}',
                    method: '{method_name}',
                    result: result ? result.toString() : 'null'
                }});
                
                {on_leave if on_leave else ''}
                
                return result;
            }};
        }});
        """

        return self.load_script(script_content)

    def replace_method(self, class_name: str, method_name: str,
                       replacement_code: str) -> bool:
        """Replace method implementation"""
        script_content = f"""
        Java.perform(function() {{
            var targetClass = Java.use('{class_name}');
            targetClass.{method_name}.implementation = function() {{
                {replacement_code}
            }};
        }});
        """

        return self.load_script(script_content)

    def modify_return_value(self, class_name: str, method_name: str,
                            new_value: Any) -> bool:
        """Modify method return value"""
        script_content = f"""
        Java.perform(function() {{
            var targetClass = Java.use('{class_name}');
            targetClass.{method_name}.implementation = function() {{
                var result = this.{method_name}.apply(this, arguments);
                
                send({{
                    type: 'return_modified',
                    class: '{class_name}',
                    method: '{method_name}',
                    original: result ? result.toString() : 'null',
                    modified: '{new_value}'
                }});
                
                return {new_value};
            }};
        }});
        """

        return self.load_script(script_content)

    def trace_calls(self, class_pattern: str = "*") -> bool:
        """Trace method calls matching pattern"""
        script_content = f"""
        Java.perform(function() {{
            var pattern = '{class_pattern}';
            
            Java.enumerateLoadedClasses({{
                onMatch: function(className) {{
                    if (className.match(pattern)) {{
                        try {{
                            var clazz = Java.use(className);
                            var methods = clazz.class.getDeclaredMethods();
                            
                            methods.forEach(function(method) {{
                                var methodName = method.getName();
                                
                                try {{
                                    clazz[methodName].overload.implementation = function() {{
                                        send({{
                                            type: 'trace',
                                            class: className,
                                            method: methodName,
                                            args: Array.prototype.slice.call(arguments).map(String)
                                        }});
                                        
                                        return this[methodName].apply(this, arguments);
                                    }};
                                }} catch(e) {{
                                    // Method might have multiple overloads
                                }}
                            }});
                        }} catch(e) {{
                            // Class might not be accessible
                        }}
                    }}
                }},
                onComplete: function() {{
                    send({{type: 'trace_complete'}});
                }}
            }});
        }});
        """

        return self.load_script(script_content)

    def hook_crypto(self) -> bool:
        """Hook cryptographic operations"""
        script_content = """
        Java.perform(function() {
            // Hook Cipher
            var Cipher = Java.use('javax.crypto.Cipher');
            
            Cipher.getInstance.overload('java.lang.String').implementation = function(transformation) {
                send({
                    type: 'crypto',
                    operation: 'Cipher.getInstance',
                    algorithm: transformation
                });
                return this.getInstance(transformation);
            };
            
            Cipher.doFinal.overload('[B').implementation = function(data) {
                send({
                    type: 'crypto',
                    operation: 'Cipher.doFinal',
                    data_length: data.length,
                    mode: this.getOpmode()
                });
                return this.doFinal(data);
            };
            
            // Hook MessageDigest
            var MessageDigest = Java.use('java.security.MessageDigest');
            
            MessageDigest.getInstance.overload('java.lang.String').implementation = function(algorithm) {
                send({
                    type: 'crypto',
                    operation: 'MessageDigest.getInstance',
                    algorithm: algorithm
                });
                return this.getInstance(algorithm);
            };
            
            // Hook SecretKeySpec
            var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
            
            SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(keyBytes, algorithm) {
                send({
                    type: 'crypto',
                    operation: 'SecretKeySpec',
                    algorithm: algorithm,
                    key_length: keyBytes.length
                });
                return this.$init(keyBytes, algorithm);
            };
        });
        """

        return self.load_script(script_content)

    def hook_file_operations(self) -> bool:
        """Hook file operations"""
        script_content = """
        Java.perform(function() {
            // Hook File operations
            var File = Java.use('java.io.File');
            
            File.$init.overload('java.lang.String').implementation = function(path) {
                send({
                    type: 'file_operation',
                    operation: 'File.init',
                    path: path
                });
                return this.$init(path);
            };
            
            File.exists.implementation = function() {
                var result = this.exists();
                send({
                    type: 'file_operation',
                    operation: 'File.exists',
                    path: this.getAbsolutePath(),
                    result: result
                });
                return result;
            };
            
            // Hook FileInputStream
            var FileInputStream = Java.use('java.io.FileInputStream');
            
            FileInputStream.$init.overload('java.lang.String').implementation = function(path) {
                send({
                    type: 'file_operation',
                    operation: 'FileInputStream',
                    path: path
                });
                return this.$init(path);
            };
            
            // Hook FileOutputStream
            var FileOutputStream = Java.use('java.io.FileOutputStream');
            
            FileOutputStream.$init.overload('java.lang.String').implementation = function(path) {
                send({
                    type: 'file_operation',
                    operation: 'FileOutputStream',
                    path: path
                });
                return this.$init(path);
            };
        });
        """

        return self.load_script(script_content)

    def hook_network(self) -> bool:
        """Hook network operations"""
        script_content = """
        Java.perform(function() {
            // Hook HttpURLConnection
            var HttpURLConnection = Java.use('java.net.HttpURLConnection');
            
            HttpURLConnection.setRequestMethod.implementation = function(method) {
                send({
                    type: 'network',
                    operation: 'setRequestMethod',
                    method: method,
                    url: this.getURL().toString()
                });
                return this.setRequestMethod(method);
            };
            
            // Hook OkHttp
            try {
                var OkHttpClient = Java.use('okhttp3.OkHttpClient');
                var Request = Java.use('okhttp3.Request');
                
                OkHttpClient.newCall.implementation = function(request) {
                    send({
                        type: 'network',
                        operation: 'OkHttp.newCall',
                        url: request.url().toString(),
                        method: request.method()
                    });
                    return this.newCall(request);
                };
            } catch(e) {
                // OkHttp not present
            }
            
            // Hook WebView
            var WebView = Java.use('android.webkit.WebView');
            
            WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
                send({
                    type: 'network',
                    operation: 'WebView.loadUrl',
                    url: url
                });
                return this.loadUrl(url);
            };
        });
        """

        return self.load_script(script_content)

    def bypass_root_detection(self) -> bool:
        """Bypass root detection"""
        script_content = """
        Java.perform(function() {
            var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
            
            RootBeer.isRooted.implementation = function() {
                send({type: 'root_bypass', method: 'RootBeer.isRooted'});
                return false;
            };
            
            // Hook file existence checks
            var File = Java.use('java.io.File');
            var rootFiles = [
                '/system/app/Superuser.apk',
                '/sbin/su',
                '/system/bin/su',
                '/system/xbin/su',
                '/data/local/xbin/su',
                '/data/local/bin/su',
                '/system/sd/xbin/su',
                '/system/bin/failsafe/su',
                '/data/local/su'
            ];
            
            File.exists.implementation = function() {
                var path = this.getAbsolutePath();
                for (var i = 0; i < rootFiles.length; i++) {
                    if (path.indexOf(rootFiles[i]) !== -1) {
                        send({type: 'root_bypass', file: path});
                        return false;
                    }
                }
                return this.exists();
            };
        });
        """

        return self.load_script(script_content)

    def bypass_ssl_pinning(self) -> bool:
        """Bypass SSL pinning"""
        script_content = """
        Java.perform(function() {
            // Bypass TrustManager
            var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            var SSLContext = Java.use('javax.net.ssl.SSLContext');
            
            var TrustManagerImpl = Java.registerClass({
                name: 'com.custom.TrustManagerImpl',
                implements: [TrustManager],
                methods: {
                    checkClientTrusted: function() {},
                    checkServerTrusted: function() {},
                    getAcceptedIssuers: function() { return []; }
                }
            });
            
            SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom')
                .implementation = function(km, tm, sr) {
                    send({type: 'ssl_bypass', method: 'SSLContext.init'});
                    return this.init(km, [TrustManagerImpl.$new()], sr);
                };
            
            // Bypass OkHttp CertificatePinner
            try {
                var CertificatePinner = Java.use('okhttp3.CertificatePinner');
                
                CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
                    send({type: 'ssl_bypass', method: 'CertificatePinner.check'});
                    return;
                };
            } catch(e) {
                // OkHttp not present
            }
        });
        """

        return self.load_script(script_content)

    def dump_memory(self, address: str, size: int) -> Optional[bytes]:
        """Dump memory at address"""
        script_content = f"""
        var address = ptr('{address}');
        var size = {size};
        
        try {{
            var data = Memory.readByteArray(address, size);
            send({{type: 'memory_dump', data: data}});
        }} catch(e) {{
            send({{type: 'error', message: e.toString()}});
        }}
        """

        if self.load_script(script_content):
            time.sleep(1)
            if 'memory_dump' in self.hooks:
                return self.hooks['memory_dump'][0]['data']

        return None

    def list_modules(self) -> List[Dict[str, Any]]:
        """List loaded modules"""
        script_content = """
        Process.enumerateModules({
            onMatch: function(module) {
                send({
                    type: 'module',
                    name: module.name,
                    base: module.base,
                    size: module.size,
                    path: module.path
                });
            },
            onComplete: function() {
                send({type: 'modules_complete'});
            }
        });
        """

        self.hooks['module'] = []
        if self.load_script(script_content):
            time.sleep(2)
            return self.hooks.get('module', [])

        return []