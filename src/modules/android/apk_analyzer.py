# src/modules/android/apk_analyzer.py
import os
import subprocess
import tempfile
import zipfile
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
import xml.etree.ElementTree as ET
import platform
import shutil

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
        self.logger.info("Skipping tool check - will verify during execution")

    def _run_tool(self, tool_name: str, args: List[str], timeout: int = 300) -> subprocess.CompletedProcess:
        """Run a tool with Windows compatibility"""
        if self.is_windows:
            # For Windows, use startupinfo to prevent console windows
            startupinfo = None
            try:
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE
            except:
                self.logger.warning("Failed to create STARTUPINFO, console windows may appear")

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
            elif tool_name == "jadx":
                # Try jadx direct execution
                cmd = f"jadx {' '.join(args)}"
                self.logger.debug(f"Running command: {cmd}")
                try:
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

    def find_apktool(self) -> Optional[str]:
        """Find apktool executable or jar file"""
        # Common locations for apktool
        possible_locations = [
            "apktool",
            "apktool.bat",
            "apktool.jar",
            str(Path.home() / "apktool" / "apktool.jar"),
            "C:/apktool/apktool.jar",
            "/usr/local/bin/apktool",
            "/usr/bin/apktool"
        ]

        for location in possible_locations:
            try:
                if location.endswith(".jar"):
                    # For jar files, check if file exists
                    jar_path = Path(location)
                    if jar_path.exists():
                        self.logger.info(f"Found apktool jar at: {jar_path}")
                        return f"java -jar {jar_path}"
                else:
                    # For executables, try running version command
                    proc = subprocess.run([location, "--version"],
                                          capture_output=True, text=True)
                    if proc.returncode == 0:
                        self.logger.info(f"Found apktool at: {location}")
                        return location
            except:
                continue

        self.logger.warning("Could not find apktool, extraction may fail")
        return None

    def find_jadx(self) -> Optional[str]:
        """Find jadx executable"""
        # Common locations for jadx
        possible_locations = [
            "jadx",
            "jadx.bat",
            str(Path.home() / "jadx" / "bin" / "jadx"),
            "C:/jadx/bin/jadx.bat",
            "/usr/local/bin/jadx",
            "/usr/bin/jadx"
        ]

        for location in possible_locations:
            try:
                proc = subprocess.run([location, "--version"],
                                      capture_output=True, text=True)
                if proc.returncode == 0:
                    self.logger.info(f"Found jadx at: {location}")
                    return location
            except:
                continue

        self.logger.warning("Could not find jadx, Java decompilation may be limited")
        return None

    def extract_with_jadx(self) -> Optional[Path]:
        """Extract APK using JADX"""
        self.logger.info("Attempting to extract APK using JADX...")
        jadx_output = Path(tempfile.mkdtemp())

        jadx_path = self.find_jadx()
        if not jadx_path:
            self.logger.error("JADX not found, cannot decompile Java code")
            return None

        try:
            # Use JADX to decompile
            if self.is_windows:
                command = f"{jadx_path} -d {str(jadx_output)} {str(self.apk_path)}"
                self.logger.info(f"Running JADX command: {command}")

                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                stdout, stderr = process.communicate(timeout=600)
                returncode = process.returncode
            else:
                result = subprocess.run(
                    [jadx_path, "-d", str(jadx_output), str(self.apk_path)],
                    capture_output=True,
                    text=True,
                    timeout=600
                )
                stdout = result.stdout
                stderr = result.stderr
                returncode = result.returncode

            if returncode != 0:
                self.logger.error(f"JADX failed with return code {returncode}")
                self.logger.error(f"stdout: {stdout}")
                self.logger.error(f"stderr: {stderr}")
                return None

            # Check if decompiled correctly
            java_files = list(jadx_output.glob('**/*.java'))
            self.logger.info(f"JADX extracted {len(java_files)} Java files")

            if java_files:
                # Log some of the found Java files for debugging
                for java_file in java_files[:5]:
                    self.logger.info(f"Sample Java file: {java_file}")

                # Check if resources directory exists (it should contain manifest and other resources)
                res_dir = jadx_output / 'resources'
                if res_dir.exists():
                    self.logger.info(f"JADX extracted resources directory")
                else:
                    self.logger.warning(f"JADX did not extract resources directory")

                return jadx_output
            else:
                self.logger.warning(f"JADX did not extract any Java files")
                return None

        except Exception as e:
            self.logger.error(f"JADX extraction failed: {e}")
            return None

    def extract(self) -> Path:
        """Extract APK contents with improved Java extraction"""
        self.logger.info("Starting APK extraction...")
        apktool_path = Path(tempfile.mkdtemp())
        self.extracted_path = apktool_path
        self.logger.info(f"Temporary extraction path: {self.extracted_path}")

        # First, try extracting with apktool
        try:
            apktool_cmd = self.find_apktool()
            if apktool_cmd:
                self.logger.info(f"Extracting APK using apktool: {apktool_cmd}")

                if apktool_cmd.startswith("java -jar"):
                    # Run as Java jar
                    jar_path = apktool_cmd.split(" ")[-1]
                    command = f"java -jar {jar_path} d -f {str(self.apk_path)} -o {str(apktool_path)}"
                    self.logger.info(f"Running command: {command}")

                    process = subprocess.Popen(
                        command,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    stdout, stderr = process.communicate(timeout=600)
                    returncode = process.returncode
                else:
                    # Run as executable
                    result = self._run_tool(
                        apktool_cmd,
                        ["d", "-f", str(self.apk_path), "-o", str(apktool_path)],
                        timeout=600
                    )
                    stdout = result.stdout
                    stderr = result.stderr
                    returncode = result.returncode

                if returncode != 0:
                    self.logger.error(f"apktool failed with return code {returncode}")
                    self.logger.error(f"stdout: {stdout}")
                    self.logger.error(f"stderr: {stderr}")
                else:
                    self.logger.info("APKTool extraction successful")
            else:
                # Fallback to basic ZIP extraction
                self.logger.warning("apktool not found, falling back to ZIP extraction")
                self._extract_as_zip()
        except Exception as e:
            self.logger.error(f"Error during APKTool extraction: {e}")
            # Continue to try other methods

        # Check what we got from apktool
        manifest_exists = (apktool_path / "AndroidManifest.xml").exists()
        smali_files = list(apktool_path.glob("**/*.smali"))
        java_files = list(apktool_path.glob("**/*.java"))

        self.logger.info(f"APKTool extraction results: Manifest exists: {manifest_exists}, "
                         f"Smali files: {len(smali_files)}, Java files: {len(java_files)}")

        # If we don't have Java files, try JADX
        if not java_files or len(java_files) < 5:
            self.logger.info("Few or no Java files found with apktool, trying JADX...")
            jadx_output = self.extract_with_jadx()

            if jadx_output:
                # Create src directory in apktool output to store Java files
                java_src_dir = apktool_path / "src"
                java_src_dir.mkdir(exist_ok=True)

                # Copy Java files from JADX output to apktool output
                jadx_java_files = list(jadx_output.glob("**/*.java"))
                self.logger.info(f"Copying {len(jadx_java_files)} Java files from JADX to {java_src_dir}")

                for java_file in jadx_java_files:
                    # Get relative path in jadx output
                    rel_path = java_file.relative_to(jadx_output / "sources")
                    # Create target path
                    target_path = java_src_dir / rel_path
                    # Create parent directories if needed
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    # Copy file
                    try:
                        shutil.copy2(java_file, target_path)
                    except Exception as e:
                        self.logger.warning(f"Error copying {java_file}: {e}")

                # Check if we need to copy resources from JADX
                if not manifest_exists:
                    jadx_res_dir = jadx_output / "resources"
                    if jadx_res_dir.exists():
                        self.logger.info(f"Copying resources from JADX")

                        # Copy resources
                        for res_file in jadx_res_dir.glob("**/*"):
                            if res_file.is_file():
                                # Get relative path
                                rel_path = res_file.relative_to(jadx_res_dir)
                                # Create target path
                                target_path = apktool_path / rel_path
                                # Create parent directories if needed
                                target_path.parent.mkdir(parents=True, exist_ok=True)
                                # Copy file
                                try:
                                    shutil.copy2(res_file, target_path)
                                except Exception as e:
                                    self.logger.warning(f"Error copying {res_file}: {e}")

        # Final check to see what we have
        java_files = list(apktool_path.glob("**/*.java"))
        self.logger.info(f"Final Java file count: {len(java_files)}")

        if java_files:
            # Log some of the found Java files for debugging
            for java_file in java_files[:5]:
                self.logger.info(f"Sample Java file: {java_file}")

        # If no AndroidManifest.xml, try to find it in the extracted files
        if not (apktool_path / "AndroidManifest.xml").exists():
            for manifest_file in apktool_path.glob("**/AndroidManifest.xml"):
                if manifest_file.exists():
                    self.logger.info(f"Found AndroidManifest.xml at {manifest_file}")
                    # Copy to root directory
                    try:
                        shutil.copy2(manifest_file, apktool_path / "AndroidManifest.xml")
                        self.logger.info(f"Copied AndroidManifest.xml to {apktool_path}")
                        break
                    except Exception as e:
                        self.logger.warning(f"Error copying AndroidManifest.xml: {e}")

        self.logger.info(f"APK extracted successfully to: {self.extracted_path}")
        return self.extracted_path

    def _extract_as_zip(self) -> Path:
        """Fallback extraction method using ZIP"""
        try:
            self.logger.info("Extracting APK as ZIP file...")
            with zipfile.ZipFile(self.apk_path, 'r') as zip_ref:
                # Extract all files
                zip_ref.extractall(self.extracted_path)
                self.logger.info(f"ZIP extraction completed to: {self.extracted_path}")

                # Check for important files
                extracted_files = list(Path(self.extracted_path).glob("**/*"))
                self.logger.info(f"Extracted {len(extracted_files)} files with ZIP method")

                # Check if AndroidManifest.xml exists (it will be in binary format)
                if (self.extracted_path / "AndroidManifest.xml").exists():
                    self.logger.info("Found AndroidManifest.xml (binary format)")

                # Look for DEX files
                dex_files = list(Path(self.extracted_path).glob("**/*.dex"))
                self.logger.info(f"Found {len(dex_files)} DEX files")

                # Try to convert DEX to JAR/Java if we have dex2jar
                if dex_files:
                    self.convert_dex_to_java()

            return self.extracted_path
        except Exception as e:
            self.logger.error(f"ZIP extraction failed: {e}")
            raise RuntimeError(f"Failed to extract APK: {e}")

    def convert_dex_to_java(self):
        """Try to convert DEX files to Java using available tools"""
        dex_files = list(self.extracted_path.glob("**/*.dex"))
        if not dex_files:
            self.logger.warning("No DEX files found for conversion")
            return

        # Try to find dex2jar
        dex2jar_path = None
        for possible_path in ["d2j-dex2jar", "d2j-dex2jar.bat", "dex2jar"]:
            try:
                result = subprocess.run([possible_path, "--help"],
                                        capture_output=True, text=True)
                if result.returncode == 0:
                    dex2jar_path = possible_path
                    self.logger.info(f"Found dex2jar at: {dex2jar_path}")
                    break
            except:
                continue

        if not dex2jar_path:
            self.logger.warning("dex2jar not found, cannot convert DEX to Java")
            return

        # Create output directory for Java files
        java_dir = self.extracted_path / "src"
        java_dir.mkdir(exist_ok=True)

        for dex_file in dex_files:
            try:
                # Convert DEX to JAR
                jar_file = self.extracted_path / f"{dex_file.stem}.jar"
                self.logger.info(f"Converting {dex_file} to {jar_file}")

                result = subprocess.run(
                    [dex2jar_path, "-o", str(jar_file), str(dex_file)],
                    capture_output=True,
                    text=True
                )

                if result.returncode != 0:
                    self.logger.error(f"dex2jar failed: {result.stderr}")
                    continue

                # Extract JAR
                jar_extract_dir = self.extracted_path / f"{dex_file.stem}_jar"
                jar_extract_dir.mkdir(exist_ok=True)

                with zipfile.ZipFile(jar_file, 'r') as jar:
                    jar.extractall(jar_extract_dir)

                # Try to convert class files to Java using any available decompiler
                class_files = list(jar_extract_dir.glob("**/*.class"))
                self.logger.info(f"Found {len(class_files)} class files in {jar_file}")

                # Try using CFR decompiler if available
                try:
                    cfr_output = java_dir / dex_file.stem
                    cfr_output.mkdir(exist_ok=True)

                    # Try to find cfr jar
                    cfr_path = None
                    for possible_path in ["cfr.jar", "cfr-0.150.jar", str(Path.home() / "cfr.jar")]:
                        jar_path = Path(possible_path)
                        if jar_path.exists():
                            cfr_path = str(jar_path)
                            break

                    if cfr_path:
                        self.logger.info(f"Decompiling JAR with CFR: {jar_file}")
                        result = subprocess.run(
                            ["java", "-jar", cfr_path, str(jar_file), "--outputdir", str(cfr_output)],
                            capture_output=True,
                            text=True
                        )

                        if result.returncode == 0:
                            self.logger.info(f"Successfully decompiled {jar_file} with CFR")
                        else:
                            self.logger.error(f"CFR decompilation failed: {result.stderr}")
                except Exception as e:
                    self.logger.error(f"Error decompiling with CFR: {e}")

            except Exception as e:
                self.logger.error(f"Error converting {dex_file}: {e}")

    # Rest of the methods remain the same - get_app_info, analyze_manifest, etc.
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