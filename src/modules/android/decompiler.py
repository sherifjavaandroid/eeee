import subprocess
import logging
import shutil
from pathlib import Path
from typing import Optional, Dict, Any, List 

class Decompiler:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.tools = {
            'apktool': self._check_apktool(),
            'jadx': self._check_jadx(),
            'dex2jar': self._check_dex2jar(),
            'enjarify': self._check_enjarify()
        }

    def _check_apktool(self) -> bool:
        """Check if apktool is available"""
        try:
            subprocess.run(['apktool', '--version'], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.logger.warning("apktool not found")
            return False

    def _check_jadx(self) -> bool:
        """Check if jadx is available"""
        try:
            subprocess.run(['jadx', '--version'], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.logger.warning("jadx not found")
            return False

    def _check_dex2jar(self) -> bool:
        """Check if dex2jar is available"""
        try:
            # Try different possible command names
            for cmd in ['d2j-dex2jar', 'd2j-dex2jar.sh', 'dex2jar']:
                try:
                    subprocess.run([cmd, '--help'], capture_output=True, check=True)
                    self.dex2jar_cmd = cmd
                    return True
                except (subprocess.CalledProcessError, FileNotFoundError):
                    continue
        except:
            pass
        self.logger.warning("dex2jar not found")
        return False

    def _check_enjarify(self) -> bool:
        """Check if enjarify is available"""
        try:
            subprocess.run(['enjarify', '--help'], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.logger.warning("enjarify not found")
            return False

    def decompile_with_apktool(self, apk_path: str, output_dir: str) -> bool:
        """Decompile APK using apktool"""
        if not self.tools['apktool']:
            self.logger.error("apktool not available")
            return False

        try:
            subprocess.run([
                'apktool', 'd', '-f', apk_path, '-o', output_dir
            ], check=True)
            self.logger.info(f"Successfully decompiled with apktool to {output_dir}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"apktool decompilation failed: {e}")
            return False

    def decompile_with_jadx(self, apk_path: str, output_dir: str) -> bool:
        """Decompile APK using jadx"""
        if not self.tools['jadx']:
            self.logger.error("jadx not available")
            return False

        try:
            subprocess.run([
                'jadx', '-d', output_dir, apk_path
            ], check=True)
            self.logger.info(f"Successfully decompiled with jadx to {output_dir}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"jadx decompilation failed: {e}")
            return False

    def dex_to_jar(self, apk_path: str, output_path: str) -> bool:
        """Convert DEX to JAR using dex2jar or enjarify"""
        if self.tools['dex2jar']:
            try:
                subprocess.run([
                    self.dex2jar_cmd, apk_path, '-o', output_path
                ], check=True)
                self.logger.info(f"Successfully converted to JAR with dex2jar: {output_path}")
                return True
            except subprocess.CalledProcessError as e:
                self.logger.error(f"dex2jar conversion failed: {e}")

        if self.tools['enjarify']:
            try:
                subprocess.run([
                    'enjarify', apk_path, '-o', output_path
                ], check=True)
                self.logger.info(f"Successfully converted to JAR with enjarify: {output_path}")
                return True
            except subprocess.CalledProcessError as e:
                self.logger.error(f"enjarify conversion failed: {e}")

        return False

    def decompile_all(self, apk_path: str, output_base_dir: str) -> Dict[str, str]:
        """Decompile using all available tools"""
        results = {}
        base_dir = Path(output_base_dir)

        # Create output directories
        apktool_dir = base_dir / 'apktool'
        jadx_dir = base_dir / 'jadx'
        jar_path = base_dir / 'classes.jar'

        # Run apktool
        if self.decompile_with_apktool(apk_path, str(apktool_dir)):
            results['apktool'] = str(apktool_dir)

        # Run jadx
        if self.decompile_with_jadx(apk_path, str(jadx_dir)):
            results['jadx'] = str(jadx_dir)

        # Convert to JAR
        if self.dex_to_jar(apk_path, str(jar_path)):
            results['jar'] = str(jar_path)

        return results

    def extract_dex(self, apk_path: str, output_dir: str) -> List[str]:
        """Extract DEX files from APK"""
        dex_files = []
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        try:
            import zipfile
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                for file_info in zip_ref.filelist:
                    if file_info.filename.endswith('.dex'):
                        dex_path = output_path / file_info.filename
                        with zip_ref.open(file_info) as source, open(dex_path, 'wb') as target:
                            shutil.copyfileobj(source, target)
                        dex_files.append(str(dex_path))

            self.logger.info(f"Extracted {len(dex_files)} DEX files")
            return dex_files

        except Exception as e:
            self.logger.error(f"Failed to extract DEX files: {e}")
            return []