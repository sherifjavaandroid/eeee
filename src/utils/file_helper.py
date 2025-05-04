import os
import shutil
import zipfile
import tarfile
import logging
from pathlib import Path
from typing import Optional, List

class FileHelper:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def create_directory(self, path: str) -> bool:
        """Create directory if it doesn't exist"""
        try:
            Path(path).mkdir(parents=True, exist_ok=True)
            return True
        except Exception as e:
            self.logger.error(f"Failed to create directory {path}: {e}")
            return False

    def copy_file(self, src: str, dst: str) -> bool:
        """Copy file from source to destination"""
        try:
            shutil.copy2(src, dst)
            return True
        except Exception as e:
            self.logger.error(f"Failed to copy file from {src} to {dst}: {e}")
            return False

    def move_file(self, src: str, dst: str) -> bool:
        """Move file from source to destination"""
        try:
            shutil.move(src, dst)
            return True
        except Exception as e:
            self.logger.error(f"Failed to move file from {src} to {dst}: {e}")
            return False

    def delete_file(self, path: str) -> bool:
        """Delete file"""
        try:
            if os.path.isfile(path):
                os.remove(path)
            return True
        except Exception as e:
            self.logger.error(f"Failed to delete file {path}: {e}")
            return False

    def delete_directory(self, path: str) -> bool:
        """Delete directory and its contents"""
        try:
            if os.path.isdir(path):
                shutil.rmtree(path)
            return True
        except Exception as e:
            self.logger.error(f"Failed to delete directory {path}: {e}")
            return False

    def extract_zip(self, zip_path: str, extract_path: str) -> bool:
        """Extract ZIP file"""
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(extract_path)
            self.logger.info(f"Extracted {zip_path} to {extract_path}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to extract ZIP file {zip_path}: {e}")
            return False

    def extract_tar(self, tar_path: str, extract_path: str) -> bool:
        """Extract TAR file"""
        try:
            with tarfile.open(tar_path, 'r:*') as tar_ref:
                tar_ref.extractall(extract_path)
            self.logger.info(f"Extracted {tar_path} to {extract_path}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to extract TAR file {tar_path}: {e}")
            return False

    def create_zip(self, source_path: str, zip_path: str) -> bool:
        """Create ZIP file from directory or file"""
        try:
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                if os.path.isdir(source_path):
                    for root, dirs, files in os.walk(source_path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            arcname = os.path.relpath(file_path, source_path)
                            zipf.write(file_path, arcname)
                else:
                    zipf.write(source_path, os.path.basename(source_path))
            self.logger.info(f"Created ZIP file {zip_path}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to create ZIP file {zip_path}: {e}")
            return False

    def find_files(self, directory: str, pattern: str) -> List[str]:
        """Find files matching pattern in directory"""
        matches = []
        try:
            for root, dirs, files in os.walk(directory):
                for filename in files:
                    if pattern in filename:
                        matches.append(os.path.join(root, filename))
            return matches
        except Exception as e:
            self.logger.error(f"Failed to find files in {directory}: {e}")
            return []

    def read_file(self, file_path: str) -> Optional[str]:
        """Read text file contents"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            self.logger.error(f"Failed to read file {file_path}: {e}")
            return None

    def write_file(self, file_path: str, content: str) -> bool:
        """Write text to file"""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        except Exception as e:
            self.logger.error(f"Failed to write file {file_path}: {e}")
            return False

def setup_output_directories(base_path: str):
    """Setup output directory structure"""
    directories = [
        'reports',
        'logs',
        'artifacts',
        'screenshots',
        'extracted',
        'exploits'
    ]

    file_helper = FileHelper()
    base_path = Path(base_path)

    for directory in directories:
        dir_path = base_path / directory
        file_helper.create_directory(str(dir_path))