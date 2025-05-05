# src/utils/tool_runner.py
import subprocess
import platform
import os
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path

class ToolRunner:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.is_windows = platform.system() == "Windows"

    def run_apktool(self, args: List[str], timeout: int = 300) -> subprocess.CompletedProcess:
        """Run apktool with proper Windows handling"""

        if self.is_windows:
            # Try different approaches for Windows

            # Method 1: Direct Java execution
            try:
                # Look for apktool.jar in common locations
                possible_paths = [
                    Path("C:/apktool/apktool.jar"),
                    Path.home() / "apktool" / "apktool.jar",
                    Path("apktool.jar"),
                    Path("C:/Program Files/apktool/apktool.jar"),
                    Path("C:/Program Files (x86)/apktool/apktool.jar"),
                    ]

                apktool_jar = None
                for path in possible_paths:
                    if path.exists():
                        apktool_jar = path
                        break

                if apktool_jar:
                    cmd = ["java", "-jar", str(apktool_jar)] + args
                    self.logger.debug(f"Running apktool via java: {' '.join(cmd)}")
                    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            except Exception as e:
                self.logger.debug(f"Direct java execution failed: {e}")

            # Method 2: Use cmd.exe to run batch file
            try:
                cmd = ["cmd", "/c", "apktool"] + args
                self.logger.debug(f"Running apktool via cmd: {' '.join(cmd)}")
                return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            except Exception as e:
                self.logger.debug(f"cmd.exe execution failed: {e}")

            # Method 3: Direct batch file with shell=True
            try:
                cmd = " ".join(["apktool"] + args)
                self.logger.debug(f"Running apktool with shell=True: {cmd}")
                return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            except Exception as e:
                self.logger.debug(f"Shell execution failed: {e}")
                raise RuntimeError(f"Failed to run apktool: {e}")
        else:
            # Standard execution for Unix-like systems
            cmd = ["apktool"] + args
            return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    def run_aapt(self, args: List[str], timeout: int = 60) -> subprocess.CompletedProcess:
        """Run aapt tool"""
        if self.is_windows:
            cmd = ["aapt.exe"] + args
        else:
            cmd = ["aapt"] + args

        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    def run_adb(self, args: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
        """Run adb tool"""
        if self.is_windows:
            cmd = ["adb.exe"] + args
        else:
            cmd = ["adb"] + args

        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)