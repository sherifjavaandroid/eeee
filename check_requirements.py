import subprocess
import sys
import os
import platform

def check_tool(tool_name, test_commands):
    """Check if a tool is available in PATH"""
    for command in test_commands:
        try:
            # For Windows, try with shell=True for batch files
            if platform.system() == "Windows":
                result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            else:
                result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            if result.returncode == 0:
                return True
        except (FileNotFoundError, subprocess.SubprocessError):
            continue

    return False

def check_requirements():
    """Check if all required tools are installed"""
    # Different command variations to try
    tools = {
        'apktool': [
            ['apktool', '--version'],
            ['apktool.bat', '--version'],
            ['java', '-jar', 'apktool.jar', '--version']
        ],
        'aapt': [
            ['aapt', 'version'],
            ['aapt.exe', 'version']
        ],
        'adb': [
            ['adb', '--version'],
            ['adb.exe', '--version']
        ],
    }

    missing_tools = []

    for tool, commands in tools.items():
        if not check_tool(tool, commands):
            missing_tools.append(tool)

    if missing_tools:
        print("Missing required tools:")
        for tool in missing_tools:
            print(f"  - {tool}")
        print("\nPlease install the missing tools and make sure they are in your PATH.")
        return False
    else:
        print("All required tools are installed.")
        return True

if __name__ == "__main__":
    if check_requirements():
        sys.exit(0)
    else:
        sys.exit(1)