# test_apk.py
import os
from pathlib import Path

# List all APK files in the current directory
print("APK files in current directory:")
for file in Path('.').glob('*.apk'):
    print(f"  - {file}")

# Check if specific files exist
files_to_check = ['apk.apk', 'diva-beta.apk', 'DIVA.apk', 'app.apk']
print("\nChecking specific files:")
for file in files_to_check:
    if Path(file).exists():
        print(f"  ✓ {file} exists")
    else:
        print(f"  ✗ {file} not found")