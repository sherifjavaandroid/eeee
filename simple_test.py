# simple_test.py
import os
import sys
import logging
from pathlib import Path

# Setup basic logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Add project to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from src.modules.android.apk_analyzer import APKAnalyzer

    # Test APK analysis directly
    apk_path = "apk.apk"
    if not Path(apk_path).exists():
        logger.error(f"APK not found: {apk_path}")
        sys.exit(1)

    logger.info(f"Testing APK: {apk_path}")
    analyzer = APKAnalyzer(apk_path)

    # Try extraction
    logger.info("Attempting extraction...")
    extracted = analyzer.extract()
    logger.info(f"Extracted to: {extracted}")

    # Try getting info
    logger.info("Getting app info...")
    info = analyzer.get_app_info()
    logger.info(f"App info: {info}")

    # Try analyzing manifest
    logger.info("Analyzing manifest...")
    issues = analyzer.analyze_manifest()
    logger.info(f"Issues found: {issues}")

except Exception as e:
    logger.error(f"Test failed: {e}", exc_info=True)