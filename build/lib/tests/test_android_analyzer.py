### 22. tests/test_android_analyzer.py

import unittest
import tempfile
import shutil
from pathlib import Path
from src.modules.android.apk_analyzer import APKAnalyzer

class TestAPKAnalyzer(unittest.TestCase):
    def setUp(self):
        self.test_apk = Path(__file__).parent / "test_data" / "test.apk"
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_extract(self):
        analyzer = APKAnalyzer(str(self.test_apk))
        extracted_path = analyzer.extract()

        self.assertTrue(extracted_path.exists())
        self.assertTrue((extracted_path / "AndroidManifest.xml").exists())

    def test_get_app_info(self):
        analyzer = APKAnalyzer(str(self.test_apk))
        info = analyzer.get_app_info()

        self.assertIn('package_name', info)
        self.assertIn('version', info)
        self.assertIn('permissions', info)

    def test_analyze_manifest(self):
        analyzer = APKAnalyzer(str(self.test_apk))
        analyzer.extract()
        issues = analyzer.analyze_manifest()

        self.assertIsInstance(issues, list)

if __name__ == '__main__':
    unittest.main()