import unittest
import tempfile
import shutil
from pathlib import Path
from src.modules.ios.ipa_analyzer import IPAAnalyzer
from src.modules.ios.binary_analyzer import BinaryAnalyzer

class TestIPAAnalyzer(unittest.TestCase):
    def setUp(self):
        self.test_ipa = Path(__file__).parent / "test_data" / "test.ipa"
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_extract(self):
        """Test IPA extraction"""
        analyzer = IPAAnalyzer(str(self.test_ipa))
        extracted_path = analyzer.extract()

        self.assertTrue(extracted_path.exists())
        self.assertTrue((extracted_path / "Payload").exists())

    def test_get_app_info(self):
        """Test getting app information"""
        analyzer = IPAAnalyzer(str(self.test_ipa))
        info = analyzer.get_app_info()

        self.assertIn('bundle_id', info)
        self.assertIn('version', info)
        self.assertIn('minimum_os', info)

    def test_analyze_info_plist(self):
        """Test Info.plist analysis"""
        analyzer = IPAAnalyzer(str(self.test_ipa))
        analyzer.extract()
        issues = analyzer.analyze_info_plist()

        self.assertIsInstance(issues, list)

class TestBinaryAnalyzer(unittest.TestCase):
    def setUp(self):
        self.test_binary = Path(__file__).parent / "test_data" / "test_binary"

    def test_get_file_type(self):
        """Test file type detection"""
        analyzer = BinaryAnalyzer(str(self.test_binary))
        file_type = analyzer.get_file_type()

        self.assertIn('full_info', file_type)
        self.assertIn('is_mach_o', file_type)

    def test_check_security_features(self):
        """Test security features checking"""
        analyzer = BinaryAnalyzer(str(self.test_binary))
        features = analyzer.check_security_features()

        self.assertIn('pie', features)
        self.assertIn('stack_canary', features)
        self.assertIn('arc', features)

    def test_extract_strings(self):
        """Test string extraction"""
        analyzer = BinaryAnalyzer(str(self.test_binary))
        strings = analyzer.extract_strings()

        self.assertIn('urls', strings)
        self.assertIn('api_keys', strings)
        self.assertIn('sensitive_data', strings)

if __name__ == '__main__':
    unittest.main()