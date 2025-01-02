import unittest
from threatvault.scanner import calculate_entropy, COMMON_SUSPICIOUS_PATTERNS

class TestScanner(unittest.TestCase):
    def test_entropy_zero_on_empty(self):
        self.assertEqual(calculate_entropy(b""), 0.0)

    def test_entropy_on_uniform_data(self):
        self.assertEqual(calculate_entropy(b"A" * 100), 0.0)

    def test_suspicious_patterns_exist(self):
        self.assertTrue(len(COMMON_SUSPICIOUS_PATTERNS) >= 5)

if __name__ == "__main__":
    unittest.main()
