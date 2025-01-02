import unittest
from threatvault.cve_engine import search_cve

class TestCVE(unittest.TestCase):
    def test_cve_search_empty(self):
        res = search_cve("NONEXISTENT_CVE_XYZ", cve_dir="cve")
        self.assertIsInstance(res, list)

if __name__ == "__main__":
    unittest.main()
