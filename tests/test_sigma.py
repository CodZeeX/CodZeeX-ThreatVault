import unittest
from threatvault.sigma_engine import match_event

class TestSigma(unittest.TestCase):
    def test_sigma_match_exact(self):
        rule = {
            "detection": {
                "selection": {
                    "Image": "C:\\Windows\\System32\\cmd.exe"
                }
            }
        }
        event = {"Image": "C:\\Windows\\System32\\cmd.exe"}
        self.assertTrue(match_event(event, rule))

    def test_sigma_match_contains(self):
        rule = {
            "detection": {
                "selection": {
                    "CommandLine|contains": "powershell"
                }
            }
        }
        event = {"CommandLine": "C:\\Windows\\System32\\powershell.exe -enc AAAA"}
        self.assertTrue(match_event(event, rule))

if __name__ == "__main__":
    unittest.main()
