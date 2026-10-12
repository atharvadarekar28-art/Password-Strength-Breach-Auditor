"""
Unit Tests for Password Strength Checker and Breach Auditor.
"""

import unittest
import sys
import os

# Add root folder
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.hibp_client import audit_pwned_password
from core.entropy_calculator import analyze_entropy, format_time_duration
from core.pattern_detector import detect_patterns
from core.scorer import calculate_score
from core.generator import generate_random_password, generate_diceware_passphrase


class TestAuditor(unittest.TestCase):

    def test_hibp_known_breach(self):
        # 'password' is known to appear tens of millions of times
        res = audit_pwned_password("password")
        self.assertTrue(res["breached"])
        self.assertGreater(res["count"], 1_000_000)
        self.assertEqual(res["sha1_prefix"], "5BAA6")
        self.assertIsNone(res["error"])

    def test_hibp_unique_password(self):
        # A long random password should not be breached
        unique_pwd = "X9#mQ!99zK$87_vLpQ2-diceware-custom-998"
        res = audit_pwned_password(unique_pwd)
        self.assertFalse(res["breached"])
        self.assertEqual(res["count"], 0)
        self.assertIsNone(res["error"])

    def test_entropy_calculation(self):
        # Test basic entropy metrics
        res = analyze_entropy("Password123!")
        self.assertEqual(res["length"], 12)
        self.assertTrue(res["has_lower"])
        self.assertTrue(res["has_upper"])
        self.assertTrue(res["has_digit"])
        self.assertTrue(res["has_symbol"])
        self.assertGreater(res["entropy_bits"], 50.0)

    def test_pattern_detection(self):
        # Sequential numbers
        p1 = detect_patterns("my123456pwd")
        names = [p["name"] for p in p1]
        self.assertIn("Sequential Numbers", names)

        # Repeated chars
        p2 = detect_patterns("aaaaaa12#")
        names2 = [p["name"] for p in p2]
        self.assertIn("Repeated Character Run", names2)

        # Keyboard walk
        p3 = detect_patterns("qwerty99!")
        names3 = [p["name"] for p in p3]
        self.assertIn("Keyboard Walk Pattern", names3)

        # Dictionary word
        p4 = detect_patterns("welcometo12")
        names4 = [p["name"] for p in p4]
        self.assertIn("Common Dictionary Word", names4)

    def test_scoring_compromised(self):
        # When breached, score must be 0 and status COMPROMISED
        ent = analyze_entropy("password")
        pats = detect_patterns("password")
        breach = {"breached": True, "count": 52000000}
        score_res = calculate_score("password", ent, pats, breach)
        self.assertEqual(score_res["score"], 0)
        self.assertTrue(score_res["is_compromised"])
        self.assertIn("COMPROMISED", score_res["status_label"])

    def test_scoring_strong_password(self):
        strong_pwd = generate_random_password(24)
        ent = analyze_entropy(strong_pwd)
        pats = detect_patterns(strong_pwd)
        breach = {"breached": False, "count": 0}
        score_res = calculate_score(strong_pwd, ent, pats, breach)
        self.assertGreaterEqual(score_res["score"], 85)
        self.assertFalse(score_res["is_compromised"])

    def test_generator(self):
        pwd = generate_random_password(16)
        self.assertEqual(len(pwd), 16)
        passphrase = generate_diceware_passphrase(4, "-")
        self.assertIn("-", passphrase)
        self.assertEqual(len(passphrase.split("-")), 4)


if __name__ == "__main__":
    unittest.main()
