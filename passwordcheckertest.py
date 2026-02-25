"""
Tests for password_checker.py
Run with: python -m pytest test_password_checker.py -v
"""

import unittest
from password_checker import analyze_password, hash_password


class TestHashPassword(unittest.TestCase):
    def test_sha256_length(self):
        result = hash_password("hello", "sha256")
        self.assertEqual(len(result), 64)

    def test_sha1_length(self):
        result = hash_password("hello", "sha1")
        self.assertEqual(len(result), 40)

    def test_md5_length(self):
        result = hash_password("hello", "md5")
        self.assertEqual(len(result), 32)

    def test_known_sha256(self):
        # SHA-256 of "abc"
        self.assertEqual(
            hash_password("abc", "sha256"),
            "ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469f490f4a65c27e5f47"[:64],
        )

    def test_invalid_algorithm(self):
        with self.assertRaises(ValueError):
            hash_password("test", "md4")


class TestAnalyzePassword(unittest.TestCase):
    def test_weak_short(self):
        r = analyze_password("ab")
        self.assertEqual(r["band"], "Weak")

    def test_common_password(self):
        r = analyze_password("password")
        self.assertEqual(r["score"], 0)

    def test_strong_password(self):
        r = analyze_password("Tr0ub4dor&3#Xyz!")
        self.assertGreaterEqual(r["score"], 80)
        self.assertEqual(r["band"], "Strong")

    def test_all_criteria_met(self):
        r = analyze_password("Abc123!@#Xyz789$")
        self.assertTrue(r["criteria"]["lowercase"])
        self.assertTrue(r["criteria"]["uppercase"])
        self.assertTrue(r["criteria"]["digits"])
        self.assertTrue(r["criteria"]["symbols"])

    def test_sequential_penalty(self):
        score_clean    = analyze_password("Abcdefgh1!XXXXXXXXX")["score"]
        score_sequence = analyze_password("Abcdefgh1!abc123")["score"]
        self.assertGreater(score_clean, score_sequence)

    def test_sha256_in_report(self):
        r = analyze_password("TestPass1!")
        self.assertEqual(len(r["sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
