"""
Unit tests for Password Strength Checker and Secure Password Generator.
"""
import unittest
from core.entropy import EntropyCalculator
from core.generator import PasswordGenerator
from core.checker import PasswordChecker


class TestEntropyCalculator(unittest.TestCase):
    def test_empty_password(self):
        res = EntropyCalculator.calculate_entropy("")
        self.assertEqual(res.entropy_bits, 0.0)
        self.assertEqual(res.pool_size, 0)

    def test_pool_size_calculation(self):
        # Only lowercase: pool 26
        pool, flags = EntropyCalculator.get_pool_size("hello")
        self.assertEqual(pool, 26)
        self.assertTrue(flags["lowercase"])
        self.assertFalse(flags["uppercase"])
        self.assertFalse(flags["digits"])
        self.assertFalse(flags["symbols"])

        # Lowercase + Digits + Symbols: 26 + 10 + 32 = 68
        pool2, flags2 = EntropyCalculator.get_pool_size("hello123!")
        self.assertTrue(flags2["lowercase"])
        self.assertTrue(flags2["digits"])
        self.assertTrue(flags2["symbols"])
        self.assertGreaterEqual(pool2, 68)

    def test_entropy_scaling(self):
        # 8-char lowercase vs 16-char mixed
        e1 = EntropyCalculator.calculate_entropy("abcdefgh")
        e2 = EntropyCalculator.calculate_entropy("aB3!kL9#mP0$vR1&")
        self.assertGreater(e2.entropy_bits, e1.entropy_bits)
        self.assertGreater(e2.entropy_bits, 70)

    def test_format_duration(self):
        self.assertIn("Instant", EntropyCalculator.format_duration(0.0001))
        self.assertIn("seconds", EntropyCalculator.format_duration(15.2))
        self.assertIn("hours", EntropyCalculator.format_duration(7200))
        self.assertIn("years", EntropyCalculator.format_duration(31536000 * 5))


class TestPasswordGenerator(unittest.TestCase):
    def test_random_password_length(self):
        res = PasswordGenerator.generate_random_password(length=20)
        self.assertEqual(len(res.password), 20)
        self.assertEqual(res.length, 20)
        self.assertGreater(res.entropy_bits, 50)

    def test_random_password_character_enforcement(self):
        res = PasswordGenerator.generate_random_password(
            length=16, use_upper=True, use_lower=True, use_digits=True, use_symbols=True
        )
        has_lower = any(c.islower() for c in res.password)
        has_upper = any(c.isupper() for c in res.password)
        has_digit = any(c.isdigit() for c in res.password)
        self.assertTrue(has_lower)
        self.assertTrue(has_upper)
        self.assertTrue(has_digit)

    def test_exclude_ambiguous_characters(self):
        for _ in range(10):
            res = PasswordGenerator.generate_random_password(
                length=30, exclude_ambiguous=True
            )
            for ambig in PasswordGenerator.AMBIGUOUS_CHARS:
                self.assertNotIn(ambig, res.password)

    def test_generate_passphrase(self):
        res = PasswordGenerator.generate_passphrase(
            num_words=4, separator="-", capitalize=True, include_number=True
        )
        parts = res.password.split("-")
        # 4 words + 1 number = 5 parts
        self.assertEqual(len(parts), 5)
        # Check first word is capitalized
        self.assertTrue(parts[0][0].isupper())
        # Check last element is a number
        self.assertTrue(parts[-1].isdigit())

    def test_generate_pin(self):
        res = PasswordGenerator.generate_pin(length=8)
        self.assertEqual(len(res.password), 8)
        self.assertTrue(res.password.isdigit())

    def test_generate_formatted_token(self):
        res = PasswordGenerator.generate_formatted_token(
            block_count=3, block_length=4, separator=":"
        )
        parts = res.password.split(":")
        self.assertEqual(len(parts), 3)
        for p in parts:
            self.assertEqual(len(p), 4)


class TestPasswordChecker(unittest.TestCase):
    def test_empty_password_check(self):
        analysis = PasswordChecker.analyze("", check_breach=False)
        self.assertEqual(analysis.score, 0)
        self.assertEqual(analysis.rating, "Very Weak")
        self.assertFalse(analysis.nist_compliant)

    def test_common_password_detection(self):
        analysis = PasswordChecker.analyze("password123", check_breach=False)
        self.assertTrue(analysis.is_common_password)
        self.assertIn("Known Commonly Used Password", [v.title for v in analysis.vulnerabilities])
        self.assertLessEqual(analysis.score, 25)

    def test_sequential_pattern_detection(self):
        analysis = PasswordChecker.analyze("mysecret12345", check_breach=False)
        self.assertIn("Sequential Pattern Detected", [v.title for v in analysis.vulnerabilities])

    def test_keyboard_walk_detection(self):
        analysis = PasswordChecker.analyze("qwertySecure99!", check_breach=False)
        self.assertIn("Keyboard Walk Detected", [v.title for v in analysis.vulnerabilities])

    def test_strong_password_analysis(self):
        # High entropy complex password
        analysis = PasswordChecker.analyze("K9#vL2$mP8!xR5@tW3&z", check_breach=False)
        self.assertGreaterEqual(analysis.score, 80)
        self.assertIn(analysis.rating, ["Strong", "Very Strong"])
        self.assertTrue(analysis.nist_compliant)


if __name__ == "__main__":
    unittest.main()
