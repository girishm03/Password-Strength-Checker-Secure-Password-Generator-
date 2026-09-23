"""
Comprehensive Password Strength Analyzer.
Evaluates entropy, NIST SP 800-63B guidelines, pattern vulnerabilities,
dictionary matches, Have I Been Pwned breach status, and provides actionable security suggestions.
"""
import re
import string
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from core.entropy import EntropyCalculator, EntropyResult
from core.wordlist import COMMON_PASSWORDS
from core.pwned import check_pwned_api


@dataclass
class VulnerabilityFinding:
    severity: str  # "HIGH", "MEDIUM", "LOW", "INFO"
    title: str
    description: str


@dataclass
class PasswordAnalysis:
    password: str
    score: int  # 0 to 100
    rating: str  # "Very Weak", "Weak", "Fair", "Strong", "Very Strong"
    length: int
    entropy: EntropyResult
    char_counts: Dict[str, int]
    vulnerabilities: List[VulnerabilityFinding]
    suggestions: List[str]
    nist_compliant: bool
    is_common_password: bool
    is_breached: bool
    breach_count: int
    breach_status_message: str


class PasswordChecker:
    # Common keyboard sequences across standard QWERTY layout
    KEYBOARD_SEQUENCES = [
        "qwerty", "wertyu", "ertyui", "rtyuio", "tyuiop",
        "asdfgh", "sdfghj", "dfghjk", "fghjkl",
        "zxcvbn", "xcvbnm",
        "1qaz", "2wsx", "3edc", "4rfv", "5tgb", "6yhn", "7ujm",
        "qazwsx", "wsxedc", "edcrfv",
    ]

    @classmethod
    def analyze(cls, password: str, check_breach: bool = True) -> PasswordAnalysis:
        """
        Performs in-depth security analysis on the provided password.
        """
        if not password:
            entropy_res = EntropyCalculator.calculate_entropy("")
            return PasswordAnalysis(
                password="",
                score=0,
                rating="Very Weak",
                length=0,
                entropy=entropy_res,
                char_counts={"lower": 0, "upper": 0, "digits": 0, "symbols": 0, "spaces": 0},
                vulnerabilities=[
                    VulnerabilityFinding("HIGH", "Empty Password", "Password cannot be empty.")
                ],
                suggestions=["Enter a password to evaluate."],
                nist_compliant=False,
                is_common_password=False,
                is_breached=False,
                breach_count=0,
                breach_status_message="No password provided.",
            )

        length = len(password)
        entropy_res = EntropyCalculator.calculate_entropy(password)

        # Count character categories
        lower_count = sum(1 for c in password if c in string.ascii_lowercase)
        upper_count = sum(1 for c in password if c in string.ascii_uppercase)
        digit_count = sum(1 for c in password if c in string.digits)
        symbol_count = sum(1 for c in password if c in string.punctuation)
        space_count = sum(1 for c in password if c.isspace())

        char_counts = {
            "lower": lower_count,
            "upper": upper_count,
            "digits": digit_count,
            "symbols": symbol_count,
            "spaces": space_count,
        }

        vulnerabilities: List[VulnerabilityFinding] = []
        suggestions: List[str] = []

        # 1. Check offline common blacklist
        normalized_pw = password.strip().lower()
        is_common = normalized_pw in COMMON_PASSWORDS
        if is_common:
            vulnerabilities.append(
                VulnerabilityFinding(
                    severity="HIGH",
                    title="Known Commonly Used Password",
                    description="This password is on the top 100 most commonly used passwords list and is cracked instantly.",
                )
            )
            suggestions.append("Never use standard dictionary words or predictable default passwords.")

        # 2. Check length vulnerabilities
        if length < 8:
            vulnerabilities.append(
                VulnerabilityFinding(
                    severity="HIGH",
                    title="Critically Short Length",
                    description=f"Length is only {length} characters. NIST guidelines mandate at least 8 characters.",
                )
            )
            suggestions.append("Increase password length to at least 12-16 characters.")
        elif length < 12:
            vulnerabilities.append(
                VulnerabilityFinding(
                    severity="MEDIUM",
                    title="Short Password",
                    description=f"Length is {length} characters. While acceptable for basic accounts, 12+ characters is recommended.",
                )
            )
            suggestions.append("Consider lengthening to 14-16+ characters or using a multi-word passphrase.")

        # 3. Check character diversity
        active_char_types = sum([
            lower_count > 0,
            upper_count > 0,
            digit_count > 0,
            symbol_count > 0,
        ])

        if active_char_types == 1:
            vulnerabilities.append(
                VulnerabilityFinding(
                    severity="HIGH",
                    title="Zero Character Diversity",
                    description="Password only contains a single character class, severely restricting the search space.",
                )
            )
            suggestions.append("Mix uppercase, lowercase, numbers, and symbols to maximize complexity.")
        elif active_char_types == 2:
            vulnerabilities.append(
                VulnerabilityFinding(
                    severity="LOW",
                    title="Limited Character Diversity",
                    description="Password only uses 2 character classes.",
                )
            )
            suggestions.append("Add special characters or numbers to expand character pool.")

        # 4. Check repeated characters (e.g. "aaa", "1111")
        repeated_pattern = re.findall(r"(.)\1{2,}", password, re.IGNORECASE)
        if repeated_pattern:
            vulnerabilities.append(
                VulnerabilityFinding(
                    severity="MEDIUM",
                    title="Repeated Consecutive Characters",
                    description=f"Contains character sequences repeated 3+ times consecutively ('{repeated_pattern[0]}').",
                )
            )
            suggestions.append("Avoid repeated repeating characters like 'aaa' or '111'.")

        # 5. Check sequential patterns (letters and digits)
        seq_found = cls._check_sequential_patterns(password)
        if seq_found:
            vulnerabilities.append(
                VulnerabilityFinding(
                    severity="MEDIUM",
                    title="Sequential Pattern Detected",
                    description=f"Contains predictable sequence: '{seq_found}'.",
                )
            )
            suggestions.append("Avoid ascending or descending sequences like '1234' or 'abcd'.")

        # 6. Check keyboard walks
        kw_found = cls._check_keyboard_walk(password)
        if kw_found:
            vulnerabilities.append(
                VulnerabilityFinding(
                    severity="MEDIUM",
                    title="Keyboard Walk Detected",
                    description=f"Contains keyboard pattern sequence: '{kw_found}'.",
                )
            )
            suggestions.append("Avoid keyboard walking patterns like 'qwerty' or 'asdfgh'.")

        # 7. Check Have I Been Pwned breach API (if enabled)
        is_breached = False
        breach_count = 0
        breach_msg = "Breach check disabled."

        if check_breach:
            is_breached, breach_count, breach_msg = check_pwned_api(password)
            if is_breached:
                vulnerabilities.append(
                    VulnerabilityFinding(
                        severity="HIGH",
                        title="Compromised in Known Data Breach",
                        description=f"Appeared in {breach_count:,} public data breaches verified via HaveIBeenPwned.",
                    )
                )
                suggestions.append("CRITICAL: Change this password immediately. It is exposed in public breach databases.")

        # Compute Composite Score (0 - 100)
        score = cls._compute_score(
            length=length,
            entropy_bits=entropy_res.entropy_bits,
            active_types=active_char_types,
            is_common=is_common,
            is_breached=is_breached,
            vulnerabilities=vulnerabilities,
        )

        rating = cls._score_to_rating(score)

        # NIST SP 800-63B Compliance check:
        # - Minimum 8 characters
        # - Not found in common breach / dictionary lists
        # - No sequential/repeated triviality
        nist_compliant = (
            length >= 8
            and not is_common
            and not is_breached
            and len([v for v in vulnerabilities if v.severity == "HIGH"]) == 0
        )

        if not suggestions:
            suggestions.append("Great job! This password adheres to high security standards.")

        return PasswordAnalysis(
            password=password,
            score=score,
            rating=rating,
            length=length,
            entropy=entropy_res,
            char_counts=char_counts,
            vulnerabilities=vulnerabilities,
            suggestions=suggestions,
            nist_compliant=nist_compliant,
            is_common_password=is_common,
            is_breached=is_breached,
            breach_count=breach_count,
            breach_status_message=breach_msg,
        )

    @classmethod
    def _check_sequential_patterns(cls, password: str) -> Optional[str]:
        """Detects sequential alphabetical or numeric series of 3 or more chars."""
        pw_lower = password.lower()
        # Digits sequence
        for i in range(len(pw_lower) - 2):
            sub = pw_lower[i : i + 3]
            if sub in "0123456789012" or sub in "987654321098":
                return sub
            if sub in "abcdefghijklmnopqrstuvwxyz" or sub in "zyxwvutsrqponmlkjihgfedcba":
                return sub
        return None

    @classmethod
    def _check_keyboard_walk(cls, password: str) -> Optional[str]:
        """Detects common keyboard walk sequences."""
        pw_lower = password.lower()
        for pattern in cls.KEYBOARD_SEQUENCES:
            if pattern in pw_lower:
                return pattern
        return None

    @classmethod
    def _compute_score(
        cls,
        length: int,
        entropy_bits: float,
        active_types: int,
        is_common: bool,
        is_breached: bool,
        vulnerabilities: List[VulnerabilityFinding],
    ) -> int:
        """
        Calculates a balanced 0-100 score reflecting realistic cryptographic defense.
        """
        if is_common or is_breached:
            # Severely penalize compromised passwords
            base = min(15, length * 2)
            return max(5, base)

        # Baseline score influenced by entropy and length
        # 60 bits is decent (~65 score), 80+ bits is very strong (85-100)
        entropy_score = min(50.0, (entropy_bits / 80.0) * 50.0)

        # Length score (up to 30 pts)
        if length < 8:
            length_score = length * 2
        elif length < 12:
            length_score = 16 + (length - 8) * 2.5
        elif length < 16:
            length_score = 24 + (length - 12) * 1.0
        else:
            length_score = min(30.0, 28 + (length - 16) * 0.2)

        # Diversity score (up to 20 pts)
        diversity_score = active_types * 5.0

        total = entropy_score + length_score + diversity_score

        # Deduct penalties for vulnerabilities
        for v in vulnerabilities:
            if v.severity == "HIGH":
                total -= 25
            elif v.severity == "MEDIUM":
                total -= 10
            elif v.severity == "LOW":
                total -= 5

        # Normalize boundaries
        final_score = int(round(max(0, min(100, total))))
        return final_score

    @staticmethod
    def _score_to_rating(score: int) -> str:
        if score < 25:
            return "Very Weak"
        elif score < 50:
            return "Weak"
        elif score < 70:
            return "Fair"
        elif score < 88:
            return "Strong"
        else:
            return "Very Strong"
