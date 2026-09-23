"""
Entropy and Brute-Force Crack Time Calculator.
Calculates character pool size, Shannon entropy, and realistic crack times across hardware tiers.
"""
import math
import string
from dataclasses import dataclass
from typing import Dict, Tuple


@dataclass
class CrackTimeEstimate:
    scenario: str
    rate_desc: str
    seconds: float
    formatted: str


@dataclass
class EntropyResult:
    entropy_bits: float
    pool_size: int
    char_types: Dict[str, bool]
    search_space: float
    crack_times: Dict[str, CrackTimeEstimate]


class EntropyCalculator:
    # Modern hardware and attack speed benchmarks (guesses per second)
    ATTACK_PROFILES = {
        "online_throttled": {
            "name": "Online (Rate Limited)",
            "rate_desc": "100 guesses / sec (Web login with throttle)",
            "rate": 1e2,
        },
        "online_fast": {
            "name": "Online (Unthrottled)",
            "rate_desc": "10,000 guesses / sec (Botnet / API spray)",
            "rate": 1e4,
        },
        "offline_single_gpu": {
            "name": "Offline GPU (Single RTX 4090)",
            "rate_desc": "10 Billion guesses / sec (10 GH/s MD5/NTLM)",
            "rate": 1e10,
        },
        "offline_rig_cluster": {
            "name": "Offline High-End GPU Cluster",
            "rate_desc": "1 Trillion guesses / sec (1 TH/s Cracking Rig)",
            "rate": 1e12,
        },
    }

    @staticmethod
    def get_pool_size(password: str) -> Tuple[int, Dict[str, bool]]:
        """Calculate the character pool size R based on character types present."""
        has_lower = any(c in string.ascii_lowercase for c in password)
        has_upper = any(c in string.ascii_uppercase for c in password)
        has_digits = any(c in string.digits for c in password)
        has_symbols = any(c in string.punctuation for c in password)
        has_whitespace = any(c.isspace() for c in password)
        has_other = any(
            c not in (string.ascii_letters + string.digits + string.punctuation + string.whitespace)
            for c in password
        )

        pool = 0
        if has_lower:
            pool += 26
        if has_upper:
            pool += 26
        if has_digits:
            pool += 10
        if has_symbols:
            pool += len(string.punctuation)
        if has_whitespace:
            pool += 1
        if has_other:
            pool += 30  # Approximation for unicode/accented characters

        char_types = {
            "lowercase": has_lower,
            "uppercase": has_upper,
            "digits": has_digits,
            "symbols": has_symbols,
            "whitespace": has_whitespace,
            "other": has_other,
        }

        return max(pool, 1), char_types

    @classmethod
    def calculate_entropy(cls, password: str) -> EntropyResult:
        """
        Calculates information entropy (bits) based on length L and pool size R:
        E = L * log2(R)
        Applies penalties for heavy character repetition.
        """
        if not password:
            return EntropyResult(
                entropy_bits=0.0,
                pool_size=0,
                char_types={k: False for k in ["lowercase", "uppercase", "digits", "symbols", "whitespace", "other"]},
                search_space=0.0,
                crack_times={},
            )

        length = len(password)
        pool, char_types = cls.get_pool_size(password)

        # Baseline theoretical entropy: L * log2(R)
        raw_entropy = length * math.log2(pool)

        # Penalty for repeated characters (e.g., 'aaaaaaaa' has pool 26 but minimal real entropy)
        unique_chars = len(set(password))
        repetition_factor = unique_chars / length
        # Adjusted entropy dampens excessive repeated chars while keeping reasonable scale
        adjusted_entropy = raw_entropy * (0.4 + 0.6 * repetition_factor)
        adjusted_entropy = round(max(0.0, adjusted_entropy), 2)

        # Combinatorial search space (pool^length)
        search_space = float(pool) ** length

        # Average combinations to guess on brute force is search_space / 2
        avg_combinations = search_space / 2.0

        crack_times = {}
        for key, profile in cls.ATTACK_PROFILES.items():
            seconds = avg_combinations / profile["rate"]
            formatted = cls.format_duration(seconds)
            crack_times[key] = CrackTimeEstimate(
                scenario=profile["name"],
                rate_desc=profile["rate_desc"],
                seconds=seconds,
                formatted=formatted,
            )

        return EntropyResult(
            entropy_bits=adjusted_entropy,
            pool_size=pool,
            char_types=char_types,
            search_space=search_space,
            crack_times=crack_times,
        )

    @staticmethod
    def format_duration(seconds: float) -> str:
        """Converts raw seconds into a friendly human-readable time scale."""
        if seconds < 0.001:
            return "Instant (< 1 millisecond)"
        elif seconds < 1:
            return f"{round(seconds * 1000, 1)} milliseconds"
        elif seconds < 60:
            return f"{round(seconds, 1)} seconds"
        elif seconds < 3600:
            return f"{round(seconds / 60, 1)} minutes"
        elif seconds < 86400:
            return f"{round(seconds / 3600, 1)} hours"
        elif seconds < 31536000:
            return f"{round(seconds / 86400, 1)} days"
        elif seconds < 31536000 * 100:
            return f"{round(seconds / 31536000, 1)} years"
        elif seconds < 31536000 * 10000:
            return f"{round(seconds / (31536000 * 100), 1)} centuries"
        elif seconds < 31536000 * 1e9:
            return f"{round(seconds / (31536000 * 1e6), 1)} million years"
        elif seconds < 31536000 * 1e12:
            return f"{round(seconds / (31536000 * 1e9), 1)} billion years"
        else:
            return "Trillions of years (Virtually Uncrackable)"
