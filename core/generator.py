"""
Cryptographically secure password and passphrase generator using Python's secrets module (CSPRNG).
Supports custom character set passwords, Diceware / XKCD-style passphrases, and formatted tokens.
"""
import secrets
import string
from dataclasses import dataclass
from typing import List, Optional
from core.wordlist import DICEWARE_WORDS
from core.entropy import EntropyCalculator


@dataclass
class GeneratedPassword:
    password: str
    length: int
    entropy_bits: float
    mode: str
    pool_size: int
    rating: str


class PasswordGenerator:
    # Ambiguous characters that look similar across fonts
    AMBIGUOUS_CHARS = "Il1O0o|'`\""

    # Default symbols recommended for high compatibility
    STANDARD_SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?"

    @classmethod
    def generate_random_password(
        cls,
        length: int = 16,
        use_upper: bool = True,
        use_lower: bool = True,
        use_digits: bool = True,
        use_symbols: bool = True,
        exclude_ambiguous: bool = False,
        custom_symbols: Optional[str] = None,
    ) -> GeneratedPassword:
        """
        Generates a cryptographically secure random password enforcing at least one
        character from each enabled category, shuffled with secrets.randbelow.
        """
        if length < 4:
            length = 4

        charset_categories: List[str] = []

        lower_chars = string.ascii_lowercase
        upper_chars = string.ascii_uppercase
        digit_chars = string.digits
        symbol_chars = custom_symbols if custom_symbols is not None else cls.STANDARD_SYMBOLS

        if exclude_ambiguous:
            lower_chars = "".join(c for c in lower_chars if c not in cls.AMBIGUOUS_CHARS)
            upper_chars = "".join(c for c in upper_chars if c not in cls.AMBIGUOUS_CHARS)
            digit_chars = "".join(c for c in digit_chars if c not in cls.AMBIGUOUS_CHARS)
            symbol_chars = "".join(c for c in symbol_chars if c not in cls.AMBIGUOUS_CHARS)

        if use_lower and lower_chars:
            charset_categories.append(lower_chars)
        if use_upper and upper_chars:
            charset_categories.append(upper_chars)
        if use_digits and digit_chars:
            charset_categories.append(digit_chars)
        if use_symbols and symbol_chars:
            charset_categories.append(symbol_chars)

        if not charset_categories:
            # Fallback if all were unchecked
            charset_categories.append(string.ascii_letters + string.digits)

        # Ensure at least one character from each selected category
        guaranteed_chars = [secrets.choice(cat) for cat in charset_categories]

        # Fill the remainder from the combined character pool
        combined_pool = "".join(charset_categories)
        remaining_count = max(0, length - len(guaranteed_chars))
        random_fill = [secrets.choice(combined_pool) for _ in range(remaining_count)]

        full_list = guaranteed_chars + random_fill

        # Cryptographically secure Fisher-Yates shuffle
        for i in range(len(full_list) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            full_list[i], full_list[j] = full_list[j], full_list[i]

        result_pw = "".join(full_list[:length])
        entropy_res = EntropyCalculator.calculate_entropy(result_pw)
        rating = cls._rate_entropy(entropy_res.entropy_bits)

        return GeneratedPassword(
            password=result_pw,
            length=len(result_pw),
            entropy_bits=entropy_res.entropy_bits,
            mode="Random Password",
            pool_size=entropy_res.pool_size,
            rating=rating,
        )

    @classmethod
    def generate_passphrase(
        cls,
        num_words: int = 5,
        separator: str = "-",
        capitalize: bool = True,
        include_number: bool = True,
        include_symbol: bool = False,
    ) -> GeneratedPassword:
        """
        Generates an XKCD / Diceware-style memorable passphrase from the curated wordlist.
        High entropy with great human memorability.
        """
        if num_words < 3:
            num_words = 3

        selected_words = [secrets.choice(DICEWARE_WORDS) for _ in range(num_words)]

        if capitalize:
            selected_words = [w.capitalize() for w in selected_words]
        else:
            selected_words = [w.lower() for w in selected_words]

        passphrase = separator.join(selected_words)

        if include_number:
            num = str(secrets.randbelow(90) + 10)  # 2-digit number (10-99)
            passphrase += f"{separator}{num}"

        if include_symbol:
            sym = secrets.choice("!@#$%^&*")
            passphrase += sym

        entropy_res = EntropyCalculator.calculate_entropy(passphrase)
        rating = cls._rate_entropy(entropy_res.entropy_bits)

        return GeneratedPassword(
            password=passphrase,
            length=len(passphrase),
            entropy_bits=entropy_res.entropy_bits,
            mode="Diceware Passphrase",
            pool_size=entropy_res.pool_size,
            rating=rating,
        )

    @classmethod
    def generate_pin(cls, length: int = 6) -> GeneratedPassword:
        """Generates a numeric PIN of specified length."""
        pin = "".join(secrets.choice(string.digits) for _ in range(length))
        entropy_res = EntropyCalculator.calculate_entropy(pin)
        return GeneratedPassword(
            password=pin,
            length=length,
            entropy_bits=entropy_res.entropy_bits,
            mode="Numeric PIN",
            pool_size=10,
            rating=cls._rate_entropy(entropy_res.entropy_bits),
        )

    @classmethod
    def generate_formatted_token(
        cls, block_count: int = 4, block_length: int = 4, separator: str = "-"
    ) -> GeneratedPassword:
        """Generates formatted token keys (e.g., ABCD-EFGH-1234-WXYZ)."""
        charset = "".join(c for c in string.ascii_uppercase + string.digits if c not in "0O1I")
        blocks = [
            "".join(secrets.choice(charset) for _ in range(block_length))
            for _ in range(block_count)
        ]
        token = separator.join(blocks)
        entropy_res = EntropyCalculator.calculate_entropy(token)
        return GeneratedPassword(
            password=token,
            length=len(token),
            entropy_bits=entropy_res.entropy_bits,
            mode="Formatted Token",
            pool_size=len(charset),
            rating=cls._rate_entropy(entropy_res.entropy_bits),
        )

    @staticmethod
    def _rate_entropy(bits: float) -> str:
        if bits < 30:
            return "Very Weak"
        elif bits < 50:
            return "Weak"
        elif bits < 70:
            return "Fair"
        elif bits < 90:
            return "Strong"
        else:
            return "Very Strong"
