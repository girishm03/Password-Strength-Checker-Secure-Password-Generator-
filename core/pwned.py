"""
Have I Been Pwned (HIBP) k-Anonymity API integration.
Safely checks if a password has appeared in compromised data breaches.
Zero-Knowledge Privacy: Only the first 5 characters of SHA-1 hash are sent.
"""
import hashlib
from typing import Tuple


def check_pwned_api(password: str, timeout: int = 5) -> Tuple[bool, int, str]:
    """
    Checks if password appears in Have I Been Pwned database using k-Anonymity.
    Returns: (is_pwned: bool, breach_count: int, status_message: str)
    """
    if not password:
        return False, 0, "Empty password"

    # Step 1: Compute uppercase SHA-1 hash of the password
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {
        "User-Agent": "CyberSecurity-Password-Tool/1.0",
        "Add-Padding": "true",  # HIBP padding for enhanced resistance to traffic analysis
    }

    try:
        # Prefer requests if available, fallback to urllib.request
        try:
            import requests
            response = requests.get(url, headers=headers, timeout=timeout)
            if response.status_code != 200:
                return False, 0, f"HIBP service returned HTTP {response.status_code}"
            data = response.text
        except ImportError:
            import urllib.request
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status != 200:
                    return False, 0, f"HIBP service returned HTTP {resp.status}"
                data = resp.read().decode("utf-8")

        # Step 2: Search for matching suffix in returned hashes
        hashes = (line.split(":") for line in data.splitlines() if ":" in line)
        for h_suffix, count_str in hashes:
            if h_suffix.strip() == suffix:
                count = int(count_str.strip())
                return True, count, f"Found in {count:,} known data breaches!"

        return False, 0, "No breach record found in HaveIBeenPwned database."

    except Exception as e:
        return False, 0, f"Network check skipped ({str(e)})"
