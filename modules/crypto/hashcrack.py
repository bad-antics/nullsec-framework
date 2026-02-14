"""
NullSec Framework — Hash Cracker Module
Multi-algorithm hash identification and dictionary/brute-force cracking.
"""

import hashlib
import itertools
import string
import re
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional

try:
    from modules import BaseModule
except ImportError:
    from __init__ import BaseModule


class HashCracker(BaseModule):
    name = "hashcrack"
    description = "Hash identification and cracking (MD5, SHA1, SHA256, SHA512, NTLM)"
    category = "crypto"
    version = "1.0.0"

    # Hash type identification by length and pattern
    HASH_PATTERNS = {
        32: [("md5", hashlib.md5), ("ntlm", None)],
        40: [("sha1", hashlib.sha1)],
        56: [("sha224", hashlib.sha224)],
        64: [("sha256", hashlib.sha256)],
        96: [("sha384", hashlib.sha384)],
        128: [("sha512", hashlib.sha512)],
    }

    # Common passwords for quick check
    COMMON_PASSWORDS = [
        "password", "123456", "12345678", "qwerty", "abc123",
        "monkey", "1234567", "letmein", "trustno1", "dragon",
        "baseball", "iloveyou", "master", "sunshine", "ashley",
        "bailey", "passw0rd", "shadow", "123123", "654321",
        "superman", "qazwsx", "michael", "football", "password1",
        "password123", "batman", "admin", "admin123", "root",
        "toor", "test", "guest", "welcome", "login",
        "starwars", "solo", "princess", "cheese", "computer",
    ]

    def validate(self) -> bool:
        hash_val = self.get_option("hash")
        hash_file = self.get_option("hashfile")
        if not hash_val and not hash_file:
            print("[!] Either hash or hashfile is required")
            return False
        return True

    def run(self, **kwargs) -> Dict:
        hash_val = self.get_option("hash", kwargs.get("hash", ""))
        hash_file = self.get_option("hashfile", kwargs.get("hashfile", ""))
        wordlist = self.get_option("wordlist", kwargs.get("wordlist", ""))
        brute_max = int(self.get_option("brute_max", kwargs.get("brute_max", 4)))
        threads = int(self.get_option("threads", kwargs.get("threads", 4)))
        algo = self.get_option("algorithm", kwargs.get("algorithm", ""))

        result = {
            "timestamp": datetime.utcnow().isoformat(),
            "cracked": [],
            "failed": [],
        }

        # Collect hashes
        hashes = []
        if hash_val:
            hashes.append(hash_val.strip())
        if hash_file:
            hashes.extend(self._load_hashes(hash_file))

        print(f"[*] Hash Cracker: {len(hashes)} hash(es) to crack")

        for h in hashes:
            h = h.strip().lower()
            if not h:
                continue

            # Identify hash type
            if algo:
                hash_type = algo
                hash_func = getattr(hashlib, algo, None)
                if hash_type == "ntlm":
                    hash_func = None
            else:
                hash_type, hash_func = self._identify_hash(h)

            print(f"\n  [*] Hash: {h[:16]}...{h[-8:]}")
            print(f"      Type: {hash_type or 'unknown'}")

            if not hash_type:
                result["failed"].append({"hash": h, "reason": "Unknown hash type"})
                continue

            # Try cracking
            cracked = None

            # 1. Common passwords
            print("      [*] Trying common passwords...")
            cracked = self._try_wordlist(h, hash_type, hash_func, self.COMMON_PASSWORDS)

            # 2. Custom wordlist
            if not cracked and wordlist:
                print(f"      [*] Trying wordlist: {wordlist}")
                words = self._load_wordlist(wordlist)
                cracked = self._try_wordlist(h, hash_type, hash_func, words)

            # 3. Rule-based mutations
            if not cracked:
                print("      [*] Trying mutations...")
                mutated = self._generate_mutations(self.COMMON_PASSWORDS[:20])
                cracked = self._try_wordlist(h, hash_type, hash_func, mutated)

            # 4. Brute force (short lengths only)
            if not cracked and brute_max <= 5:
                print(f"      [*] Brute-forcing up to {brute_max} chars...")
                cracked = self._brute_force(h, hash_type, hash_func, brute_max)

            if cracked:
                entry = {"hash": h, "type": hash_type, "plaintext": cracked}
                result["cracked"].append(entry)
                print(f"      [+] CRACKED: {cracked}")
            else:
                result["failed"].append({"hash": h, "type": hash_type, "reason": "Not found"})
                print("      [-] Not cracked")

        print(f"\n[*] Results: {len(result['cracked'])}/{len(hashes)} cracked")
        return result

    def _identify_hash(self, hash_str):
        """Identify hash type by length and format."""
        # Clean hash
        hash_str = hash_str.strip()
        if not re.match(r'^[a-f0-9]+$', hash_str, re.I):
            return None, None

        length = len(hash_str)
        candidates = self.HASH_PATTERNS.get(length, [])

        if candidates:
            name, func = candidates[0]
            return name, func
        return None, None

    def _compute_hash(self, plaintext, hash_type, hash_func):
        """Compute hash of plaintext."""
        if hash_type == "ntlm":
            return hashlib.new("md4", plaintext.encode("utf-16le")).hexdigest()
        if hash_func:
            return hash_func(plaintext.encode()).hexdigest()
        return None

    def _try_wordlist(self, target_hash, hash_type, hash_func, words):
        """Try to crack hash using a word list."""
        for word in words:
            computed = self._compute_hash(word, hash_type, hash_func)
            if computed and computed.lower() == target_hash.lower():
                return word
        return None

    def _generate_mutations(self, words):
        """Generate common password mutations."""
        mutated = []
        for word in words:
            mutated.append(word)
            mutated.append(word.capitalize())
            mutated.append(word.upper())
            mutated.append(word + "1")
            mutated.append(word + "123")
            mutated.append(word + "!")
            mutated.append(word + "@")
            mutated.append(word + "#")
            # Leet speak
            leet = word.replace("a", "@").replace("e", "3").replace("o", "0").replace("i", "1").replace("s", "$")
            mutated.append(leet)
            mutated.append(word[::-1])  # Reversed
            # Year suffixes
            for year in ["2023", "2024", "2025"]:
                mutated.append(word + year)
        return mutated

    def _brute_force(self, target_hash, hash_type, hash_func, max_len):
        """Brute force with increasing length."""
        charset = string.ascii_lowercase + string.digits
        for length in range(1, max_len + 1):
            for combo in itertools.product(charset, repeat=length):
                candidate = "".join(combo)
                computed = self._compute_hash(candidate, hash_type, hash_func)
                if computed and computed.lower() == target_hash.lower():
                    return candidate
        return None

    def _load_hashes(self, filepath):
        """Load hashes from file."""
        try:
            with open(filepath) as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"  [!] Hash file not found: {filepath}")
            return []

    def _load_wordlist(self, filepath):
        """Load wordlist file."""
        try:
            with open(filepath) as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"  [!] Wordlist not found: {filepath}")
            return []


if __name__ == "__main__":
    import sys
    cracker = HashCracker()
    if len(sys.argv) > 1:
        cracker.set_option("hash", sys.argv[1])
    else:
        # Demo: crack md5("password")
        cracker.set_option("hash", "5f4dcc3b5aa765d61d8327deb882cf99")
    result = cracker.execute()
    print(json.dumps(result, indent=2, default=str))
