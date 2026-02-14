"""
NullSec Framework — Cipher Analyzer Module
Analyze and identify encryption ciphers, encoding schemes, and cryptographic weaknesses.
"""

import re
import json
import base64
import binascii
import math
from collections import Counter
from datetime import datetime
from typing import Dict, List, Optional

try:
    from modules import BaseModule
except ImportError:
    from __init__ import BaseModule


class CipherAnalyzer(BaseModule):
    name = "cipheranalyzer"
    description = "Cipher identification, encoding detection, and cryptographic weakness analysis"
    category = "crypto"
    version = "1.0.0"

    # Encoding detection patterns
    ENCODING_TESTS = [
        ("Base64", r'^[A-Za-z0-9+/]+=*$', lambda x: base64.b64decode(x)),
        ("Base64URL", r'^[A-Za-z0-9_-]+=*$', lambda x: base64.urlsafe_b64decode(x + "==")),
        ("Hex", r'^[0-9a-fA-F]+$', lambda x: binascii.unhexlify(x)),
        ("Base32", r'^[A-Z2-7]+=*$', lambda x: base64.b32decode(x)),
    ]

    # Known cipher characteristics
    CIPHER_PROFILES = {
        "AES-CBC": {
            "block_size": 16,
            "indicators": ["high entropy", "length multiple of 16"],
        },
        "AES-GCM": {
            "block_size": 16,
            "indicators": ["high entropy", "12-byte nonce prefix"],
        },
        "DES": {
            "block_size": 8,
            "indicators": ["length multiple of 8", "moderate entropy"],
        },
        "3DES": {
            "block_size": 8,
            "indicators": ["length multiple of 8", "high entropy"],
        },
        "RSA": {
            "indicators": ["very long", "high entropy", "starts with ASN.1"],
        },
        "ChaCha20": {
            "indicators": ["high entropy", "no block alignment"],
        },
        "RC4": {
            "indicators": ["high entropy", "no block alignment", "variable length"],
        },
        "XOR": {
            "indicators": ["low entropy", "repeating patterns"],
        },
        "ROT13": {
            "indicators": ["ascii range", "letter frequency anomaly"],
        },
        "Caesar": {
            "indicators": ["ascii range", "shifted frequency distribution"],
        },
    }

    # English letter frequency (for substitution cipher detection)
    ENGLISH_FREQ = {
        'e': 0.127, 't': 0.091, 'a': 0.082, 'o': 0.075, 'i': 0.070,
        'n': 0.067, 's': 0.063, 'h': 0.061, 'r': 0.060, 'd': 0.043,
        'l': 0.040, 'c': 0.028, 'u': 0.028, 'm': 0.024, 'w': 0.024,
        'f': 0.022, 'g': 0.020, 'y': 0.020, 'p': 0.019, 'b': 0.015,
        'v': 0.010, 'k': 0.008, 'j': 0.002, 'x': 0.002, 'q': 0.001,
        'z': 0.001,
    }

    def validate(self) -> bool:
        data = self.get_option("data")
        datafile = self.get_option("datafile")
        if not data and not datafile:
            print("[!] Either data or datafile is required")
            return False
        return True

    def run(self, **kwargs) -> Dict:
        data = self.get_option("data", kwargs.get("data", ""))
        datafile = self.get_option("datafile", kwargs.get("datafile", ""))

        if datafile:
            data = self._read_file(datafile)

        if not data:
            return {"error": "No data to analyze"}

        print(f"[*] Cipher Analyzer: {len(data)} bytes")

        result = {
            "timestamp": datetime.utcnow().isoformat(),
            "input_length": len(data),
            "analysis": {},
        }

        # 1. Encoding detection
        print("\n  [*] Encoding Detection:")
        encodings = self._detect_encoding(data)
        result["analysis"]["encodings"] = encodings
        for enc in encodings:
            print(f"    [+] {enc['type']}: confidence {enc['confidence']:.0%}")
            if enc.get("decoded_preview"):
                print(f"        Preview: {enc['decoded_preview'][:60]}")

        # 2. Entropy analysis
        print("\n  [*] Entropy Analysis:")
        entropy = self._calculate_entropy(data.encode() if isinstance(data, str) else data)
        result["analysis"]["entropy"] = entropy
        print(f"    [+] Shannon entropy: {entropy['shannon']:.4f} bits/byte")
        print(f"    [+] Classification: {entropy['classification']}")
        print(f"    [+] Randomness: {entropy['randomness']:.1%}")

        # 3. Block alignment
        print("\n  [*] Block Analysis:")
        block_info = self._analyze_blocks(data)
        result["analysis"]["blocks"] = block_info
        for bs, aligned in block_info.items():
            if aligned:
                print(f"    [+] Aligned to {bs}-byte blocks")

        # 4. Pattern detection
        print("\n  [*] Pattern Detection:")
        patterns = self._detect_patterns(data)
        result["analysis"]["patterns"] = patterns
        for p in patterns:
            print(f"    [+] {p}")

        # 5. Cipher identification
        print("\n  [*] Cipher Identification:")
        candidates = self._identify_cipher(data, entropy, block_info, patterns)
        result["analysis"]["cipher_candidates"] = candidates
        for c in candidates:
            print(f"    [+] {c['cipher']}: {c['confidence']:.0%} ({c['reason']})")

        # 6. Substitution cipher analysis
        if entropy["classification"] in ("text-like", "low"):
            print("\n  [*] Substitution Cipher Analysis:")
            sub_analysis = self._analyze_substitution(data)
            result["analysis"]["substitution"] = sub_analysis
            if sub_analysis.get("rot13_candidate"):
                print(f"    [+] ROT13 decode: {sub_analysis['rot13_result'][:60]}")
            if sub_analysis.get("caesar_shift"):
                print(f"    [+] Caesar shift {sub_analysis['caesar_shift']}: {sub_analysis['caesar_result'][:60]}")

        # 7. XOR analysis
        if len(data) < 10000:
            print("\n  [*] XOR Key Analysis:")
            xor_results = self._analyze_xor(data.encode() if isinstance(data, str) else data)
            result["analysis"]["xor"] = xor_results
            if xor_results.get("likely_key"):
                print(f"    [+] Likely single-byte key: 0x{xor_results['likely_key']:02x}")

        # 8. Weakness assessment
        print("\n  [*] Weakness Assessment:")
        weaknesses = self._assess_weaknesses(data, entropy, block_info)
        result["analysis"]["weaknesses"] = weaknesses
        for w in weaknesses:
            print(f"    [!] {w['severity'].upper()}: {w['description']}")

        return result

    def _detect_encoding(self, data):
        """Detect encoding type of the data."""
        results = []
        for name, pattern, decoder in self.ENCODING_TESTS:
            if re.match(pattern, data.strip()):
                try:
                    decoded = decoder(data.strip())
                    decoded_str = decoded.decode("utf-8", errors="replace")
                    printable_ratio = sum(1 for c in decoded_str if c.isprintable()) / max(len(decoded_str), 1)
                    confidence = min(0.5 + printable_ratio * 0.5, 0.99)
                    results.append({
                        "type": name,
                        "confidence": confidence,
                        "decoded_preview": decoded_str[:100] if printable_ratio > 0.5 else None,
                        "decoded_length": len(decoded),
                    })
                except Exception:
                    pass
        return sorted(results, key=lambda x: x["confidence"], reverse=True)

    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of the data."""
        if not data:
            return {"shannon": 0, "classification": "empty", "randomness": 0}

        freq = Counter(data)
        length = len(data)
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )

        max_entropy = 8.0  # bits per byte
        randomness = entropy / max_entropy

        if entropy < 3.0:
            classification = "low"
        elif entropy < 5.0:
            classification = "text-like"
        elif entropy < 7.0:
            classification = "compressed-or-encrypted"
        elif entropy < 7.9:
            classification = "high"
        else:
            classification = "near-random"

        return {
            "shannon": round(entropy, 4),
            "max": max_entropy,
            "randomness": round(randomness, 4),
            "classification": classification,
            "unique_bytes": len(freq),
        }

    def _analyze_blocks(self, data):
        """Check if data length aligns with common block sizes."""
        raw = data.encode() if isinstance(data, str) else data
        length = len(raw)
        return {
            "8": length % 8 == 0,
            "16": length % 16 == 0,
            "32": length % 32 == 0,
            "64": length % 64 == 0,
        }

    def _detect_patterns(self, data):
        """Detect repeating patterns in the data."""
        patterns = []
        raw = data.encode() if isinstance(data, str) else data

        # Check for repeating blocks
        for bs in [8, 16]:
            blocks = [raw[i:i+bs] for i in range(0, len(raw) - bs + 1, bs)]
            if len(blocks) > 1:
                block_counts = Counter(tuple(b) for b in blocks)
                repeated = {k: v for k, v in block_counts.items() if v > 1}
                if repeated:
                    patterns.append(f"Repeating {bs}-byte blocks found ({len(repeated)} unique)")

        # Check for null bytes
        null_count = raw.count(b'\x00') if isinstance(raw, bytes) else data.count('\x00')
        if null_count > len(raw) * 0.1:
            patterns.append(f"High null byte ratio ({null_count/len(raw):.1%})")

        # Check for ASCII-only
        if isinstance(data, str) and all(32 <= ord(c) <= 126 for c in data):
            patterns.append("ASCII printable only")

        return patterns

    def _identify_cipher(self, data, entropy, blocks, patterns):
        """Identify likely cipher based on analysis."""
        candidates = []
        raw = data.encode() if isinstance(data, str) else data

        if entropy["classification"] in ("high", "near-random"):
            if blocks["16"]:
                candidates.append({
                    "cipher": "AES-CBC/ECB",
                    "confidence": 0.6,
                    "reason": "High entropy + 16-byte block alignment",
                })
            if blocks["8"] and not blocks["16"]:
                candidates.append({
                    "cipher": "DES/3DES",
                    "confidence": 0.5,
                    "reason": "High entropy + 8-byte block alignment",
                })
            if not blocks["8"] and not blocks["16"]:
                candidates.append({
                    "cipher": "ChaCha20/RC4 (stream)",
                    "confidence": 0.4,
                    "reason": "High entropy + no block alignment",
                })

        if entropy["classification"] in ("low", "text-like"):
            candidates.append({
                "cipher": "XOR/Caesar/ROT13",
                "confidence": 0.5,
                "reason": "Low entropy suggests simple substitution",
            })

        if any("Repeating" in p for p in patterns):
            candidates.append({
                "cipher": "ECB mode (weak)",
                "confidence": 0.7,
                "reason": "Repeating ciphertext blocks indicate ECB",
            })

        if len(raw) > 256 and entropy["classification"] == "near-random":
            candidates.append({
                "cipher": "RSA",
                "confidence": 0.3,
                "reason": "Large high-entropy block",
            })

        return sorted(candidates, key=lambda x: x["confidence"], reverse=True)

    def _analyze_substitution(self, data):
        """Analyze for simple substitution ciphers."""
        result = {}

        # ROT13
        rot13 = data.translate(str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
        ))
        # Check if ROT13 produces more English-like text
        rot13_score = self._english_score(rot13)
        orig_score = self._english_score(data)
        if rot13_score > orig_score * 1.5:
            result["rot13_candidate"] = True
            result["rot13_result"] = rot13

        # Caesar cipher: try all shifts
        best_shift = 0
        best_score = orig_score
        best_result = data

        for shift in range(1, 26):
            shifted = ""
            for c in data:
                if c.isalpha():
                    base = ord('A') if c.isupper() else ord('a')
                    shifted += chr((ord(c) - base + shift) % 26 + base)
                else:
                    shifted += c
            score = self._english_score(shifted)
            if score > best_score:
                best_score = score
                best_shift = shift
                best_result = shifted

        if best_shift > 0 and best_score > orig_score * 1.5:
            result["caesar_shift"] = best_shift
            result["caesar_result"] = best_result

        return result

    def _english_score(self, text):
        """Score text based on English letter frequency similarity."""
        text_lower = text.lower()
        total = sum(1 for c in text_lower if c.isalpha())
        if total == 0:
            return 0

        freq = Counter(c for c in text_lower if c.isalpha())
        score = sum(
            abs(freq.get(letter, 0) / total - expected)
            for letter, expected in self.ENGLISH_FREQ.items()
        )
        return 1.0 / (1.0 + score)

    def _analyze_xor(self, data):
        """Analyze for single-byte XOR encryption."""
        best_key = 0
        best_score = 0

        for key in range(256):
            decoded = bytes(b ^ key for b in data[:200])
            try:
                text = decoded.decode("utf-8", errors="replace")
                score = self._english_score(text)
                if score > best_score:
                    best_score = score
                    best_key = key
            except Exception:
                pass

        if best_score > 0.5:
            return {"likely_key": best_key, "confidence": best_score}
        return {}

    def _assess_weaknesses(self, data, entropy, blocks):
        """Assess cryptographic weaknesses."""
        weaknesses = []

        if any(blocks.get(str(bs)) for bs in [8, 16]) and entropy["classification"] == "high":
            # Check for ECB mode
            raw = data.encode() if isinstance(data, str) else data
            for bs in [16, 8]:
                chunk_blocks = [raw[i:i+bs] for i in range(0, len(raw), bs)]
                if len(chunk_blocks) != len(set(chunk_blocks)):
                    weaknesses.append({
                        "severity": "high",
                        "description": f"ECB mode detected — repeating {bs}-byte ciphertext blocks",
                    })

        if entropy["shannon"] < 3.0 and len(data) > 10:
            weaknesses.append({
                "severity": "high",
                "description": "Very low entropy — weak or no encryption",
            })

        if len(data) < 16:
            weaknesses.append({
                "severity": "medium",
                "description": "Short ciphertext — vulnerable to brute force",
            })

        if blocks.get("8") and not blocks.get("16"):
            weaknesses.append({
                "severity": "medium",
                "description": "8-byte block alignment suggests DES/3DES (deprecated)",
            })

        return weaknesses

    def _read_file(self, filepath):
        """Read data from file."""
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            try:
                return data.decode("utf-8")
            except UnicodeDecodeError:
                return data
        except FileNotFoundError:
            print(f"  [!] File not found: {filepath}")
            return None


if __name__ == "__main__":
    import sys
    analyzer = CipherAnalyzer()
    if len(sys.argv) > 1:
        analyzer.set_option("data", sys.argv[1])
    else:
        # Demo: analyze base64-encoded text
        analyzer.set_option("data", "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0Lg==")
    result = analyzer.execute()
    print(json.dumps(result, indent=2, default=str))
