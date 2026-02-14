"""
NullSec Framework — Port Scanner Module
Fast async-style port scanning with service detection.
"""

import socket
import json
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

try:
    from modules import BaseModule
except ImportError:
    from __init__ import BaseModule


class PortScanner(BaseModule):
    name = "portscan"
    description = "Fast multi-threaded port scanner with service detection"
    category = "recon"
    version = "1.0.0"

    # Common port/service mappings
    SERVICE_MAP = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
        143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
        1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
        8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
    }

    # Scan profiles
    PROFILES = {
        "quick": [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995,
                  3306, 3389, 5432, 8080, 8443],
        "common": list(range(1, 1025)),
        "full": list(range(1, 65536)),
        "web": [80, 443, 8080, 8443, 8000, 8888, 9090, 3000, 5000],
        "database": [1433, 1521, 3306, 5432, 6379, 9200, 27017, 5984,
                     7474, 8529, 9042, 28015],
    }

    def validate(self) -> bool:
        target = self.get_option("target")
        if not target:
            print("[!] Target is required. Set with: set target <ip>")
            return False
        return True

    def run(self, **kwargs) -> Dict:
        target = self.get_option("target", kwargs.get("target", ""))
        profile = self.get_option("profile", kwargs.get("profile", "quick"))
        timeout = float(self.get_option("timeout", kwargs.get("timeout", 1.0)))
        threads = int(self.get_option("threads", kwargs.get("threads", 100)))
        banner = self.get_option("banner", kwargs.get("banner", False))

        ports = self.PROFILES.get(profile, self.PROFILES["quick"])
        if isinstance(self.get_option("ports"), str):
            ports = [int(p) for p in self.get_option("ports").split(",")]

        print(f"[*] Scanning {target} — {len(ports)} ports ({profile} profile)")
        print(f"[*] Threads: {threads} | Timeout: {timeout}s | Banner grab: {banner}")

        open_ports = []
        start = time.time()

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(self._scan_port, target, port, timeout, banner): port
                for port in ports
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
                    service = result.get("service", "unknown")
                    banner_str = f" — {result['banner'][:60]}" if result.get("banner") else ""
                    print(f"  [+] {result['port']}/tcp open  {service}{banner_str}")

        elapsed = round(time.time() - start, 2)
        open_ports.sort(key=lambda x: x["port"])

        print(f"\n[*] Scan complete: {len(open_ports)} open ports in {elapsed}s")

        return {
            "target": target,
            "profile": profile,
            "total_ports_scanned": len(ports),
            "open_ports": open_ports,
            "open_count": len(open_ports),
            "scan_duration": elapsed,
        }

    def _scan_port(self, host, port, timeout, grab_banner):
        """Scan a single port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                entry = {
                    "port": port,
                    "state": "open",
                    "service": self.SERVICE_MAP.get(port, "unknown"),
                }
                if grab_banner:
                    entry["banner"] = self._grab_banner(sock, host, port)
                sock.close()
                return entry
            sock.close()
        except (socket.error, OSError):
            pass
        return None

    def _grab_banner(self, sock, host, port):
        """Attempt to grab service banner."""
        try:
            if port in (80, 8080, 8443, 443):
                sock.send(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
            elif port == 22:
                pass  # SSH sends banner automatically
            else:
                sock.send(b"\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            return banner[:256]
        except (socket.error, OSError):
            return ""


if __name__ == "__main__":
    import sys
    scanner = PortScanner()
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    profile = sys.argv[2] if len(sys.argv) > 2 else "quick"
    scanner.set_option("target", target)
    scanner.set_option("profile", profile)
    scanner.set_option("banner", True)
    result = scanner.execute()
    print(json.dumps(result, indent=2))
