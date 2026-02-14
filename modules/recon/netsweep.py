"""
NullSec Framework — Network Sweeper Module
Host discovery and network enumeration.
"""

import socket
import struct
import json
import time
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List
from ipaddress import IPv4Network, IPv4Address

try:
    from modules import BaseModule
except ImportError:
    from __init__ import BaseModule


class NetSweep(BaseModule):
    name = "netsweep"
    description = "Network host discovery and enumeration"
    category = "recon"
    version = "1.0.0"

    def validate(self) -> bool:
        target = self.get_option("target")
        if not target:
            print("[!] Target network required (e.g., 192.168.1.0/24)")
            return False
        return True

    def run(self, **kwargs) -> Dict:
        target = self.get_option("target", kwargs.get("target", ""))
        threads = int(self.get_option("threads", kwargs.get("threads", 50)))
        timeout = float(self.get_option("timeout", kwargs.get("timeout", 1.0)))
        method = self.get_option("method", kwargs.get("method", "tcp"))

        try:
            network = IPv4Network(target, strict=False)
        except ValueError:
            return {"error": f"Invalid network: {target}"}

        hosts = list(network.hosts())
        print(f"[*] Sweeping {target} — {len(hosts)} addresses")
        print(f"[*] Method: {method} | Threads: {threads}")

        alive = []
        start = time.time()

        with ThreadPoolExecutor(max_workers=threads) as executor:
            if method == "tcp":
                futures = {
                    executor.submit(self._tcp_ping, str(h), timeout): str(h)
                    for h in hosts
                }
            elif method == "arp":
                futures = {
                    executor.submit(self._arp_ping, str(h), timeout): str(h)
                    for h in hosts
                }
            else:
                futures = {
                    executor.submit(self._icmp_ping, str(h), timeout): str(h)
                    for h in hosts
                }

            for future in as_completed(futures):
                host = futures[future]
                result = future.result()
                if result:
                    alive.append(result)
                    hostname = self._reverse_lookup(host)
                    name_str = f" ({hostname})" if hostname else ""
                    print(f"  [+] {host}{name_str} — {result.get('method', 'unknown')}")

        elapsed = round(time.time() - start, 2)
        alive.sort(key=lambda x: IPv4Address(x["ip"]))

        print(f"\n[*] Sweep complete: {len(alive)}/{len(hosts)} hosts alive in {elapsed}s")

        return {
            "network": target,
            "total_hosts": len(hosts),
            "alive_hosts": len(alive),
            "hosts": alive,
            "scan_duration": elapsed,
        }

    def _tcp_ping(self, host, timeout):
        """TCP SYN check on common ports."""
        ports = [80, 443, 22, 445, 139, 3389]
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                if sock.connect_ex((host, port)) == 0:
                    sock.close()
                    return {"ip": host, "method": f"tcp/{port}", "port": port}
                sock.close()
            except (socket.error, OSError):
                continue
        return None

    def _icmp_ping(self, host, timeout):
        """ICMP ping using system ping command."""
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", str(int(timeout)), host],
                capture_output=True, timeout=timeout + 1
            )
            if result.returncode == 0:
                # Extract RTT
                output = result.stdout.decode()
                rtt = ""
                if "time=" in output:
                    rtt = output.split("time=")[1].split()[0]
                return {"ip": host, "method": "icmp", "rtt": rtt}
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return None

    def _arp_ping(self, host, timeout):
        """ARP-based discovery (requires arping or similar)."""
        try:
            result = subprocess.run(
                ["arping", "-c", "1", "-w", str(int(timeout)), host],
                capture_output=True, timeout=timeout + 1
            )
            if result.returncode == 0:
                output = result.stdout.decode()
                mac = ""
                if "[" in output:
                    mac = output.split("[")[1].split("]")[0]
                return {"ip": host, "method": "arp", "mac": mac}
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # Fall back to TCP
            return self._tcp_ping(host, timeout)
        return None

    def _reverse_lookup(self, ip):
        """Reverse DNS lookup."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return None


if __name__ == "__main__":
    import sys
    sweeper = NetSweep()
    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.0/24"
    sweeper.set_option("target", target)
    result = sweeper.execute()
    print(json.dumps(result, indent=2))
