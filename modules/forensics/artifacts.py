"""
NullSec Framework — Artifact Collector Module
Collect and catalog forensic artifacts from live or mounted systems.
"""

import os
import re
import json
import hashlib
import stat
from datetime import datetime
from typing import Dict, List

try:
    from modules import BaseModule
except ImportError:
    from __init__ import BaseModule


class ArtifactCollector(BaseModule):
    name = "artifacts"
    description = "Forensic artifact collection — users, processes, configs, persistence, and timeline"
    category = "forensics"
    version = "1.0.0"

    # Artifact categories and their file locations
    ARTIFACT_MAP = {
        "users": {
            "files": ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers"],
            "dirs": ["/home", "/root"],
        },
        "network": {
            "files": [
                "/etc/hosts", "/etc/resolv.conf", "/etc/hostname",
                "/etc/network/interfaces", "/etc/sysconfig/network-scripts",
                "/etc/iptables/rules.v4", "/etc/iptables/rules.v6",
            ],
            "proc": ["/proc/net/tcp", "/proc/net/udp", "/proc/net/arp"],
        },
        "persistence": {
            "dirs": [
                "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
                "/etc/cron.weekly", "/etc/cron.monthly",
                "/etc/systemd/system", "/etc/init.d",
                "/var/spool/cron/crontabs",
            ],
            "files": [
                "/etc/crontab", "/etc/rc.local",
                "/etc/profile", "/etc/bash.bashrc",
            ],
        },
        "ssh": {
            "files": ["/etc/ssh/sshd_config"],
            "user_files": [
                ".ssh/authorized_keys", ".ssh/known_hosts",
                ".ssh/config", ".ssh/id_rsa", ".ssh/id_rsa.pub",
                ".ssh/id_ed25519", ".ssh/id_ed25519.pub",
            ],
        },
        "shell_history": {
            "user_files": [
                ".bash_history", ".zsh_history", ".ash_history",
                ".python_history", ".mysql_history", ".psql_history",
            ],
        },
        "system": {
            "files": [
                "/etc/os-release", "/etc/hostname", "/etc/machine-id",
                "/proc/version", "/proc/cmdline", "/proc/cpuinfo",
                "/proc/meminfo", "/proc/uptime",
            ],
        },
        "web_servers": {
            "dirs": [
                "/etc/nginx", "/etc/apache2", "/etc/httpd",
                "/var/www", "/var/log/nginx", "/var/log/apache2",
            ],
            "files": [
                "/etc/nginx/nginx.conf",
                "/etc/apache2/apache2.conf",
            ],
        },
        "suspicious": {
            "dirs": ["/tmp", "/var/tmp", "/dev/shm"],
            "patterns": {
                "hidden_files": r"^\.",
                "world_writable": None,
                "setuid": None,
                "recently_modified": None,
            },
        },
    }

    def validate(self) -> bool:
        return True

    def run(self, **kwargs) -> Dict:
        root_path = self.get_option("root", kwargs.get("root", "/"))
        categories = self.get_option("categories", kwargs.get("categories", "all"))
        output_dir = self.get_option("output", kwargs.get("output", ""))
        collect_hashes = self.get_option("hashes", kwargs.get("hashes", True))

        print(f"[*] Artifact Collector: root={root_path}")

        if categories == "all":
            cats = list(self.ARTIFACT_MAP.keys())
        else:
            cats = [c.strip() for c in categories.split(",")]

        print(f"  [+] Categories: {', '.join(cats)}")

        result = {
            "timestamp": datetime.utcnow().isoformat(),
            "root_path": root_path,
            "artifacts": {},
            "summary": {},
        }

        for cat in cats:
            if cat not in self.ARTIFACT_MAP:
                print(f"  [!] Unknown category: {cat}")
                continue

            print(f"\n  [*] Collecting: {cat}")
            config = self.ARTIFACT_MAP[cat]
            artifacts = []

            # Collect specific files
            for filepath in config.get("files", []):
                full_path = os.path.join(root_path, filepath.lstrip("/"))
                artifact = self._collect_file(full_path, collect_hashes)
                if artifact:
                    artifacts.append(artifact)
                    print(f"    [+] {filepath}")

            # Collect proc entries
            for filepath in config.get("proc", []):
                artifact = self._collect_proc(filepath)
                if artifact:
                    artifacts.append(artifact)
                    print(f"    [+] {filepath}")

            # Scan directories
            for dirpath in config.get("dirs", []):
                full_dir = os.path.join(root_path, dirpath.lstrip("/"))
                dir_artifacts = self._scan_directory(full_dir, collect_hashes)
                artifacts.extend(dir_artifacts)
                if dir_artifacts:
                    print(f"    [+] {dirpath}: {len(dir_artifacts)} items")

            # Per-user files
            for user_file in config.get("user_files", []):
                user_artifacts = self._collect_user_files(
                    root_path, user_file, collect_hashes
                )
                artifacts.extend(user_artifacts)
                for a in user_artifacts:
                    print(f"    [+] {a['path']}")

            # Special: suspicious file detection
            if cat == "suspicious":
                suspicious = self._find_suspicious(root_path)
                artifacts.extend(suspicious)
                if suspicious:
                    print(f"    [!] {len(suspicious)} suspicious items found")

            result["artifacts"][cat] = artifacts
            result["summary"][cat] = len(artifacts)

        # SUID/SGID binary scan
        if "suspicious" in cats:
            print(f"\n  [*] Scanning for SUID/SGID binaries...")
            suid_bins = self._find_suid(root_path)
            result["artifacts"].setdefault("suid_binaries", suid_bins)
            result["summary"]["suid_binaries"] = len(suid_bins)
            print(f"    [+] Found {len(suid_bins)} SUID/SGID binaries")

        total = sum(result["summary"].values())
        print(f"\n[*] Collection complete: {total} artifacts across {len(cats)} categories")

        # Save output if requested
        if output_dir:
            self._save_report(result, output_dir)

        return result

    def _collect_file(self, filepath, collect_hashes=True):
        """Collect metadata and optionally content of a file."""
        try:
            st = os.stat(filepath)
            artifact = {
                "path": filepath,
                "type": "file",
                "size": st.st_size,
                "mode": oct(st.st_mode),
                "uid": st.st_uid,
                "gid": st.st_gid,
                "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(),
                "atime": datetime.fromtimestamp(st.st_atime).isoformat(),
                "ctime": datetime.fromtimestamp(st.st_ctime).isoformat(),
            }

            if collect_hashes and st.st_size < 10 * 1024 * 1024:  # < 10MB
                try:
                    with open(filepath, "rb") as f:
                        data = f.read()
                    artifact["md5"] = hashlib.md5(data).hexdigest()
                    artifact["sha256"] = hashlib.sha256(data).hexdigest()
                except PermissionError:
                    artifact["hash_error"] = "permission denied"

            # Read small config files
            if st.st_size < 65536:
                try:
                    with open(filepath, "r", errors="replace") as f:
                        artifact["content_preview"] = f.read(4096)
                except PermissionError:
                    pass

            return artifact
        except (FileNotFoundError, PermissionError, OSError):
            return None

    def _collect_proc(self, filepath):
        """Collect /proc pseudo-filesystem entries."""
        try:
            with open(filepath, "r") as f:
                content = f.read(8192)
            return {
                "path": filepath,
                "type": "proc",
                "content": content,
            }
        except (FileNotFoundError, PermissionError, OSError):
            return None

    def _scan_directory(self, dirpath, collect_hashes=True, max_files=100):
        """Scan a directory for artifacts."""
        artifacts = []
        try:
            if not os.path.isdir(dirpath):
                return artifacts
            for entry in sorted(os.listdir(dirpath))[:max_files]:
                full = os.path.join(dirpath, entry)
                if os.path.isfile(full):
                    art = self._collect_file(full, collect_hashes)
                    if art:
                        artifacts.append(art)
                elif os.path.isdir(full):
                    artifacts.append({
                        "path": full,
                        "type": "directory",
                    })
        except PermissionError:
            pass
        return artifacts

    def _collect_user_files(self, root_path, filename, collect_hashes):
        """Collect a specific file from all user home directories."""
        artifacts = []
        homes_dir = os.path.join(root_path, "home")
        try:
            if os.path.isdir(homes_dir):
                for user in os.listdir(homes_dir):
                    filepath = os.path.join(homes_dir, user, filename)
                    art = self._collect_file(filepath, collect_hashes)
                    if art:
                        art["user"] = user
                        artifacts.append(art)

            # Also check root
            root_file = os.path.join(root_path, "root", filename)
            art = self._collect_file(root_file, collect_hashes)
            if art:
                art["user"] = "root"
                artifacts.append(art)
        except PermissionError:
            pass
        return artifacts

    def _find_suspicious(self, root_path):
        """Find suspicious files in common temp directories."""
        suspicious = []
        temp_dirs = ["/tmp", "/var/tmp", "/dev/shm"]

        for tmp_dir in temp_dirs:
            full_dir = os.path.join(root_path, tmp_dir.lstrip("/"))
            try:
                if not os.path.isdir(full_dir):
                    continue
                for entry in os.listdir(full_dir):
                    full = os.path.join(full_dir, entry)
                    try:
                        st = os.stat(full)
                        reasons = []

                        # Hidden files
                        if entry.startswith("."):
                            reasons.append("hidden")

                        # Executable in temp
                        if os.path.isfile(full) and st.st_mode & stat.S_IXUSR:
                            reasons.append("executable")

                        # World-writable
                        if st.st_mode & stat.S_IWOTH:
                            reasons.append("world-writable")

                        # Recently modified (last 24h)
                        age = datetime.now().timestamp() - st.st_mtime
                        if age < 86400:
                            reasons.append("recent")

                        if reasons:
                            suspicious.append({
                                "path": full,
                                "type": "suspicious",
                                "reasons": reasons,
                                "size": st.st_size,
                                "mode": oct(st.st_mode),
                                "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(),
                            })
                    except (PermissionError, OSError):
                        pass
            except PermissionError:
                pass

        return suspicious

    def _find_suid(self, root_path, max_results=100):
        """Find SUID/SGID binaries."""
        suid_bins = []
        search_dirs = ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"]

        for search_dir in search_dirs:
            full_dir = os.path.join(root_path, search_dir.lstrip("/"))
            try:
                if not os.path.isdir(full_dir):
                    continue
                for entry in os.listdir(full_dir):
                    if len(suid_bins) >= max_results:
                        break
                    full = os.path.join(full_dir, entry)
                    try:
                        st = os.stat(full)
                        if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                            suid_bins.append({
                                "path": full,
                                "mode": oct(st.st_mode),
                                "uid": st.st_uid,
                                "gid": st.st_gid,
                                "suid": bool(st.st_mode & stat.S_ISUID),
                                "sgid": bool(st.st_mode & stat.S_ISGID),
                            })
                    except (PermissionError, OSError):
                        pass
            except PermissionError:
                pass

        return suid_bins

    def _save_report(self, result, output_dir):
        """Save artifact report to file."""
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(output_dir, f"artifacts_{timestamp}.json")
        with open(filepath, "w") as f:
            json.dump(result, f, indent=2, default=str)
        print(f"\n  [+] Report saved: {filepath}")


if __name__ == "__main__":
    import sys
    collector = ArtifactCollector()
    if len(sys.argv) > 1:
        collector.set_option("root", sys.argv[1])
    result = collector.execute()
    print(json.dumps({"summary": result["summary"]}, indent=2))
