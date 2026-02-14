"""
NullSec Framework — Log Analyzer Module
Parse, analyze, and detect suspicious patterns in system and application logs.
"""

import re
import os
import json
import gzip
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional

try:
    from modules import BaseModule
except ImportError:
    from __init__ import BaseModule


class LogAnalyzer(BaseModule):
    name = "loganalyzer"
    description = "Log file analysis with anomaly detection, pattern matching, and timeline reconstruction"
    category = "forensics"
    version = "1.0.0"

    # Suspicious patterns to detect
    SUSPICIOUS_PATTERNS = {
        "brute_force": {
            "patterns": [
                r"Failed password for .+ from (\S+)",
                r"authentication failure.*rhost=(\S+)",
                r"Invalid user .+ from (\S+)",
                r"FAILED LOGIN .+ FROM (\S+)",
            ],
            "severity": "high",
            "threshold": 5,
        },
        "privilege_escalation": {
            "patterns": [
                r"sudo:.+COMMAND=.*(\/bin\/sh|\/bin\/bash|su\s|passwd|chmod\s+[4267]|chown)",
                r"su\[\d+\]: .+ to root",
                r"COMMAND=.*(wget|curl|nc |ncat |netcat)",
            ],
            "severity": "high",
        },
        "web_attack": {
            "patterns": [
                r"(\.\./|\.\.\\)",
                r"(union\s+select|select\s+.*from|insert\s+into|drop\s+table)",
                r"(<script|javascript:|onerror=|onload=)",
                r"(/etc/passwd|/etc/shadow|/proc/self)",
                r"(cmd\.exe|powershell|command\.com)",
            ],
            "severity": "critical",
        },
        "port_scan": {
            "patterns": [
                r"Connection from (\S+) port \d+",
                r"SYN flood|port scan|scan detected",
            ],
            "severity": "medium",
        },
        "data_exfil": {
            "patterns": [
                r"(scp|rsync|curl\s+-T|wget\s+--post)",
                r"(base64|xxd|nc\s+-l)",
                r"(\.tar\.gz|\.zip|\.7z).*(?:upload|send|post)",
            ],
            "severity": "high",
        },
        "malware_indicators": {
            "patterns": [
                r"(/tmp/\.\w+|/dev/shm/\.\w+)",
                r"(chmod\s+777|chmod\s+\+x\s+/tmp)",
                r"(crontab|at\s+-f|systemctl\s+enable)",
                r"(reverse.shell|bind.shell|meterpreter)",
            ],
            "severity": "critical",
        },
    }

    # Common log timestamp formats
    TIMESTAMP_FORMATS = [
        (r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', "%Y-%m-%dT%H:%M:%S"),
        (r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', None),  # syslog: "Jan  1 00:00:00"
        (r'\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}', "%d/%b/%Y:%H:%M:%S"),  # Apache CLF
        (r'\d{10}\.\d+', None),  # Unix timestamp
    ]

    def validate(self) -> bool:
        logfile = self.get_option("logfile")
        logdir = self.get_option("logdir")
        if not logfile and not logdir:
            print("[!] Either logfile or logdir is required")
            return False
        return True

    def run(self, **kwargs) -> Dict:
        logfile = self.get_option("logfile", kwargs.get("logfile", ""))
        logdir = self.get_option("logdir", kwargs.get("logdir", ""))
        max_lines = int(self.get_option("max_lines", kwargs.get("max_lines", 100000)))

        result = {
            "timestamp": datetime.utcnow().isoformat(),
            "files_analyzed": [],
            "total_lines": 0,
            "alerts": [],
            "statistics": {},
            "timeline": [],
            "ip_activity": {},
        }

        # Collect log files
        files = []
        if logfile:
            files.append(logfile)
        if logdir:
            files.extend(self._find_logs(logdir))

        print(f"[*] Log Analyzer: {len(files)} file(s)")

        all_alerts = []
        ip_counter = Counter()
        hourly_activity = Counter()
        event_types = Counter()
        total_lines = 0

        for filepath in files:
            print(f"\n  [*] Analyzing: {filepath}")
            lines = self._read_log(filepath, max_lines)
            if not lines:
                continue

            total_lines += len(lines)
            result["files_analyzed"].append({
                "path": filepath,
                "lines": len(lines),
            })

            # Scan for suspicious patterns
            for category, config in self.SUSPICIOUS_PATTERNS.items():
                matches = []
                for i, line in enumerate(lines):
                    for pattern in config["patterns"]:
                        match = re.search(pattern, line, re.I)
                        if match:
                            ts = self._extract_timestamp(line)
                            matches.append({
                                "line_number": i + 1,
                                "content": line.strip()[:200],
                                "timestamp": ts,
                                "match": match.group(0)[:100],
                            })

                            # Track IPs
                            ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
                            if ip_match:
                                ip_counter[ip_match.group(1)] += 1

                            # Track hourly activity
                            if ts:
                                hour_key = ts[:13] if len(ts) >= 13 else ts
                                hourly_activity[hour_key] += 1

                            event_types[category] += 1
                            break

                if matches:
                    threshold = config.get("threshold", 1)
                    if len(matches) >= threshold:
                        alert = {
                            "file": filepath,
                            "category": category,
                            "severity": config["severity"],
                            "count": len(matches),
                            "samples": matches[:5],
                        }
                        all_alerts.append(alert)
                        sev = config["severity"].upper()
                        print(f"    [{sev}] {category}: {len(matches)} occurrences")

        # Compile results
        result["total_lines"] = total_lines
        result["alerts"] = sorted(all_alerts, key=lambda x: {
            "critical": 0, "high": 1, "medium": 2, "low": 3
        }.get(x["severity"], 4))

        # IP activity summary
        result["ip_activity"] = {
            "top_ips": dict(ip_counter.most_common(20)),
            "unique_ips": len(ip_counter),
        }

        # Event statistics
        result["statistics"] = {
            "event_types": dict(event_types),
            "total_alerts": len(all_alerts),
            "critical": len([a for a in all_alerts if a["severity"] == "critical"]),
            "high": len([a for a in all_alerts if a["severity"] == "high"]),
            "medium": len([a for a in all_alerts if a["severity"] == "medium"]),
        }

        # Timeline (hourly breakdown)
        result["timeline"] = dict(hourly_activity.most_common(48))

        # Print summary
        print(f"\n[*] Analysis Complete:")
        print(f"    Lines analyzed: {total_lines:,}")
        print(f"    Total alerts: {len(all_alerts)}")
        print(f"    Critical: {result['statistics']['critical']}")
        print(f"    High: {result['statistics']['high']}")
        print(f"    Unique IPs: {result['ip_activity']['unique_ips']}")

        if ip_counter:
            print(f"\n    Top IPs:")
            for ip, count in ip_counter.most_common(5):
                print(f"      {ip}: {count} events")

        return result

    def _find_logs(self, directory):
        """Find log files in a directory."""
        log_files = []
        log_patterns = [".log", ".log.1", ".log.gz", "syslog", "auth.log",
                       "access.log", "error.log", "messages", "secure"]
        try:
            for root, dirs, files in os.walk(directory):
                for f in files:
                    if any(f.endswith(p) or f == p for p in log_patterns):
                        log_files.append(os.path.join(root, f))
        except PermissionError:
            pass
        return sorted(log_files)

    def _read_log(self, filepath, max_lines):
        """Read log file, handling gzip."""
        try:
            if filepath.endswith(".gz"):
                with gzip.open(filepath, "rt", errors="replace") as f:
                    return [f.readline() for _ in range(max_lines) if f.readline()]
            else:
                with open(filepath, "r", errors="replace") as f:
                    lines = []
                    for i, line in enumerate(f):
                        if i >= max_lines:
                            break
                        lines.append(line)
                    return lines
        except (PermissionError, FileNotFoundError, OSError) as e:
            print(f"    [!] Cannot read: {e}")
            return []

    def _extract_timestamp(self, line):
        """Extract timestamp from a log line."""
        for pattern, fmt in self.TIMESTAMP_FORMATS:
            match = re.search(pattern, line)
            if match:
                return match.group(0)
        return None


if __name__ == "__main__":
    import sys
    analyzer = LogAnalyzer()
    if len(sys.argv) > 1:
        path = sys.argv[1]
        if os.path.isdir(path):
            analyzer.set_option("logdir", path)
        else:
            analyzer.set_option("logfile", path)
    else:
        analyzer.set_option("logdir", "/var/log")
    result = analyzer.execute()
    print(json.dumps(result, indent=2, default=str))
