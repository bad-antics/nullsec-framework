"""
NullSec Framework — Directory Brute-Forcer Module
Discover hidden directories and files on web servers.
"""

import ssl
import socket
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from datetime import datetime
from typing import Dict, List

try:
    from modules import BaseModule
except ImportError:
    from __init__ import BaseModule


class DirBrute(BaseModule):
    name = "dirbrute"
    description = "Web directory and file brute-forcer with built-in wordlist"
    category = "web"
    version = "1.0.0"

    # Built-in common paths wordlist
    COMMON_PATHS = [
        # Admin panels
        "admin", "administrator", "admin.php", "admin.html", "admin/login",
        "wp-admin", "wp-login.php", "cpanel", "webmail", "phpmyadmin",
        "adminer", "adminer.php", "manager", "manage", "dashboard",
        # Config / sensitive
        ".env", ".git", ".git/config", ".git/HEAD", ".svn",
        ".htaccess", ".htpasswd", "web.config", "robots.txt", "sitemap.xml",
        "crossdomain.xml", "security.txt", ".well-known/security.txt",
        "config.php", "config.yml", "config.json", "settings.php",
        "wp-config.php", "wp-config.php.bak", "wp-config.php.old",
        "database.yml", ".env.local", ".env.production", ".env.bak",
        # Backup files
        "backup", "backup.sql", "backup.zip", "backup.tar.gz",
        "db.sql", "dump.sql", "database.sql", "data.sql",
        "site.tar.gz", "www.zip", "public.zip",
        # API endpoints
        "api", "api/v1", "api/v2", "api/swagger", "api/docs",
        "swagger", "swagger-ui", "swagger.json", "openapi.json",
        "graphql", "graphiql", "playground",
        # Development
        "test", "testing", "dev", "development", "staging",
        "debug", "console", "shell", "phpinfo.php", "info.php",
        "server-status", "server-info", "status", "health", "healthcheck",
        # CMS
        "wp-content", "wp-includes", "wp-json",
        "sites/default", "modules", "themes", "plugins",
        "vendor", "node_modules", "bower_components",
        # Auth
        "login", "signin", "signup", "register", "logout",
        "auth", "oauth", "sso", "forgot-password", "reset-password",
        # Common dirs
        "uploads", "upload", "files", "media", "images", "img",
        "assets", "static", "public", "private", "tmp", "temp",
        "cache", "logs", "log", "error_log", "access.log",
        "include", "includes", "inc", "lib", "src",
        "cgi-bin", "scripts", "js", "css", "fonts",
    ]

    # File extensions to append
    EXTENSIONS = ["", ".php", ".html", ".asp", ".aspx", ".jsp", ".txt", ".bak", ".old"]

    def validate(self) -> bool:
        url = self.get_option("url")
        if not url:
            print("[!] Target URL is required")
            return False
        return True

    def run(self, **kwargs) -> Dict:
        url = self.get_option("url", kwargs.get("url", "")).rstrip("/")
        threads = int(self.get_option("threads", kwargs.get("threads", 10)))
        timeout = int(self.get_option("timeout", kwargs.get("timeout", 5)))
        wordlist = self.get_option("wordlist", kwargs.get("wordlist", ""))
        extensions = self.get_option("extensions", kwargs.get("extensions", ""))
        show_codes = self.get_option("show_codes", kwargs.get("show_codes", "200,301,302,403"))

        print(f"[*] Directory Brute-Force: {url}")

        # Build path list
        if wordlist:
            paths = self._load_wordlist(wordlist)
        else:
            paths = self.COMMON_PATHS

        # Extension handling
        if extensions:
            exts = extensions.split(",")
        else:
            exts = [""]  # No extension by default for speed

        # Valid status codes
        valid_codes = [int(c.strip()) for c in show_codes.split(",")]

        # Build full URL list
        targets = []
        for path in paths:
            for ext in exts:
                full_path = f"{path}{ext}" if ext and "." not in path else path
                targets.append(f"{url}/{full_path}")

        print(f"  [+] Testing {len(targets)} paths with {threads} threads")

        result = {
            "url": url,
            "timestamp": datetime.utcnow().isoformat(),
            "total_tested": len(targets),
            "found": [],
        }

        found = []
        tested = 0

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(self._check_url, t, timeout): t
                for t in targets
            }

            for future in as_completed(futures):
                tested += 1
                if tested % 50 == 0:
                    print(f"  [*] Progress: {tested}/{len(targets)}", end="\r")

                try:
                    code, size, redirect = future.result()
                    if code and code in valid_codes:
                        path = futures[future].replace(url, "")
                        entry = {
                            "path": path,
                            "status": code,
                            "size": size,
                        }
                        if redirect:
                            entry["redirect"] = redirect
                        found.append(entry)

                        status_icon = {
                            200: "✓",
                            301: "→",
                            302: "→",
                            403: "✗",
                        }.get(code, "?")

                        redir_note = f" → {redirect}" if redirect else ""
                        print(f"  [{status_icon}] {code} | {size:>6}B | {path}{redir_note}")
                except Exception:
                    pass

        # Sort by status code
        found.sort(key=lambda x: (x["status"], x["path"]))
        result["found"] = found

        print(f"\n[*] Scan complete: {len(found)} paths discovered")

        # Categorize findings
        by_status = {}
        for f in found:
            by_status.setdefault(f["status"], []).append(f["path"])
        for code, paths in sorted(by_status.items()):
            print(f"    {code}: {len(paths)} paths")

        return result

    def _check_url(self, url, timeout):
        """Check if a URL exists. Returns (status_code, content_length, redirect_url)."""
        try:
            req = Request(url, method="HEAD", headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) NullSec/1.0",
            })
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            resp = urlopen(req, timeout=timeout, context=ctx)
            size = int(resp.headers.get("Content-Length", 0))
            redirect = resp.url if resp.url != url else None
            return resp.status, size, redirect
        except HTTPError as e:
            size = int(e.headers.get("Content-Length", 0)) if e.headers else 0
            return e.code, size, None
        except (URLError, socket.timeout, OSError):
            return None, 0, None

    def _load_wordlist(self, filepath):
        """Load paths from a wordlist file."""
        try:
            with open(filepath) as f:
                return [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            print(f"  [!] Wordlist not found: {filepath}")
            return self.COMMON_PATHS


if __name__ == "__main__":
    import sys
    bruter = DirBrute()
    url = sys.argv[1] if len(sys.argv) > 1 else "http://example.com"
    bruter.set_option("url", url)
    result = bruter.execute()
    print(json.dumps(result, indent=2, default=str))
