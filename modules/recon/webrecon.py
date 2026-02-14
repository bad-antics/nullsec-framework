"""
NullSec Framework — Web Recon Module
Web application reconnaissance and fingerprinting.
"""

import json
import re
import ssl
import socket
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import urlparse
from datetime import datetime
from typing import Dict, List

try:
    from modules import BaseModule
except ImportError:
    from __init__ import BaseModule


class WebRecon(BaseModule):
    name = "webrecon"
    description = "Web application reconnaissance and technology fingerprinting"
    category = "recon"
    version = "1.0.0"

    # Technology signatures
    TECH_SIGNATURES = {
        # Server
        "Apache": {"header": "Server", "pattern": r"Apache"},
        "Nginx": {"header": "Server", "pattern": r"nginx"},
        "IIS": {"header": "Server", "pattern": r"Microsoft-IIS"},
        "Cloudflare": {"header": "Server", "pattern": r"cloudflare"},
        "LiteSpeed": {"header": "Server", "pattern": r"LiteSpeed"},

        # Frameworks
        "WordPress": {"body": r"wp-content|wp-includes|wordpress"},
        "Drupal": {"body": r"Drupal|drupal\.js|sites/default"},
        "Joomla": {"body": r"Joomla|/media/jui/"},
        "Django": {"header": "X-Frame-Options", "body": r"csrfmiddlewaretoken"},
        "Rails": {"header": "X-Powered-By", "pattern": r"Phusion Passenger"},
        "Laravel": {"body": r"laravel|Laravel"},
        "Express": {"header": "X-Powered-By", "pattern": r"Express"},
        "Next.js": {"body": r"__NEXT_DATA__|/_next/"},
        "React": {"body": r"react\.production|reactDOM|__REACT"},
        "Vue.js": {"body": r"Vue\.js|__vue__|v-cloak"},
        "Angular": {"body": r"ng-version|angular\.js|ng-app"},

        # CDN/Services
        "jQuery": {"body": r"jquery[\.-][\d]|jQuery"},
        "Bootstrap": {"body": r"bootstrap\.min|bootstrap\.css"},
        "Google Analytics": {"body": r"google-analytics\.com|gtag|ga\.js"},
        "Google Tag Manager": {"body": r"googletagmanager\.com"},
    }

    def validate(self) -> bool:
        url = self.get_option("url")
        if not url:
            print("[!] URL is required")
            return False
        return True

    def run(self, **kwargs) -> Dict:
        url = self.get_option("url", kwargs.get("url", ""))
        timeout = int(self.get_option("timeout", kwargs.get("timeout", 10)))

        print(f"[*] Reconnaissance: {url}")

        result = {
            "url": url,
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Fetch page
        headers_data, body, status = self._fetch(url, timeout)
        result["status_code"] = status

        if status == 0:
            result["error"] = "Connection failed"
            return result

        # Headers analysis
        result["headers"] = dict(headers_data)
        result["server"] = headers_data.get("Server", "Unknown")

        # Technology detection
        result["technologies"] = self._detect_technologies(headers_data, body)
        print(f"  [+] Technologies detected: {len(result['technologies'])}")
        for tech in result["technologies"]:
            print(f"      • {tech}")

        # Security headers
        result["security_headers"] = self._check_security_headers(headers_data)
        missing = [h for h, v in result["security_headers"].items() if not v["present"]]
        print(f"  [+] Security headers missing: {len(missing)}")

        # SSL/TLS info
        parsed = urlparse(url)
        if parsed.scheme == "https":
            result["ssl"] = self._check_ssl(parsed.hostname, 443)
            if result["ssl"].get("issuer"):
                print(f"  [+] SSL Issuer: {result['ssl']['issuer']}")

        # Meta information
        result["meta"] = self._extract_meta(body)

        # Interesting paths
        result["paths"] = self._extract_paths(body, url)
        print(f"  [+] Paths found: {len(result['paths'])}")

        # Email addresses
        result["emails"] = self._extract_emails(body)
        if result["emails"]:
            print(f"  [+] Emails found: {len(result['emails'])}")

        return result

    def _fetch(self, url, timeout):
        """Fetch URL content."""
        try:
            req = Request(url, headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Marshall/1.0",
                "Accept": "text/html,application/xhtml+xml",
            })
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            resp = urlopen(req, timeout=timeout, context=ctx)
            body = resp.read().decode("utf-8", errors="replace")
            return resp.headers, body, resp.status
        except HTTPError as e:
            return e.headers, "", e.code
        except (URLError, socket.timeout, OSError):
            return {}, "", 0

    def _detect_technologies(self, headers, body):
        """Detect technologies from headers and body."""
        detected = []
        for tech, sig in self.TECH_SIGNATURES.items():
            # Header-based detection
            if "header" in sig and "pattern" in sig:
                header_val = headers.get(sig["header"], "")
                if re.search(sig["pattern"], header_val, re.I):
                    detected.append(tech)
                    continue
            # Body-based detection
            if "body" in sig:
                if re.search(sig["body"], body, re.I):
                    detected.append(tech)
        return detected

    def _check_security_headers(self, headers):
        """Check for security-related HTTP headers."""
        checks = {
            "Content-Security-Policy": {"present": False, "value": ""},
            "X-Content-Type-Options": {"present": False, "value": ""},
            "X-Frame-Options": {"present": False, "value": ""},
            "Strict-Transport-Security": {"present": False, "value": ""},
            "X-XSS-Protection": {"present": False, "value": ""},
            "Referrer-Policy": {"present": False, "value": ""},
            "Permissions-Policy": {"present": False, "value": ""},
        }
        for header in checks:
            val = headers.get(header, "")
            if val:
                checks[header] = {"present": True, "value": val}
        return checks

    def _check_ssl(self, hostname, port):
        """Get SSL certificate information."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(5)
                s.connect((hostname, port))
                cert = s.getpeercert(binary_form=False) or {}
                return {
                    "subject": str(cert.get("subject", "")),
                    "issuer": str(cert.get("issuer", "")),
                    "notBefore": cert.get("notBefore", ""),
                    "notAfter": cert.get("notAfter", ""),
                    "version": s.version(),
                }
        except (ssl.SSLError, socket.error, OSError):
            return {"error": "SSL check failed"}

    def _extract_meta(self, body):
        """Extract meta tags."""
        meta = {}
        for match in re.finditer(r'<meta\s+([^>]+)>', body, re.I):
            attrs = match.group(1)
            name = re.search(r'name=["\']([^"\']+)["\']', attrs)
            content = re.search(r'content=["\']([^"\']+)["\']', attrs)
            if name and content:
                meta[name.group(1)] = content.group(1)
        title = re.search(r'<title>([^<]+)</title>', body, re.I)
        if title:
            meta["title"] = title.group(1).strip()
        return meta

    def _extract_paths(self, body, base_url):
        """Extract internal paths from the page."""
        paths = set()
        parsed = urlparse(base_url)
        for match in re.finditer(r'(?:href|src|action)=["\']([^"\'#]+)["\']', body, re.I):
            path = match.group(1)
            if path.startswith("/") or path.startswith(base_url):
                paths.add(path)
            elif not path.startswith("http") and not path.startswith("//"):
                paths.add("/" + path)
        return sorted(paths)[:100]

    def _extract_emails(self, body):
        """Extract email addresses from page content."""
        emails = set(re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', body))
        return sorted(emails)[:20]


if __name__ == "__main__":
    import sys
    recon = WebRecon()
    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    recon.set_option("url", url)
    result = recon.execute()
    print(json.dumps(result, indent=2, default=str))
