# NullSec Framework

```
    ███▄    █  █    ██  ██▓     ██▓      ██████ ▓█████  ▄████▄  
    ██ ▀█   █  ██  ▓██▒▓██▒    ▓██▒    ▒██    ▒ ▓█   ▀ ▒██▀ ▀█  
   ▓██  ▀█ ██▒▓██  ▒██░▒██░    ▒██░    ░ ▓██▄   ▒███   ▒▓█    ▄ 
   ▓██▒  ▐▌██▒▓▓█  ░██░▒██░    ▒██░      ▒   ██▒▒▓█  ▄ ▒▓▓▄ ▄██▒
   ▒██░   ▓██░▒▒█████▓ ░██████▒░██████▒▒██████▒▒░▒████▒▒ ▓███▀ ░
   ░ ▒░   ▒ ▒ ░▒▓▒ ▒ ▒ ░ ▒░▓  ░░ ▒░▓  ░▒ ▒▓▒ ▒ ░░░ ▒░ ░░ ░▒ ▒  ░
   ░ ░░   ░ ▒░░░▒░ ░ ░ ░ ░ ▒  ░░ ░ ▒  ░░ ░▒  ░ ░ ░ ░  ░  ░  ▒   
      ░   ░ ░  ░░░ ░ ░   ░ ░     ░ ░   ░  ░  ░     ░   ░        
      ░   ░    ░   ░       ░       ░         ░     ░   ░ ░      
            ░                          ░    ░           ░        
   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   █░░░░░░░░░░░░░░░ F R A M E W O R K ░░░░░░░░░░░░░░░░░░░░░░░█
   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
                       bad-antics
```

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Go](https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white)
![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)

> **The unified command center for all NullSec security tools**

## Overview

**NullSec Framework** is a modular penetration testing and security research framework that integrates all NullSec tools into a cohesive environment. It provides a unified interface for reconnaissance, exploitation, forensics, and post-exploitation activities.

## Features

- 🎯 **Unified Interface** - Single CLI for all NullSec modules
- 📦 **Module System** - Easy integration of new tools
- 🔧 **Auto-Configuration** - Detects and configures available tools
- 📊 **Session Management** - Track targets, findings, and artifacts
- 🔄 **Workflow Automation** - Chain modules for complex operations
- 📝 **Reporting** - Generate detailed assessment reports

## Integrated Toolkits

### Reconnaissance
| Tool | Language | Description |
|------|----------|-------------|
| [nullsec-recon](https://github.com/bad-antics/nullsec-recon) | Go, Rust, Python | Active/passive reconnaissance toolkit |
| [nullsec-portscan](https://github.com/bad-antics/nullsec-portscan) | Elixir | Lightning-fast async port scanner |
| [nullsec-sniffer](https://github.com/bad-antics/nullsec-sniffer) | Clojure | Network packet analyzer |

### Exploitation
| Tool | Language | Description |
|------|----------|-------------|
| [nullsec-exploit](https://github.com/bad-antics/nullsec-exploit) | Python, C, Rust | Exploit development toolkit |
| [nullsec-injector](https://github.com/bad-antics/nullsec-injector) | Odin | Process memory injector |
| [nullsec-web](https://github.com/bad-antics/nullsec-web) | TypeScript, Python | Web application security |

### Cryptography
| Tool | Language | Description |
|------|----------|-------------|
| [nullsec-crypto](https://github.com/bad-antics/nullsec-crypto) | Rust, Python, C, Crystal | Cryptographic analysis toolkit |
| [nullsec-hashwitch](https://github.com/bad-antics/nullsec-hashwitch) | Julia | High-performance hash cracker |

### Forensics & Analysis
| Tool | Language | Description |
|------|----------|-------------|
| [nullsec-forensics](https://github.com/bad-antics/nullsec-forensics) | Go, Python, Rust | Digital forensics toolkit |
| [nullsec-logwipe](https://github.com/bad-antics/nullsec-logwipe) | Scala | Log analysis and manipulation |

### Stealth & Evasion
| Tool | Language | Description |
|------|----------|-------------|
| [nullsec-stealth](https://github.com/bad-antics/nullsec-stealth) | Crystal, Lua, D, Haskell, V | Anti-detection toolkit |
| [nullsec-cloaker](https://github.com/bad-antics/nullsec-cloaker) | Erlang | Process and file cloaking |

### Command & Control
| Tool | Language | Description |
|------|----------|-------------|
| [nullsec-beacon](https://github.com/bad-antics/nullsec-beacon) | OCaml | Lightweight beacon system |
| [nullsec-keysniff](https://github.com/bad-antics/nullsec-keysniff) | F# | Keyboard event monitor |

### Wireless
| Tool | Language | Description |
|------|----------|-------------|
| [nullsec-wifi](https://github.com/bad-antics/nullsec-wifi) | Kotlin, Java | WiFi security toolkit |
| [nullsec-bluetooth](https://github.com/bad-antics/nullsec-bluetooth) | Kotlin, Java | Bluetooth security toolkit |

### Mobile
| Tool | Language | Description |
|------|----------|-------------|
| [nullsec-android](https://github.com/bad-antics/nullsec-android) | Kotlin, Java | Android security toolkit |
| [nullsec-ios](https://github.com/bad-antics/nullsec-ios) | Swift, Objective-C | iOS security toolkit |

## Installation

```bash
# Clone framework
git clone https://github.com/bad-antics/nullsec-framework.git
cd nullsec-framework

# Install dependencies
pip install -r requirements.txt

# Initialize framework
./nullsec init

# Auto-detect and configure modules
./nullsec setup --auto
```

## Quick Start

```bash
# Start interactive shell
./nullsec console

# List available modules
nullsec> modules list

# Load a module
nullsec> use recon/portscan

# Set options
nullsec> set target 192.168.1.0/24
nullsec> set ports 1-1000

# Run module
nullsec> run

# Generate report
nullsec> report html output.html
```

## Module Management

```bash
# Install a module
./nullsec module install nullsec-beacon

# Update all modules
./nullsec module update --all

# Create new module
./nullsec module create my-tool --language python

# List installed modules
./nullsec module list --installed
```

## Configuration

```yaml
# ~/.nullsec/config.yaml
framework:
  workspace: ~/nullsec-workspace
  auto_save: true
  verbose: false

modules:
  path: ~/.nullsec/modules
  auto_load: true

database:
  type: sqlite
  path: ~/.nullsec/data.db

reporting:
  default_format: html
  include_screenshots: true
```

## Language Support

The framework supports modules written in **30+ programming languages**:

| Category | Languages |
|----------|-----------|
| **Systems** | Rust, Go, C, C++, Zig, Odin, D, V |
| **Scripting** | Python, Ruby, Lua, Perl |
| **JVM** | Kotlin, Java, Scala, Clojure |
| **Functional** | Haskell, OCaml, F#, Erlang, Elixir |
| **Web** | TypeScript, JavaScript |
| **Apple** | Swift, Objective-C |
| **Other** | Nim, Crystal, Julia |

## Directory Structure

```
nullsec-framework/
├── nullsec              # Main entry point
├── core/                # Framework core
│   ├── console.py       # Interactive console
│   ├── module.py        # Module management
│   ├── session.py       # Session handling
│   └── config.py        # Configuration
├── modules/             # Module directory
│   ├── recon/
│   ├── exploit/
│   ├── forensics/
│   └── ...
├── lib/                 # Shared libraries
├── data/                # Data files
└── docs/                # Documentation
```

## Creating Modules

```python
# modules/my_module/my_module.py
from nullsec.core.module import Module

class MyModule(Module):
    name = "my_module"
    description = "My custom module"
    author = "bad-antics"
    
    options = {
        "target": {"required": True, "description": "Target address"},
        "port": {"required": False, "default": 80, "description": "Port number"}
    }
    
    def run(self):
        target = self.options["target"]
        self.log_info(f"Running against {target}")
        # Module logic here
        return self.results
```

## Related Projects

- [NullSec Linux](https://github.com/bad-antics/nullsec-linux) - Security-focused Linux distribution
- [NullSec Docs](https://github.com/bad-antics/nullsec-docs) - Documentation and tutorials
- [NullSec Themes](https://github.com/bad-antics/nullsec-themes) - Terminal and editor themes

## Community

- **Discord**: [discord.gg/killers](https://discord.gg/killers)
- **GitHub**: [@bad-antics](https://github.com/bad-antics)

## Disclaimer

This framework is intended for authorized security testing and educational purposes only. Users are responsible for obtaining proper authorization before testing any systems. Unauthorized access to computer systems is illegal.

## License

NullSec Proprietary License

## Author

**bad-antics** - NullSec Security Team

---

*The unified penetration testing platform*
