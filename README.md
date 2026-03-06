# 🦥 SLOTH — Scanner Orchestrator

🛡 **SLOTH** is a terminal-based security scanning orchestrator that unifies multiple popular security tools into a single, controlled pipeline with an interactive TUI, live progress tracking, and clean HTML/JSON reports.

The project focuses on **reliability**, **operator experience**, and **readable results** — no fragile stdout parsing, no unpredictable behavior.

---

### 🎯 Designed for

- AppSec / DevSecOps engineers
- Pentesters / Red Team operators
- Security researchers
- Automated reconnaissance and initial security assessment

---

### ✨ Key Features

- 🧩 Multi-tool orchestration (14 tools)
- 🎛 Scan profiles: `fast`, `balanced`, `deep`
- 🐢 Slow scanners isolated in a separate menu (Nikto / Nuclei / Dalfox / sqlmap)
- 📊 Rich terminal TUI
  - live step status: `queued`, `running`, `done`, `failed`, `skipped`
  - progress bar and elapsed time per step
- 🧾 HTML and JSON reports
- ⚡ Parallel step execution (configurable)
- 🔌 Custom scanner selection
- 🛠 Built-in tool installer — detects missing tools, installs language runtimes (Go) automatically
- 🌐 REST API mode (`serve` subcommand)
- 🐳 Docker support
- 🖥 Cross-platform: Linux (apt/yum/pacman), macOS (Homebrew), Windows (hints)

---

### 🔧 Integrated Tools

| Tool       | Purpose                              | Install method        |
|------------|--------------------------------------|-----------------------|
| nmap       | Port scanner (basic + vulners)       | apt / brew / choco    |
| nikto      | Web vulnerability scanner (slow)     | apt / brew            |
| sslscan    | TLS/SSL analysis                     | apt / brew            |
| whatweb    | Technology fingerprinting            | apt / brew            |
| dirsearch  | Directory brute-force                | apt / pip             |
| subfinder  | Subdomain enumeration                | brew / go install     |
| nuclei     | Template-based scanner (slow)        | brew / go install     |
| httpx      | Live host prober                     | brew / go install     |
| wafw00f    | WAF detection                        | apt / pip             |
| katana     | JS-aware web crawler                 | brew / go install     |
| testssl    | Deep TLS analysis                    | apt / brew            |
| dalfox     | XSS parameter fuzzing (slow)         | brew / go install     |
| sqlmap     | SQL injection detection (slow)       | apt / pip             |
| dnsx       | DNS resolution & brute-force         | brew / go install     |

> Tools marked **go install** require the Go runtime. SLOTH will offer to install it automatically.

---

### 🚀 Installation

#### Requirements

- Python **3.10+**
- Linux (Kali / Ubuntu / Debian / Arch), macOS, or Windows (WSL recommended)

#### Python dependencies

```bash
pip install -r requirements.txt
```

#### Security tools

Launch SLOTH and use **menu 7 → Check / install tools** to see what's missing and install everything in one click. For tools requiring Go, SLOTH will automatically offer to install the Go runtime first.

Manual install examples:

```bash
# apt (Debian/Ubuntu/Kali)
sudo apt-get install -y nmap nikto sslscan whatweb dirsearch wafw00f sqlmap testssl.sh

# Go-based tools (Go runtime required)
sudo apt-get install -y golang-go
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/hahwul/dalfox/v2@latest
```

> **Note:** `go install` places binaries in `~/go/bin`. SLOTH detects them there automatically, even if `~/go/bin` is not in your `PATH`.

---

### ▶️ Usage

#### Interactive TUI (default)

```bash
python start.py
```

#### Non-interactive CLI scan

```bash
python start.py scan <target> [--profile fast|balanced|deep] [--steps all] [--parallel]
```

#### REST API server

```bash
python start.py serve [--host 0.0.0.0] [--port 8000]
# POST /api/scan  |  GET /api/scan/<run_id>  |  GET /api/scans
```

#### Docker

```bash
docker build -t sloth .
docker run --rm -it sloth scan <target>
```

On first launch:
- `config.yaml` is generated automatically with safe defaults
- Missing tools can be verified and installed from **menu 7**

---

### 📋 Scan Profiles

| Profile    | Use case                              | Timeout / step |
|------------|---------------------------------------|----------------|
| `fast`     | Quick recon (default)                 | 15 min         |
| `balanced` | Reasonable depth                      | 30 min         |
| `deep`     | Full scan (all ports, more templates) | 2 hours        |

---

### 📄 Reports

After each scan a timestamped directory is created:

```
scans/
└── YYYYMMDD-HHMMSS_target/
    ├── raw/
    │   ├── nmap_basic/
    │   ├── subdomains/
    │   ├── httpx/
    │   └── ... (one dir per tool)
    └── reports/
        ├── summary.json
        └── report.html
```

---

### ⚙️ Advanced Settings (menu 6)

| Setting              | Default | Description                              |
|----------------------|---------|------------------------------------------|
| `parallel`           | `True`  | Run steps concurrently (up to 6 workers) |
| `concurrency`        | `3`     | Max parallel targets                     |
| `skip_existing`      | `False` | Skip steps with existing output files    |
| `fail_fast`          | `False` | Stop on first failed step                |
| `seclists_path`      | —       | Path to SecLists for heavy wordlists     |

---

### ✅ Completed roadmap items

- [x] Parallel step execution
- [x] Docker image
- [x] API / JSON output
- [x] Slow scanner isolation (Dalfox, sqlmap, Nikto, Nuclei)
- [x] Artifact chaining (subfinder → httpx/dnsx, katana → dalfox)
- [x] Cross-platform install menu with Go runtime auto-install
- [x] HTML + JSON reports

### 🔜 Planned

- Integration with vulnerability management platforms
- Nuclei template auto-update
- Target list / batch scanning
