# 🦥 SLOTH — Scanner Orchestrator

🛡 **SLOTH (Scanner Orchestrator)** is a terminal-based security scanning orchestrator  
that unifies multiple popular security tools into a single, controlled pipeline  
with an interactive TUI and clean HTML reports.

The project focuses on **reliability**, **operator experience**, and **readable results**,  
without fragile stdout parsing or unpredictable behavior.

---

### 🎯 Designed for

- AppSec / DevSecOps engineers
- Pentesters / Red Team operators
- Security researchers
- Automated reconnaissance and initial security assessment

---

### ✨ Key Features

- 🧩 Multi-tool orchestration
- 🎛 Scan profiles: `fast`, `balanced`, `deep`
- 🐢 Slow scanners isolated (Nikto / Nuclei)
- 📊 Rich terminal UI (TUI)
  - live step status: `queued`, `running`, `done`, `failed`
  - progress visualization
- 🧾 Clean and readable HTML reports
- 🔁 Continue working after scan completion
- ⚙️ Advanced configuration options
- 🔌 Custom scanner selection
- 🚫 No fragile stdout parsing (stable execution model)

---

### 🔧 Integrated Tools

| Tool       | Purpose                              |
|------------|--------------------------------------|
| subfinder  | Subdomain enumeration                |
| whatweb    | Technology fingerprinting            |
| sslscan    | TLS / SSL analysis                   |
| nmap       | Ports, services, scripts             |
| dirsearch  | Directory brute-force                |
| nikto     | Web vulnerabilities (slow)           |
| nuclei     | Template-based checks (slow)         |

---

### 🚀 Installation

### Requirements

- Python **3.10+**
- Linux (Kali / Ubuntu / Debian)
- Installed security tools:
  - `nmap`
  - `subfinder`
  - `whatweb`
  - `sslscan`
  - `dirsearch`
  - `nikto`
  - `nuclei`
  
### Python dependencies

```bash
pip install -r requirements.txt
```
---

### ▶️ Usage
```
python start.py
```
On first launch:
- config.yaml is generated automatically
- Missing tools can be verified or installed from the menu
- Safe defaults are applied
  
---
### 📄 Reports

After each scan, a dedicated directory is created:

```text
scans/
└── YYYYMMDD-HHMMSS_target/
    ├── raw/
    │   └── tool outputs and logs
    └── reports/
        └── report.html
```	
---

Roadmap:
- Parallel step execution
- Docker image
- API / JSON output
- Integration with vulnerability management platforms
	
---
