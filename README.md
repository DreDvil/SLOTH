<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> 5f8fe56 (edit README)
SLOTH - Scanner Orchestrator

🛡 Scanner Orchestrator is a terminal-based security scanning orchestrator that unifies multiple popular security tools into a single controlled pipeline with an interactive TUI and clean HTML reports.

Designed for:
	•	AppSec / DevSecOps engineers
	•	Pentesters / Red Team
	•	Security researchers
	•	Automated reconnaissance & initial security assessment

⸻

✨ Key Features
	🧩 Multi-tool orchestration
	🎛 Scan profiles: fast, balanced, deep
	🐢 Slow scanners isolated (Nikto / Nuclei)
	📊 Rich TUI (terminal UI):
	    • live status (queued / running / done / failed)
	    • progress bar
	🧾 Clean HTML reports
	🔁 Continue working after scan completion
	⚙️ Advanced configuration
	🔌 Custom scanner selection
	🚫 No fragile stdout parsing (stable execution)

⸻

🔧 Integrated Tools

Tool	Purpose
subfinded - Subdomain enumeration
whatweb - Technology fingerprinting
sslscan - TLS / SSL analysis
nmap - Ports, services, scripts
dirsearch - Directory brute-force
nikto (slow) - Web vulnerabilities
nuclei (slow) - Template-based checks

⸻

🚀 Installation

Requirements
	•	Python 3.10+
	•	Linux (Kali / Ubuntu / Debian)
	•	Installed tools:
	•	nmap
	•	subfinder
	•	whatweb
	•	sslscan
	•	dirsearch
	•	nikto
	•	nuclei

Python dependencies
<<<<<<< HEAD
=======
# Scanner Orchestrator
>>>>>>> 2eed5b1 (edit README)
=======
>>>>>>> 5f8fe56 (edit README)

pip install -r requirements.txt

⸻

▶️ Usage

python start.py

On first run:
	•	config.yaml is generated automatically
	•	Missing tools can be verified/installed from the menu

⸻

🧭 Main Menu

1  Set target
2  Choose profile (fast / balanced / deep)
3  Select scanners (custom subset)
4  Run scan (selected / ALL fast)
5  Run slow scans (Nikto / Nuclei)
6  Advanced settings
0  Exit


⸻

⚡ Scan Profiles

fast (default)
	•	quick reconnaissance
	•	short timeouts
	•	Nikto / Nuclei excluded

balanced
	•	deeper checks
	•	moderate timeouts
	•	suitable for regular audits

deep
	•	maximum coverage
	•	long timeouts
	•	recommended only for targeted scans

⸻

🐢 Slow Scanners Strategy

Nikto and Nuclei are intentionally separated because they:
	•	can run for a long time
	•	may trigger WAF / rate limits
	•	significantly increase scan duration

They are:
	•	❌ NOT part of ALL
	•	▶️ executed explicitly via menu
	•	⏱ protected by step-level timeouts
	•	⚠️ clearly marked as slow

⸻

📄 Reports

After each scan:

scans/
└── YYYYMMDD-HHMMSS_target/
    ├── raw/
    └── reports/
        └── report.html

HTML report includes:
	•	step summary table
	•	execution time
	•	status per scanner
	•	scanner output (tail)
	•	links to raw logs

No horizontal scrolling, readable on any screen.

⸻

⚙️ Advanced Settings

concurrency_targets	- Future multi-target support
skip_existing -	Skip existing artifacts
fail_fast - Stop pipeline on error
seclists_path - Custom SecLists path

<<<<<<< HEAD
=======

⸻

🧠 Architecture

High-level architecture

┌────────────────────┐
│        User        │
│   (Terminal UI)    │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│  Scanner Orchestrator
│  (Python / Rich UI)│
└─────────┬──────────┘
          │
          ▼
┌──────────────────────────────────────┐
│            Scan Pipeline              │
│                                      │
│  subfinder  whatweb  sslscan          │
│  nmap_basic nmap_vulners dirsearch    │
│                                      │
│  (optional slow scans)                │
│  nikto        nuclei                  │
└─────────┬────────────────────────────┘
          │
          ▼
┌────────────────────┐
│  Artifacts / Logs  │
│  HTML Report       │
└────────────────────┘

Design principles
	•	Each scanner = isolated step
	•	Status = exit code + output file
	•	STDOUT is never parsed
	•	Resilient to noisy CLI output
	•	Deterministic results

>>>>>>> 5f8fe56 (edit README)
⸻

🛣 Roadmap
	•	Parallel step execution
	•	JSON API
	•	Export to information aggregator
 	•	Docker image
	•	YAML-driven pipelines

⸻

🤝 Contributing

Pull requests and ideas are welcome.
<<<<<<< HEAD
If you use this tool — don’t forget to ⭐ star the repo.
=======
If you use this tool — don’t forget to ⭐ star the repo.
>>>>>>> 5f8fe56 (edit README)
