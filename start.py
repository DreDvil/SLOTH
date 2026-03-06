#!/usr/bin/env python3
# Scanner Orchestrator (SPEC-1 MVP)
# v17: +httpx, wafw00f, katana, testssl, dalfox, sqlmap, dnsx; artifact chaining

from __future__ import annotations

import json
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
import datetime
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml
import typer
import tldextract
from jinja2 import Environment, FileSystemLoader, select_autoescape

from rich.console import Console, Group
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.text import Text
from rich.align import Align
from rich.progress_bar import ProgressBar
from rich import box

app = typer.Typer(add_completion=False, help="Scanner Orchestrator (SPEC-1 MVP)")

DEFAULT_CFG_YAML = """\
# Scanner Orchestrator (SPEC-1 MVP) config (v17)
report:
  # html | json | both
  format: both

dirsearch:
  # default = built-in wordlist (fast), seclists = SecLists wordlist (slow/heavy)
  wordlist_mode: default
  include_status: "200,204,301,302"
  exclude_status: "404,401"
  follow_redirects: true
  max_redirects: 3
  threads_fast: 25
  threads_balanced: 50
  threads_deep: 80

profiles:
  fast:
    step_timeout_sec: 900
    nikto_timeout_sec: 600
    nuclei_timeout_sec: 600
    dalfox_timeout_sec: 1200
    sqlmap_timeout_sec: 1800
    testssl_timeout_sec: 600
    nmap_basic:
      timing: "-T4"
      ports: "-F"
      extra: ["-sC", "-sV", "-Pn", "-4", "--max-retries", "2", "--host-timeout", "10m"]
    nmap_vulners:
      timing: "-T4"
      ports: "-p 80,443"
      extra: ["-Pn", "-4", "--script", "vulners", "--max-retries", "2", "--host-timeout", "15m"]
    nuclei:
      severity: "high,critical"
      rate_limit: 50
      concurrency: 10
    katana:
      depth: 2
      js_crawl: true
      max_response_size: 2
    dalfox:
      workers: 10
      timeout: 10
    testssl:
      severity: "HIGH"
  balanced:
    step_timeout_sec: 1800
    nikto_timeout_sec: 900
    nuclei_timeout_sec: 1200
    dalfox_timeout_sec: 1800
    sqlmap_timeout_sec: 3600
    testssl_timeout_sec: 900
    nmap_basic:
      timing: "-T3"
      ports: "-p 80,443,8080,8443"
      extra: ["-sC", "-sV", "-Pn", "-4", "--max-retries", "3", "--host-timeout", "20m"]
    nmap_vulners:
      timing: "-T3"
      ports: "-p 80,443,8080,8443"
      extra: ["-Pn", "-4", "--script", "vulners", "--max-retries", "3", "--host-timeout", "30m"]
    nuclei:
      severity: "medium,high,critical"
      rate_limit: 100
      concurrency: 25
    katana:
      depth: 4
      js_crawl: true
      max_response_size: 4
    dalfox:
      workers: 20
      timeout: 15
    testssl:
      severity: "MEDIUM"
  deep:
    step_timeout_sec: 7200
    nikto_timeout_sec: 1800
    nuclei_timeout_sec: 3600
    dalfox_timeout_sec: 3600
    sqlmap_timeout_sec: 7200
    testssl_timeout_sec: 1800
    nmap_basic:
      timing: "-T3"
      ports: "-p-"
      extra: ["-sC", "-sV", "-Pn", "-4", "--max-retries", "5", "--host-timeout", "60m"]
    nmap_vulners:
      timing: "-T3"
      ports: "-p 80,443,8080,8443"
      extra: ["-Pn", "-4", "--script", "vulners", "--max-retries", "5", "--host-timeout", "60m"]
    nuclei:
      severity: "low,medium,high,critical"
      rate_limit: 200
      concurrency: 50
    katana:
      depth: 6
      js_crawl: true
      max_response_size: 8
    dalfox:
      workers: 40
      timeout: 30
    testssl:
      severity: "LOW"
"""


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def ensure_cfg(path: Path) -> None:
    if not path.exists():
        path.write_text(DEFAULT_CFG_YAML, encoding="utf-8")


def load_cfg(path: Path) -> Dict:
    ensure_cfg(path)
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def cfg_get(cfg: Dict, *keys, default=None):
    cur = cfg
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def slugify(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r"[^a-z0-9]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s[:80] if s else "target"


def which(bin_name: str) -> Optional[str]:
    return shutil.which(bin_name)


def is_url(s: str) -> bool:
    return s.startswith("http://") or s.startswith("https://")


def extract_host(target: str) -> str:
    if is_url(target):
        import urllib.parse
        u = urllib.parse.urlparse(target)
        return u.hostname or target
    return target


def registrable_domain_from_target(target: str) -> Optional[str]:
    host = extract_host(target)
    ext = tldextract.extract(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return None


def tail_file(path: Path, max_lines: int) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        if len(lines) <= max_lines:
            return "\n".join(lines)
        return "\n".join(lines[-max_lines:])
    except Exception:
        return ""


def run_cmd(cmd: List[str], out_file: Path, timeout_sec: int) -> Tuple[int, str]:
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with out_file.open("w", encoding="utf-8", errors="replace") as f:
        f.write("=== cmd ===\n")
        f.write(" ".join(shlex.quote(x) for x in cmd) + "\n\n")
        f.flush()
        proc = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT, text=True)
        try:
            proc.wait(timeout=timeout_sec if timeout_sec and timeout_sec > 0 else None)
        except subprocess.TimeoutExpired:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            f.write("\n\n=== orchestrator ===\nTIMEOUT\n")
            f.flush()
            return (124, tail_file(out_file, 120))
    return (proc.returncode or 0, tail_file(out_file, 200))


# Cache help text per binary (one subprocess call per binary, not per flag)
@lru_cache(maxsize=64)
def _get_help_text(bin_name: str) -> str:
    p = which(bin_name)
    if not p:
        return ""
    try:
        return subprocess.check_output([p, "-h"], stderr=subprocess.STDOUT, text=True, timeout=5)
    except Exception:
        return ""


def help_supports(bin_name: str, flag: str) -> bool:
    return flag in _get_help_text(bin_name)


# ---------------------------------------------------------------------------
# Tool registry & cross-platform install helpers
# ---------------------------------------------------------------------------

# apt/yum/pacman/brew = package name; pip/go = package/module path; win = install hint
# bins = list of possible binary names (first found wins); omit to use key as name
TOOL_REGISTRY: Dict[str, Dict] = {
    "nmap": {
        "name": "Nmap",       "desc": "Port scanner (basic + vulners)",
        "apt": "nmap",        "yum": "nmap",     "pacman": "nmap",
        "brew": "nmap",       "pip": None,        "go": None,
        "win": "choco install nmap  OR  https://nmap.org/download.html",
    },
    "nikto": {
        "name": "Nikto",      "desc": "Web vulnerability scanner (slow)",
        "apt": "nikto",       "yum": "nikto",    "pacman": None,
        "brew": "nikto",      "pip": None,        "go": None,
        "win": "WSL / Kali WSL recommended",
    },
    "sslscan": {
        "name": "SSLScan",    "desc": "TLS/SSL analysis",
        "apt": "sslscan",     "yum": None,       "pacman": "sslscan",
        "brew": "sslscan",    "pip": None,        "go": None,
        "win": "WSL / Kali WSL recommended",
    },
    "whatweb": {
        "name": "WhatWeb",    "desc": "Technology fingerprinting",
        "apt": "whatweb",     "yum": None,       "pacman": None,
        "brew": "whatweb",    "pip": None,        "go": None,
        "win": "WSL / Kali WSL recommended",
    },
    "dirsearch": {
        "name": "Dirsearch",  "desc": "Directory brute-force",
        "apt": "dirsearch",   "yum": None,       "pacman": None,
        "brew": None,         "pip": "dirsearch", "go": None,
        "win": "pip install dirsearch",
    },
    "subfinder": {
        "name": "Subfinder",  "desc": "Subdomain enumeration",
        "apt": None,          "yum": None,       "pacman": None,
        "brew": "subfinder",  "pip": None,
        "go": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder",
        "runtime": "go",
        "win": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    },
    "nuclei": {
        "name": "Nuclei",     "desc": "Template-based scanner (slow)",
        "apt": None,          "yum": None,       "pacman": None,
        "brew": "nuclei",     "pip": None,
        "go": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei",
        "runtime": "go",
        "win": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    },
    # ── New tools ──────────────────────────────────────────────────────────
    "httpx": {
        "name": "httpx",      "desc": "Live host prober (reads subdomains.txt)",
        "apt": None,          "yum": None,       "pacman": None,
        "brew": "httpx",      "pip": None,
        "go": "github.com/projectdiscovery/httpx/cmd/httpx",
        "runtime": "go",
        "win": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    },
    "wafw00f": {
        "name": "wafw00f",    "desc": "WAF detection",
        "apt": "wafw00f",     "yum": None,       "pacman": None,
        "brew": "wafw00f",    "pip": "wafw00f",   "go": None,
        "win": "pip install wafw00f",
    },
    "katana": {
        "name": "Katana",     "desc": "JS-aware web crawler",
        "apt": None,          "yum": None,       "pacman": None,
        "brew": "katana",     "pip": None,
        "go": "github.com/projectdiscovery/katana/cmd/katana",
        "runtime": "go",
        "win": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    },
    "testssl": {
        "name": "testssl",    "desc": "Deep TLS analysis",
        "bins": ["testssl", "testssl.sh"],   # Kali installs as testssl.sh
        "apt": "testssl.sh",  "yum": None,       "pacman": "testssl",
        "brew": "testssl",    "pip": None,        "go": None,
        "win": "WSL / Kali WSL recommended",
    },
    "dalfox": {
        "name": "Dalfox",     "desc": "XSS parameter fuzzing (slow)",
        "apt": None,          "yum": None,       "pacman": None,
        "brew": "dalfox",     "pip": None,
        "go": "github.com/hahwul/dalfox/v2",
        "runtime": "go",
        "win": "go install github.com/hahwul/dalfox/v2@latest",
    },
    "sqlmap": {
        "name": "sqlmap",     "desc": "SQL injection detection (slow)",
        "apt": "sqlmap",      "yum": "sqlmap",   "pacman": "sqlmap",
        "brew": "sqlmap",     "pip": "sqlmap",    "go": None,
        "win": "pip install sqlmap",
    },
    "dnsx": {
        "name": "dnsx",       "desc": "DNS resolution & brute-force",
        "apt": None,          "yum": None,       "pacman": None,
        "brew": "dnsx",       "pip": None,
        "go": "github.com/projectdiscovery/dnsx/cmd/dnsx",
        "runtime": "go",
        "win": "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    },
}

_OS_LABELS: Dict[str, str] = {
    "apt":     "Debian / Ubuntu / Kali  (apt)",
    "yum":     "RHEL / Fedora / CentOS  (dnf/yum)",
    "pacman":  "Arch Linux  (pacman)",
    "brew":    "macOS  (Homebrew)",
    "win":     "Windows",
    "unknown": "Linux (unknown package manager)",
}

RUNTIME_REGISTRY: Dict[str, Dict] = {
    "go": {
        "name": "Go",
        "check": "go",
        "desc": "Go language runtime (required for ProjectDiscovery tools & Dalfox)",
        "apt": "golang-go",   "yum": "golang",   "pacman": "go",
        "brew": "go",         "pip": None,
        "win": "https://golang.org/dl/  OR  choco install golang",
    },
}


def detect_os() -> str:
    """Return package-manager key: 'apt', 'yum', 'pacman', 'brew', 'win', 'unknown'."""
    if sys.platform == "win32":
        return "win"
    if sys.platform == "darwin":
        return "brew"
    for pm, key in [("apt-get", "apt"), ("apt", "apt"),
                    ("dnf", "yum"), ("yum", "yum"),
                    ("pacman", "pacman")]:
        if shutil.which(pm):
            return key
    return "unknown"


def _check_runtime(runtime_key: str) -> bool:
    """Return True if a language runtime binary is available."""
    info = RUNTIME_REGISTRY.get(runtime_key, {})
    return shutil.which(info.get("check", runtime_key)) is not None


def _runtime_install_cmd(runtime_key: str, os_type: str) -> Optional[str]:
    """Return install command for a language runtime, or None if manual."""
    info = RUNTIME_REGISTRY.get(runtime_key, {})
    if os_type == "win":
        return info.get("win")
    if os_type == "brew":
        pkg = info.get("brew")
        return f"brew install {pkg}" if pkg else None
    pkg = info.get(os_type)
    if pkg:
        if os_type == "apt":    return f"sudo apt-get install -y {pkg}"
        if os_type == "yum":    return f"sudo dnf install -y {pkg}"
        if os_type == "pacman": return f"sudo pacman -S --noconfirm {pkg}"
    return None


def get_runtime_status() -> List[Dict]:
    """Return status dict for every runtime in RUNTIME_REGISTRY."""
    os_type = detect_os()
    result  = []
    for key, info in RUNTIME_REGISTRY.items():
        path  = shutil.which(info.get("check", key)) or ""
        found = bool(path)
        icmd  = None if found else _runtime_install_cmd(key, os_type)
        result.append({
            "key":         key,
            "name":        info["name"],
            "desc":        info["desc"],
            "found":       found,
            "path":        path,
            "install_cmd": icmd,
        })
    return result


def _install_cmd(tool_key: str, os_type: str) -> Optional[str]:
    """Return a shell command that installs the tool, or None if fully manual."""
    info = TOOL_REGISTRY.get(tool_key, {})
    if os_type == "win":
        return info.get("win")
    if os_type == "brew":
        if info.get("brew"):
            return f"brew install {info['brew']}"
        if info.get("pip"):
            return f"pip3 install {info['pip']}"
        if info.get("go"):
            return f"go install {info['go']}@latest"
        return None
    # Linux variants (apt / yum / pacman / unknown)
    pm_pkg = info.get(os_type)
    if pm_pkg:
        if os_type == "apt":
            return f"sudo apt-get install -y {pm_pkg}"
        if os_type == "yum":
            return f"sudo dnf install -y {pm_pkg}"
        if os_type == "pacman":
            return f"sudo pacman -S --noconfirm {pm_pkg}"
    if info.get("pip"):
        return f"pip3 install {info['pip']}"
    if info.get("go"):
        go = shutil.which("go") or "go"
        return f"{go} install {info['go']}@latest"
    return None


def _find_tool_bin(key: str) -> Optional[str]:
    """Find a tool's binary, checking all known aliases (e.g. testssl / testssl.sh)."""
    info = TOOL_REGISTRY.get(key, {})
    for name in info.get("bins", [key]):
        p = shutil.which(name)
        if p:
            return p
    return None


def get_tool_status() -> List[Dict]:
    """Return status dict for every tool in TOOL_REGISTRY."""
    os_type = detect_os()
    result  = []
    for key, info in TOOL_REGISTRY.items():
        path  = _find_tool_bin(key)
        found = path is not None
        icmd  = None if found else _install_cmd(key, os_type)
        result.append({
            "key":         key,
            "name":        info["name"],
            "desc":        info["desc"],
            "found":       found,
            "path":        path or "",
            "install_cmd": icmd,
        })
    return result


def run_install(cmd: str, console: Console) -> bool:
    """Execute an install command. Returns True on success."""
    console.print(f"  [dim]$ {cmd}[/]")
    try:
        rc = subprocess.run(shlex.split(cmd), text=True).returncode
        if rc == 0:
            _get_help_text.cache_clear()   # newly installed tool will be picked up
            console.print("  [green]Done.[/]")
            return True
        console.print(f"  [red]Failed (exit {rc}).[/]")
        return False
    except Exception as e:
        console.print(f"  [red]Error: {e}[/]")
        return False


# ---------------------------------------------------------------------------
# Scanner command builders
# ---------------------------------------------------------------------------

def cmd_nmap_basic(target: str, out_dir: Path, profile: Dict) -> Tuple[List[str], List[Path], Path]:
    raw_dir = out_dir / "raw" / "nmap_basic"
    raw_dir.mkdir(parents=True, exist_ok=True)
    base      = raw_dir / "out"
    artifacts = [base.with_suffix(".nmap"), base.with_suffix(".gnmap"), base.with_suffix(".xml")]
    host      = extract_host(target)
    timing    = profile.get("timing", "-T4")
    ports     = profile.get("ports", "-F")
    extra     = profile.get("extra", ["-sC", "-sV", "-Pn"])
    cmd       = ["nmap", timing] + ports.split() + extra + ["-oA", str(base), host]
    return cmd, artifacts, (raw_dir / "out.txt")


def cmd_nmap_vulners(target: str, out_dir: Path, profile: Dict) -> Tuple[List[str], List[Path], Path]:
    raw_dir = out_dir / "raw" / "nmap_vulners"
    raw_dir.mkdir(parents=True, exist_ok=True)
    base      = raw_dir / "out"
    artifacts = [base.with_suffix(".nmap"), base.with_suffix(".gnmap"), base.with_suffix(".xml")]
    host      = extract_host(target)
    timing    = profile.get("timing", "-T4")
    ports     = profile.get("ports", "-p 80,443")
    extra     = profile.get("extra", ["-Pn", "--script", "vulners"])
    cmd       = ["nmap", timing] + ports.split() + extra + ["-oA", str(base), host]
    return cmd, artifacts, (raw_dir / "out.txt")


def cmd_subdomains(target: str, out_dir: Path) -> Tuple[List[str], List[Path], Path, Optional[str]]:
    raw_dir  = out_dir / "raw" / "subdomains"
    raw_dir.mkdir(parents=True, exist_ok=True)
    out_txt  = raw_dir / "subdomains.txt"
    domain   = registrable_domain_from_target(target)
    if not domain:
        return ([], [out_txt], (raw_dir / "out.txt"), None)
    cmd = ["subfinder", "-silent", "-d", domain, "-o", str(out_txt)]
    return cmd, [out_txt], (raw_dir / "out.txt"), domain


def cmd_whatweb(target: str, out_dir: Path) -> Tuple[List[str], List[Path], Path]:
    raw_dir  = out_dir / "raw" / "whatweb"
    raw_dir.mkdir(parents=True, exist_ok=True)
    out_json = raw_dir / "out.json"
    cmd      = ["whatweb", "-a", "3", "--log-json", str(out_json), target]
    return cmd, [out_json], (raw_dir / "out.txt")


def cmd_sslscan(target: str, out_dir: Path) -> Tuple[List[str], List[Path], Path]:
    raw_dir = out_dir / "raw" / "sslscan"
    raw_dir.mkdir(parents=True, exist_ok=True)
    out_xml = raw_dir / "out.xml"
    host    = extract_host(target)
    cmd     = ["sslscan", "--xml=" + str(out_xml), f"{host}:443"]
    return cmd, [out_xml], (raw_dir / "out.txt")


def find_seclists_wordlist(seclists_path: Path) -> Optional[Path]:
    candidates = []
    base = seclists_path / "Discovery" / "Web-Content"
    if base.exists():
        candidates += list(base.glob("*directory-list-2.3-medium*.txt"))
        candidates += list(base.glob("*directory-list-2.3-medium*.txt.gz"))
    if not candidates:
        return None
    return sorted(candidates, key=lambda p: p.stat().st_size, reverse=True)[0]


def cmd_dirsearch(
    target: str, out_dir: Path, cfg: Dict, profile_name: str, seclists_path: Optional[Path]
) -> Tuple[List[str], List[Path], Path]:
    raw_dir  = out_dir / "raw" / "dirsearch"
    raw_dir.mkdir(parents=True, exist_ok=True)
    out_json = raw_dir / "out.json"
    out_txt  = raw_dir / "out.txt"
    ds       = cfg_get(cfg, "dirsearch", default={}) or {}
    mode     = ds.get("wordlist_mode", "default")
    include_status = ds.get("include_status")
    exclude_status = ds.get("exclude_status")
    follow   = bool(ds.get("follow_redirects", True))
    max_redir = int(ds.get("max_redirects", 3))
    threads  = str(int(ds.get(f"threads_{profile_name}", ds.get("threads_fast", 25))))

    cmd = ["dirsearch", "-u", target, "-e", "php,asp,aspx,html,js,txt",
           "-f", "--format", "json", "-o", str(out_json)]
    if help_supports("dirsearch", "--quiet"):
        cmd += ["--quiet"]
    if help_supports("dirsearch", "--no-color"):
        cmd += ["--no-color"]
    if help_supports("dirsearch", "-t"):
        cmd += ["-t", threads]
    if mode == "seclists":
        if not seclists_path:
            raise RuntimeError("SecLists path is required for seclists wordlist_mode")
        wl = find_seclists_wordlist(seclists_path)
        if not wl:
            raise RuntimeError(f"Wordlist not found under {seclists_path}/Discovery/Web-Content/")
        cmd += ["-w", str(wl)]
    if include_status:
        if help_supports("dirsearch", "-i"):
            cmd += ["-i", str(include_status)]
        elif help_supports("dirsearch", "--include-status"):
            cmd += ["--include-status", str(include_status)]
    if exclude_status:
        if help_supports("dirsearch", "-x"):
            cmd += ["-x", str(exclude_status)]
        elif help_supports("dirsearch", "--exclude-status"):
            cmd += ["--exclude-status", str(exclude_status)]
    if follow and help_supports("dirsearch", "--follow-redirects"):
        cmd += ["--follow-redirects"]
    if help_supports("dirsearch", "--max-redirects"):
        cmd += ["--max-redirects", str(max_redir)]
    return cmd, [out_json], out_txt


def cmd_nikto(target: str, out_dir: Path) -> Tuple[List[str], List[Path], Path]:
    raw_dir = out_dir / "raw" / "nikto"
    raw_dir.mkdir(parents=True, exist_ok=True)
    out_txt = raw_dir / "out.txt"
    cmd     = ["nikto", "-h", target, "-output", str(out_txt)]
    return cmd, [out_txt], out_txt


def cmd_nuclei(target: str, out_dir: Path, profile_cfg: Dict) -> Tuple[List[str], List[Path], Path]:
    raw_dir = out_dir / "raw" / "nuclei"
    raw_dir.mkdir(parents=True, exist_ok=True)
    out_txt = raw_dir / "out.txt"
    cmd     = ["nuclei", "-u", target]
    if help_supports("nuclei", "-jsonl"):
        cmd += ["-jsonl", "-o", str(out_txt)]
    elif help_supports("nuclei", "-json"):
        cmd += ["-json", "-o", str(out_txt)]
    else:
        cmd += ["-o", str(out_txt)]
    sev = profile_cfg.get("severity")
    if sev and help_supports("nuclei", "-severity"):
        cmd += ["-severity", str(sev)]
    rl = profile_cfg.get("rate_limit")
    if rl:
        if help_supports("nuclei", "-rl"):
            cmd += ["-rl", str(int(rl))]
        elif help_supports("nuclei", "-rate-limit"):
            cmd += ["-rate-limit", str(int(rl))]
    conc = profile_cfg.get("concurrency")
    if conc and help_supports("nuclei", "-c"):
        cmd += ["-c", str(int(conc))]
    if help_supports("nuclei", "-silent"):
        cmd += ["-silent"]
    return cmd, [out_txt], out_txt


# ── New tools ────────────────────────────────────────────────────────────────

def _wait_for_artifact(path: Path, max_sec: int = 120) -> bool:
    """Block until path exists and is non-empty, or timeout. Returns True if found."""
    deadline = time.time() + max_sec
    while time.time() < deadline:
        if path.exists() and path.stat().st_size > 0:
            return True
        time.sleep(2)
    return False


def cmd_httpx(out_dir: Path) -> Tuple[List[str], List[Path], Path, bool]:
    """Probe live hosts from subfinder's subdomains.txt; waits up to 120 s in parallel mode."""
    raw_dir   = out_dir / "raw" / "httpx"
    raw_dir.mkdir(parents=True, exist_ok=True)
    out_txt   = raw_dir / "alive_hosts.txt"
    log_file  = raw_dir / "out.txt"
    subs_file = out_dir / "raw" / "subdomains" / "subdomains.txt"
    if not _wait_for_artifact(subs_file):
        return [], [out_txt], log_file, False
    cmd = ["httpx", "-l", str(subs_file), "-o", str(out_txt), "-silent"]
    if help_supports("httpx", "-threads"):
        cmd += ["-threads", "50"]
    elif help_supports("httpx", "-t"):
        cmd += ["-t", "50"]
    return cmd, [out_txt], log_file, True


def cmd_dnsx(out_dir: Path) -> Tuple[List[str], List[Path], Path, bool]:
    """Resolve subdomains from subfinder's subdomains.txt; waits up to 120 s in parallel mode."""
    raw_dir   = out_dir / "raw" / "dnsx"
    raw_dir.mkdir(parents=True, exist_ok=True)
    out_txt   = raw_dir / "resolved.txt"
    log_file  = raw_dir / "out.txt"
    subs_file = out_dir / "raw" / "subdomains" / "subdomains.txt"
    if not _wait_for_artifact(subs_file):
        return [], [out_txt], log_file, False
    cmd = ["dnsx", "-l", str(subs_file), "-o", str(out_txt), "-silent"]
    return cmd, [out_txt], log_file, True


def cmd_wafw00f(target: str, out_dir: Path) -> Tuple[List[str], List[Path], Path]:
    """Detect WAF. Exit 0 = WAF found, exit 1 = no WAF (both are valid results)."""
    raw_dir  = out_dir / "raw" / "wafw00f"
    raw_dir.mkdir(parents=True, exist_ok=True)
    log_file = raw_dir / "out.txt"
    cmd      = ["wafw00f", "-a", target]   # -a = check all WAFs
    return cmd, [log_file], log_file


def cmd_katana(target: str, out_dir: Path, profile_cfg: Dict) -> Tuple[List[str], List[Path], Path]:
    """JS-aware web crawler; writes urls.txt consumed by dalfox."""
    raw_dir  = out_dir / "raw" / "katana"
    raw_dir.mkdir(parents=True, exist_ok=True)
    out_txt  = raw_dir / "urls.txt"
    log_file = raw_dir / "out.txt"
    cmd      = ["katana", "-u", target, "-o", str(out_txt), "-silent"]
    depth    = profile_cfg.get("depth", 3)
    if help_supports("katana", "-d"):
        cmd += ["-d", str(depth)]
    if profile_cfg.get("js_crawl", True) and help_supports("katana", "-jc"):
        cmd += ["-jc"]
    max_resp = profile_cfg.get("max_response_size")
    if max_resp and help_supports("katana", "-mrs"):
        cmd += ["-mrs", str(max_resp)]
    return cmd, [out_txt], log_file


def cmd_testssl(target: str, out_dir: Path, profile_cfg: Dict) -> Tuple[List[str], List[Path], Path]:
    """Deep TLS analysis (testssl / testssl.sh); replaces sslscan in deep profile."""
    raw_dir  = out_dir / "raw" / "testssl"
    raw_dir.mkdir(parents=True, exist_ok=True)
    out_json = raw_dir / "out.json"
    log_file = raw_dir / "out.txt"
    host     = extract_host(target)
    severity = profile_cfg.get("severity", "MEDIUM")
    bin_path = shutil.which("testssl") or shutil.which("testssl.sh") or "testssl"
    cmd      = [bin_path, "--jsonfile", str(out_json), "--severity", severity, f"{host}:443"]
    return cmd, [out_json], log_file


def cmd_dalfox(target: str, out_dir: Path, profile_cfg: Dict) -> Tuple[List[str], List[Path], Path]:
    """XSS fuzzer; uses katana's urls.txt when available, else falls back to target URL."""
    raw_dir   = out_dir / "raw" / "dalfox"
    raw_dir.mkdir(parents=True, exist_ok=True)
    out_txt   = raw_dir / "out.txt"
    urls_file = out_dir / "raw" / "katana" / "urls.txt"
    if urls_file.exists() and urls_file.stat().st_size > 0:
        cmd = ["dalfox", "file", str(urls_file), "-o", str(out_txt), "--silence"]
    else:
        cmd = ["dalfox", "url",  target,          "-o", str(out_txt), "--silence"]
    workers = profile_cfg.get("workers", 20)
    if help_supports("dalfox", "--worker"):
        cmd += ["--worker", str(workers)]
    timeout = profile_cfg.get("timeout", 10)
    if help_supports("dalfox", "--timeout"):
        cmd += ["--timeout", str(timeout)]
    return cmd, [out_txt], out_txt


def cmd_sqlmap(target: str, out_dir: Path) -> Tuple[List[str], List[Path], Path]:
    """SQL injection detection via sqlmap --batch."""
    raw_dir    = out_dir / "raw" / "sqlmap"
    raw_dir.mkdir(parents=True, exist_ok=True)
    output_dir = raw_dir / "results"
    log_file   = raw_dir / "out.txt"
    cmd        = ["sqlmap", "-u", target, "--batch", "--output-dir", str(output_dir)]
    return cmd, [output_dir], log_file


# ---------------------------------------------------------------------------
# Scanner registry
# ---------------------------------------------------------------------------

SCANNERS: List[Tuple[str, str, str]] = [
    ("nmap_basic",  "Nmap (basic)",               "fast"),
    ("nmap_vulners","Nmap (vuln/vulners)",         "medium"),
    ("dirsearch",   "Dirsearch",                  "fast"),
    ("subdomains",  "Subdomain enumeration",       "fast"),
    ("dnsx",        "dnsx (DNS resolve)",          "fast"),
    ("httpx",       "httpx (live host probe)",     "fast"),
    ("whatweb",     "WhatWeb",                    "fast"),
    ("wafw00f",     "WAF detection",              "fast"),
    ("sslscan",     "SSLScan (443)",              "fast"),
    ("katana",      "Katana (JS crawler)",        "medium"),
    ("testssl",     "testssl (deep TLS)",         "medium"),
    ("nikto",       "Nikto (slow)",               "slow"),
    ("nuclei",      "Nuclei (slow)",              "slow"),
    ("dalfox",      "Dalfox XSS (slow)",          "slow"),
    ("sqlmap",      "sqlmap SQLi (slow)",          "slow"),
    ("all",         "ALL (recommended fast recon)","fast"),
]

# httpx and dnsx wait for subdomains.txt → keep them after subdomains
# wafw00f before dirsearch to detect WAF before brute-force
RECOMMENDED_ORDER_FAST = [
    "subdomains", "dnsx", "httpx",
    "whatweb", "wafw00f", "sslscan",
    "nmap_basic", "nmap_vulners", "dirsearch",
]
SLOW_STEPS = ["nikto", "nuclei", "dalfox", "sqlmap"]

STATUS_STYLE = {
    "queued":  "white",
    "running": "yellow",
    "done":    "green",
    "failed":  "red",
    "skipped": "grey50",
}


# ---------------------------------------------------------------------------
# State dataclasses
# ---------------------------------------------------------------------------

@dataclass
class Advanced:
    concurrency_targets: int = 3
    skip_existing: bool = False
    fail_fast: bool = False
    parallel: bool = True          # run steps concurrently
    seclists_path: Optional[str] = None


@dataclass
class AppState:
    target: str = ""
    profile: str = "fast"
    selected: List[str] = field(default_factory=lambda: ["all"])
    out_root: str = "./scans"
    advanced: Advanced = field(default_factory=Advanced)


# ---------------------------------------------------------------------------
# UI helpers
# ---------------------------------------------------------------------------

def _small_table(title: str) -> Table:
    return Table(title=title, box=box.MINIMAL_DOUBLE_HEAD, show_header=True, expand=False, padding=(0, 1))


def make_dashboard(state: AppState) -> Panel:
    t = _small_table("Scanner Orchestrator (SPEC-1 MVP)")
    t.add_column("Field", style="bold", width=18, no_wrap=True)
    t.add_column("Value", overflow="fold")
    t.add_row("Target",     state.target or "[grey50]<not set>[/]")
    t.add_row("Profile",    state.profile)
    t.add_row("Selected",   ", ".join(state.selected) if state.selected else "[grey50]<none>[/]")
    t.add_row("Output dir", state.out_root)
    adv = state.advanced
    adv_str = (
        f"parallel={adv.parallel}, concurrency={adv.concurrency_targets}, "
        f"skip_existing={adv.skip_existing}, fail_fast={adv.fail_fast}, "
        f"seclists={adv.seclists_path or '<auto/none>'}"
    )
    t.add_row("Advanced", adv_str)
    missing_tools = [TOOL_REGISTRY[k]["name"] for k in TOOL_REGISTRY if not _find_tool_bin(k)]
    if missing_tools:
        t.add_row("Tools", f"[red]missing: {', '.join(missing_tools)}[/]  →  menu 7 to install")
    else:
        t.add_row("Tools", "[green]all installed[/]")
    return Panel(Align.left(t), border_style="grey50", padding=(0, 1))


def make_menu() -> Panel:
    t = _small_table("Main menu")
    t.add_column("#", style="bold", width=3, no_wrap=True)
    t.add_column("Action", overflow="fold")
    t.add_row("1", "Set target")
    t.add_row("2", "Choose profile (fast/balanced/deep)")
    t.add_row("3", "Select scanners (custom subset)")
    t.add_row("4", "Run scan (selected / ALL fast)")
    t.add_row("5", "Run slow scans (Nikto / Nuclei / Dalfox / sqlmap)")
    t.add_row("6", "Advanced settings")
    t.add_row("7", "Check / install tools")
    t.add_row("0", "Exit")
    return Panel(Align.left(t), border_style="grey50", padding=(0, 1))


def make_scanners_table() -> Panel:
    t = _small_table("Scanners")
    t.add_column("ID",    style="bold", width=3,  no_wrap=True)
    t.add_column("Key",   width=14, no_wrap=True)
    t.add_column("Name",  overflow="fold")
    t.add_column("Speed", width=7, no_wrap=True)
    for i, (k, name, speed) in enumerate(SCANNERS, start=1):
        colour = "red" if speed == "slow" else ("yellow" if speed == "medium" else "white")
        t.add_row(str(i), k, f"[{colour}]{name}[/{colour}]", speed)
    cap = Text("Tip: ALL runs only fast recon steps. Use menu 5 for slow scans.", style="grey50")
    return Panel(Group(Align.left(t), cap), border_style="grey50", padding=(0, 1))


def prompt(console: Console, text: str, default: Optional[str] = None) -> str:
    if default is None or default == "":
        return console.input(text)
    return console.input(f"{text} [grey50]({default})[/] ") or default


def parse_scanner_choice(s: str) -> List[str]:
    s = s.strip()
    if not s:
        return []
    parts    = [p.strip() for p in s.split(",") if p.strip()]
    all_keys = [x[0] for x in SCANNERS]
    keys: List[str] = []
    for p in parts:
        if p.isdigit():
            idx = int(p) - 1
            if 0 <= idx < len(SCANNERS):
                keys.append(SCANNERS[idx][0])
        else:
            keys.append(p)
    if "all" in keys:
        return ["all"]
    out: List[str] = []
    for k in keys:
        if k in all_keys and k != "all":
            out.append(k)
    seen: set = set(); res: List[str] = []
    for k in out:
        if k not in seen:
            res.append(k); seen.add(k)
    return res


def plan_steps(state: AppState) -> List[str]:
    if not state.selected or "all" in state.selected:
        return RECOMMENDED_ORDER_FAST[:]
    return state.selected[:]


def plan_slow_steps() -> List[str]:
    return SLOW_STEPS[:]


def step_timeout_global(cfg: Dict, profile: str) -> int:
    return int(cfg_get(cfg, "profiles", profile, "step_timeout_sec", default=900))


def step_timeout_for(cfg: Dict, profile: str, step: str) -> int:
    base = step_timeout_global(cfg, profile)
    _map = {
        "nikto":   "nikto_timeout_sec",
        "nuclei":  "nuclei_timeout_sec",
        "dalfox":  "dalfox_timeout_sec",
        "sqlmap":  "sqlmap_timeout_sec",
        "testssl": "testssl_timeout_sec",
    }
    key = _map.get(step)
    if key:
        return int(cfg_get(cfg, "profiles", profile, key, default=base))
    return base


def ensure_run_dirs(state: AppState) -> Path:
    ts      = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    run_dir = Path(state.out_root).expanduser().resolve() / f"{ts}_{slugify(state.target)}"
    (run_dir / "raw").mkdir(parents=True, exist_ok=True)
    (run_dir / "reports").mkdir(parents=True, exist_ok=True)
    return run_dir


def build_step_cmd(step: str, state: AppState, cfg: Dict, run_dir: Path):
    """Return (cmd, artifacts, log_file, can_run, desc) for a given step."""
    prof = cfg_get(cfg, "profiles", state.profile, default={}) or {}

    if step == "nmap_basic":
        cmd, artifacts, log_file = cmd_nmap_basic(state.target, run_dir, prof.get("nmap_basic", {}))
        return (cmd, artifacts, log_file, True, f"nmap basic ({state.profile})")

    if step == "nmap_vulners":
        cmd, artifacts, log_file = cmd_nmap_vulners(state.target, run_dir, prof.get("nmap_vulners", {}))
        return (cmd, artifacts, log_file, True, f"nmap vulners ({state.profile})")

    if step == "subdomains":
        cmd, artifacts, log_file, dom = cmd_subdomains(state.target, run_dir)
        if not dom:
            return ([], artifacts, log_file, False, "subdomains skipped (no domain)")
        return (cmd, artifacts, log_file, True, f"subfinder on {dom}")

    if step == "whatweb":
        cmd, artifacts, log_file = cmd_whatweb(state.target, run_dir)
        return (cmd, artifacts, log_file, True, "whatweb")

    if step == "sslscan":
        cmd, artifacts, log_file = cmd_sslscan(state.target, run_dir)
        return (cmd, artifacts, log_file, True, "sslscan 443")

    if step == "dirsearch":
        seclists = Path(state.advanced.seclists_path).expanduser() if state.advanced.seclists_path else None
        cmd, artifacts, log_file = cmd_dirsearch(state.target, run_dir, cfg, state.profile, seclists)
        return (cmd, artifacts, log_file, True, "dirsearch (quiet json)")

    if step == "nikto":
        cmd, artifacts, log_file = cmd_nikto(state.target, run_dir)
        return (cmd, artifacts, log_file, True, "nikto (slow)")

    if step == "nuclei":
        nuclei_cfg = prof.get("nuclei", {}) or {}
        cmd, artifacts, log_file = cmd_nuclei(state.target, run_dir, nuclei_cfg)
        return (cmd, artifacts, log_file, True, "nuclei (slow)")

    # ── New tools ─────────────────────────────────────────────────────────

    if step == "httpx":
        cmd, artifacts, log_file, can_run = cmd_httpx(run_dir)
        desc = "httpx (live host probe)" if can_run else "httpx skipped (no subdomains.txt)"
        return (cmd, artifacts, log_file, can_run, desc)

    if step == "dnsx":
        cmd, artifacts, log_file, can_run = cmd_dnsx(run_dir)
        desc = "dnsx (DNS resolve)" if can_run else "dnsx skipped (no subdomains.txt)"
        return (cmd, artifacts, log_file, can_run, desc)

    if step == "wafw00f":
        cmd, artifacts, log_file = cmd_wafw00f(state.target, run_dir)
        return (cmd, artifacts, log_file, True, "wafw00f (WAF detection)")

    if step == "katana":
        katana_cfg = prof.get("katana", {}) or {}
        cmd, artifacts, log_file = cmd_katana(state.target, run_dir, katana_cfg)
        return (cmd, artifacts, log_file, True, "katana (JS crawl)")

    if step == "testssl":
        testssl_cfg = prof.get("testssl", {}) or {}
        cmd, artifacts, log_file = cmd_testssl(state.target, run_dir, testssl_cfg)
        return (cmd, artifacts, log_file, True, "testssl (deep TLS)")

    if step == "dalfox":
        dalfox_cfg = prof.get("dalfox", {}) or {}
        cmd, artifacts, log_file = cmd_dalfox(state.target, run_dir, dalfox_cfg)
        return (cmd, artifacts, log_file, True, "dalfox (XSS fuzz)")

    if step == "sqlmap":
        cmd, artifacts, log_file = cmd_sqlmap(state.target, run_dir)
        return (cmd, artifacts, log_file, True, "sqlmap (SQL injection)")

    raise ValueError(f"Unknown step: {step}")


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

def write_summary_json(run_dir: Path, summary: Dict) -> Path:
    p = run_dir / "reports" / "summary.json"
    p.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    return p


def render_html_report(run_dir: Path, summary: Dict) -> Path:
    tpl_dir = Path(__file__).parent / "templates"
    env     = Environment(loader=FileSystemLoader(str(tpl_dir)), autoescape=select_autoescape(["html"]))
    tpl     = env.get_template("report.html.j2")
    out     = run_dir / "reports" / "report.html"
    out.write_text(tpl.render(summary=summary), encoding="utf-8")
    return out


# ---------------------------------------------------------------------------
# Core runner (sequential or parallel)
# ---------------------------------------------------------------------------

def _step_outcome(step: str, rc: int, base_desc: str) -> Tuple[str, bool]:
    """Return (display_desc, is_success) for a completed step.

    Handles tools where a non-zero exit code is still a valid result
    (e.g. wafw00f exits 1 when no WAF is found).
    """
    if step == "wafw00f":
        if rc == 0:
            return "wafw00f: WAF detected", True
        if rc == 1:
            return "wafw00f: no WAF found", True
    return base_desc, (rc == 0)


def run_steps(steps: List[str], state: AppState, cfg: Dict, console: Console, title_suffix: str = "") -> Path:
    if not state.target:
        console.print("[red]Target is not set.[/]")
        raise RuntimeError("target not set")

    run_dir      = ensure_run_dirs(state)
    rows: Dict[str, Dict]   = {s: {"status": "queued", "elapsed": "-", "desc": ""} for s in steps}
    steps_results: Dict[str, Dict] = {}
    lock         = threading.Lock()
    stop_event   = threading.Event()

    def steps_table() -> Table:
        t = Table(
            title="Steps" + (f" {title_suffix}" if title_suffix else ""),
            box=box.MINIMAL_DOUBLE_HEAD, expand=False, padding=(0, 1),
        )
        t.add_column("Step",          style="bold", width=14, no_wrap=True)
        t.add_column("Status",        width=10, no_wrap=True)
        t.add_column("Elapsed",       width=9,  no_wrap=True)
        t.add_column("Note / Output", overflow="fold", width=48)
        for s in steps:
            st    = rows[s]["status"]
            style = STATUS_STYLE.get(st, "white")
            t.add_row(s, f"[{style}]{st}[/{style}]", rows[s]["elapsed"], rows[s]["desc"])
        return t

    bar = ProgressBar(total=len(steps), completed=0)
    txt = Text("Scanning 0%", style="bold")

    def render_ui() -> Group:
        done = sum(1 for s in steps if rows[s]["status"] in ("done", "failed", "skipped"))
        pct  = int(done / max(1, len(steps)) * 100)
        bar.completed = done
        txt.plain = f"Scanning {pct}%"
        return Group(
            Panel(Align.left(steps_table()), border_style="grey50", padding=(0, 1)),
            Panel(Group(Align.left(txt), bar), border_style="grey50", padding=(0, 1)),
        )

    summary: Dict = {
        "target":      state.target,
        "profile":     state.profile,
        "selected":    state.selected,
        "run_dir":     str(run_dir),
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "parallel":    state.advanced.parallel,
        "steps":       [],
    }

    def run_one(s: str) -> None:
        if stop_event.is_set():
            with lock:
                rows[s]["status"] = "skipped"
                rows[s]["desc"]   = "skipped (fail_fast)"
            steps_results[s] = {"step": s, "status": "skipped", "note": "fail_fast", "log_file": "", "tail": ""}
            return

        try:
            cmd, artifacts, log_file, can_run, desc = build_step_cmd(s, state, cfg, run_dir)
        except Exception as e:
            with lock:
                rows[s]["status"] = "failed"
                rows[s]["desc"]   = f"build error: {e}"
            steps_results[s] = {"step": s, "status": "failed", "note": str(e), "log_file": "", "tail": ""}
            if state.advanced.fail_fast:
                stop_event.set()
            return

        with lock:
            rows[s]["desc"] = desc

        if state.advanced.skip_existing and artifacts and all(
            (p.exists() if p.is_file() else (p.exists() and any(p.iterdir()))) for p in artifacts
        ):
            with lock:
                rows[s]["status"] = "skipped"
                rows[s]["desc"]   = "skipped (existing artifacts)"
            steps_results[s] = {
                "step": s, "status": "skipped", "note": "existing",
                "log_file": str(log_file), "tail": "",
            }
            return

        if not can_run or not cmd:
            with lock:
                rows[s]["status"] = "skipped"
                rows[s]["desc"]   = desc
            steps_results[s] = {
                "step": s, "status": "skipped", "note": desc,
                "log_file": str(log_file), "tail": "",
            }
            return

        with lock:
            rows[s]["status"]  = "running"
            rows[s]["elapsed"] = "0s"

        t0      = time.time()
        timeout = step_timeout_for(cfg, state.profile, s)
        rc, tail = run_cmd(cmd, log_file, timeout_sec=timeout)
        elapsed  = int(time.time() - t0)

        final_desc, ok = _step_outcome(s, rc, desc)
        status = "done" if ok else "failed"

        with lock:
            rows[s]["status"]  = status
            rows[s]["elapsed"] = f"{elapsed}s"
            rows[s]["desc"]    = final_desc

        steps_results[s] = {
            "step":        s,
            "status":      status,
            "exit_code":   rc,
            "elapsed_sec": elapsed,
            "cmd":         cmd,
            "log_file":    str(log_file),
            "tail":        tail,
        }

        if status == "failed" and state.advanced.fail_fast:
            stop_event.set()

    with Live(render_ui(), refresh_per_second=8, console=console, transient=False) as live:
        if state.advanced.parallel and len(steps) > 1:
            max_workers = min(len(steps), 6)
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [executor.submit(run_one, s) for s in steps]
                while any(not f.done() for f in futures):
                    live.update(render_ui())
                    time.sleep(0.125)
                for f in futures:
                    try:
                        f.result()
                    except Exception:
                        pass
        else:
            for s in steps:
                run_one(s)
                live.update(render_ui())
                if stop_event.is_set():
                    break
        live.update(render_ui())

    for s in steps:
        if s in steps_results:
            summary["steps"].append(steps_results[s])

    summary["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    summary_json = write_summary_json(run_dir, summary)
    fmt = cfg_get(cfg, "report", "format", default="both")
    if fmt in ("html", "both"):
        render_html_report(run_dir, summary)

    console.print("\n[bold]Run complete[/]")
    console.print(f"Summary: [cyan]{summary_json}[/]")
    html = run_dir / "reports" / "report.html"
    if html.exists():
        console.print(f"HTML report: [cyan]{html}[/]")

    return run_dir


# ---------------------------------------------------------------------------
# Interactive TUI menus
# ---------------------------------------------------------------------------

def menu_select_scanners(state: AppState, console: Console) -> None:
    console.clear()
    console.print(make_scanners_table())
    s = prompt(console, "Enter scanner IDs (comma-separated)", ",".join(state.selected) if state.selected else "all")
    chosen = parse_scanner_choice(s)
    if chosen:
        state.selected = chosen


def menu_profile(state: AppState, console: Console) -> None:
    console.clear()
    t = _small_table("Choose profile")
    t.add_column("#",       style="bold", width=3,  no_wrap=True)
    t.add_column("Profile", width=10, no_wrap=True)
    t.add_column("Meaning", overflow="fold")
    t.add_row("1", "fast",     "recon-like (fewer templates, lower rate)")
    t.add_row("2", "balanced", "reasonable depth")
    t.add_row("3", "deep",     "long scan (more ports/templates)")
    console.print(Panel(Align.left(t), border_style="grey50", padding=(0, 1)))
    ch = prompt(console, "Choose", "1").strip()
    state.profile = {"1": "fast", "2": "balanced", "3": "deep"}.get(ch, state.profile)


def menu_target(state: AppState, console: Console) -> None:
    console.clear()
    state.target = prompt(console, "Target (IP/CIDR/domain/URL)", state.target).strip()


def menu_advanced(state: AppState, console: Console) -> None:
    console.clear()
    adv = state.advanced
    t = _small_table("Advanced settings")
    t.add_column("#",       style="bold", width=3,  no_wrap=True)
    t.add_column("Setting", width=18, no_wrap=True)
    t.add_column("Value",   overflow="fold")
    t.add_row("1", "parallel",      str(adv.parallel))
    t.add_row("2", "concurrency",   str(adv.concurrency_targets))
    t.add_row("3", "skip_existing", str(adv.skip_existing))
    t.add_row("4", "fail_fast",     str(adv.fail_fast))
    t.add_row("5", "seclists_path", adv.seclists_path or "")
    t.add_row("0", "back", "")
    console.print(Panel(Align.left(t), border_style="grey50", padding=(0, 1)))
    ch = prompt(console, "Choose", "0").strip()
    if ch == "1":
        adv.parallel = not adv.parallel
    elif ch == "2":
        adv.concurrency_targets = int(prompt(console, "Enter concurrency", str(adv.concurrency_targets)))
    elif ch == "3":
        adv.skip_existing = not adv.skip_existing
    elif ch == "4":
        adv.fail_fast = not adv.fail_fast
    elif ch == "5":
        adv.seclists_path = (
            prompt(console, "Enter SecLists path (blank to clear)", adv.seclists_path or "").strip() or None
        )


def menu_check_tools(console: Console) -> None:
    """Interactive tool-check + one-click install screen."""
    while True:
        console.clear()
        statuses    = get_tool_status()
        rt_statuses = get_runtime_status()
        os_type     = detect_os()
        os_label    = _OS_LABELS.get(os_type, os_type)
        missing     = [s for s in statuses if not s["found"]]

        # Runtimes needed only by currently-missing tools
        needed_rt_keys = {
            TOOL_REGISTRY[s["key"]].get("runtime")
            for s in missing
            if TOOL_REGISTRY.get(s["key"], {}).get("runtime")
        }
        missing_rt     = [s for s in rt_statuses if s["key"] in needed_rt_keys and not s["found"]]
        installable_rt = [s for s in missing_rt if s["install_cmd"]]

        # Build unified ordered install list: runtimes first, then tools
        # Tools blocked by a missing runtime are included but flagged
        all_items: List[Dict] = []
        for s in installable_rt:
            all_items.append({**s, "_kind": "runtime"})
        for s in missing:
            if not s["install_cmd"]:
                continue
            tool_rt = TOOL_REGISTRY.get(s["key"], {}).get("runtime")
            blocked = bool(tool_rt and not _check_runtime(tool_rt))
            all_items.append({**s, "_kind": "tool", "_blocked": blocked, "_rt": tool_rt})

        # ── Runtime dependencies table (only if any needed) ─────────────────
        if missing_rt:
            rt_t = _small_table("Runtime Dependencies")
            rt_t.add_column("Runtime", width=11, no_wrap=True, style="bold")
            rt_t.add_column("Status",  width=8,  no_wrap=True)
            rt_t.add_column("Path / Install command", overflow="fold")
            for s in rt_statuses:
                if s["key"] not in needed_rt_keys:
                    continue
                if s["found"]:
                    rt_t.add_row(s["name"], "[green]found[/]", s["path"])
                else:
                    hint = s["install_cmd"] or "[grey50]install manually[/]"
                    rt_t.add_row(s["name"], "[red]missing[/]", hint)
            console.print(Panel(Align.left(rt_t), border_style="yellow", padding=(0, 1)))

        # ── Tool status table ────────────────────────────────────────────────
        t = _small_table("Tool Status")
        t.add_column("Tool",   width=11, no_wrap=True, style="bold")
        t.add_column("Status", width=8,  no_wrap=True)
        t.add_column("Path / Install command", overflow="fold")
        for s in statuses:
            if s["found"]:
                t.add_row(s["name"], "[green]found[/]", s["path"])
            else:
                tool_rt = TOOL_REGISTRY.get(s["key"], {}).get("runtime")
                if tool_rt and not _check_runtime(tool_rt):
                    rt_name = RUNTIME_REGISTRY.get(tool_rt, {}).get("name", tool_rt)
                    hint = f"[yellow]needs {rt_name} runtime — install it first[/]"
                else:
                    hint = s["install_cmd"] or "[grey50]see README / install manually[/]"
                t.add_row(s["name"], "[red]missing[/]", hint)

        # ── Actions table ────────────────────────────────────────────────────
        actions = _small_table("Actions")
        actions.add_column("#",      style="bold", width=3, no_wrap=True)
        actions.add_column("Action", overflow="fold")
        n_available = sum(1 for x in all_items if not x.get("_blocked"))
        if all_items:
            actions.add_row("1", f"Install ALL available  ({n_available} item(s))")
            for i, item in enumerate(all_items, start=2):
                if item["_kind"] == "runtime":
                    actions.add_row(str(i), f"[yellow]Install runtime {item['name']}[/]  —  {item['install_cmd']}")
                elif item.get("_blocked"):
                    rt_name = RUNTIME_REGISTRY.get(item["_rt"], {}).get("name", item["_rt"])
                    actions.add_row(str(i), f"[dim]Install {item['name']}  (blocked: {rt_name} missing)[/]")
                else:
                    actions.add_row(str(i), f"Install {item['name']}  —  {item['install_cmd']}")
        actions.add_row("0", "Back")

        footer = Text(f"Detected platform: {os_label}", style="grey50")
        console.print(Panel(Group(Align.left(t), footer), border_style="grey50", padding=(0, 1)))
        console.print(Panel(Align.left(actions), border_style="grey50", padding=(0, 1)))

        if not missing:
            console.print("[green]All tools are installed.[/]")
            console.input("\nPress Enter to return to menu...")
            return

        ch = prompt(console, "Choose", "0").strip()
        if ch == "0":
            return
        if ch == "1" and all_items:
            for item in all_items:
                if item.get("_blocked"):
                    continue
                label = f"runtime {item['name']}" if item["_kind"] == "runtime" else item["name"]
                console.print(f"\n[bold]Installing {label}...[/]")
                run_install(item["install_cmd"], console)
            console.input("\nPress Enter to continue...")
        else:
            try:
                idx = int(ch) - 2
                if 0 <= idx < len(all_items):
                    item = all_items[idx]
                    if item.get("_blocked"):
                        rt_name = RUNTIME_REGISTRY.get(item["_rt"], {}).get("name", item["_rt"])
                        console.print(f"[red]Cannot install {item['name']}: {rt_name} runtime is missing.[/]")
                        console.input("\nPress Enter to continue...")
                    else:
                        label = f"runtime {item['name']}" if item["_kind"] == "runtime" else item["name"]
                        console.print(f"\n[bold]Installing {label}...[/]")
                        run_install(item["install_cmd"], console)
                        console.input("\nPress Enter to continue...")
            except (ValueError, IndexError):
                pass


def main_loop() -> None:
    console = Console()
    cfg     = load_cfg(Path("config.yaml"))
    state   = AppState()

    while True:
        console.clear()
        console.print(make_dashboard(state))
        console.print(make_menu())
        ch = prompt(console, "Choose", "1").strip()
        if ch == "1":
            menu_target(state, console)
        elif ch == "2":
            menu_profile(state, console)
        elif ch == "3":
            menu_select_scanners(state, console)
        elif ch == "4":
            run_steps(plan_steps(state), state, cfg, console, title_suffix="(fast/all-selected)")
            console.input("\nPress Enter to return to menu...")
        elif ch == "5":
            console.clear()
            console.print(Panel(
                "[bold]Slow scans[/] (Nikto / Nuclei / Dalfox / sqlmap) may take a long time.",
                border_style="yellow", padding=(0, 1),
            ))
            if prompt(console, "Continue? [y/N]", "N").strip().lower() == "y":
                run_steps(plan_slow_steps(), state, cfg, console, title_suffix="(slow)")
                console.input("\nPress Enter to return to menu...")
        elif ch == "6":
            menu_advanced(state, console)
        elif ch == "7":
            menu_check_tools(console)
        elif ch == "0":
            break


# ---------------------------------------------------------------------------
# Typer commands
# ---------------------------------------------------------------------------

@app.callback(invoke_without_command=True)
def default(ctx: typer.Context) -> None:
    """Start interactive TUI (default when no subcommand given)."""
    if ctx.invoked_subcommand is None:
        main_loop()


@app.command("scan")
def scan_cmd(
    target:        str           = typer.Argument(...,    help="Target IP/domain/URL"),
    profile:       str           = typer.Option("fast",   help="Scan profile: fast|balanced|deep"),
    steps:         str           = typer.Option("all",    "--steps",        help="Comma-separated steps or 'all'"),
    out_root:      str           = typer.Option("./scans","--out",          help="Output directory"),
    parallel:      bool          = typer.Option(True,     "--parallel/--no-parallel", help="Run steps in parallel"),
    json_out:      bool          = typer.Option(False,    "--json",         is_flag=True, help="Print summary JSON to stdout"),
    seclists:      Optional[str] = typer.Option(None,     "--seclists",     help="SecLists path"),
    fail_fast:     bool          = typer.Option(False,    "--fail-fast",    help="Stop on first failure"),
    skip_existing: bool          = typer.Option(False,    "--skip-existing",help="Skip existing artifacts"),
) -> None:
    """Run a scan non-interactively (CLI / CI mode)."""
    from io import StringIO

    cfg   = load_cfg(Path("config.yaml"))
    state = AppState(
        target=target,
        profile=profile,
        selected=parse_scanner_choice(steps) or ["all"],
        out_root=out_root,
        advanced=Advanced(
            parallel=parallel,
            fail_fast=fail_fast,
            skip_existing=skip_existing,
            seclists_path=seclists,
        ),
    )
    planned = plan_steps(state)

    if json_out:
        quiet   = Console(file=StringIO(), force_terminal=False)
        run_dir = run_steps(planned, state, cfg, quiet)
        sp = run_dir / "reports" / "summary.json"
        typer.echo(
            sp.read_text(encoding="utf-8")
            if sp.exists()
            else json.dumps({"error": "no summary", "run_dir": str(run_dir)})
        )
    else:
        run_steps(planned, state, cfg, Console())


@app.command("serve")
def serve_cmd(
    host:     str = typer.Option("0.0.0.0", "--host", help="Bind host"),
    port:     int = typer.Option(8000,      "--port", help="Bind port"),
    out_root: str = typer.Option("./scans", "--out",  help="Output directory"),
) -> None:
    """Start the JSON REST API server (requires: pip install fastapi 'uvicorn[standard]')."""
    try:
        import uvicorn
        from fastapi import BackgroundTasks, FastAPI, HTTPException
        from pydantic import BaseModel
    except ImportError:
        typer.echo("Install API deps: pip install fastapi 'uvicorn[standard]'", err=True)
        raise typer.Exit(1)

    from io import StringIO

    api = FastAPI(title="Scanner Orchestrator API", version="1.0.0")
    cfg = load_cfg(Path("config.yaml"))

    _jobs: Dict[str, Dict] = {}
    _jobs_lock = threading.Lock()

    class ScanRequest(BaseModel):
        target:        str
        profile:       str           = "fast"
        steps:         str           = "all"
        parallel:      bool          = True
        fail_fast:     bool          = False
        skip_existing: bool          = False
        seclists_path: Optional[str] = None

    def _run_scan_bg(run_id: str, state: AppState) -> None:
        quiet = Console(file=StringIO(), force_terminal=False)
        try:
            with _jobs_lock:
                _jobs[run_id]["status"] = "running"
            planned = plan_steps(state)
            run_dir = run_steps(planned, state, cfg, quiet)
            sp      = run_dir / "reports" / "summary.json"
            summary = json.loads(sp.read_text(encoding="utf-8")) if sp.exists() else {}
            with _jobs_lock:
                _jobs[run_id].update({"status": "done", "summary": summary, "run_dir": str(run_dir)})
        except Exception as e:
            with _jobs_lock:
                _jobs[run_id].update({"status": "failed", "error": str(e)})

    @api.get("/api/health")
    def health():
        return {"status": "ok", "version": "1.0.0"}

    @api.post("/api/scan", status_code=202)
    def start_scan(req: ScanRequest):
        ts     = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
        run_id = f"{ts}_{slugify(req.target)}"
        state  = AppState(
            target=req.target,
            profile=req.profile,
            selected=parse_scanner_choice(req.steps) or ["all"],
            out_root=out_root,
            advanced=Advanced(
                parallel=req.parallel,
                fail_fast=req.fail_fast,
                skip_existing=req.skip_existing,
                seclists_path=req.seclists_path,
            ),
        )
        with _jobs_lock:
            _jobs[run_id] = {
                "run_id": run_id, "status": "queued",
                "target": req.target, "profile": req.profile,
            }
        threading.Thread(target=_run_scan_bg, args=(run_id, state), daemon=True).start()
        return {"run_id": run_id, "status": "queued"}

    @api.get("/api/scan/{run_id}")
    def get_scan(run_id: str):
        with _jobs_lock:
            job = _jobs.get(run_id)
        if not job:
            raise HTTPException(status_code=404, detail="run_id not found")
        return job

    @api.get("/api/scans")
    def list_scans():
        with _jobs_lock:
            return [
                {"run_id": k, "status": v["status"], "target": v.get("target"), "profile": v.get("profile")}
                for k, v in _jobs.items()
            ]

    typer.echo(f"Scanner Orchestrator API  →  http://{host}:{port}/api/health")
    typer.echo("Endpoints: POST /api/scan  |  GET /api/scan/<run_id>  |  GET /api/scans")
    uvicorn.run(api, host=host, port=port)


if __name__ == "__main__":
    raise SystemExit(app())
