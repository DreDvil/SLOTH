#!/usr/bin/env python3
# Scanner Orchestrator (SPEC-1 MVP)
# v16: parallel steps, JSON API (serve command), scan CLI command, help cache

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
# Scanner Orchestrator (SPEC-1 MVP) config (v16)
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
  balanced:
    step_timeout_sec: 1800
    nikto_timeout_sec: 900
    nuclei_timeout_sec: 1200
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
  deep:
    step_timeout_sec: 7200
    nikto_timeout_sec: 1800
    nuclei_timeout_sec: 3600
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


# Cache help text per binary (avoids spawning N subprocesses for N flags)
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
TOOL_REGISTRY: Dict[str, Dict] = {
    "nmap": {
        "name": "Nmap",      "desc": "Port scanner (basic + vulners)",
        "apt": "nmap",       "yum": "nmap",      "pacman": "nmap",
        "brew": "nmap",      "pip": None,         "go": None,
        "win": "choco install nmap  OR  https://nmap.org/download.html",
    },
    "nikto": {
        "name": "Nikto",     "desc": "Web vulnerability scanner (slow)",
        "apt": "nikto",      "yum": "nikto",     "pacman": None,
        "brew": "nikto",     "pip": None,         "go": None,
        "win": "WSL / Kali WSL recommended",
    },
    "sslscan": {
        "name": "SSLScan",   "desc": "TLS/SSL analysis",
        "apt": "sslscan",    "yum": None,        "pacman": "sslscan",
        "brew": "sslscan",   "pip": None,         "go": None,
        "win": "WSL / Kali WSL recommended",
    },
    "whatweb": {
        "name": "WhatWeb",   "desc": "Technology fingerprinting",
        "apt": "whatweb",    "yum": None,        "pacman": None,
        "brew": "whatweb",   "pip": None,         "go": None,
        "win": "WSL / Kali WSL recommended",
    },
    "dirsearch": {
        "name": "Dirsearch", "desc": "Directory brute-force",
        "apt": "dirsearch",  "yum": None,        "pacman": None,
        "brew": None,        "pip": "dirsearch",  "go": None,
        "win": "pip install dirsearch",
    },
    "subfinder": {
        "name": "Subfinder",  "desc": "Subdomain enumeration",
        "apt": None,          "yum": None,        "pacman": None,
        "brew": "subfinder",  "pip": None,
        "go": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder",
        "win": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    },
    "nuclei": {
        "name": "Nuclei",    "desc": "Template-based scanner (slow)",
        "apt": None,         "yum": None,        "pacman": None,
        "brew": "nuclei",    "pip": None,
        "go": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei",
        "win": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
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


def get_tool_status() -> List[Dict]:
    """Return status dict for every tool in TOOL_REGISTRY."""
    os_type = detect_os()
    result = []
    for key, info in TOOL_REGISTRY.items():
        path  = shutil.which(key)
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
            _get_help_text.cache_clear()   # so newly installed tool is picked up
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
    base = raw_dir / "out"
    artifacts = [base.with_suffix(".nmap"), base.with_suffix(".gnmap"), base.with_suffix(".xml")]
    host = extract_host(target)
    timing = profile.get("timing", "-T4")
    ports = profile.get("ports", "-F")
    extra = profile.get("extra", ["-sC", "-sV", "-Pn"])
    cmd = ["nmap", timing] + ports.split() + extra + ["-oA", str(base), host]
    return cmd, artifacts, (raw_dir / "out.txt")


def cmd_nmap_vulners(target: str, out_dir: Path, profile: Dict) -> Tuple[List[str], List[Path], Path]:
    raw_dir = out_dir / "raw" / "nmap_vulners"
    raw_dir.mkdir(parents=True, exist_ok=True)
    base = raw_dir / "out"
    artifacts = [base.with_suffix(".nmap"), base.with_suffix(".gnmap"), base.with_suffix(".xml")]
    host = extract_host(target)
    timing = profile.get("timing", "-T4")
    ports = profile.get("ports", "-p 80,443")
    extra = profile.get("extra", ["-Pn", "--script", "vulners"])
    cmd = ["nmap", timing] + ports.split() + extra + ["-oA", str(base), host]
    return cmd, artifacts, (raw_dir / "out.txt")


def cmd_subdomains(target: str, out_dir: Path) -> Tuple[List[str], List[Path], Path, Optional[str]]:
    raw_dir = out_dir / "raw" / "subdomains"
    raw_dir.mkdir(parents=True, exist_ok=True)
    out_txt = raw_dir / "subdomains.txt"
    domain = registrable_domain_from_target(target)
    if not domain:
        return ([], [out_txt], (raw_dir / "out.txt"), None)
    cmd = ["subfinder", "-silent", "-d", domain, "-o", str(out_txt)]
    return cmd, [out_txt], (raw_dir / "out.txt"), domain


def cmd_whatweb(target: str, out_dir: Path) -> Tuple[List[str], List[Path], Path]:
    raw_dir = out_dir / "raw" / "whatweb"
    raw_dir.mkdir(parents=True, exist_ok=True)
    out_json = raw_dir / "out.json"
    cmd = ["whatweb", "-a", "3", "--log-json", str(out_json), target]
    return cmd, [out_json], (raw_dir / "out.txt")


def cmd_sslscan(target: str, out_dir: Path) -> Tuple[List[str], List[Path], Path]:
    raw_dir = out_dir / "raw" / "sslscan"
    raw_dir.mkdir(parents=True, exist_ok=True)
    out_xml = raw_dir / "out.xml"
    host = extract_host(target)
    cmd = ["sslscan", "--xml=" + str(out_xml), f"{host}:443"]
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
    raw_dir = out_dir / "raw" / "dirsearch"
    raw_dir.mkdir(parents=True, exist_ok=True)
    out_json = raw_dir / "out.json"
    out_txt = raw_dir / "out.txt"
    ds = cfg_get(cfg, "dirsearch", default={}) or {}
    mode = ds.get("wordlist_mode", "default")
    include_status = ds.get("include_status")
    exclude_status = ds.get("exclude_status")
    follow = bool(ds.get("follow_redirects", True))
    max_redir = int(ds.get("max_redirects", 3))
    threads = ds.get(f"threads_{profile_name}", ds.get("threads_fast", 25))
    threads = str(int(threads))

    cmd = [
        "dirsearch",
        "-u", target,
        "-e", "php,asp,aspx,html,js,txt",
        "-f",
        "--format", "json",
        "-o", str(out_json),
    ]

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
            raise RuntimeError(
                f"Dirsearch wordlist not found under SecLists: "
                f"{seclists_path}/Discovery/Web-Content/*directory-list-2.3-medium*"
            )
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
    cmd = ["nikto", "-h", target, "-output", str(out_txt)]
    return cmd, [out_txt], out_txt


def cmd_nuclei(target: str, out_dir: Path, profile_cfg: Dict) -> Tuple[List[str], List[Path], Path]:
    raw_dir = out_dir / "raw" / "nuclei"
    raw_dir.mkdir(parents=True, exist_ok=True)
    out_txt = raw_dir / "out.txt"
    cmd = ["nuclei", "-u", target]

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


# ---------------------------------------------------------------------------
# Scanner registry
# ---------------------------------------------------------------------------

SCANNERS: List[Tuple[str, str, str]] = [
    ("nmap_basic",  "Nmap (basic)",               "fast"),
    ("nmap_vulners","Nmap (vuln/vulners)",         "medium"),
    ("dirsearch",   "Dirsearch",                  "fast"),
    ("subdomains",  "Subdomain enumeration",       "fast"),
    ("whatweb",     "WhatWeb",                    "fast"),
    ("sslscan",     "SSLScan (443)",              "fast"),
    ("nikto",       "Nikto (slow)",               "slow"),
    ("nuclei",      "Nuclei (slow)",              "slow"),
    ("all",         "ALL (recommended fast recon)","fast"),
]

RECOMMENDED_ORDER_FAST = ["subdomains", "whatweb", "sslscan", "nmap_basic", "nmap_vulners", "dirsearch"]
SLOW_STEPS = ["nikto", "nuclei"]

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
        f"parallel={adv.parallel}, "
        f"concurrency={adv.concurrency_targets}, "
        f"skip_existing={adv.skip_existing}, "
        f"fail_fast={adv.fail_fast}, "
        f"seclists={adv.seclists_path or '<auto/none>'}"
    )
    t.add_row("Advanced", adv_str)
    missing_tools = [TOOL_REGISTRY[k]["name"] for k in TOOL_REGISTRY if not shutil.which(k)]
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
    t.add_row("5", "Run slow scans (Nikto/Nuclei)")
    t.add_row("6", "Advanced settings")
    t.add_row("7", "Check / install tools")
    t.add_row("0", "Exit")
    return Panel(Align.left(t), border_style="grey50", padding=(0, 1))


def make_scanners_table() -> Panel:
    t = _small_table("Scanners")
    t.add_column("ID",    style="bold", width=3,  no_wrap=True)
    t.add_column("Key",   width=14, no_wrap=True)
    t.add_column("Name",  overflow="fold")
    t.add_column("Speed", width=6, no_wrap=True)
    for i, (k, name, speed) in enumerate(SCANNERS, start=1):
        style = "red" if speed == "slow" else "white"
        t.add_row(str(i), k, f"[{style}]{name}[/{style}]" if speed == "slow" else name, speed)
    cap = Text("Tip: ALL runs only fast recon steps. Use menu item 5 for slow scans.", style="grey50")
    return Panel(Group(Align.left(t), cap), border_style="grey50", padding=(0, 1))


def prompt(console: Console, text: str, default: Optional[str] = None) -> str:
    if default is None or default == "":
        return console.input(text)
    return console.input(f"{text} [grey50]({default})[/] ") or default


def parse_scanner_choice(s: str) -> List[str]:
    s = s.strip()
    if not s:
        return []
    parts = [p.strip() for p in s.split(",") if p.strip()]
    keys: List[str] = []
    all_keys = [x[0] for x in SCANNERS]
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
    if step == "nikto":
        return int(cfg_get(cfg, "profiles", profile, "nikto_timeout_sec", default=base))
    if step == "nuclei":
        return int(cfg_get(cfg, "profiles", profile, "nuclei_timeout_sec", default=base))
    return base


def ensure_run_dirs(state: AppState) -> Path:
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    run_dir = Path(state.out_root).expanduser().resolve() / f"{ts}_{slugify(state.target)}"
    (run_dir / "raw").mkdir(parents=True, exist_ok=True)
    (run_dir / "reports").mkdir(parents=True, exist_ok=True)
    return run_dir


def build_step_cmd(step: str, state: AppState, cfg: Dict, run_dir: Path):
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
    raise ValueError(step)


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

def write_summary_json(run_dir: Path, summary: Dict) -> Path:
    p = run_dir / "reports" / "summary.json"
    p.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    return p


def render_html_report(run_dir: Path, summary: Dict) -> Path:
    tpl_dir = Path(__file__).parent / "templates"
    env = Environment(loader=FileSystemLoader(str(tpl_dir)), autoescape=select_autoescape(["html"]))
    tpl = env.get_template("report.html.j2")
    out = run_dir / "reports" / "report.html"
    out.write_text(tpl.render(summary=summary), encoding="utf-8")
    return out


# ---------------------------------------------------------------------------
# Core runner (sequential or parallel)
# ---------------------------------------------------------------------------

def run_steps(steps: List[str], state: AppState, cfg: Dict, console: Console, title_suffix: str = "") -> Path:
    if not state.target:
        console.print("[red]Target is not set.[/]")
        raise RuntimeError("target not set")

    run_dir = ensure_run_dirs(state)
    rows: Dict[str, Dict] = {s: {"status": "queued", "elapsed": "-", "desc": ""} for s in steps}
    steps_results: Dict[str, Dict] = {}
    lock = threading.Lock()
    stop_event = threading.Event()

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
            st = rows[s]["status"]
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

    # ------------------------------------------------------------------
    # Worker: runs one step, updates rows + steps_results (thread-safe)
    # ------------------------------------------------------------------
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

        if state.advanced.skip_existing and artifacts and all(p.exists() for p in artifacts):
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

        status = "done" if rc == 0 else "failed"
        with lock:
            rows[s]["status"]  = status
            rows[s]["elapsed"] = f"{elapsed}s"
            rows[s]["desc"]    = desc

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

    # ------------------------------------------------------------------
    # Live display + execution (sequential or parallel)
    # ------------------------------------------------------------------
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

    # Preserve original step order in summary
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
    t.add_row("1", "parallel",    str(adv.parallel))
    t.add_row("2", "concurrency", str(adv.concurrency_targets))
    t.add_row("3", "skip_existing", str(adv.skip_existing))
    t.add_row("4", "fail_fast",   str(adv.fail_fast))
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
    """Interactive tool check + one-click install screen."""
    while True:
        console.clear()
        statuses    = get_tool_status()
        os_type     = detect_os()
        os_label    = _OS_LABELS.get(os_type, os_type)
        missing     = [s for s in statuses if not s["found"]]
        installable = [s for s in missing  if s["install_cmd"]]

        # ── Status table ──────────────────────────────────────────────────
        t = _small_table("Tool Status")
        t.add_column("Tool",   width=11, no_wrap=True, style="bold")
        t.add_column("Status", width=8,  no_wrap=True)
        t.add_column("Path / Install command", overflow="fold")
        for s in statuses:
            if s["found"]:
                t.add_row(s["name"], "[green]found[/]",   s["path"])
            else:
                hint = s["install_cmd"] or "[grey50]see README / install manually[/]"
                t.add_row(s["name"], "[red]missing[/]", hint)

        # ── Action table ──────────────────────────────────────────────────
        actions = _small_table("Actions")
        actions.add_column("#",      style="bold", width=3, no_wrap=True)
        actions.add_column("Action", overflow="fold")
        if installable:
            actions.add_row("1", f"Install ALL missing  ({len(installable)} tool(s))")
            for i, s in enumerate(installable, start=2):
                actions.add_row(str(i), f"Install {s['name']}  —  {s['install_cmd']}")
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
        if ch == "1" and installable:
            for s in installable:
                console.print(f"\n[bold]Installing {s['name']}...[/]")
                run_install(s["install_cmd"], console)
            console.input("\nPress Enter to continue...")
        else:
            try:
                idx = int(ch) - 2
                if 0 <= idx < len(installable):
                    s = installable[idx]
                    console.print(f"\n[bold]Installing {s['name']}...[/]")
                    run_install(s["install_cmd"], console)
                    console.input("\nPress Enter to continue...")
            except (ValueError, IndexError):
                pass


def main_loop() -> None:
    console = Console()
    cfg = load_cfg(Path("config.yaml"))
    state = AppState()

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
                "[bold]Slow scans[/] Nikto and Nuclei may take a long time depending on target/WAF/CDN.",
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
    target:        str           = typer.Argument(...,   help="Target IP/domain/URL"),
    profile:       str           = typer.Option("fast",  help="Scan profile: fast|balanced|deep"),
    steps:         str           = typer.Option("all",   "--steps",         help="Comma-separated steps or 'all'"),
    out_root:      str           = typer.Option("./scans","--out",           help="Output directory"),
    parallel:      bool          = typer.Option(True,    "--parallel/--no-parallel", help="Run steps in parallel"),
    json_out:      bool          = typer.Option(False,   "--json",           is_flag=True, help="Print summary JSON to stdout"),
    seclists:      Optional[str] = typer.Option(None,    "--seclists",       help="SecLists path"),
    fail_fast:     bool          = typer.Option(False,   "--fail-fast",      help="Stop on first failure"),
    skip_existing: bool          = typer.Option(False,   "--skip-existing",  help="Skip existing artifacts"),
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
        # Suppress Rich TUI output; print summary JSON to stdout
        quiet = Console(file=StringIO(), force_terminal=False)
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
            sp = run_dir / "reports" / "summary.json"
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
                "run_id":  run_id,
                "status":  "queued",
                "target":  req.target,
                "profile": req.profile,
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
