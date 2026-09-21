#!/usr/bin/env python3
"""
deploy.py — Distro-aware bootstrap for PortShim.

Detects the target Linux distribution, selects the correct package manager,
and installs all required system packages, Go tools, Python deps, and skills.

Usage:
    python deploy.py                           # Standard install (recon + lightweight exploit tools)
    python deploy.py --with-msf                # Also install Metasploit (1GB+)
    python deploy.py --dry-run                 # Show commands without executing
    python deploy.py --skip-go                 # Skip Go tool installs
    python deploy.py --skip-skills             # Skip Anthropic skill install

Supported distros: Debian/Ubuntu (apt), RHEL/Fedora (dnf), Arch (pacman),
                   openSUSE (zypper), Alpine (apk)

Lightweight exploit tools included in base install:
  - hydra        Network login cracker (SSH, HTTP, FTP brute-force)
  - sshpass      Non-interactive SSH password auth
  - paramiko     Python SSH automation library
  - nmap NSE     Vulners + brute-force scripts

Wireless assessment tools:
  - aircrack-ng, hcxdumptool, hcxtools, macchanger

Cracking tools:
  - hashcat, john, hashid

Network scanning:
  - masscan       Fast port scanner (1000x nmap speed)

Exploit lookup:
  - exploitdb     searchsploit CVE-to-exploit mapping

Optional add-ons:
  --with-msf     Metasploit Framework (full exploit database, 1GB+)
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

# Distro detection: known release files → package manager
DISTRO_MAP = {
    "/etc/debian_version": "apt",
    "/etc/redhat-release": "dnf",
    "/etc/fedora-release": "dnf",
    "/etc/arch-release": "pacman",
    "/etc/SuSE-release": "zypper",
    "/etc/alpine-release": "apk",
    "/etc/centos-release": "dnf",
}

# Package names per distro
PACKAGE_MAP = {
    "nmap": {"apt": "nmap", "dnf": "nmap", "pacman": "nmap", "zypper": "nmap", "apk": "nmap"},
    "git": {"apt": "git", "dnf": "git", "pacman": "git", "zypper": "git", "apk": "git"},
    "go": {"apt": "golang-go", "dnf": "golang", "pacman": "go", "zypper": "go", "apk": "go"},
    "python3": {"apt": "python3", "dnf": "python3", "pacman": "python", "zypper": "python3", "apk": "python3"},
    "pip": {"apt": "python3-pip", "dnf": "python3-pip", "pacman": "python-pip", "zypper": "python3-pip", "apk": "py3-pip"},
    "python3-venv": {"apt": "python3-venv", "dnf": "python3", "pacman": "python", "zypper": "python3", "apk": "python3"},
    "nodejs": {"apt": "nodejs", "dnf": "nodejs", "pacman": "nodejs", "zypper": "nodejs", "apk": "nodejs"},
    "npm": {"apt": "npm", "dnf": "npm", "pacman": "npm", "zypper": "npm", "apk": "npm"},
    "graphviz": {"apt": "graphviz", "dnf": "graphviz", "pacman": "graphviz", "zypper": "graphviz", "apk": "graphviz"},
    # Lightweight exploit tools (base install)
    "hydra": {"apt": "hydra", "dnf": "hydra", "pacman": "hydra", "zypper": "hydra", "apk": "hydra"},
    "sshpass": {"apt": "sshpass", "dnf": "sshpass", "pacman": "sshpass", "zypper": "sshpass", "apk": "sshpass"},
    # Wireless assessment tools (optional for portshim wireless)
    "aircrack-ng": {"apt": "aircrack-ng", "dnf": "aircrack-ng", "pacman": "aircrack-ng", "zypper": "aircrack-ng", "apk": "aircrack-ng"},
    # Wireless assessment tools
    "hcxdumptool": {"apt": "hcxdumptool", "dnf": "hcxdumptool", "pacman": "hcxdumptool", "zypper": "hcxdumptool", "apk": "hcxdumptool"},
    "hcxtools": {"apt": "hcxtools", "dnf": "hcxtools", "pacman": "hcxtools", "zypper": "hcxtools", "apk": "hcxtools"},
    "macchanger": {"apt": "macchanger", "dnf": "macchanger", "pacman": "macchanger", "zypper": "macchanger", "apk": "macchanger"},
    # Cracking tools
    "hashcat": {"apt": "hashcat", "dnf": "hashcat", "pacman": "hashcat", "zypper": "hashcat", "apk": "hashcat"},
    "john": {"apt": "john", "dnf": "john", "pacman": "john", "zypper": "john", "apk": "john"},
    # Network scanning
    "masscan": {"apt": "masscan", "dnf": "masscan", "pacman": "masscan", "zypper": "masscan", "apk": "masscan"},
    # Exploit lookup
    "exploitdb": {"apt": "exploitdb", "dnf": "exploitdb", "pacman": "exploitdb", "zypper": "exploitdb", "apk": "exploitdb"},
}

GO_TOOLS = [
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
]

PIP_PACKAGES = [
    "openpyxl",
    "python-docx",
    "python-pptx",
    "pyyaml",
    "requests",
    "fpdf2",
    "paramiko",
    "hashid",
]

# Anthropic skills to install (targeted — not all 817)
ANTHROPIC_SKILLS = [
    "conducting-wireless-network-penetration-test",
    "performing-wireless-security-assessment-with-kismet",
    "performing-wifi-password-cracking-with-aircrack",
    "scanning-network-with-nmap-advanced",
    "prioritizing-vulnerabilities-with-cvss-scoring",
    "conducting-full-scope-red-team-engagement",
    "executing-red-team-engagement-planning",
    "performing-privilege-escalation-on-linux",
    "performing-lateral-movement-with-wmiexec",
    "performing-cloud-penetration-testing-with-pacu",
    "performing-gcp-penetration-testing-with-gcpbucketbrute",
    "performing-kubernetes-penetration-testing",
    "performing-active-directory-vulnerability-assessment",
    "performing-endpoint-vulnerability-remediation",
    "building-vulnerability-aging-and-sla-tracking",
    "implementing-vulnerability-remediation-sla",
    "building-vulnerability-exception-tracking-system",
    "post-exploiting-microsoft-graph-with-graphrunner",
    "performing-red-team-phishing-with-gophish",
    "performing-threat-emulation-with-atomic-red-team",
    "red-teaming-llms-with-garak",
    "generating-threat-intelligence-reports",
    "detecting-lateral-movement-in-network",
    "detecting-privilege-escalation-attempts",
    "performing-aws-privilege-escalation-assessment",
]


def detect_distro() -> str | None:
    """Detect Linux distribution by probing release files."""
    for path, pkg_mgr in DISTRO_MAP.items():
        if os.path.exists(path):
            return pkg_mgr
    # Fallback: try common package managers
    for mgr in ["apt", "dnf", "pacman", "zypper", "apk"]:
        if shutil.which(mgr):
            return mgr
    return None


def run_cmd(cmd: list[str], dry_run: bool = False, critical: bool = False):
    """Run a command, or print it if dry-run. Raises on failure if critical."""
    print(f"  {'[DRY]' if dry_run else '[RUN]'} {' '.join(cmd)}")
    if not dry_run:
        result = subprocess.run(cmd, capture_output=False)
        if result.returncode != 0:
            msg = f"  ERROR: Command failed with exit {result.returncode}: {' '.join(cmd)}"
            if critical:
                raise RuntimeError(msg)
            print(f"  WARNING: {msg}", file=sys.stderr)


def install_system_packages(pkg_mgr: str, dry_run: bool = False, with_msf: bool = False):
    """Install required system packages."""
    base_pkgs = ["nmap", "git", "go", "python3", "pip", "python3-venv", "nodejs", "npm", "graphviz",
                  "hydra", "sshpass", "aircrack-ng", "hcxdumptool", "hcxtools", "macchanger",
                  "hashcat", "john", "masscan", "exploitdb"]
    packages = [PACKAGE_MAP[pkg][pkg_mgr] for pkg in base_pkgs
                if pkg_mgr in PACKAGE_MAP[pkg]]

    if pkg_mgr == "apt":
        run_cmd(["sudo", "apt", "update", "-qq"], dry_run)
        run_cmd(["sudo", "apt", "install", "-y"] + packages, dry_run)
    elif pkg_mgr == "dnf":
        run_cmd(["sudo", "dnf", "install", "-y"] + packages, dry_run)
    elif pkg_mgr == "pacman":
        run_cmd(["sudo", "pacman", "-S", "--noconfirm"] + packages, dry_run)
    elif pkg_mgr == "zypper":
        run_cmd(["sudo", "zypper", "install", "-y"] + packages, dry_run)
    elif pkg_mgr == "apk":
        run_cmd(["sudo", "apk", "add"] + packages, dry_run)

    # Optional: Metasploit (1GB+)
    if with_msf:
        print("  Installing Metasploit (this may take a while)...")
        if pkg_mgr == "apt":
            run_cmd(["sudo", "apt", "install", "-y", "metasploit-framework"], dry_run)
        elif pkg_mgr == "dnf":
            run_cmd(["sudo", "dnf", "install", "-y", "metasploit"], dry_run)
        elif pkg_mgr == "pacman":
            # Arch — Metasploit is in AUR, try paru/yay first
            for aur in ["paru", "yay"]:
                if shutil.which(aur):
                    run_cmd([aur, "-S", "--noconfirm", "metasploit"], dry_run)
                    break
            else:
                print("  WARNING: No AUR helper (paru/yay) found. Install Metasploit manually:")
                print("    git clone https://aur.archlinux.org/metasploit.git && cd metasploit && makepkg -si")
        elif pkg_mgr == "zypper":
            run_cmd(["sudo", "zypper", "install", "-y", "metasploit"], dry_run)
        elif pkg_mgr == "apk":
            print("  WARNING: Metasploit not available on Alpine. Use Docker or manual install.")


def install_go_tools(dry_run: bool = False):
    """Install Go-based security tools."""
    for tool in GO_TOOLS:
        run_cmd(["go", "install", tool], dry_run, critical=True)

    # Ensure ~/go/bin is in PATH for subsequent use in this session
    go_bin = Path.home() / "go" / "bin"
    go_bin_str = str(go_bin)
    current_path = os.environ.get("PATH", "")
    if go_bin_str not in current_path:
        os.environ["PATH"] = f"{go_bin_str}:{current_path}"


def ensure_go_bin_in_path(dry_run: bool = False):
    """Ensure ~/go/bin is in the user's PATH, shell-agnostic.

    Detects the active shell and writes the appropriate export syntax
    to its config file. Falls back to ~/.profile (POSIX) or prints
    instructions if no suitable config file is found.
    """
    go_bin = Path.home() / "go" / "bin"
    if not go_bin.exists():
        return

    go_bin_str = str(go_bin)
    current_path = os.environ.get("PATH", "")
    if go_bin_str in current_path:
        if not dry_run:
            print(f"  {go_bin_str} already in PATH.")
        return

    # ── Config files to try, ordered by shell-specific first ──
    shell = os.environ.get("SHELL", "")

    # Priority-ordered candidates: (path, export_line, description)
    candidates = [
        # Fish
        (Path.home() / ".config" / "fish" / "config.fish",
         f"\nset -gx PATH $PATH {go_bin_str}\n",
         "fish config"),
        # Zsh
        (Path.home() / ".zshrc",
         f"\nexport PATH=\"$PATH:{go_bin_str}\"\n",
         "zsh config"),
        # Bash (Linux default)
        (Path.home() / ".bashrc",
         f"\nexport PATH=\"$PATH:{go_bin_str}\"\n",
         "bash config"),
        # POSIX profile (sourced by sh, dash, ksh, and most login shells)
        (Path.home() / ".profile",
         f"\nexport PATH=\"$PATH:{go_bin_str}\"\n",
         "POSIX profile"),
    ]

    # If we know the shell, try its config first
    known = {"/bin/fish": 0, "/bin/zsh": 1, "/bin/bash": 2}
    if shell in known:
        # Move known shell to front of list
        idx = known[shell]
        candidates.insert(0, candidates.pop(idx))

    # Try each candidate config file
    for rc_path, export_line, label in candidates:
        if rc_path.exists():
            content = rc_path.read_text()
            if go_bin_str in content:
                if not dry_run:
                    print(f"  {go_bin_str} already in {rc_path.name} ({label}).")
                return
            if not dry_run:
                with open(rc_path, "a") as f:
                    f.write(export_line)
            print(f"  Added {go_bin_str} to {rc_path.name} ({label}).")
            print(f"  Run 'source {rc_path}' or restart your shell for changes to take effect.")
            return

    # No config file found at all — print universal instructions
    print(f"  WARNING: {go_bin_str} not in PATH and no shell config file found.")
    print(f"  Add this line to your shell's config file:")
    if shell == "/bin/fish":
        print(f"    set -gx PATH $PATH {go_bin_str}")
    else:
        print(f"    export PATH=\"$PATH:{go_bin_str}\"")
    if shell:
        print(f"  (detected shell: {shell})")


def _in_venv() -> bool:
    """Return True if running inside a virtual environment."""
    return sys.prefix != sys.base_prefix


def install_python_deps(dry_run: bool = False):
    """Install Python dependencies.

    On PEP 668 distros (Arch, Debian 12+, Fedora 38+), bare ``pip install``
    fails with ``externally-managed-environment``.  This function detects
    whether we are inside a venv, and if not, creates ``.venv`` in the
    project root and installs there.
    """
    project_root = Path(__file__).resolve().parent
    if _in_venv():
        # Already inside a virtual environment — use python -m pip.
        run_cmd([sys.executable, "-m", "pip", "install"] + PIP_PACKAGES, dry_run)
        return
    venv_dir = project_root / ".venv"
    pip_path = venv_dir / "bin" / "pip"
    if pip_path.exists():
        # Venv already set up — reuse.
        pass
    elif venv_dir.exists():
        # Stale venv (exists but no pip) — recreate with --clear.
        run_cmd([sys.executable, "-m", "venv", "--clear", str(venv_dir)],
                dry_run, critical=True)
    else:
        run_cmd([sys.executable, "-m", "venv", str(venv_dir)],
                dry_run, critical=True)
    python = str(venv_dir / "bin" / "python")
    run_cmd([python, "-m", "pip", "install"] + PIP_PACKAGES, dry_run)


def install_anthropic_skills(dry_run: bool = False):
    """Install targeted Anthropic cybersecurity skills via npx."""
    base_cmd = [
        "npx", "skills", "add",
        "mukul975/Anthropic-Cybersecurity-Skills",
        "--agent", "hermes-agent",
        "-g", "--copy", "-y",
    ]
    for skill in ANTHROPIC_SKILLS:
        base_cmd.extend(["--skill", skill])
    run_cmd(base_cmd, dry_run)


def install_nmap_vulners(dry_run: bool = False):
    """Install nmap-vulners NSE script."""
    import tempfile

    nmap_scripts = Path.home() / ".nmap" / "scripts"
    if not dry_run:
        nmap_scripts.mkdir(parents=True, exist_ok=True)

    vulners_path = nmap_scripts / "vulners.nse"
    if vulners_path.exists():
        print("  nmap-vulners already installed.")
        return

    tmpdir = Path(tempfile.mkdtemp(prefix="nmap-vulners-"))
    run_cmd([
        "git", "clone", "https://github.com/vulnersCom/nmap-vulners.git",
        str(tmpdir)
    ], dry_run)
    run_cmd([
        "cp", str(tmpdir / "vulners.nse"), str(vulners_path)
    ], dry_run)
    run_cmd(["nmap", "--script-updatedb"], dry_run)


def symlink_project_skills(dry_run: bool = False):
    """Symlink PortShim skills into Hermes skills directory."""
    hermes_skills = Path.home() / ".hermes" / "skills"
    project_skills = Path(__file__).resolve().parent / "skills"

    if not dry_run:
        hermes_skills.mkdir(parents=True, exist_ok=True)

    for skill_dir in project_skills.iterdir():
        if not skill_dir.is_dir():
            continue
        if skill_dir.name.startswith("."):
            continue

        # Determine category from directory name
        category = "devops"  # default — all PortShim skills are security/devops
        cat_dest = hermes_skills / category / skill_dir.name

        if cat_dest.exists():
            print(f"  Skill already linked: {skill_dir.name}")
            continue

        cat_dest.parent.mkdir(parents=True, exist_ok=True)

        if not dry_run:
            os.symlink(str(skill_dir.resolve()), str(cat_dest))
        print(f"  Linked: {skill_dir.name} → {cat_dest}")


def main():
    parser = argparse.ArgumentParser(description="PortShim — distro-aware deployment")
    parser.add_argument("--dry-run", action="store_true", help="Show commands without executing")
    parser.add_argument("--skip-go", action="store_true", help="Skip Go tool installs")
    parser.add_argument("--skip-skills", action="store_true", help="Skip Anthropic skill install")
    parser.add_argument("--skip-nmap-vulners", action="store_true", help="Skip nmap-vulners install")
    parser.add_argument("--with-msf", action="store_true", help="Also install Metasploit Framework (1GB+)")
    args = parser.parse_args()

    if sys.platform == "win32":
        print("deploy.py is designed for Linux targets. Detected Windows.")
        print("Run with --dry-run to see the install plan, then run on the Linux machine.")
        args.dry_run = True

    pkg_mgr = detect_distro()

    if pkg_mgr:
        print(f"Detected: {pkg_mgr}")
    else:
        print("WARNING: Could not detect package manager. Install manually:")
        print("  Packages: nmap, git, go, python3, pip, nodejs, npm, graphviz, hydra, sshpass, aircrack-ng, hcxdumptool, hcxtools, macchanger, hashcat, john, masscan, exploitdb")
        print("  Go tools: " + ", ".join(GO_TOOLS))
        print("  Python: " + ", ".join(PIP_PACKAGES))
        sys.exit(1)

    print("\n=== Phase 1: System Packages ===")
    print("  (includes: nmap, git, go, python, node, graphviz, hydra, sshpass, aircrack-ng, hcxdumptool, hcxtools, macchanger, hashcat, john, masscan, exploitdb)")
    if args.with_msf:
        print("  (Metasploit requested — this may take several minutes)")
    install_system_packages(pkg_mgr, args.dry_run, with_msf=args.with_msf)

    if not args.skip_go:
        print("\n=== Phase 2: Go Security Tools ===")
        install_go_tools(args.dry_run)
        print("\n=== Phase 2b: PATH Setup ===")
        ensure_go_bin_in_path(args.dry_run)

    print("\n=== Phase 3: Python Dependencies ===")
    print("  (includes: openpyxl, python-docx, python-pptx, paramiko, hashid)")
    install_python_deps(args.dry_run)

    if not args.skip_skills:
        print("\n=== Phase 4: Anthropic Cybersecurity Skills ===")
        install_anthropic_skills(args.dry_run)

    if not args.skip_nmap_vulners:
        print("\n=== Phase 5: nmap-vulners NSE ===")
        install_nmap_vulners(args.dry_run)

    print("\n=== Phase 6: PortShim Skills ===")
    symlink_project_skills(args.dry_run)

    print("\n" + "=" * 50)
    if args.dry_run:
        print("DRY RUN COMPLETE — no changes made.")
    else:
        print("DEPLOYMENT COMPLETE.")
        print("  Lightweight exploit tools: hydra, sshpass, paramiko")
        print("  Wireless: aircrack-ng, hcxdumptool, hcxtools, macchanger")
        print("  Cracking: hashcat, john")
        print("  Cracking (pip): hashid")
        print("  Scanning: masscan")
        print("  Exploit lookup: exploitdb")
        if args.with_msf:
            print("  Metasploit Framework: installed")
        else:
            print("  Metasploit: skipped (use --with-msf to include)")
        print("Run 'hermes' and load: /skill site-assessment-pipeline")
    print("=" * 50)


if __name__ == "__main__":
    main()
