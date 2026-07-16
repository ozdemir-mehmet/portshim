# Deployment Manifest

Everything needed to deploy PortShim on a Linux target.

## Automatic (deploy.py)

```bash
python deploy.py          # Full install
python deploy.py --dry-run  # Preview only
```

## Manual Per-Distro

### Debian / Ubuntu
```bash
sudo apt update && sudo apt install -y nmap git golang-go python3 python3-pip nodejs npm graphviz
```

### RHEL / Fedora
```bash
sudo dnf install -y nmap git golang python3 python3-pip nodejs npm graphviz
```

### Arch
```bash
sudo pacman -S --noconfirm nmap git go python python-pip nodejs npm graphviz
```

### openSUSE
```bash
sudo zypper install -y nmap git go python3 python3-pip nodejs nodejs-npm graphviz
```

### Alpine
```bash
sudo apk add nmap git go python3 py3-pip nodejs npm graphviz
```

## Go Tools (All Distros)

```bash
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
nuclei -update-templates
```

## Python Dependencies

```bash
pip install openpyxl python-docx python-pptx pyyaml requests fpdf2
```

## nmap-vulners

```bash
mkdir -p ~/.nmap/scripts
git clone https://github.com/vulnersCom/nmap-vulners.git /tmp/nmap-vulners
cp /tmp/nmap-vulners/vulners.nse ~/.nmap/scripts/
nmap --script-updatedb
```

## Anthropic Skills

```bash
# See references/anthropic-skills-manifest.md for full command
# Or run: bash scripts/install-skills.sh
```

## Project Skills → Hermes

```bash
bash scripts/install-skills.sh
# Then in Hermes: /reload-skills
```

## Verify

```bash
nmap --version
nuclei --version
httpx --version
python -c "import openpyxl; print('OK')"
python scripts/check-skill-freshness.py
hermes skills list | grep site-assessment
```
