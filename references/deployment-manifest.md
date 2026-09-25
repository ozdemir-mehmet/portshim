# Deployment Manifest

Everything needed to deploy PortShim on a Linux target.

> For what each tool is, which phase uses it, and which parts of the pipeline break when it
> is absent, see [`tool-dependencies.md`](tool-dependencies.md). This file only covers
> installation.

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

## Anthropic Cybersecurity Skills

```bash
python3 deploy.py             # installs them; --skip-skills omits them
```

These are Anthropic's own published cybersecurity skills, fetched from their repository.
They are not part of this tree, and nothing here depends on them being present.

## Harness → Your Agent

```bash
# No installer script ships. The harness is exposed to an agent with one shell
# alias and one instruction file — copy the two commands from
# references/agent-integration.md, section "Exposing it to an agent".
```

## Verify

```bash
nmap --version
nuclei --version
httpx --version
python -c "import openpyxl; print('OK')"
python3 portshim --help
python3 portshim discover --fast      # exercises the network path, read-only
```
