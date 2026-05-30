```
██████╗  ██████╗ ███████╗████████╗███╗   ███╗ ██████╗ ██████╗ ████████╗███████╗███╗   ███╗
██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝████╗ ████║██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝████╗ ████║
██████╔╝██║   ██║███████╗   ██║   ██╔████╔██║██║   ██║██████╔╝   ██║   █████╗  ██╔████╔██║
██╔═══╝ ██║   ██║╚════██║   ██║   ██║╚██╔╝██║██║   ██║██╔══██╗   ██║   ██╔══╝  ██║╚██╔╝██║
██║     ╚██████╔╝███████║   ██║   ██║ ╚═╝ ██║╚██████╔╝██║  ██║   ██║   ███████╗██║ ╚═╝ ██║
╚═╝      ╚═════╝ ╚══════╝   ╚═╝   ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝     ╚═╝

                     ██████╗██╗     ██╗
                    ██╔════╝██║     ██║
                    ██║     ██║     ██║
                    ██║     ██║     ██║
                    ╚██████╗███████╗██║
                     ╚═════╝╚══════╝╚═╝

                    PostmortemCLI v0.2.5-beta
                       by Filip Andersson, 2026
                  Email Security Analysis Tool for SMHI
```

# PostmortemCLI – Email Security Analyzer

> Diploma project – Chas Academy SUVX24  
> Developed by Filip Andersson, 2026  
> Client: SMHI IT Security

PostmortemCLI is a containerized CLI tool for structured, automated security
analysis of email files. It receives, parses and analyzes `.eml` and `.msg`
files for indicators of phishing, malware, spoofing and other email-based
threats – without storing any data or sending raw content to external services.

Built as a final graduation project at Chas Academy (program SUVX24), developed
at the request of SMHI's IT security function with a need for standardized,
GDPR-compliant email threat analysis tooling suitable for service desk use.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Threat Intelligence Sources](#threat-intelligence-sources)
- [Verdicts](#verdicts)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [GDPR and Data Handling](#gdpr-and-data-handling)
- [Project Structure](#project-structure)
- [Running Tests](#running-tests)
- [Releasing a New Version](#releasing-a-new-version)
- [Private Registry / Enterprise Deployment](#private-registry--enterprise-deployment)
- [Disclaimer](#disclaimer)
- [Copyright](#copyright)

---

## Overview

Email remains one of the most exploited attack vectors against organizations.
PostmortemCLI provides a standardized, sandboxed method for analyzing suspicious
emails – extracting metadata, verifying authentication mechanisms, identifying
threat indicators and producing a structured verdict – all within an isolated
container that self-destructs after each session.

The tool is stateless by design: no email content, attachments or headers are
retained after analysis. Only anonymized identifiers – IP addresses, SHA256
hashes and URL strings – are sent to external threat intelligence sources.
Raw email content never leaves the system.

---

## Features

- Receives `.eml` and `.msg` files via SMTP listener or direct file scan
- Parses SMTP headers per RFC 822, including full Received-chain analysis
- Extracts body text, HTML, URLs (via regex and href attributes) and attachments
- Verifies SPF, DKIM (cryptographic signature via dkimpy) and DMARC via DNS
- Checks sender IP, URLs and attachment hashes against nine threat intelligence sources
- Generates a structured **Post-Mortem Incident Report** with unique report ID
- Delivers a clear security verdict with plain-language explanation
- Includes a GDPR declaration in every report specifying exactly what data was sent externally
- Interactive CLI with SMTP listener running as background daemon thread
- Cross-platform launcher: Windows, Linux, macOS
- Automatic public/private registry detection (`--pull never` for private registries)
- Containerized, stateless – self-destructs on exit (`--rm`)
- 194 unit tests, ~1.5 seconds runtime

---

## Threat Intelligence Sources

| Source | Type | Checks | API Key |
|---|---|---|---|
| Spamhaus ZEN | DNSBL | Sender IP | No |
| Spamhaus DBL | DNSBL | URL domains | No |
| URLhaus | REST API | Malware URLs | No |
| MalwareBazaar | REST API | Attachment hashes (SHA256) | No |
| ThreatFox | REST API | IPs, domains, hashes | No |
| AbuseIPDB | REST API | IP abuse confidence score | Optional |
| VirusTotal | REST API | URL / file / IP – 70+ AV engines | Required |
| EmailRep | REST API | Sender address reputation | Optional |
| Google Safe Browsing | REST API | Phishing / malware URLs | Required |

---

## Verdicts

| Verdict | Criteria |
|---|---|
| `MOST LIKELY SAFE` | SPF, DKIM and DMARC pass. No known threat indicators in URLs, attachments or headers. |
| `MOST LIKELY UNSAFE` | At least one confirmed negative signal: SPF fail, known malware hash, URL on blocklist, clear header manipulation. |
| `FURTHER ANALYSIS REQUIRED` | Mixed signals: e.g. DMARC absent but SPF passes, or unknown file type in attachment without known signature. |

---

## Architecture

```
postmortemcli start / scan / listen          (host machine)
        │
        ▼
launcher.py                  detects platform (Windows/Linux/macOS)
        │                    detects runtime (Podman / Docker)
        │                    detects registry (public / private)
        │
        ▼
Docker / Podman              starts isolated container
        │                    -it --rm -v $(pwd):/data -p 1025:1025
        │
        ▼
main.py                      CLI coordinator inside container
        │                    verify_container_environment()
        │                    dictionary-based command dispatcher
        │
        ├── smtp_reciever.py  aiosmtpd SMTP handler on port 1025 (daemon thread)
        │        │            handle_DATA() – raw bytes preserved for DKIM
        │        ▼
        ├── parser.py         RFC 822 headers, MIME body, URLs, attachments
        │        │            .msg → extract-msg → RFC 822 normalization
        │        ▼
        ├── analyzer.py       nine threat intelligence checks
        │        │            check_headers / check_authentication
        │        │            check_reputation / check_urls / check_attachments
        │        │            _calculate_verdict()
        │        ▼
        └── reporter.py       Post-Mortem Incident Report
                              PMRT-YYYYMMDD-HHMMSS unique report ID
                              GDPR declaration per report

postmortemcli send <file>    (host machine – separate terminal)
        │
        └── smtplib → localhost:1025 → smtp_reciever.py inside container
```

**Tech stack:** Python 3.12, aiosmtpd, dnspython, dkimpy, extract-msg, requests  
**Container runtime:** Docker / Podman  
**Threat sources:** Spamhaus, URLhaus, MalwareBazaar, ThreatFox, AbuseIPDB,
VirusTotal, EmailRep, Google Safe Browsing

---

## Installation

### Requirements

- Python 3.10 or higher
- Docker Desktop (Windows/macOS) or Podman (Linux)

### Install from GitHub

```bash
pip install git+https://github.com/Filipanderssondev/PostmortemCLI-email-security-analyzer.git
```

The container image is pulled automatically on first run from Docker Hub.

### Environment variables (optional API keys)

```bash
cp .env.example .env
# Edit .env with your API keys
```

```env
ABUSEIPDB_API_KEY=your_key         # abuseipdb.com – free tier
VIRUSTOTAL_API_KEY=your_key        # virustotal.com – free tier
EMAILREP_API_KEY=your_key          # emailrep.io – optional
GOOGLE_SAFE_BROWSING_KEY=your_key  # console.cloud.google.com – free tier
```

The tool runs without API keys. Sources requiring keys are gracefully skipped
if not configured.

---

## Usage

### Start the tool

```bash
postmortemcli start
```

Starts the container, launches the SMTP listener on port 1025 and opens the
interactive prompt.

### Scan files directly

```bash
# From inside the interactive prompt
postmortemcli > scan /data/suspicious.eml
postmortemcli > scan /data/a.eml /data/b.msg
```

### Send files to the running listener (second terminal)

```bash
# While postmortemcli start is running in Terminal 1
postmortemcli send suspicious.eml invoice.msg
```

The file is sent via SMTP to the running container on localhost:1025.
Analysis output appears in Terminal 1 together with the full incident report.

### Available commands inside the prompt

```
scan <file> [files...]   Analyze one or more email files (.eml or .msg)
send <file> [files...]   Send files to SMTP listener
listen                   Restart SMTP listener
help                     Show available commands
exit                     Quit and destroy container
```

### Exit

```bash
postmortemcli > exit
```

Container shuts down and removes itself automatically. No data is retained.

---

## Configuration

### Override the container image

```bash
export POSTMORTEM_IMAGE=your-registry/your-image:tag
```

Add to `~/.bashrc` to make it permanent.

Private registries are detected automatically. If the image address does not
match a known public registry (docker.io, ghcr.io), the launcher passes
`--pull never` to prevent network pull attempts and uses the locally available
image.

---

## GDPR and Data Handling

PostmortemCLI is designed with GDPR compliance as a first-class architectural
constraint.

**What is sent externally:**
- IP addresses (from Received headers) → Spamhaus, ThreatFox, AbuseIPDB, VirusTotal
- SHA256 hashes of attachments → MalwareBazaar, ThreatFox, VirusTotal
- URL strings → URLhaus, ThreatFox, VirusTotal, Google Safe Browsing
- Sender email address → EmailRep (legitimate interest basis)

**What is never sent externally:**
- Email body content
- Attachment content
- Recipient addresses
- Subject line

**No data is stored.** The container runs with `--rm` – the entire runtime
environment is destroyed on exit. No logs, no session data, no email content
persists between sessions.

Every generated report includes a GDPR declaration specifying exactly which
data was sent to which external service during that specific analysis.

---

## Project Structure

```
├── launcher.py                    Host entrypoint – platform, runtime and registry detection
├── main.py                        Container CLI coordinator
├── release.py                     Version bump, commit, tag and push automation
├── pyproject.toml                 Package configuration and dependencies
├── requirements.txt               Container Python dependencies
├── Dockerfile                     Container build definition
├── .env.example                   API key template
├── src/
│   ├── parser.py                  RFC 822 parsing – headers, body, URLs, attachments
│   ├── smtp_reciever.py           aiosmtpd SMTP handler – handle_DATA, raw bytes
│   ├── logger.py                  Centralized logging – terminal + session file
│   ├── analyzer.py                Threat analysis – nine sources, verdict logic
│   └── reporter.py                Post-Mortem Incident Report generation
├── tests/
│   ├── pytest/                    Unit tests (194 tests, ~1.5s, no network required)
│   └── samples/                   Test email files (.eml, .msg)
└── private-registry-setup/        Enterprise deployment example scripts
    ├── setup.example.sh
    └── .env.example
```

---

## Running Tests

```bash
# Unit tests – no network required, all external calls mocked
pytest

# Full test suite with coverage
pytest --cov=src
```

---

## Releasing a New Version

```bash
python release.py 0.3.4-beta
```

This automatically:
1. Scans all project files for the current version string
2. Replaces with the new version
3. Commits the changes
4. Creates and pushes a git tag
5. Triggers CI/CD → Docker Hub

CI/CD (GitHub Actions) runs tests on every push and builds the container image
only on tag push.

---

## Private Registry / Enterprise Deployment

Example scripts for deploying PostmortemCLI in a restricted enterprise
environment with a private container registry, mandatory security scanning
and no direct internet access from the target machine.

This is the pattern used during development against a real government
IT environment. Generalized here for reuse.

> **Note:** Requires Linux on both local machine and image server.
> PostmortemCLI itself runs on Windows, Linux and macOS.

### How it works

```
Docker Hub
    │
    │  [1] Trivy scan (on image server via SSH)
    ▼
Image server (SSH access)
    │
    │  [2] buildah pull → buildah tag → buildah push
    ▼
Private registry (Harbor or equivalent)
    │
    │  [3] podman pull
    ▼
Local machine
```

### Setup

**1. Copy the example files**

```bash
mkdir ~/.postmortemcli
cp private-registry-setup/.env.example ~/.postmortemcli/.env
cp private-registry-setup/setup.example.sh ~/.postmortemcli/setup.sh
chmod +x ~/.postmortemcli/setup.sh
```

**2. Fill in your credentials**

```bash
nano ~/.postmortemcli/.env
```

**3. Register the update command**

```bash
# Add to ~/.bashrc
alias postmortemcli-update='~/.postmortemcli/setup.sh'
source ~/.bashrc
```

**4. Run an update**

```bash
postmortemcli-update v0.2.5-beta
```

### What the update script does

```
[0/5] Remove all existing postmortemcli images locally and on the image server
      → Guarantees no stale version remains anywhere in the chain
[1/5] Trivy security scan – runs on the image server via SSH
      → Scans the Docker Hub image for CRITICAL and HIGH vulnerabilities
         before it is admitted to the internal network
      → Confirmation required (y/n)
[2/5] Pull from Docker Hub via buildah
      → SHA256 hash recorded at pull time
[3/5] Retag for private registry
      → Same SHA256 hash throughout – no modification possible
[4/5] Push to private registry
      → Confirmation required (y/n)
[5/5] Pull to local machine
      → ~/.bashrc updated automatically with the new image reference
```

### Requirements

**Image server**

| Tool | Purpose |
|---|---|
| `buildah` | Pull, tag and push container images |
| `trivy` | Vulnerability scanning |
| SSH access | Script connects via SSH |

**Local machine**

| Tool | Purpose |
|---|---|
| `podman` | Run containers (rootless) |
| `ssh` | Connect to image server |
| Python 3.10+ | Run PostmortemCLI |

### Security considerations

- `.env` contains credentials – never commit it
- Trivy scan is enforced before any image reaches the internal network
- SHA256 hash is preserved end-to-end – any modification would produce a different hash
- Two manual confirmation steps prevent unintended registry changes
- No registry addresses, credentials or server names appear in source code or container image

Example files: [`private-registry-setup/`](private-registry-setup/)

---

## Disclaimer

This tool is a prototype developed for educational and research purposes as
part of a diploma project at Chas Academy. It is not intended for use in
production environments without further security review and hardening.

API keys included in `.env` are not committed to this repository.
SMHI-specific configuration lives in `~/.postmortemcli/` on the local machine
and is excluded from both version control and the container image.

---

## Copyright

Copyright (c) 2026 Filip Andersson. All rights reserved.