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

                        PostmortemCLI v0.3.14-beta
                           by Filip Andersson, 2026
             Containerized Email Security Analysis for Incident Triage
```

# PostmortemCLI — Email Security Analyzer

> **Diploma project/Capstone project** — Chas Academy SUVX24
> Developed by Filip Andersson, 2026
> Commissioned by *The Swedish Meteorological and Hydrological Institute (SMHI), IT-Production Department, IT-Security unit as production tooling for first line service desk security operations.

---
<!--
## ⚠️ First Time Setup Required

**PostmortemCLI does not work out of the box.** Before running the tool for the
first time, you must run a setup package that creates the required configuration
directory, configures your API keys, and prepares the container environment.

There are two setup packages depending on your environment:

| Environment | Setup package |
|---|---|
| Personal / public use | `postmortemcli-setup` |
| Organization / enterprise (private registry) | `postmortemcli-enterprise-setup` |

Jump to the guide that applies to you:
- [Personal use — First Time Setup](#a-personal-use--first-time-setup)
- [Enterprise use — First Time Setup](#b-enterprise-use--first-time-setup)

---
-->

## Table of Contents

1. [Abstract](#1-abstract)
2. [Target Audience](#2-target-audience)
3. [Document Status](#3-document-status)
4. [Disclaimer](#4-disclaimer)
5. [Scope and Limitations](#5-scope-and-limitations)
6. [Method](#6-method)
7. [Architecture](#7-architecture)
8. [Verdicts](#8-verdicts)
9. [Threat Intelligence Sources](#9-threat-intelligence-sources)
10. [GDPR and Privacy](#10-gdpr-and-privacy)
11. [Requirements](#11-requirements)
12. [Installation and First Time Setup](#12-installation-and-first-time-setup)
    - [A. Personal use — First Time Setup](#a-personal-use--first-time-setup)
    - [B. Enterprise use — First Time Setup](#b-enterprise-use--first-time-setup)
13. [Configuration](#13-configuration)
14. [User Guide](#14-user-guide)
    - [14.1 Starting the tool](#141-starting-the-tool)
    - [14.2 Scanning files directly](#142-scanning-files-directly)
    - [14.3 Sending files via SMTP](#143-sending-files-via-smtp)
    - [14.4 Reading the report](#144-reading-the-report)
    - [14.5 Supported commands](#145-supported-commands)
    - [14.6 Updating the tool](#146-updating-the-tool)
    - [14.7 Exiting](#147-exiting)
15. [Enterprise Deployment](#15-enterprise-deployment)
16. [Project Structure](#16-project-structure)
17. [Test Suite](#17-test-suite)
18. [Known Limitations](#18-known-limitations)
19. [Future Development](#19-future-development)
20. [License](#20-license)

---

## 1. Abstract

PostmortemCLI is a containerized CLI tool for structured, stateless security
analysis of suspicious email files. It receives, parses, and analyzes `.eml`
and `.msg` files for indicators of phishing, malware, spoofing, business email
compromise, and other email-based threats — across nine independent threat
intelligence sources — without storing any data or transmitting raw email
content to external services.

The tool is built around a defense-in-depth model: no single source determines
the verdict. All nine sources contribute independently, and the final assessment
weighs their combined signals. A container that self-destructs after each session
guarantees that no residual data persists between analyses.

---

## 2. Target Audience

- **Security analysts and IT security teams** who need a fast, standardized
  first-line assessment of suspicious emails reported by users.
- **Service desk operators** who receive forwarded suspicious emails and need a
  clear, actionable verdict without deep technical expertise.
- **Organizations** operating in regulated or privacy-sensitive environments that
  require a documented, auditable email triage process.
- **Developers and security engineers** who want to understand, extend, or adapt
  the tool for their own environment.

---

## 3. Document Status

This repository is actively maintained and reflects the current production-ready
state of the tool as submitted for academic examination at Chas Academy, June 2026.

The tool is intentionally versioned at `v0.3.14-beta`. All core functionality is
implemented and verified across target platforms. Open items are documented in
[Section 18](#18-known-limitations) and [Section 19](#19-future-development).
A `1.0.0` release is planned following examination and resolution of the
documented open items.

> **Note:** The setup packages (`postmortemcli-setup` and
> `postmortemcli-enterprise-setup`) are currently in development and will be
> published alongside the `1.0.0` release. Until then, follow the manual setup
> instructions in [Section 12](#12-installation-and-first-time-setup).

---

## 4. Disclaimer

> **Note:** This tool is a prototype developed for educational and operational
> research purposes as part of a diploma project. It has been deployed and
> verified in an organizational production-adjacent environment, but is not
> intended for use in critical production systems without further security
> review, hardening, and validation appropriate to the deployment context.

---

## 5. Scope and Limitations

- The tool is designed for first-line triage of suspicious emails, not as a
  replacement for a full SIEM or endpoint detection solution.
- Analysis is limited to `.eml` and `.msg` file formats. Live email integration
  (direct IMAP/Exchange access) is outside the current scope.
- The tool operates without persistent storage. No historical analysis or
  trending across sessions is supported in the current version.
- IPv6 sender IP extraction is not yet implemented —
  see [Section 18](#18-known-limitations).
- Hardware and network requirements vary by environment. Always verify
  compatibility before deployment.
- Sensitive information specific to any organization's internal infrastructure
  is withheld from this repository. This will not hinder participation in the
  public guide.

---

## 6. Method

The solution was implemented as a four-phase pipeline running inside an
isolated, stateless container. The host machine provides only a launcher
(`launcher.py`) that detects the platform, runtime, and registry type, then
starts the container with the appropriate flags. All analysis logic executes
inside the container, which self-destructs on exit.

An email file is submitted either via direct file scan or by forwarding it
over SMTP to a local listener on port 1025. The SMTP receiver
(`smtp_reciever.py`) uses `aiosmtpd`'s low-level `handle_DATA` hook to
capture the raw RFC 822 bytes of the message — preserving the exact byte
content required for cryptographic DKIM signature verification. The
higher-level `AsyncMessage` abstraction was evaluated and rejected because
it reformats the message and destroys the byte-exact content the DKIM
signature covers.

The parser (`parser.py`) extracts structured data: headers, sender identity,
URLs, and attachment content. The analyzer (`analyzer.py`) runs five
independent control modules against nine threat intelligence sources — two
DNS blocklists queried via `dnspython`, and seven REST APIs queried via
`requests` over HTTPS. Only anonymized identifiers are transmitted: IP
addresses, URLs, SHA-256 hashes, and the sender address. Raw content never
leaves the system.

The verdict engine (`_calculate_verdict()`) weighs the combined signals from
all sources and produces one of three outcomes. The reporter (`reporter.py`)
generates a structured Post-Mortem Incident Report with a unique ID, a
plain-language motivation, and a GDPR declaration specifying exactly which
data was transmitted during the session. The report is saved to the host
filesystem via a volume mount that persists after the container exits.

---

## 7. Architecture

```
Host machine (Windows / Linux)
│
├── Terminal 1
│   postmortemcli start
│       │
│       └── launcher.py
│               ├── Detects platform (Windows / Linux)
│               ├── Detects runtime (Docker / Podman)
│               ├── Detects registry type (public / private → --pull never)
│               ├── Injects API keys via --env-file ~/.postmortemcli/.env
│               └── Mounts: ~/.postmortemcli → /data:z
│                           ./cwd → /cwd:ro
│
└── Terminal 2
    postmortemcli send suspicious.eml
        │
        └── smtplib → localhost:1025 (raw RFC 822 bytes)
                │
                ▼
┌─────────────────────────────────────────────────────┐
│  Container  (/app)  POSTMORTEM_CONTAINER=1  --rm    │
│                                                     │
│  main.py ─────────────────────────────────────────  │
│      │                                              │
│  smtp_reciever.py        logger.py                  │
│  aiosmtpd · port 1025                               │
│  handle_DATA() → raw bytes preserved for DKIM       │
│      │                                              │
│  parser.py                                          │
│  RFC 822 · .eml + .msg · headers · URLs · hashes   │
│      │                                              │
│  analyzer.py                                        │
│  ├── check_headers()        BEC / spoofing          │
│  ├── check_authentication() SPF · DKIM · DMARC      │
│  ├── check_reputation()     sender IP               │
│  ├── check_urls()           all links               │
│  ├── check_attachments()    SHA-256 hashes          │
│  └── _calculate_verdict()   weighted signal sum     │
│      │                                              │
│  reporter.py                                        │
│  PMRT-ID · GDPR declaration · plain-language report │
│  save_report() → /data/reports/ → host filesystem  │
└─────────────────────────────────────────────────────┘
         │                      │
         ▼                      ▼
  DNS (dnspython)        Nine external threat
  SPF · DMARC            intelligence sources
  DKIM (dkimpy)          (anonymized identifiers only)
```

**Key architectural decisions:**

- `handle_DATA` instead of `AsyncMessage` — preserves raw bytes required for
  cryptographic DKIM verification. The higher-level abstraction reformats the
  message and destroys the byte-exact content the signature covers.
- `dnspython` instead of MXToolbox — MXToolbox has no programmatic API. Direct
  DNS lookups give lower latency, better privacy, and no third-party dependency.
- Nine sources instead of one — VirusTotal's free tier (4 requests/minute) is
  insufficient as a sole source. Overlapping, independent sources implement
  defense-in-depth and compensate for individual false positives.
- `--env-file` instead of `python-dotenv` — API keys never enter the container
  image. They are injected at runtime from the host filesystem, keeping the
  image stateless and credential-free.

---

## 8. Verdicts

Every analysis produces one of three outcomes:

| Verdict | Meaning |
|---|---|
| `MOST LIKELY SAFE` | SPF, DKIM, and DMARC pass. No threat indicators found across all sources. |
| `MOST LIKELY UNSAFE` | One or more confirmed negative signals from independent sources. |
| `FURTHER ANALYSIS REQUIRED` | Mixed or weak signals. Manual review recommended. |

Each verdict is accompanied by a plain-language explanation of the specific
signals that triggered it, designed to be readable by non-technical personnel.

---

## 9. Threat Intelligence Sources

| Source | Type | Checks | Key required |
|---|---|---|---|
| Spamhaus ZEN | DNSBL | Sender IP reputation | No |
| Spamhaus DBL | DNSBL | URL domain reputation | No |
| URLhaus (abuse.ch) | API | Active malware URLs | Optional (`ABUSE_CH_API_KEY`) |
| MalwareBazaar (abuse.ch) | API | Attachment SHA-256 hashes | Optional (`ABUSE_CH_API_KEY`) |
| ThreatFox (abuse.ch) | API | IP / domain / hash IOCs | Optional (`ABUSE_CH_API_KEY`) |
| AbuseIPDB | API | IP confidence score 0–100 | Optional (`ABUSEIPDB_API_KEY`) |
| VirusTotal | API | URL · file · IP · 70+ engines | Required (`VIRUSTOTAL_API_KEY`) |
| Google Safe Browsing | API | URL phishing / malware | Required (`GOOGLE_SAFE_BROWSING_KEY`) |
| EmailRep | API | Sender address reputation | Optional (`EMAILREP_API_KEY`) |

> URLhaus, MalwareBazaar, and ThreatFox share a single `ABUSE_CH_API_KEY`
> under the abuse.ch umbrella.

> EmailRep integration is fully implemented but requires manual approval from
> emailrep.io. Functionality activates automatically once an API key is
> configured.

---

## 10. GDPR and Privacy

PostmortemCLI is designed for compliance with GDPR Article 25 (data protection
by design and by default).

**What is transmitted externally:**
- IP addresses extracted from `Received` headers
- URLs found in the message body
- SHA-256 cryptographic hashes of attachments
- The sender email address (for EmailRep lookups)

**What is never transmitted:**
- Raw email content
- Message body text
- Attachment file data
- Subject lines or other personally identifiable content

**Why hashes are GDPR-safe:** A SHA-256 hash is a one-way mathematical
function. It is computationally infeasible to reconstruct the original file
from its hash. External databases compare the hash against known malware
signatures without receiving or storing any content from the analyzed email.

Every generated report includes a GDPR declaration specifying exactly which
data was transmitted to which external service during that specific analysis
session.

---

## 11. Requirements

**All environments:**
- Python 3.10 or higher
- Docker Desktop (Windows / macOS) or Podman (Linux)
- Network access to external threat intelligence APIs

**Enterprise environments additionally require:**
- Access to your organization's internal container registry
- Buildah and Podman installed on the update machine
- Trivy installed and accessible via SSH on the staging server
- API keys obtained from your organization's IT security function

---

## 12. Installation and First Time Setup

> ⚠️ **First time setup is required before running `postmortemcli start`.**
> Skipping setup means the tool has no API keys, no configuration directory,
> and no container image configured. It will not work.

---

### A. Personal use — First Time Setup

**Step 1 — Install Docker Desktop**

Download and install Docker Desktop for your platform:
- Windows / macOS: https://www.docker.com/products/docker-desktop
- Linux: install Podman via your package manager (`sudo apt install podman`
  or `sudo dnf install podman`)

Make sure Docker Desktop is running before continuing.

**Step 2 — Install PostmortemCLI**

```bash
pip install git+https://github.com/Filipanderssondev/PostmortemCLI-email-security-analyzer.git
```

**Step 3 — Install the setup package**

> **Note:** `postmortemcli-setup` is currently in development.
> Until it is published, perform the manual steps below instead.

**Step 3 (manual) — Create configuration directory**

```bash
# Linux / macOS
mkdir -p ~/.postmortemcli/reports

# Windows (PowerShell)
New-Item -ItemType Directory -Force "$env:APPDATA\postmortemcli\reports"
```

**Step 4 — Get your API keys**

Register for free API keys at the following services:

| Service | Registration URL |
|---|---|
| VirusTotal (required) | https://www.virustotal.com/gui/join-us |
| Google Safe Browsing (required) | https://developers.google.com/safe-browsing/v4/get-started |
| AbuseIPDB (optional) | https://www.abuseipdb.com/register |
| abuse.ch / URLhaus (optional) | https://auth.abuse.ch/register |
| EmailRep (optional) | https://emailrep.io/key |

**Step 5 — Create your `.env` file**

```bash
# Linux / macOS
nano ~/.postmortemcli/.env

# Windows (PowerShell — use Notepad or VS Code, NOT standard PowerShell redirect)
notepad "$env:APPDATA\postmortemcli\.env"
```

Add your keys, one per line:

```env
VIRUSTOTAL_API_KEY=your_key_here
GOOGLE_SAFE_BROWSING_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
ABUSE_CH_API_KEY=your_key_here
EMAILREP_API_KEY=your_key_here
```

> ⚠️ **Windows users:** Save the file with **LF line endings**, not CRLF.
> In VS Code: click "CRLF" in the bottom right corner and change it to "LF"
> before saving. CRLF silently breaks all API calls.

**Step 6 — Verify setup**

```bash
postmortemcli --version
```

**Step 7 — Run**

```bash
postmortemcli start
```

The container image is pulled automatically from Docker Hub on first run.
This may take a minute. After that, the tool starts instantly.

---

### B. Enterprise use — First Time Setup

> This guide is for organizations running a private internal container
> registry. It assumes your IT security function has already configured
> the internal registry and can provide you with registry credentials
> and API keys.

**Step 1 — Install Podman**

```bash
# RHEL / Fedora
sudo dnf install podman

# Verify
podman --version
```

**Step 2 — Install PostmortemCLI**

```bash
pip install git+https://github.com/Filipanderssondev/PostmortemCLI-email-security-analyzer.git
```

**Step 3 — Install the enterprise setup package**

> **Note:** `postmortemcli-enterprise-setup` is currently in development.
> Until it is published, perform the manual steps below instead.

**Step 3 (manual) — Create configuration directory**

```bash
mkdir -p ~/.postmortemcli/reports
```

**Step 4 — Create your `.env` file**

Contact your IT security function to obtain:
- Internal registry address and credentials
- Organization API keys for VirusTotal, AbuseIPDB, abuse.ch, Google Safe Browsing

```bash
nano ~/.postmortemcli/.env
```

```env
VIRUSTOTAL_API_KEY=your_org_key_here
GOOGLE_SAFE_BROWSING_KEY=your_org_key_here
ABUSEIPDB_API_KEY=your_org_key_here
ABUSE_CH_API_KEY=your_org_key_here
EMAILREP_API_KEY=your_org_key_here

REGISTRY_HOST=your-internal-registry.example.com
REGISTRY_USER=your_username
REGISTRY_PASSWORD=your_password
```

**Step 5 — Set POSTMORTEM_IMAGE**

Your IT security function will provide the full image path for your
organization's internal registry. Add it to your shell profile:

```bash
echo 'export POSTMORTEM_IMAGE=your-registry.example.com/postmortemcli:v0.3.14-beta' >> ~/.bashrc
source ~/.bashrc
```

**Step 6 — Pull the container image**

```bash
podman pull $POSTMORTEM_IMAGE
```

**Step 7 — Verify setup**

```bash
postmortemcli --version
```

**Step 8 — Run**

```bash
postmortemcli start
```

The tool will use `--pull never` automatically because it detects a private
registry. The image must be present locally — it will never be fetched
from the internet.

---

## 13. Configuration

### API keys

All API keys are stored in `~/.postmortemcli/.env` (Linux) or
`%APPDATA%\postmortemcli\.env` (Windows). They are injected into the
container at runtime via `--env-file` and are never stored in the container
image or in this repository.

See `.env.example` in the repository root for a complete template.

### Container image override

To use a custom or private registry image, set the `POSTMORTEM_IMAGE`
environment variable:

```bash
# Linux
export POSTMORTEM_IMAGE=your-registry.example.com/postmortemcli:v0.3.14-beta
echo 'export POSTMORTEM_IMAGE=...' >> ~/.bashrc

# Windows (PowerShell)
$env:POSTMORTEM_IMAGE = "your-registry.example.com/postmortemcli:v0.3.14-beta"
```

When `POSTMORTEM_IMAGE` points to a private registry, `launcher.py`
automatically activates `--pull never` mode.

---

## 14. User Guide

### 14.1 Starting the tool

Open a terminal and run:

```bash
postmortemcli start
```

This starts the container, launches the SMTP listener on port 1025, and
opens the interactive prompt:

```
PostmortemCLI v0.3.14-beta
────────────────────────────────────────
postmortemcli >
```

### 14.2 Scanning files directly

From inside the interactive prompt:

```
postmortemcli > scan /cwd/suspicious.eml
postmortemcli > scan /cwd/invoice.msg
```

The file must be in the directory from which `postmortemcli start` was run.
It is mounted read-only at `/cwd` inside the container.

### 14.3 Sending files via SMTP

Open a second terminal and run:

```bash
# Single file
postmortemcli send suspicious.eml

# Multiple files
postmortemcli send email1.eml email2.msg
```

Files are transmitted to the running container via SMTP on `localhost:1025`.
Results appear in the first terminal.

### 14.4 Reading the report

```
══════════════════════════════════════════════════════
POST-MORTEM INCIDENT REPORT
Report ID:  PMRT-20260601-143021
Generated:  2026-06-01 14:30:21
Version:    v0.3.14-beta
══════════════════════════════════════════════════════

VERDICT:  MOST LIKELY UNSAFE

SUMMARY
  Flags raised:    10
  Sources checked: 9

AUTHENTICATION
  SPF:   FAIL
  DKIM:  UNSIGNED
  DMARC: NOT CONFIGURED

THREAT INDICATORS
  [CRITICAL] Spamhaus ZEN:   sender IP listed
  [CRITICAL] URLhaus:        active malware distribution URL detected
  [CRITICAL] AbuseIPDB:      confidence score 100/100
  [HIGH]     VirusTotal:     13/92 engines flagged sender IP

GDPR DECLARATION
  Transmitted externally: IP address, URLs, attachment hashes
  Raw email content:      NOT transmitted
  Retention:              NO DATA RETAINED — STATELESS
══════════════════════════════════════════════════════
```

Reports are saved to `~/.postmortemcli/reports/` (Linux) or
`%APPDATA%\postmortemcli\reports\` (Windows) and persist after the
container exits.

### 14.5 Supported commands

```
scan <file> [files...]    Analyze one or more email files (.eml or .msg)
listen                    Restart the SMTP listener if it has stopped
help                      Show available commands
exit                      Quit and destroy the container
```

### 14.6 Updating the tool

**Personal / public:**

```bash
postmortemcli update v0.3.14-beta
```

**Enterprise:**

```bash
postmortemcli update v0.3.14-beta
```

The same command works for both environments. The launcher detects the
registry type and runs the appropriate update flow automatically.

### 14.7 Exiting

```
postmortemcli > exit
```

The container shuts down and removes itself (`--rm`). No data is retained
on the container filesystem.

---

## 15. Enterprise Deployment

### Private registry environments

`launcher.py` automatically detects private registries by checking whether
`POSTMORTEM_IMAGE` points to a known public registry (`docker.io`, `ghcr.io`,
`quay.io`, etc.). If not, it sets `--pull never` — the image is never fetched
over the network and must be present locally.

### Recommended update workflow

```
1. pip install --upgrade postmortemcli     Update host-side launcher
2. Remove previous image (local + staging) Clean up old versions
3. Security scan (Trivy)                   --severity=CRITICAL,HIGH
4. Manual approval prompt (y/n)            Operator confirms scan results
5. Pull from public registry               buildah pull docker.io/...
6. Retag for internal registry             buildah tag ...
7. Authenticate and push                   Credentials from .env
8. Pull to local runtime                   podman pull internal-registry/...
9. Update POSTMORTEM_IMAGE reference       Points to new internal tag
```

### SELinux environments (RHEL / Fedora)

The configuration directory is mounted with `:z` to enable SELinux
relabeling. The working directory is mounted `:ro` (read-only), which
is compatible with SELinux enforcement on home directories.

Verified on rootless Podman on RHEL with SELinux in enforcing mode.

---

## 16. Project Structure

```
PostmortemCLI-email-security-analyzer/
│
├── launcher.py              Host entrypoint — platform, runtime, registry detection
├── main.py                  Container CLI — command dispatcher, SMTP coordinator
├── release.py               Version bump automation — git tag + DockerHub trigger
├── smoke_test.py            Network-dependent live API verification
│
├── pyproject.toml           Package configuration, version source of truth
├── requirements.txt         Python dependencies
├── Dockerfile               Container build definition (Debian slim base)
├── .dockerignore            Excludes credentials and local setup from image
├── .gitignore               Excludes credentials and enterprise setup from repo
├── .env.example             Template for API key configuration
│
├── src/
│   ├── __init__.py
│   ├── smtp_reciever.py     SMTP handler — aiosmtpd, handle_DATA, queue-based
│   ├── parser.py            Email parsing — RFC 822, MIME, .eml, .msg, URLs
│   ├── analyzer.py          Threat analysis — 9 sources, 5 modules, verdict logic
│   ├── reporter.py          Report generation — PMRT-ID, GDPR declaration
│   └── logger.py            Centralized logging — terminal INFO + file DEBUG
│
├── tests/
│   ├── phishing_email.eml
│   ├── malware_attachment.eml
│   └── test_*.py            169 unit tests covering all analysis modules
│
└── docs/
    └── enterprise-setup/    Reference deployment guide for private registry environments
```

---

## 17. Test Suite

| Test file | Scenario | Expected verdict |
|---|---|---|
| `clean_legitimate.eml` | SPF/DKIM/DMARC pass, no indicators | SAFE |
| `spf_fail.eml` | SPF hard fail | FURTHER ANALYSIS |
| `dkim_fail.eml` | DKIM signature invalid | FURTHER ANALYSIS |
| `dmarc_missing.eml` | No DMARC record | FURTHER ANALYSIS |
| `bec_reply_to.eml` | From/Reply-To domain mismatch | FURTHER ANALYSIS |
| `eicar_attachment.eml` | EICAR test signature in attachment | UNSAFE |
| `mime_mismatch.eml` | MIME type does not match magic bytes | FURTHER ANALYSIS |
| `malicious_url.eml` | Typosquatting URL in body | UNSAFE |
| `forged_received.eml` | Inconsistent Received header chain | FURTHER ANALYSIS |
| `full_combination.eml` | All indicators combined | UNSAFE |

```bash
# Unit tests
pytest tests/ -v

# Live API verification (requires configured API keys)
python smoke_test.py
```

---

## 18. Known Limitations

- **IPv6 sender IP extraction** — IPv4 only. Emails relayed via IPv6 will
  not trigger IP reputation checks.
- **Extended MIME type coverage** — Image formats (JPEG, PNG, GIF) and
  older Office binary formats (OLE2) not yet covered.
- **EmailRep pending** — Integration complete, awaiting manual API approval
  from emailrep.io.
- **Base image CVEs** — Trivy reports 2 CRITICAL and 6 HIGH CVEs in
  `ncurses` and `perl-base` in the Debian slim base image. No upstream fixes
  available. These packages are not used by the application.
- **VirusTotal rate limiting** — Free tier: 4 requests/minute. Emails with
  more than 4 URLs may have some URLs skipped. Cosmetic issue only.

---

## 19. Future Development

**Short-term**
- Tiered output: compact default + `--full` flag for full report
- Flag severity weighting in `_calculate_verdict()`
- Formatted `--help` with all flags (`--json`, `--no-color`, `--verbose`, `--skip`)
- Version pre-check in `release.py` to prevent duplicate builds
- In-place progress indicator (ANSI / `rich`)
- Extended MIME magic byte coverage
- IPv6 support in sender IP extraction

**Setup packages**
- `postmortemcli-setup` — automated first time setup for personal use
- `postmortemcli-enterprise-setup` — automated first time setup for
  organizations with private registry, internal credentials, and
  enterprise API keys

**Server-side deployment**
- Dedicated inbound SMTP address with MX record
- On-demand container spawning per incoming message
- STARTTLS support on port 587
- Queue-based architecture for high-volume handling

**Extended analysis**
- Local SQLite threat database for organizational indicator history
- S/MIME certificate chain validation
- SIEM / ticketing system webhook integration
- Local LLM-generated report summaries (Ollama, air-gapped)

---

## 20. License

This project is licensed under the **MIT License**.

You are free to use, modify, and distribute this software for any purpose —
personal or commercial. The only requirement is that the original copyright
notice and license text are retained in all copies or derivatives.
This means Filip Andersson must always be credited as the original author,
regardless of how the software is modified or extended.

---

MIT License

Copyright (c) 2026 Filip Andersson

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

*PostmortemCLI — Stateless Email Security Analysis for Rapid Incident Triage*
*Chas Academy SUVX24 · Diploma Project · 2026 · for SMHI IT-PRODUCTION
