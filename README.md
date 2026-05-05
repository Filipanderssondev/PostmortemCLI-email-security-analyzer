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

                       by Filip Andersson, 2026
                  Email Security Analysis Tool for SMHI
```

# PostmortemCLI – Email Security Analyzer

> Diploma project – Chas Academy SUVX24  
> Developed by Filip Andersson, 2026

PostmortemCLI is a containerized CLI tool for structured security analysis of
email files. It receives, parses and analyzes `.eml` and `.msg` files for
indicators of phishing, malware, spoofing and other email-based threats –
without storing any data or sending raw content to external services.

Built as a final graduation project at Chas Academy, developed at the request
of a Swedish government organization with a need for standardized email threat
analysis tooling.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [Disclaimer](#disclaimer)
- [Copyright](#copyright)

---

## Overview

Email remains one of the most exploited attack vectors against organizations.
PostmortemCLI provides a standardized, sandboxed method for analyzing suspicious
emails – extracting metadata, identifying threats and producing a structured
verdict – all within an isolated container that self-destructs after each session.

The tool is designed to be safe by default: only anonymized identifiers such as
IP addresses and cryptographic hashes are ever sent to external threat
intelligence sources. No raw email content or attachments leave the system.

---

## Features

**Currently implemented (Phase 1)**
- Receives `.eml` and `.msg` files via SMTP or direct file scan
- Extracts and parses SMTP headers per RFC 822
- Extracts body text, HTML, URLs and attachments
- Interactive CLI with SMTP listener running in background
- Centralized session logging
- Containerized, stateless – no persistent storage
- Cross-platform: Windows, Linux, macOS

**In development (Fas 2–4)**
- SPF / DKIM / DMARC verification via DNS
- URL checks against URLhaus and Spamhaus
- Attachment hash checks against VirusTotal and MalwareBazaar
- Structured verdict: `SÄKERT` / `OSÄKERT` / `YTTERLIGARE ANALYS BEHÖVS`
- Report generation and SMTP return to sender

---

## Architecture

```
postmortemcli start          (host machine)
        │
        ▼
launcher.py                  detects platform + runtime
        │
        ▼
Docker / Podman              starts isolated container
        │
        ▼
main.py                      CLI entrypoint inside container
        ├── smtp_reciever.py  SMTP listener on port 1025 (background thread)
        └── parser.py        extracts headers, URLs, attachments
                │
                ▼
        analyzer.py          threat checks      (in development)
                │
                ▼
        reporter.py          structured output  (in development)
```

**Tech stack:** Python, aiosmtpd, dnspython, Docker/Podman  
**Threat sources:** Spamhaus, URLhaus, VirusTotal, MalwareBazaar

---

## Installation

### Requirements

- Python 3.10 or higher
- Docker Desktop (Windows/Mac) or Podman (Linux)

### Install

```bash
pip install git+https://github.com/filipandersson/post-mortem.git
```

The container image is pulled automatically on first run.

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

### Send files to the running listener

```bash
# From a second terminal while postmortemcli start is running
postmortemcli send suspicious.eml invoice.msg
```

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

Container shuts down and removes itself automatically.

---

## Configuration

By default PostmortemCLI pulls from Docker Hub. To override the container
image, set the `POSTMORTEM_IMAGE` environment variable:

```bash
export POSTMORTEM_IMAGE=your-registry/your-image:tag
```

Add to `~/.bashrc` to make it permanent.

---

## Project Structure

```
├── launcher.py              Host entrypoint – platform and runtime detection
├── main.py                  Container CLI logic
├── pyproject.toml           Package configuration
├── requirements.txt         Python dependencies
├── Dockerfile               Container build definition
├── src/
│   ├── parser.py            Email parsing – headers, body, URLs, attachments
│   ├── smtp_reciever.py     SMTP handler
│   ├── logger.py            Centralized logging
│   ├── analyzer.py          Threat analysis (in development)
│   └── reporter.py          Report generation (in development)
└── tests/
    └── samples/             Test email files
```

---

## Disclaimer

This tool is a prototype developed for educational and research purposes as
part of a diploma project. It is not intended for use in production
environments without further security review and hardening.

---

## Copyright
Copyright (c) 2026 Filip Andersson. All rights reserved.
