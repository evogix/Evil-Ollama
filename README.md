```
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║     ███████╗██╗   ██╗██╗██╗         ██████╗ ██╗     ██╗      █████╗     ║
║     ██╔════╝██║   ██║██║██║        ██╔═══██╗██║     ██║     ██╔══██╗    ║
║     █████╗  ██║   ██║██║██║        ██║   ██║██║     ██║     ███████║    ║
║     ██╔══╝  ╚██╗ ██╔╝██║██║        ██║   ██║██║     ██║     ██╔══██║    ║
║     ███████╗ ╚████╔╝ ██║███████╗   ╚██████╔╝███████╗███████╗██║  ██║    ║
║     ╚══════╝  ╚═══╝  ╚═╝╚══════╝    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝    ║
║                                                                          ║
║     ██████╗ ██╗     ██╗      █████╗ ███╗   ███╗ █████╗                 ║
║     ██╔══██╗██║     ██║     ██╔══██╗████╗ ████║██╔══██╗                ║
║     ██████╔╝██║     ██║     ███████║██╔████╔██║███████║                ║
║     ██╔═══╝ ██║     ██║     ██╔══██║██║╚██╔╝██║██╔══██║                ║
║     ██║     ███████╗███████╗██║  ██║██║ ╚═╝ ██║██║  ██║                ║
║     ╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝                ║
║                                                                          ║
║     🔥 Exposed Ollama Instance Hunter v3.0 🔥                           ║
║     Find · Exploit · Proxy · PWN                                        ║
║                                                                          ║
║     [ For Authorized Security Testing Only ]                             ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
```

# 🦙 EVIL-OLLAMA

> **Next-Gen Exposed Ollama Instance Finder, Vulnerability Scanner & Proxy Tool**
>
> Find publicly exposed Ollama LLM instances across the internet, scan for vulnerabilities, proxy through them, and more.

```
╔══════════════════════════════════════════════════════════════════════════╗
║  [+] TARGET:      Any exposed Ollama instance                          ║
║  [+] METHOD:      Async TCP · DNS · CT Logs · Shodan · Censys · FOFA  ║
║  [+] VULN SCAN:   Auth · CVE-2024-37032 · SSRF · CORS · Metrics       ║
║  [+] PROXY:       OpenAI-compatible · Chat · Generate                  ║
║  [+] STATUS:      ACTIVE                                               ║
╚══════════════════════════════════════════════════════════════════════════╝
```

---

## 🔥 FEATURES

| Category | Features |
|----------|----------|
| **🔍 SCANNING** | Random IP (weighted) · CIDR · IP List · DNS Discovery · CT Logs · Shodan · Censys · FOFA · **9 methods total** |
| **💀 VULNERABILITY** | Auth check · CVE-2024-37032 (RCE) · Model Create/Delete · CORS · SSRF · Metrics · Info Disclosure · Timing · **10 checks** |
| **🔌 PROXY** | OpenAI SDK compatible · Streaming · Full API forward · All HTTP methods |
| **💬 CHAT** | Interactive · Batch mode · System prompts · Temperature · Raw API |
| **🔎 FINGERPRINT** | 18 endpoints · GPU detection · Model analysis · Size calc · Running models |
| **📦 MODELS** | List · Pull info · Deep analyze · Size breakdown |
| **📊 EXPORT** | HTML (beautiful) · CSV · JSON · Vuln stats · Geo distribution |
| **🤖 AUTO-PWN** | Scan → Vuln Scan → Geolocate → Proxy → Report — **one command** |
| **📡 MONITOR** | CLI-only daemon · Telegram alerts · Auto-export | 

---

## ⚡ QUICK START

### 🛠 Installation

```bash
git clone https://github.com/evogix/Evil-Ollama
cd Evil-Ollama
pip install aiohttp flask requests
chmod +x launcher.sh
```

### 🎯 Basic Scan

```bash
# Scan 10,000 random IPs for Ollama instances
./launcher.sh scan --random 10000

# Scan with geolocation + export
./launcher.sh scan --random 10000 --geo --export html --notify
```

---

## 💀 COMMANDS

### 🔍 SCANNING

```bash
# Random IP scan (weighted for real-world density)
./launcher.sh scan --random 10000

# CIDR range scan
./launcher.sh scan --cidr 0.0.0.0/8

# DNS discovery — find ollama.example.com, ai.example.com, etc.
./launcher.sh scan --dns example.com

# Certificate Transparency log discovery
./launcher.sh scan --ct example.com

# Internet DB search
./launcher.sh scan --shodan API_KEY
./launcher.sh scan --censys ID:SECRET
./launcher.sh scan --fofa EMAIL:KEY

# Scan with extras
./launcher.sh scan --random 5000 --geo --export html --notify
```

### 💀 VULNERABILITY SCANNING

```bash
# Scan a specific instance
./launcher.sh vuln --target 1.2.3.4:11434

# Scan ALL found instances
./launcher.sh vuln --all

# Exploit a specific CVE
./launcher.sh exploit --cve CVE-2024-37032 --target 1.2.3.4:11434
```

Vulnerability checks:

```
  💀 [CRITICAL] CVE-2024-37032 — RCE via Crafted Model Import
  💀 [HIGH    ] No Authentication — Open API access
  💀 [HIGH    ] Unauthenticated Model Creation
  💀 [HIGH    ] Unauthenticated Model Deletion
  💀 [HIGH    ] CVE-2024-39721 — SSRF in Model Pulling
  💀 [MEDIUM  ] CORS Misconfiguration
  💀 [MEDIUM  ] Prometheus Metrics Exposed
  💀 [LOW     ] Server Information Disclosure
  💀 [LOW     ] No CSRF Protection
  💀 [LOW     ] Response Timing Leak
```

### 🔌 PROXY (OpenAI Compatible)

```bash
# Start proxy to remote Ollama
./launcher.sh proxy --target 1.2.3.4:11434 --port 8080

# Use with OpenAI SDK:
# from openai import OpenAI
# client = OpenAI(base_url="http://127.0.0.1:8080/v1/", api_key="ollama")
```

### 💬 INTERACTIVE CHAT

```bash
# Chat with a remote model
./launcher.sh chat --target 1.2.3.4:11434

# Batch execute prompts from file
./launcher.sh chat --batch prompts.txt --target 1.2.3.4:11434

# Chat commands: /help, /models, /clear, /model N, /system, /temp, /raw, /info, /export
```

### 🔎 DEEP FINGERPRINT

```bash
# Fingerprint a single instance
./launcher.sh fingerprint --target 1.2.3.4:11434

# Fingerprint ALL found instances
./launcher.sh fingerprint --all
```

Checks 18 endpoints including: `/api/tags`, `/api/version`, `/api/ps`, `/api/show`, `/api/blobs`, `/api/pull`, `/api/push`, `/api/create`, `/api/delete`, `/api/copy`, `/api/embed`, `/v1/models`, `/docs`, `/metrics`, `/debug`, `/health`, `/status`

### 📦 MODEL OPERATIONS

```bash
# List models with details
./launcher.sh models --target 1.2.3.4:11434

# Pull model info/config
./launcher.sh models --pull 1.2.3.4:11434 llama3.2

# Deep analyze a model
./launcher.sh models --analyze 1.2.3.4:11434 llama3.2
```

### 📊 EXPORT

```bash
./launcher.sh export --format html    # Beautiful HTML report with geo & vuln stats
./launcher.sh export --format csv     # CSV for analysis
./launcher.sh export --format json    # Raw JSON
./launcher.sh export --format all     # All formats
```

### 🤖 AUTO-PWN (One Command)

```bash
# Scan → Vuln Scan → Geolocate → Proxy → Report
./launcher.sh autopwn --random 5000
```

### 📡 MONITOR DAEMON

```bash
# Continuous scanning (CLI only, no web)
./launcher.sh monitor --interval 3600 --random 5000 --notify --export html
```

### ⚙️ CONFIGURATION

```bash
evilollama config --show                               # Show config
evilollama config --telegram-token "BOT_TOKEN"          # Telegram alerts
evilollama config --telegram-chat "CHAT_ID"
evilollama config --find-chat-id                        # Auto-detect chat ID
evilollama config --shodan-key "API_KEY"
evilollama config --set scan_timeout 3                  # Custom setting
```

---

## 📊 SAMPLE OUTPUT

```
╔══════════════════════════════════════════════════════════════════╗
║                    🦙 EVIL-OLLAMA v3.0                          ║
╚══════════════════════════════════════════════════════════════════╝

[12:30:01] [▶ STEP ] Step 1/4: Scanning 5000 random IPs...
[12:30:01] [🎯 INFO] Scanning 5000 hosts on port 11434 (concurrency: 1000)
[░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░] 45% | 2250/5000 | 850/s | Found: 12 | ETA: 3.2s
[12:30:07] [🦙 FOUND] 203.0.113.42:11434 | v0.1.32 | llama3.2, mistral, codellama
[12:30:07] [🦙 FOUND] 198.51.100.73:11434 | v0.3.0 | llama3.1, nomic-embed-text
[...]

[12:30:10] [▶ STEP ] Step 2/4: Geolocating...
[12:30:10] [📍 GEO ] 203.0.113.42 → San Francisco, US | DigitalOcean
[12:30:11] [📍 GEO ] 198.51.100.73 → London, UK | Hetzner

[12:30:11] [▶ STEP ] Step 3/4: Vulnerability scanning...
[12:30:11] [🔴 VULN] 203.0.113.42:11434
  💀 [HIGH    ] No Authentication Required
  💀 [CRITICAL] Potential RCE via Crafted Model Import (CVE-2024-37032)
  💀 [HIGH    ] Unauthenticated Model Creation

[12:30:14] [▶ STEP ] Step 4/4: Generating report...
[12:30:14] [📄 OK   ] HTML report saved: evilollama_report.html (45.2 KB)

╔══════════════════════════════════════════════════════════════════╗
║  🚀 AUTO-PWN COMPLETE                                           ║
║  Instances found:     7                                         ║
║  Total models:        23                                        ║
║  Vulnerabilities:     12                                        ║
║  CVEs detected:       5                                         ║
║  Report:              evilollama_report.html                          ║
╚══════════════════════════════════════════════════════════════════╝

[12:30:15] [🔌 PROXY] Proxy → 127.0.0.1:9090 → 203.0.113.42:11434
```

---

## 🛡️ CVE DATABASE

| CVE ID | Severity | CVSS | Description | Affected Versions |
|--------|----------|------|-------------|-------------------|
| CVE-2024-37032 | **CRITICAL** | 9.1 | RCE via crafted model file (path traversal) | < 0.1.47 |
| CVE-2024-39720 | **HIGH** | 7.5 | Prompt injection via crafted system prompt | < 0.1.34 |
| CVE-2024-39721 | **HIGH** | 7.5 | SSRF in model pulling mechanism | < 0.1.34 |
| CVE-2024-39722 | **HIGH** | 7.3 | Path traversal in API endpoints | < 0.1.34 |
| CVE-2025-23104 | **HIGH** | 8.2 | API authentication bypass in /api/pull | < 0.3.0 |

---

## 📋 REQUIREMENTS

```
pip install aiohttp flask requests
```

---

## ⚠️ LEGAL DISCLAIMER

```
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║  This tool is for AUTHORIZED SECURITY TESTING only.                      ║
║                                                                          ║
║  Only use on systems you own or have explicit written permission         ║
║  to test. Unauthorized scanning or exploitation is ILLEGAL.              ║
║                                                                          ║
║  The authors assume no liability for misuse.                             ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
```

---

```
╔══════════════════════════════════════════════════════════════════════════╗
║  EVIL-OLLAMA v3.0 · https://github.com/evogix/Evil-Ollama               ║
║  For authorized security research & bug bounty purposes only            ║
╚══════════════════════════════════════════════════════════════════════════╝
```
