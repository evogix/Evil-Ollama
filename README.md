# 🦙 Ollama Hunter v2.0

**Find publicly exposed Ollama instances & proxy through them.**
For authorized security testing and bug bounty hunting only.

## 🔥 New in v2.0

| Feature | Description |
|---------|-------------|
| ⚡ **Masscan** | 1000x faster scanning via masscan binary |
| 🔎 **Shodan/Censys/FOFA** | Find instances from internet DBs |
| 🌐 **Web Dashboard** | Browser UI with proxy mgmt & live chat |
| 📍 **Geolocation** | Country, city, ISP of every instance |
| 🚨 **CVE Check** | Auto-detect vulnerable Ollama versions |
| 📊 **HTML/CSV/JSON Export** | Professional reports |
| 🤖 **Auto-Pwn** | One command: scan → proxy → dashboard |
| 🔄 **Monitor Daemon** | Continuous 24/7 scanning |
| 🔍 **Fingerprint** | Deep instance analysis |
| 📱 **Telegram** | Instant alerts on new instances |

## ⚡ Quick Install

```bash
pip install aiohttp flask requests
wget -O ollama-hunter.py https://raw.githubusercontent.com/YOUR_USER/ollama-hunter/main/ollama-hunter.py
chmod +x ollama-hunter.py
# Or clone:
git clone https://github.com/YOUR_USER/ollama-hunter
cd ollama-hunter && pip install -r requirements.txt
```

## 🎯 Commands

### 🔍 SCANNING — 5 different methods

```bash
# Async TCP scan (default)
ollama-hunter scan --random 10000

# Masscan (1000x faster, needs masscan installed)
ollama-hunter scan --masscan 0.0.0.0/8

# CIDR range
ollama-hunter scan --cidr 192.168.1.0/24

# IP list file
ollama-hunter scan --file ips.txt

# Shodan search (set API key first)
ollama-hunter scan --shodan API_KEY

# Censys search
ollama-hunter scan --censys API_ID:SECRET

# FOFA search
ollama-hunter scan --fofa EMAIL:KEY

# With extras
ollama-hunter scan --random 5000 --geo --export html --notify
```

### 🌐 WEB DASHBOARD

```bash
# Browser-based management UI
ollama-hunter web --port 5000

# Opens browser automatically. Features:
# 📋 Instance list with models & geo
# 🔌 One-click proxy creation
# 💬 Built-in chat interface
# 📡 Trigger scans from browser
# ⚙️ Config management (API keys)
```

### 🔌 PROXY

```bash
# Proxy a specific instance
ollama-hunter proxy --target 203.0.113.42:11434 --port 8080

# Auto-proxy the first found instance
ollama-hunter proxy --auto

# Proxy ALL found instances (different ports)
ollama-hunter proxy --all --port 9000
# This starts proxies on ports 9000, 9001, 9002, ...

# Then use with OpenAI SDK:
from openai import OpenAI
client = OpenAI(base_url="http://localhost:8080/v1/", api_key="ollama")
```

### 💬 CHAT

```bash
# Interactive CLI chat
ollama-hunter chat --target 203.0.113.42:11434

# Commands inside chat: /models, /clear, /model N, /info, /export, /help
```

### 📊 EXPORT

```bash
ollama-hunter export --format html    # Beautiful report with geo tables
ollama-hunter export --format csv     # CSV for Excel/analysis
ollama-hunter export --format json    # Raw JSON
ollama-hunter export --format all     # All formats
```

### 🔍 FINGERPRINT

```bash
ollama-hunter fingerprint --target 203.0.113.42:11434
# Shows: version, models, total size, response time, CVEs, running models
```

### 📋 SHOW

```bash
ollama-hunter show                    # Table of all instances
ollama-hunter show --geo              # With geolocation lookup
ollama-hunter show --export html      # Show + export
```

### 🔄 MONITOR DAEMON

```bash
# Continuous scanning (every hour by default)
ollama-hunter monitor --interval 3600 --random 5000 --notify --export html
```

### 🤖 AUTO-PWN (One Command)

```bash
# Scan → Find → Geolocate → Export report → Start Dashboard
ollama-hunter autopwn --random 10000 --port 9090
```

### ⚙️ CONFIG

```bash
ollama-hunter config --show                              # View all config
ollama-hunter config --telegram-token "BOT_TOKEN"        # Set Telegram
ollama-hunter config --telegram-chat "CHAT_ID"
ollama-hunter config --shodan-key "API_KEY"
ollama-hunter config --set my_var "value"                # Custom key
```

## 📊 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Ollama Hunter v2.0                       │
├──────────┬──────────┬──────────┬──────────┬────────────────┤
│ Scanner  │ Internet │   Web    │  Proxy   │    Chat CLI    │
│ (async)  │ DB APIs  │Dashboard│  Server  │                │
│ Masscan  │ Shodan   │  HTML   │  Flask   │  Interactive   │
│ TCP      │ Censys   │  JS UI  │ Forward  │  Streaming     │
└──────────┴──────────┴──────────┴──────────┴────────────────┘
     │          │          │          │              │
     └──────────┴──────────┴──────────┴──────────────┘
                        │
              ┌─────────▼─────────┐
              │  found_instances   │
              │    .json (DB)      │
              └───────────────────┘
```

## 🛡️ Ethical Use

This tool is for:
- **Bug bounty hunters** — Finding exposed AI infrastructure
- **Penetration testers** — Identifying misconfigured services
- **Security researchers** — Studying exposed LLM deployments

> ⚠️ Only use on systems you are authorized to test.

## 📋 Requirements

```
pip install aiohttp flask requests
```

Optional for faster scanning: `apt install masscan`

## 💡 CVE Database Included

Automatically checks Ollama versions against known CVEs:
- **CVE-2024-37032** — RCE via crafted model file (CRITICAL, affects < 0.1.47)
- More CVEs added as discovered

## 📱 Telegram Notifications

Receive instant alerts when new instances are found:

```bash
ollama-hunter config --telegram-token "123:ABC"
ollama-hunter config --telegram-chat "123456"
ollama-hunter scan --random 5000 --notify
```

## 🚀 One-liner Install

```bash
pip install aiohttp flask requests && \
wget -O ollama-hunter.py https://raw.githubusercontent.com/YOUR_USER/ollama-hunter/main/ollama-hunter.py && \
chmod +x ollama-hunter.py && \
echo "Done! Run: python3 ollama-hunter.py --help"
```

## 🔍 Why Exposed Ollama Matters

Ollama defaults to `127.0.0.1:11434`, but many users expose it to `0.0.0.0` without auth, allowing:
- **GPU compute theft** — Run expensive models for free
- **Data access** — Sensitive info in model outputs
- **Model theft** — Download proprietary models
- **Criminal use** — Use instance for malicious purposes

**Responsible Disclosure:** Report exposed instances responsibly.
