#!/bin/sh
# Evil-Ollama v3.0 — Exposed Ollama Hunter & Security Tool
# Usage: ./launcher.sh <command> [options]
#   ./launcher.sh scan --random 10000
#   ./launcher.sh vuln --target 1.2.3.4:11434
#   ./launcher.sh chat --target 1.2.3.4:11434

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/evilollama.py" "$@"
