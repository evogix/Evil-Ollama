#!/bin/sh
# Evil-Ollama v3.0 — Exposed Ollama Hunter & Security Tool
# Usage: ./launcher.sh <command> [options]
#   ./launcher.sh scan --random 10000
#   ./launcher.sh vuln --target 1.2.3.4:11434
#   ./launcher.sh chat --target 1.2.3.4:11434

SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
if [ -f "$SCRIPT_DIR/evilollama/__init__.py" ]; then
    exec python3 -m evilollama "$@"
elif [ -f "$SCRIPT_DIR/evilollama.py" ]; then
    exec python3 "$SCRIPT_DIR/evilollama.py" "$@"
else
    echo "Error: evilollama module not found"
    exit 1
fi
