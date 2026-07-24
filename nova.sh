#!/usr/bin/env bash
# Nova - Next-Gen Ollama Hunter v3.0
# Easy launcher script
# Usage: ./nova.sh <command> [options]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/evilollama.py" "$@"
