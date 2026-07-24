#!/usr/bin/env bash
# Ollama Hunter - Easy launcher script
# Add to PATH or symlink: ln -sf $(pwd)/ollama-hunter.sh /data/data/com.termux/files/usr/bin/ollama-hunter

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/ollama-hunter.py" "$@"
