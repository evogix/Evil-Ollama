#!/bin/bash
# Ollama Hunter - Installer
set -e

echo "🚀 Installing Ollama Hunter..."

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required. Install it first."
    exit 1
fi

# Install dependencies
echo "📦 Installing Python dependencies..."
pip3 install aiohttp flask requests 2>/dev/null || pip install aiohttp flask requests

# Make script executable
chmod +x ollama-hunter.py

echo ""
echo "✅ Ollama Hunter installed successfully!"
echo ""
echo "Quick start:"
echo "  python ollama-hunter.py scan --random 1000"
echo "  python ollama-hunter.py show"
echo "  python ollama-hunter.py chat --target <ip>:11434"
echo "  python ollama-hunter.py proxy --target <ip>:11434 --port 8080"
echo ""
echo "Full help:"
echo "  python ollama-hunter.py --help"
