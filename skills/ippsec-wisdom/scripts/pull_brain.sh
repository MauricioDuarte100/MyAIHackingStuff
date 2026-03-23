#!/bin/bash
# pull_brain.sh - IppSec Wisdom Downloader
# Use this script when you have >2GB of free space to populate the knowledge base.

BRAIN_DIR="$HOME/.gemini/knowledge/pentesting/ippsec_wisdom"
REPO_DIR="$HOME/mcps/IaRAG"

echo "[*] IppSec Brain Updater"
echo "[*] Checking disk space..."

# Check for git-lfs
if ! command -v git-lfs &> /dev/null; then
    echo "[!] Git LFS not found. Installing..."
    sudo apt-get install git-lfs -y
    git lfs install
fi

# Clone/Pull repo
if [ ! -d "$REPO_DIR" ]; then
    echo "[*] Cloning IaRAG repo..."
    git clone https://github.com/MauricioDuarte100/IaRAG.git "$REPO_DIR"
else
    echo "[*] Updating repo..."
    cd "$REPO_DIR"
    git pull
fi

# Pull LFS files (The actual database)
echo "[*] Pulling LFS data (1.2GB)..."
cd "$REPO_DIR"
git lfs pull

# Run Extractor
echo "[*] Extracting wisdom to Markdown..."
# We reuse the native extractor we created
python3 "$REPO_DIR/extract_sqlite.py"

echo "[✅] Brain updated at $BRAIN_DIR"
