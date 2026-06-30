#!/usr/bin/env bash
set -e

echo "=== REeve setup ==="

# 1. Check Python
python3 --version || { echo "Python 3.11+ required"; exit 1; }

# 2. Check Java
if [ -z "$JAVA_HOME" ]; then
    echo ""
    echo "JAVA_HOME is not set. REeve requires Java 21+."
    echo "Download Temurin JDK 21 from: https://adoptium.net/temurin/releases/?version=21"
    echo ""
    echo "On macOS (no sudo):"
    echo "  mkdir -p ~/java"
    echo "  tar -xzf OpenJDK21U-jdk_x64_mac_hotspot_*.tar.gz -C ~/java"
    echo "  export JAVA_HOME=~/java/<extracted-dir>/Contents/Home"
    echo ""
    echo "Then re-run this script."
    exit 1
fi
java -version

# 3. Check Ghidra
if [ -z "$GHIDRA_INSTALL_DIR" ]; then
    echo ""
    echo "GHIDRA_INSTALL_DIR is not set."
    echo "Download Ghidra from: https://ghidra-sre.org/"
    echo "Then set:  export GHIDRA_INSTALL_DIR=/path/to/ghidra_<version>_PUBLIC"
    exit 1
fi
echo "Ghidra: $GHIDRA_INSTALL_DIR"

# 4. Check API key
if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo ""
    echo "ANTHROPIC_API_KEY is not set."
    echo "Set it with:  export ANTHROPIC_API_KEY=sk-ant-..."
    exit 1
fi
echo "Anthropic API key: set"

# 5. Install Python deps
pip install -e . --quiet

# 6. Install PyGhidra into Ghidra
python3 -c "
import pyghidra, pathlib
install_dir = pathlib.Path('$GHIDRA_INSTALL_DIR')
if not pyghidra.started():
    pyghidra.start(install_dir=install_dir)
print('PyGhidra OK')
" 2>/dev/null || echo "PyGhidra will initialise on first run."

echo ""
echo "=== Setup complete ==="
echo ""
echo "Usage:"
echo "  reeve analyze <binary> --goal 'identify vulnerabilities'"
echo "  reeve chat <binary>"
echo "  reeve report <session.reeve.json> --format md"
