#!/bin/bash
# LFI SSH Fuzzer - Dependency Installation Script
# Run this script to install all required dependencies

echo "==========================================="
echo "LFI SSH Fuzzer - Installation Script"
echo "==========================================="
echo ""

# Check Python version
echo "[*] Checking Python version..."
python3 --version || { echo "[-] Python3 not found. Please install Python 3.8+"; exit 1; }

# Install Python dependencies
echo "[*] Installing Python dependencies..."
pip3 install colorama --user || pip install colorama --user

# Optional dependencies
echo "[*] Installing optional dependencies..."
pip3 install requests beautifulsoup4 urllib3 --user 2>/dev/null || pip install requests beautifulsoup4 urllib3 --user 2>/dev/null

# Create necessary directories
echo "[*] Creating directories..."
mkdir -p artifacts
mkdir -p config_examples
mkdir -p tests

# Create default configuration files if they don't exist
echo "[*] Setting up configuration files..."

if [ ! -f user_agents.txt ]; then
    echo "[+] Creating user_agents.txt..."
    cat > user_agents.txt << 'EOF'
# Default User Agents
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0
curl/7.88.1
EOF
fi

if [ ! -f proxies.txt ]; then
    echo "[+] Creating proxies.txt..."
    cat > proxies.txt << 'EOF'
# Proxy examples
http://127.0.0.1:8080
http://127.0.0.1:8081
EOF
fi

if [ ! -f cookies.txt ]; then
    echo "[+] Creating cookies.txt..."
    cat > cookies.txt << 'EOF'
# Cookie examples
PHPSESSID=abc123def456ghi789
session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
EOF
fi

# Make script executable
echo "[*] Setting executable permissions..."
chmod +x lfi_ssh_fuzzer.py 2>/dev/null
chmod +x install_dependencies.sh 2>/dev/null

echo ""
echo "==========================================="
echo "[+] Installation complete!"
echo "==========================================="
echo ""
echo "Quick start:"
echo "  python3 lfi_ssh_fuzzer.py -h          # Show help"
echo "  python3 lfi_ssh_fuzzer.py             # Basic mode"
echo "  python3 lfi_ssh_fuzzer.py -adv        # Advanced mode"
echo ""
echo "Configuration files created:"
echo "  • user_agents.txt"
echo "  • proxies.txt"
echo "  • cookies.txt"
echo "  • artifacts/ (output directory)"
echo ""
