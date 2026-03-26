#!/bin/bash
# DNS Security Monitor - Automated Setup Script
# This script automates the entire setup process

set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  DNS Security Monitoring Platform - Setup Script          ║"
echo "║  Author: Security Team                                     ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Functions
log_info() {
    echo -e "${GREEN}[*]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[x]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Step 1: System Update
step_system_update() {
    log_info "Step 1: Updating system packages..."

    apt update
    apt upgrade -y

    log_info "Installing essential tools..."
    apt install -y \
        curl wget git build-essential \
        python3 python3-pip python3-venv \
        pkg-config libpcre3 libpcre3-dev \
        net-tools dnsutils

    log_info "✓ System update complete"
}

# Step 2: Install Suricata
step_install_suricata() {
    log_info "Step 2: Installing Suricata..."

    if command -v suricata &> /dev/null; then
        log_warn "Suricata already installed"
        suricata --version
        return
    fi

    apt install -y suricata

    log_info "✓ Suricata installation complete"
    suricata --version
}

# Step 3: Configure Suricata
step_configure_suricata() {
    log_info "Step 3: Configuring Suricata..."

    # Detect network interface
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)

    if [ -z "$INTERFACE" ]; then
        log_error "Could not detect network interface"
        log_info "Available interfaces:"
        ip link show
        exit 1
    fi

    log_info "Detected interface: $INTERFACE"

    # Create directories
    mkdir -p /etc/suricata
    mkdir -p /var/log/suricata
    mkdir -p /var/lib/suricata

    chown -R suricata:suricata /var/log/suricata
    chown -R suricata:suricata /var/lib/suricata

    # Create configuration file
    log_info "Creating Suricata configuration..."

    cat > /etc/suricata/suricata.yaml << EOF
%YAML 1.1
---

HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
EXTERNAL_NET: "!\$HOME_NET"

af-packet:
  - interface: $INTERFACE
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    flow_hash:
      enabled: true
      toserver-ok-evasion: false
      toclient-ok-evasion: false
    bpf-filter: "udp port 53"
    copy-mode: ips-transparent

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - http
        - dns
        - file-data
        - drop
        - ssh
        - stats
      payload: yes
      metadata: no
      eve-log-dir: /var/log/suricata/

logging:
  default-log-level: notice
  outputs:
  - console:
      enabled: yes
  - file:
      enabled: yes
      level: info
      filename: /var/log/suricata/suricata.log
EOF

    log_info "✓ Suricata configuration complete"
}

# Step 4: Start Suricata
step_start_suricata() {
    log_info "Step 4: Starting Suricata..."

    systemctl daemon-reload
    systemctl enable suricata
    systemctl start suricata

    sleep 2

    if systemctl is-active --quiet suricata; then
        log_info "✓ Suricata is running"
        systemctl status suricata --no-pager
    else
        log_error "Failed to start Suricata"
        systemctl status suricata --no-pager
        exit 1
    fi
}

# Step 5: Backend Setup
step_backend_setup() {
    log_info "Step 5: Setting up Backend (FastAPI)..."

    cd backend

    # Create virtual environment
    python3 -m venv venv
    source venv/bin/activate

    # Upgrade pip
    pip install --upgrade pip

    # Install dependencies
    pip install -r requirements.txt

    # Create systemd service
    cat > /etc/systemd/system/dns-monitor-backend.service << EOF
[Unit]
Description=DNS Security Monitor - Backend
After=network.target

[Service]
Type=simple
User=$SUDO_USER
WorkingDirectory=$PWD
ExecStart=$PWD/venv/bin/python main.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload

    log_info "✓ Backend setup complete"
    log_info "   Python version: $(python3 --version)"
}

# Step 6: Frontend Setup (Optional - for local dev)
step_frontend_setup() {
    log_info "Step 6: Setting up Frontend (React)..."

    # Check if Node.js is installed
    if ! command -v node &> /dev/null; then
        log_info "Installing Node.js..."
        curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
        apt install -y nodejs
    fi

    cd ../frontend

    # Install dependencies
    npm install

    log_info "✓ Frontend setup complete"
    log_info "   Node version: $(node --version)"
    log_info "   NPM version: $(npm --version)"
}

# Step 7: Generate Test Data
step_test_traffic() {
    log_info "Step 7: Generating test DNS traffic..."

    cd ..

    # Generate some test queries
    for i in {1..10}; do
        nslookup google.com 8.8.8.8 > /dev/null 2>&1
        nslookup example.com 1.1.1.1 > /dev/null 2>&1
        sleep 1
    done

    log_info "✓ Test traffic generated"
}

# Step 8: Verification
step_verify() {
    log_info "Step 8: Verifying setup..."

    echo ""
    log_info "Checking Suricata..."
    if systemctl is-active --quiet suricata; then
        log_info "  ✓ Suricata is running"
    else
        log_error "  ✗ Suricata is NOT running"
    fi

    log_info "Checking eve.json..."
    if [ -f /var/log/suricata/eve.json ]; then
        LINES=$(wc -l < /var/log/suricata/eve.json)
        log_info "  ✓ eve.json found ($LINES events)"
    else
        log_warn "  ✗ eve.json not found yet (wait for DNS traffic)"
    fi

    log_info "Checking Python..."
    if command -v python3 &> /dev/null; then
        log_info "  ✓ Python $(python3 --version | cut -d' ' -f2)"
    fi

    log_info "Checking Node.js..."
    if command -v node &> /dev/null; then
        log_info "  ✓ Node $(node --version)"
    fi

    echo ""
}

# Main Setup Flow
main() {
    check_root

    log_info "Starting DNS Security Monitor setup..."
    echo ""

    # Run setup steps
    step_system_update
    echo ""

    step_install_suricata
    echo ""

    step_configure_suricata
    echo ""

    step_start_suricata
    echo ""

    # Optional: Backend and Frontend
    read -p "Set up Backend? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        step_backend_setup
        echo ""
    fi

    read -p "Set up Frontend? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        step_frontend_setup
        echo ""
    fi

    step_test_traffic
    echo ""

    step_verify
    echo ""

    # Print next steps
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║                 SETUP COMPLETE! 🎉                        ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""

    log_info "Next steps:"
    echo "  1. Start Backend: cd backend && source venv/bin/activate && python main.py"
    echo "  2. Start Frontend: cd frontend && npm run dev"
    echo "  3. Generate Traffic: python3 scripts/generate_dns_traffic.py"
    echo "  4. Open Browser: http://localhost:5173"
    echo ""

    log_info "Verify Suricata is capturing:"
    echo "  tail -f /var/log/suricata/eve.json"
    echo ""

    log_info "Check Suricata logs:"
    echo "  sudo journalctl -u suricata -f"
    echo ""
}

# Execute main
main
