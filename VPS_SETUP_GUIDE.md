# 🚀 DNS Security Monitoring Platform - Complete VPS Setup Guide

## 📋 Prerequisites

- A Linux VPS (Ubuntu 20.04+ or similar)
- Root or sudo access
- Minimum 2GB RAM, 20GB disk space
- Network interface already configured

## ⚙️ STEP 1: System Update & Dependencies

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install basic tools
sudo apt install -y curl wget git build-essential

# Install Python 3 and pip
sudo apt install -y python3 python3-pip python3-venv

# Install Node.js (for frontend)
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

# Install pkg-config and development libraries
sudo apt install -y pkg-config libpcre3 libpcre3-dev

# Verify installations
python3 --version
node --version
npm --version
```

## ⚙️ STEP 2: Install Suricata

### Option A: From Ubuntu Repository (Faster)

```bash
# Install Suricata from apt
sudo apt install -y suricata

# Verify installation
suricata --version
```

### Option B: From Source (Latest Version)

```bash
# Install dependencies
sudo apt install -y autoconf automake libtool pkg-config libpcre3-dev libpcre3 \
  libnet1-dev libyaml-dev libjansson-dev libcap-ng-dev zlib1g-dev libmagic-dev \
  libgeoip-dev libnetfilter-queue-dev libnetfilter-queue1 libnfnetlink-dev

# Clone Suricata repository
git clone https://github.com/OISF/suricata.git
cd suricata

# Build and install
./autogen.sh
./configure --enable-nfqueue --enable-geoip --enable-python --enable-jansson
make -j$(nproc)
sudo make install
sudo ldconfig

# Verify
suricata --version
```

## ⚙️ STEP 3: Configure Suricata

### Identify Network Interface

```bash
# List network interfaces
ip link show

# Get interface details
ip addr show

# Usually eth0, ens0, or ens3
# Note your interface name for configuration
```

### Create Suricata Configuration

```bash
# Create configuration directory
sudo mkdir -p /etc/suricata
sudo mkdir -p /var/log/suricata
sudo mkdir -p /var/lib/suricata

# Set proper permissions
sudo chown -R suricata:suricata /var/log/suricata
sudo chown -R suricata:suricata /var/lib/suricata

# Create Eve JSON output
sudo cat > /etc/suricata/suricata.yaml << 'EOF'
%YAML 1.1
---

# Network interface to sniff on - CHANGE THIS!
HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
EXTERNAL_NET: "!$HOME_NET"

af-packet:
  - interface: eth0  # CHANGE THIS to your interface
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    flow_hash:
      enabled: true
      toserver-ok-evasion: false
      toclient-ok-evasion: false
    use-mmap: no
    toggle: no
    bpf-filter: "udp port 53"  # Only capture DNS traffic
    copy-mode: ips-transparent

# Output configuration
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
      payload-buffer-size: 4096
      metadata: no
      use-stream-depth: no
      eve-log-dir: /var/log/suricata/

# Logging
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
```

### Important Configuration Notes

```bash
# If you don't know your interface, run:
ip route | grep default

# Example output: "default via 192.168.1.1 dev eth0"
# Your interface is: eth0

# For cloud VPS (AWS, Linode, DigitalOcean, etc.):
# - AWS: usually eth0
# - DigitalOcean: usually eth0 or ens3
# - Linode: usually eth0
# - Azure: usually eth0
# - GCP: usually eth0
```

## ⚙️ STEP 4: Update Suricata Rules

```bash
# Update the rule-update tool (surichecker)
cd /opt/suricata/bin
sudo suricata-update update-sources
sudo suricata-update enable-source et/open
sudo surichecker update

# Or update manually using default rules
sudo cp /usr/share/suricata/rules/* /var/lib/suricata/
```

## ⚙️ STEP 5: Start Suricata

### Run Suricata (Foreground - for testing)

```bash
# Run in foreground to see if it starts correctly
sudo suricata -c /etc/suricata/suricata.yaml -i eth0 -v

# If it works, press Ctrl+C to stop
```

### Create Systemd Service (Production)

```bash
# Create systemd service file
sudo cat > /etc/systemd/system/suricata.service << 'EOF'
[Unit]
Description=Suricata IDS/IPS
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml -i eth0 -D
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
RestartSec=30s

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable suricata
sudo systemctl start suricata

# Check status
sudo systemctl status suricata

# View logs
sudo journalctl -u suricata -f
```

## ⚙️ STEP 6: Verify Suricata is Capturing DNS

### Check Eve.json Output

```bash
# Wait for traffic, then check the log
sleep 5
tail -f /var/log/suricata/eve.json

# You should see JSON-formatted DNS events like:
# {"timestamp":"2024-03-27T14:23:45.123456+0000","event_type":"dns",...}

# If no events, check pcap permissions:
sudo chmod 644 /var/log/suricata/eve.json
```

### Troubleshooting

```bash
# If no events are being captured:

# 1. Check if Suricata is running
ps aux | grep suricata

# 2. Check the log
tail -50 /var/log/suricata/suricata.log

# 3. Generate test DNS traffic
nslookup google.com 8.8.8.8

# 4. Check network stats
sudo netstat -an | grep :53

# 5. Verify interface is correct
ip link show | grep eth0

# 6. Check firewall rules
sudo ufw status
```

## 📊 STEP 7: Generate DNS Traffic

```bash
# Option 1: Using nslookup in a loop
for i in {1..100}; do
  nslookup google.com 8.8.8.8
  nslookup example.com 1.1.1.1
  nslookup github.com 8.8.8.8
  sleep 2
done &

# Option 2: Using Python script (from the scripts folder)
# First, install dnspython
pip3 install dnspython

# Then run the generator
python3 scripts/generate_dns_traffic.py &
```

## 🔙 STEP 8: Set Up Backend (FastAPI)

```bash
# Create virtual environment
mkdir -p ~/dns-monitor
cd ~/dns-monitor
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r backend/requirements.txt

# Start FastAPI server
python3 backend/main.py

# Server will run on http://0.0.0.0:8000
# Access health check: curl http://localhost:8000/health
```

## 🎨 STEP 9: Set Up Frontend (React)

### On your local machine or a separate terminal:

```bash
# Navigate to frontend
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev

# Frontend will be available at http://localhost:5173
```

### Connect to Remote VPS

If running on a remote VPS:

```bash
# 1. Build the frontend
npm run build

# 2. Install a simple server
npm install -g serve

# 3. Serve the build
serve -s dist -l 3000

# 4. Update backend API URL in App.tsx to match your VPS IP/domain
```

## 🔗 STEP 10: Connect Components

```bash
# DNS Traffic → Suricata → eve.json
# eve.json ← FastAPI Backend
# FastAPI Backend ← React Frontend (WebSocket)

# Make sure:
# 1. Suricata is writing to /var/log/suricata/eve.json ✓
# 2. FastAPI backend can read eve.json ✓
# 3. Frontend can connect to WebSocket (ws://backend:8000/ws/logs) ✓
```

## ✅ Verification Checklist

```bash
# 1. Check Suricata is running
sudo systemctl status suricata

# 2. Check eve.json is being written to
ls -lh /var/log/suricata/eve.json
tail /var/log/suricata/eve.json

# 3. Check FastAPI is running
curl http://localhost:8000/health

# 4. Generate test traffic
python3 scripts/generate_dns_traffic.py &

# 5. Watch the frontend dashboard update in real time

# 6. Trigger an alert by querying suspicious domain
nslookup dga-malware.ml 8.8.8.8
```

## 📁 Expected Directory Structure

```
/var/log/suricata/
├── eve.json              # Main DNS events log
├── suricata.log         # Suricata logs
├── stats.log            # Statistics

/etc/suricata/
└── suricata.yaml        # Configuration file

~/dns-monitor/
├── backend/
│   ├── main.py
│   ├── requirements.txt
│   └── venv/
└── frontend/
    ├── src/
    ├── package.json
    ├── vite.config.ts
    └── node_modules/
```

## 🚨 Common Issues & Solutions

### Issue: "EVE file not found"
```bash
# Solution: Check permissions and paths
sudo ls -la /var/log/suricata/
sudo chown -R suricata:suricata /var/log/suricata
```

### Issue: "No DNS events in eve.json"
```bash
# Solution: Generate traffic manually
for i in {1..10}; do nslookup google.com 8.8.8.8; done

# Or check the BPF filter
sudo suricata -c /etc/suricata/suricata.yaml -i eth0 --list-app-layer-protos
```

### Issue: "WebSocket connection refused"
```bash
# Solution: Make sure FastAPI is running
curl http://localhost:8000/health

# Check firewall
sudo ufw allow 8000
```

### Issue: "DNS queries not being captured"
```bash
# Solution: Check if interface is correct
ip link show
ip route | grep default

# Update interface in /etc/suricata/suricata.yaml
# Then restart Suricata
sudo systemctl restart suricata
```

## 🔄 Quick Start Commands

```bash
# Terminal 1: Start Suricata
sudo systemctl start suricata
sudo journalctl -u suricata -f

# Terminal 2: Start Backend
cd backend
source venv/bin/activate
python3 main.py

# Terminal 3: Start Frontend
cd frontend
npm run dev

# Terminal 4: Generate DNS Traffic
python3 scripts/generate_dns_traffic.py
```

## 📚 Additional Resources

- Suricata Documentation: https://docs.suricata.io/
- FastAPI Documentation: https://fastapi.tiangolo.com/
- React Documentation: https://react.dev/
- DNS Protocol: https://en.wikipedia.org/wiki/Domain_Name_System

---

**Now you have a fully functional DNS Security Monitoring Platform running on your VPS!** 🎉
