# 🚀 DNS Security Platform - Quick Start & Deployment Guide

## 📋 5-Minute Quick Start (Local)

### Prerequisite Check
```bash
# Verify Python is installed
python3 --version  # Should be 3.8+

# Verify Node.js is installed
node --version     # Should be 16+
npm --version      # Should be 8+
```

### Step 1: Terminal 1 - Start Backend
```bash
cd backend

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start FastAPI server
python3 main.py

# Output should show:
# INFO:     Application startup complete
# INFO:     Uvicorn running on http://0.0.0.0:8000
```

### Step 2: Terminal 2 - Start Frontend
```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev

# Output should show:
#   ➜  Local:   http://localhost:5173/
#   ➜  press h + enter to show help
```

### Step 3: Terminal 3 - Generate DNS Traffic
```bash
cd scripts

# Install dependencies
pip install -r requirements.txt

# Run traffic generator
python3 generate_dns_traffic.py

# Output should show:
# [*] DNS Traffic Generator - dnspython Method
# [*] Generating DNS queries...
# [2024-03-27 14:23:45] Query #1: A record for google.com (via 8.8.8.8)
#     ✓ Response received (1 records)
```

### Step 4: Open Dashboard
```
http://localhost:5173
```

You should see:
- ✅ Live DNS queries streaming in
- ✅ Real-time alerts
- ✅ Domain analysis with risk scores

---

## 🖥️ VPS Deployment (Ubuntu 20.04+)

### Option A: Automated Setup (Recommended)
```bash
# Download and run the setup script
sudo bash setup.sh

# The script will:
# 1. Update system
# 2. Install Suricata
# 3. Configure network interface detection
# 4. Start Suricata service
# 5. Set up Python backend
# 6. Set up Node.js frontend
# 7. Verify all components
```

### Option B: Manual Setup

#### Step 1: Connect to VPS
```bash
ssh root@your-vps-ip

# Update system
sudo apt update && sudo apt upgrade -y
```

#### Step 2: Install Suricata
```bash
# Install from repository
sudo apt install -y suricata

# Verify installation
suricata --version
```

#### Step 3: Detect Network Interface
```bash
# Find your network interface
ip route | grep default

# Output example: "default via 192.168.1.1 dev eth0"
# Your interface: eth0

# List all interfaces
ip link show
```

#### Step 4: Create Suricata Configuration
```bash
# Create config directory
sudo mkdir -p /etc/suricata /var/log/suricata

# Create configuration (replace eth0 with your interface)
sudo tee /etc/suricata/suricata.yaml > /dev/null << 'EOF'
%YAML 1.1
---

HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
EXTERNAL_NET: "!$HOME_NET"

af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    bpf-filter: "udp port 53"

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
```

#### Step 5: Start Suricata
```bash
# Create systemd service
sudo tee /etc/systemd/system/suricata.service > /dev/null << 'EOF'
[Unit]
Description=Suricata IDS/IPS
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml -i eth0 -D
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=30s

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable suricata
sudo systemctl start suricata

# Check status
sudo systemctl status suricata
```

#### Step 6: Install Python & Backend
```bash
# Install Python and pip
sudo apt install -y python3 python3-pip python3-venv

# Clone or download project
git clone <your-repo> dns-monitor
cd dns-monitor/backend

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create systemd service
sudo tee /etc/systemd/system/dns-monitor-backend.service > /dev/null << 'EOF'
[Unit]
Description=DNS Security Monitor - Backend
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/dns-monitor/backend
ExecStart=/root/dns-monitor/backend/venv/bin/python main.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable dns-monitor-backend
sudo systemctl start dns-monitor-backend
```

#### Step 7: Install Node.js & Frontend
```bash
# Install Node.js
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

# Navigate to frontend
cd ../frontend

# Install dependencies
npm install

# Build frontend
npm run build

# Install web server
sudo npm install -g serve

# Create systemd service
sudo tee /etc/systemd/system/dns-monitor-frontend.service > /dev/null << 'EOF'
[Unit]
Description=DNS Security Monitor - Frontend
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/dns-monitor/frontend
ExecStart=/usr/local/bin/serve -s dist -l 3000
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable dns-monitor-frontend
sudo systemctl start dns-monitor-frontend
```

#### Step 8: Verify All Services
```bash
# Check all services
sudo systemctl status suricata
sudo systemctl status dns-monitor-backend
sudo systemctl status dns-monitor-frontend

# Check logs
sudo tail -f /var/log/suricata/eve.json
curl http://localhost:8000/health
curl http://localhost:3000
```

---

## 🧪 Testing & Verification

### Generate DNS Traffic
```bash
# Method 1: Bash loop
for i in {1..20}; do
  nslookup google.com 8.8.8.8
  nslookup example.com 1.1.1.1
  nslookup github.com 8.8.4.4
  sleep 2
done

# Method 2: Python script
cd scripts
pip install dnspython
python3 generate_dns_traffic.py
```

### Verify Suricata Capture
```bash
# Watch live eve.json output
tail -f /var/log/suricata/eve.json

# Count DNS events
grep -c '"event_type":"dns"' /var/log/suricata/eve.json

# Pretty print with jq
tail -f /var/log/suricata/eve.json | jq '.dns'
```

### Test Backend API
```bash
# Health check
curl http://localhost:8000/health

# Get statistics
curl http://localhost:8000/api/stats

# Expected output:
# {"total_domains_tracked":42,"active_websocket_connections":1,"fast_flux_domains":0}
```

### Test Frontend Dashboard
```bash
# Open in browser
http://your-vps-ip:3000
# or for SSL
https://your-vps-ip:3000
```

---

## 📊 Expected Output Examples

### Live Dashboard Output
```
╔═══════════════════════════════════════════════════════════╗
║         🛡️  DNS Security Monitor                         ║
║      Real-time threat detection & analysis               ║
╚═══════════════════════════════════════════════════════════╝

STATS:
  • Domains Tracked:      45
  • Active Connections:   1
  • Total Alerts:         3

LIVE LOGS:
  [INFO]  2024-03-27 14:23:45 - QUERY: google.com (A)
          SOURCE: 192.168.1.100 → 8.8.8.8
          TTL: 300

  [ALERT] 2024-03-27 14:23:47 - QUERY: d94ea7d8db472.com (A)
          ⚠️  Low TTL (45s) - possible cache poisoning
          SEVERITY: Warning

  [ALERT] 2024-03-27 14:23:49 - QUERY: fast-flux.com (A)
          🚨 Fast-flux detected: 4 IPs
          SEVERITY: Critical

ALERTS:
  [14:23:47] d94ea7d8db472.com
             Low TTL (45s) detected

  [14:23:49] fast-flux.com
             Fast-flux detected: 4 different IPs

TOP DOMAINS:
  1. google.com              [25%] green   (Safe)
  2. fast-flux.com           [92%] red     (Critical)
  3. d94ea7d8db472.com       [65%] yellow  (Warning)
```

### eve.json Sample Output
```json
{"timestamp":"2024-03-27T14:23:45.123456+0000","event_type":"dns","src_ip":"192.168.1.100","dns":{"rrname":"google.com","rrtype":"A","rcode":"NOERROR","ttl":300,"answers":["142.250.185.46"]}}
{"timestamp":"2024-03-27T14:23:47.234567+0000","event_type":"dns","src_ip":"192.168.1.100","dns":{"rrname":"dga-malware.ml","rrtype":"A","rcode":"NXDOMAIN","ttl":0,"answers":[]}}
{"timestamp":"2024-03-27T14:23:49.345678+0000","event_type":"dns","src_ip":"192.168.1.100","dns":{"rrname":"fast-flux.com","rrtype":"A","rcode":"NOERROR","ttl":10,"answers":["10.0.0.1","10.0.0.2","10.0.0.3"]}}
```

---

## ✅ Deployment Checklist

- [ ] Suricata installed and running
- [ ] Network interface configured correctly
- [ ] eve.json being written to with DNS events
- [ ] FastAPI backend running on port 8000
- [ ] React frontend running on port 3000 or 5173
- [ ] WebSocket connection working (/ws/logs)
- [ ] DNS traffic generator running
- [ ] Dashboard showing live events
- [ ] Alerts being triggered for suspicious domains
- [ ] Risk scoring working (0-100 scale)
- [ ] FastAPI health check returns 200
- [ ] Systemd services configured (optional)

---

## 🔒 Security Hardening

### Firewall Rules
```bash
# Allow SSH
sudo ufw allow 22/tcp

# Allow backend
sudo ufw allow 8000/tcp

# Allow frontend
sudo ufw allow 3000/tcp
sudo ufw allow 3000/tcp

# Block all other ports
sudo ufw default deny incoming
sudo ufw enable
```

### Nginx Reverse Proxy (Optional)
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location /api {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /ws {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    location / {
        proxy_pass http://localhost:3000;
    }
}
```

### SSL/TLS (Let's Encrypt)
```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot certonly --nginx -d your-domain.com
```

---

## 📈 Performance Tuning

### Suricata Optimization
```yaml
# In /etc/suricata/suricata.yaml
af-packet:
  - interface: eth0
    threads: 8                    # Increase for more cores
    cluster-id: 99
    cluster-type: cluster_flow
```

### Backend Optimization
```python
# In backend/main.py
# Increase batch processing
BATCH_SIZE = 1000
FLUSH_INTERVAL = 5  # seconds
```

---

## 🆘 Troubleshooting

### Issue: No DNS Events

```bash
# 1. Check Suricata is running
sudo systemctl status suricata

# 2. Check interface is correct
ip route | grep default

# 3. Generate test traffic manually
nslookup google.com 8.8.8.8

# 4. Check eve.json has write permissions
ls -la /var/log/suricata/eve.json

# 5. Check if Suricata has DNS rule
grep -i "dns" /etc/suricata/suricata.yaml
```

### Issue: WebSocket Connection Failed

```bash
# 1. Check backend is running
curl http://localhost:8000/health

# 2. Check firewall
sudo ufw status

# 3. Check logs
sudo journalctl -u dns-monitor-backend -f

# 4. Allow port 8000
sudo ufw allow 8000/tcp
```

### Issue: High CPU/Memory Usage

```bash
# Check Suricata CPU usage
top -p $(pgrep suricata)

# Reduce BPF filter to DNS only
bpf-filter: "udp port 53"

# Reduce threads
threads: 2

# Restart
sudo systemctl restart suricata
```

---

## 📞 Support & Resources

- **Suricata Docs**: https://docs.suricata.io/
- **FastAPI Docs**: https://fastapi.tiangolo.com/
- **React Docs**: https://react.dev/
- **GitHub Issues**: Create an issue on the repo

---

## 🎓 Learning Path

1. **Week 1**: Deploy on local VPS, understand DNS traffic
2. **Week 2**: Customize detection rules
3. **Week 3**: Add database persistence
4. **Week 4**: Set up alerting (Slack, email, PagerDuty)
5. **Week 5**: Advanced threat intelligence integration

---

**Now you're ready to deploy!** 🚀

Start with `/setup.sh` on a fresh Ubuntu VPS, or follow the manual steps above.
