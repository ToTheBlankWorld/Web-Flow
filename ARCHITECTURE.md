# 🏗️ DNS Security Platform - Architecture & Implementation Guide

## 📐 System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Client Browser                            │
│                    (http://localhost:5173)                       │
└────────────┬─────────────────────────────────────────────────────┘
             │
             │ HTTP/WebSocket
             ▼
┌─────────────────────────────────────────────────────────────────┐
│              Frontend (React + TypeScript + Vite)               │
│                                                                  │
│  ┌──────────────┐  ┌────────────────┐  ┌─────────────────┐      │
│  │  Dashboard   │  │  AlertsPanel   │  │  DomainAnalysis │      │
│  │              │  │                │  │                 │      │
│  │ • Stats Box  │  │ • Alert List   │  │ • Risk Scoring  │      │
│  │ • Query Rate │  │ • Severity     │  │ • IPs per Domain│      │
│  │              │  │ • Timestamps   │  │ • TTL Analysis  │      │
│  └──────────────┘  └────────────────┘  └─────────────────┘      │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │           LogsPanel                                      │   │
│  │    (Terminal-style live DNS event stream)               │   │
│  └──────────────────────────────────────────────────────────┘   │
└────────────┬────────────────────────────────────────────────────┘
             │
             │ ws://localhost:8000/ws/logs
             │ (WebSocket - Real-time streaming)
             ▼
┌─────────────────────────────────────────────────────────────────┐
│         Backend (FastAPI + Python + WebSocket)                  │
│                                                                  │
│  ┌──────────────┐      ┌──────────────┐      ┌──────────────┐   │
│  │  Main App    │─────▶│ ConnectionMgr│─────▶│  WebSocket   │   │
│  │              │      │              │      │  Broadcaster │   │
│  └──────────────┘      └──────────────┘      └──────────────┘   │
│         │                                                        │
│         │ Reads async                                           │
│         ▼                                                        │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  DNSDetector Engine                                      │   │
│  │                                                           │   │
│  │  • detect_cache_poisoning()  [TTL < 60s]                │   │
│  │  • detect_fast_flux()        [3+ IPs]                   │   │
│  │  • detect_suspicious_domain() [patterns]                │   │
│  │  • detect_dns_hijacking()    [NXDOMAIN]                 │   │
│  │                                                           │   │
│  │  analyze_dns_event() → (alert, severity)                │   │
│  └──────────────────────────────────────────────────────────┘   │
│         │                                                        │
│         │ Watches file                                          │
│         ▼                                                        │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  LogFileWatcher (watch_suricata_logs)                    │   │
│  │                                                           │   │
│  │  • Monitors /var/log/suricata/eve.json                   │   │
│  │  • Parses JSON events                                    │   │
│  │  • Filters DNS events                                    │   │
│  │  • Broadcasts to WebSocket clients                       │   │
│  └──────────────────────────────────────────────────────────┘   │
└────────────┬────────────────────────────────────────────────────┘
             │
             │ File read (async)
             ▼
┌─────────────────────────────────────────────────────────────────┐
│        Suricata IDS/IPS + Eve.json Logging                      │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │  Packet Sniffer      │  Rule Engine     │  Eve Logger        │
│  │                      │                  │                    │
│  │ • Captures UDP:53    │  • Evaluates     │  • JSON Output     │
│  │ • af-packet I/O      │    rules         │  • Rich metadata   │
│  │ • BPF filter:        │  • Generates     │  • Real-time       │
│  │   udp port 53        │    events        │                    │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│         ▲                                                        │
│         │ Sniffs DNS traffic                                    │
│         │                                                        │
└─────────┼────────────────────────────────────────────────────────┘
          │
          │ UDP packets on port 53
          │
┌─────────┴────────────────────────────────────────────────────────┐
│              Network Interface (eth0, ens0, etc.)                │
│                                                                  │
│  ◀──────────────────────────────────────────────────────────▶   │
│                    DNS Traffic Stream                            │
│                                                                  │
│  Example:                                                        │
│  • 192.168.1.100:53241 → 8.8.8.8:53    (google.com)            │
│  • 192.168.1.100:53242 → 1.1.1.1:53    (example.com)           │
│  • 192.168.1.100:53243 → 8.8.8.8:53    (dga-malware.ml)        │
└──────────────────────────────────────────────────────────────────┘
```

---

## 🔄 Data Flow

### 1. DNS Query → Suricata Capture
```
User/Application sends DNS query
         ↓
Query travels on network (UDP port 53)
         ↓
Suricata af-packet intercepts
         ↓
BPF filter "udp port 53" matches
         ↓
Suricata logs to /var/log/suricata/eve.json
```

### 2. eve.json → FastAPI Processing
```
eve.json contains: {"timestamp":..., "event_type":"dns", "dns":{...}}
         ↓
Backend watch_suricata_logs() reads file
         ↓
Parses JSON line by line
         ↓
Filters for event_type == "dns"
         ↓
Extracts: domain, IPs, TTL, response code
```

### 3. FastAPI → Threat Detection
```
Parsed DNS event
         ↓
DNSDetector.analyze_dns_event() runs 4 checks:
  • detect_cache_poisoning()
  • detect_fast_flux()
  • detect_suspicious_domain()
  • detect_dns_hijacking()
         ↓
Returns: alert_level, alert_reason, severity
```

### 4. Backend → Frontend (WebSocket)
```
DNSLog object created with all metadata
         ↓
ConnectionManager.broadcast() to all clients
         ↓
Browser receives via WebSocket
         ↓
React components re-render
         ↓
Dashboard updates in real-time
```

---

## 🧠 Detection Logic Details

### Cache Poisoning Detection
```python
def detect_cache_poisoning(ttl: int) -> (bool, str):
    # Cache poisoning typically uses very short TTLs
    if ttl < 60 and ttl > 0:
        return True, f"Low TTL ({ttl}s) - cache poisoning indicator"
```

**Why it works:**
- Normal DNS responses have TTL 300-86400 seconds
- Attackers use low TTL (10-60) to quickly rotate back to clean servers
- Helps avoid detection

### Fast-Flux Detection
```python
def detect_fast_flux(domain: str, ip: str) -> (bool, str):
    # Track all IPs for each domain
    # If 3+ IPs found, it's likely fast-flux
    if len(domain_ips[domain]) >= 3:
        return True, "Multiple IPs indicate fast-flux malware"
```

**Why it works:**
- Fast-flux malware rotates IPs every few seconds
- Rotates through compromised hosts
- Each query might return different IP
- Signature of infected infrastructure

### Suspicious Domain Detection
```python
PATTERNS = [
    r'^[a-z0-9]{20,}\.',    # 20+ random chars
    r'\.tk$',                # Suspicious TLD
    r'\.ml$',                # Suspicious TLD
    r'^dga-',                # DGA prefix
    r'update.*\.',           # Update phishing
]
```

**Why it works:**
- DGA (Domain Generation Algorithm) domains are random
- Suspicious TLDs (.tk, .ml) are cheap and often used for malware
- Phishing patterns common in attacks

### DNS Hijacking Detection
```python
def detect_dns_hijacking(response_code: str) -> (bool, str):
    if response_code == "NXDOMAIN":
        return True, "NXDOMAIN - possible DNS hijacking"
```

**Why it works:**
- Legitimate DNS returns NOERROR
- Hijacked DNS returns NXDOMAIN (domain doesn't exist)
- Redirects to phishing/malware sites

---

## 📊 Risk Scoring System

```
Base Score: 0

Cache Poisoning (Low TTL):    +20 points
Fast-Flux (3+ IPs):           +30 points  (Major threat)
Suspicious Pattern:           +25 points
Per Alert Detected:           +10 points each
DNS Hijacking:                +20 points

Total: 0-100
├─ 0-30:   GREEN   (Safe)
├─ 31-70:  YELLOW  (Warning)
└─ 71+:    RED     (Critical)
```

**Example Scores:**
```
google.com              → 0    (Normal)
dga-malware.ml          → 50   (Suspicious pattern)
fast-flux.com (4 IPs)   → 80   (Critical threat)
cache-poison.com (TTL:10) → 60 (High threat)
```

---

## 🔌 API Endpoints Reference

### HTTP REST Endpoints

#### GET `/`
```
Response: {"name": "DNS Security Monitoring Platform", "version": "1.0.0", "status": "running"}
```

#### GET `/health`
```
Response: {
    "status": "healthy",
    "timestamp": "2024-03-27T14:23:45.123456",
    "active_connections": 1
}
```

#### GET `/api/stats`
```
Response: {
    "total_domains_tracked": 42,
    "active_websocket_connections": 1,
    "fast_flux_domains": 2
}
```

### WebSocket Endpoint

#### WS `/ws/logs`

**Connection:**
```javascript
const ws = new WebSocket("ws://localhost:8000/ws/logs");
```

**Received Messages (JSON):**
```json
{
    "timestamp": "2024-03-27T14:23:45.123456+0000",
    "domain": "google.com",
    "src_ip": "192.168.1.100",
    "dest_ip": "8.8.8.8",
    "query_type": "A",
    "ttl": 300,
    "response_code": "NOERROR",
    "alert_level": "INFO",
    "alert_reason": "Normal DNS query",
    "severity": "info"
}
```

---

## 📁 File Locations

### Suricata
```
/etc/suricata/suricata.yaml          # Configuration
/var/log/suricata/eve.json           # DNS events (main file)
/var/log/suricata/suricata.log       # Suricata logs
/var/log/suricata/stats.log          # Statistics
```

### Backend
```
~/dns-monitor/backend/main.py        # FastAPI application
~/dns-monitor/backend/venv/          # Virtual environment
~/dns-monitor/backend/requirements.txt
```

### Frontend
```
~/dns-monitor/frontend/src/          # React source
~/dns-monitor/frontend/dist/         # Built files
~/dns-monitor/frontend/node_modules/ # Dependencies
```

### Test Data
```
~/dns-monitor/test_eve.json          # Sample DNS events
~/dns-monitor/scripts/generate_dns_traffic.py
~/dns-monitor/scripts/generate_dns_traffic.sh
```

---

## 🔧 Configuration Options

### Suricata (suricata.yaml)

```yaml
# Network interface to sniff on
af-packet:
  - interface: eth0

# Only capture DNS (UDP port 53)
bpf-filter: "udp port 53"

# Output format and location
outputs:
  - eve-log:
      enabled: yes
      filename: eve.json
      types:
        - dns
```

### Backend (main.py)

```python
# Detection thresholds
LOW_TTL_THRESHOLD = 60              # Seconds
FAST_FLUX_IPS_THRESHOLD = 3         # Number of IPs

# Server configuration
HOST = "0.0.0.0"
PORT = 8000

# Eve.json path
EVE_FILE = "/var/log/suricata/eve.json"
```

### Frontend (App.tsx)

```typescript
// WebSocket server URL
const wsUrl = "ws://localhost:8000/ws/logs";

// API base URL
const apiUrl = "http://localhost:8000";

// Connection retry interval
const reconnectDelay = 3000; // milliseconds
```

---

## 🚀 Scaling Considerations

### Single Server (Recommended for < 50 queries/sec)
```
┌─────────────────┐
│  Suricata       │
│  Backend        │
│  Frontend       │
│  eve.json       │
└─────────────────┘
```

### Multi-Server Setup (Required for > 100 queries/sec)
```
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│  Suricata        │  │  Suricata        │  │  Suricata        │
│  (Sensor 1)      │  │  (Sensor 2)      │  │  (Sensor 3)      │
└────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘
         │                     │                     │
         └─────────────────────┴─────────────────────┘
                       │
                       ▼
            ┌──────────────────────┐
            │  PostgreSQL Database │
            │  (Event Storage)     │
            └──────────┬───────────┘
                       │
         ┌─────────────┴──────────────┐
         │                            │
         ▼                            ▼
    ┌─────────────┐             ┌──────────────┐
    │ FastAPI     │             │  Frontend    │
    │ (Backend)   │             │ (via CDN)    │
    └─────────────┘             └──────────────┘
```

### Database Integration
```python
# Replace eve.json with PostgreSQL
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "postgresql://user:password@db:5432/dns_monitor"
engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)

async def save_dns_event(event: DNSLog):
    session = Session()
    session.add(event)
    session.commit()
```

---

## 📈 Performance Metrics

### Typical Performance (Single Server)

| Metric | Value |
|--------|-------|
| Queries/sec | 50-100 |
| Latency | < 100ms |
| Memory (Backend) | 50-100 MB |
| Memory (Frontend) | 20-50 MB |
| Disk Usage (eve.json) | ~1 MB per 10k events |
| CPU Usage | 5-15% |

### Optimization Tips

1. **Suricata BPF Filter**
   - Limit to DNS: `bpf-filter: "udp port 53"`
   - Saves CPU and memory

2. **Backend Batch Processing**
   - Process events in batches
   - Reduces I/O overhead

3. **Frontend Pagination**
   - Keep logs to last 100 entries
   - Prevents UI slowdown

4. **Database Indexes**
   - Index on domain, timestamp
   - Improves query performance

---

## 🔐 Security Recommendations

### 1. Network Security
```bash
# UFW Firewall Rules
sudo ufw allow 22/tcp          # SSH
sudo ufw allow 8000/tcp        # Backend API
sudo ufw allow 3000/tcp        # Frontend
sudo ufw default deny incoming
sudo ufw enable
```

### 2. Application Security
- ✅ CORS restricted to localhost only
- ✅ Input validation on all endpoints
- ✅ No SQL injection (JSON-based storage)
- ✅ WebSocket rate limiting (optional)

### 3. Data Security
- ✅ eve.json permissions: 0600
- ✅ Regular backups of eve.json
- ✅ Log rotation enabled

### 4. Access Control
- ✅ Run Suricata as unprivileged user
- ✅ Backend runs with least privileges
- ✅ SSH key-based authentication

---

## 🎓 Advanced Topics

### Custom Detection Rules
```python
class DNSDetector:
    def detect_your_threat(self, domain: str) -> tuple[bool, str]:
        """Your custom threat logic"""
        if "your-pattern" in domain:
            return True, "Your threat detected"
        return False, ""
```

### Machine Learning Integration
```python
# Using scikit-learn for anomaly detection
from sklearn.ensemble import IsolationForest

def detect_anomaly(features: list) -> bool:
    model = IsolationForest()
    return model.predict([features])[0] == -1  # -1 = anomaly
```

### Threat Intelligence Feeds
```python
# Check against known malicious IPs/domains
import requests

def check_threat_intel(domain: str) -> bool:
    response = requests.get(f"https://api.abuseipdb.com/api/v2/check?domain={domain}")
    return response.json()['is_whitelisted'] == False
```

### Alerting Integration
```python
# Send alerts to Slack, email, PagerDuty, etc.
import smtplib

def alert_critical_threat(domain: str):
    # Send email
    send_email(f"Critical threat: {domain}")

    # Send Slack message
    send_slack_message(f"🚨 Critical: {domain}")

    # Create PagerDuty incident
    create_pagerduty_incident(domain)
```

---

## 📚 References

- Suricata Official: https://suricata.io/
- Fast-Flux Malware: https://en.wikipedia.org/wiki/Fast_flux_network
- DNS Cache Poisoning: https://en.wikipedia.org/wiki/DNS_spoofing
- DGA Detection: https://en.wikipedia.org/wiki/Domain_generation_algorithm
- FastAPI: https://fastapi.tiangolo.com/
- React: https://react.dev/

---

**Architecture designed for security, performance, and extensibility!** 🛡️
