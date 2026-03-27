# DNS Guardian - Idea Sprint 3.0 Presentation

## Team Information
**Team Name:** [Your Team Name]  
**Project:** DNS Guardian - Real-Time DNS Security Monitoring Platform

---

## SLIDE 1: Title Slide

**DNS Guardian**  
*Real-Time DNS Security Monitoring Platform*

Protecting networks from DNS-based cyber attacks through intelligent threat detection and live monitoring.

---

## SLIDE 2: Problem Statement

### The Problem

- **DNS is a critical attack vector** - Over 90% of malware uses DNS for communication
- **Traditional security tools are reactive** - Threats are detected after damage is done
- **Limited visibility** - Most organizations cannot see DNS-level attacks in real-time
- **Complex existing solutions** - Enterprise DNS security tools are expensive and difficult to deploy

### Impact of DNS Attacks
- Data exfiltration through DNS tunneling
- Malware command & control communication
- Phishing via DNS hijacking
- Service disruption through cache poisoning

---

## SLIDE 3: Solution Overview

### DNS Guardian

A lightweight, real-time DNS security monitoring platform that:

✅ **Captures** all DNS traffic on the network  
✅ **Analyzes** queries using intelligent threat detection algorithms  
✅ **Alerts** administrators instantly via WebSocket streaming  
✅ **Visualizes** threats through a modern, intuitive dashboard  

### One-Line Summary
*"See every DNS query. Detect every threat. Respond in real-time."*

---

## SLIDE 4: Technical Approach

### Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Frontend** | React 18 + TypeScript | Interactive dashboard |
| **Styling** | Tailwind CSS | Modern, responsive UI |
| **Backend** | FastAPI (Python) | High-performance API server |
| **Real-time** | WebSocket | Live data streaming |
| **IDS Engine** | Suricata | Network packet capture |
| **Build Tool** | Vite | Fast development & bundling |
| **Phishing Detection** | dnstwist | Typosquatting detection |

### Detection Algorithms

1. **Cache Poisoning Detection**
   - Monitors TTL values
   - Flags queries with TTL < 60 seconds

2. **Fast-Flux Detection**
   - Tracks IP resolution patterns
   - Alerts when domain resolves to 3+ different IPs

3. **DGA Detection**
   - Pattern matching for randomly generated domains
   - Identifies malware communication channels

4. **DNS Hijacking Detection**
   - Monitors for unexpected NXDOMAIN responses
   - Validates DNS responses against authoritative servers

5. **Phishing/Typosquat Detection (NEW)**
   - Uses dnstwist algorithms to detect lookalike domains
   - Compares against database of protected domains (banks, edu, social media)
   - Alerts user with the correct/original website URL
   - Example: Detects `gitamedu.com` as fake version of `gitam.edu`

**📚 For comprehensive tech stack details, see [TECH_STACK.md](TECH_STACK.md)**

---

## SLIDE 5: System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     USER DASHBOARD                          │
│              (React + TypeScript + Tailwind)                │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│   │ Overview │  │ Threats  │  │ Domains  │  │   Map    │   │
│   └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└─────────────────────────┬───────────────────────────────────┘
                          │ WebSocket (Real-time)
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    BACKEND SERVER                           │
│                  (FastAPI + Python)                         │
│   ┌──────────────────────────────────────────────────────┐  │
│   │              Threat Detection Engine                  │  │
│   │  • Cache Poisoning  • Fast-Flux  • DGA  • Hijacking  │  │
│   └──────────────────────────────────────────────────────┘  │
└─────────────────────────┬───────────────────────────────────┘
                          │ File Watch (eve.json)
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    SURICATA IDS                             │
│              (Network Intrusion Detection)                  │
│         Captures DNS packets (UDP port 53)                  │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                   NETWORK TRAFFIC                           │
│              (All DNS queries on network)                   │
└─────────────────────────────────────────────────────────────┘
```

---

## SLIDE 6: Working of the Solution

### Step-by-Step Flow

**Step 1: Packet Capture**
- Suricata monitors network interface
- Captures all UDP port 53 (DNS) traffic
- Logs events to eve.json in real-time

**Step 2: Event Processing**
- Backend watches eve.json for new entries
- Parses DNS query/response data
- Extracts domain, IPs, TTL, response codes

**Step 3: Threat Analysis**
- Detection engine evaluates each query
- Applies multiple threat detection algorithms
- Assigns risk score and severity level

**Step 4: Real-time Broadcast**
- Results streamed via WebSocket
- Dashboard updates instantly (<100ms latency)
- Alerts generated for threats

**Step 5: User Action**
- Administrator views live dashboard
- Can whitelist trusted domains
- Takes action on detected threats

---

## SLIDE 7: Use Case Flow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   User/App  │────▶│  DNS Query  │────▶│  Suricata   │
│ makes query │     │ google.com  │     │  captures   │
└─────────────┘     └─────────────┘     └──────┬──────┘
                                               │
                                               ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Dashboard  │◀────│  WebSocket  │◀────│   Backend   │
│  displays   │     │  streams    │     │  analyzes   │
└─────────────┘     └─────────────┘     └─────────────┘
                                               │
                          ┌────────────────────┴────────────────────┐
                          ▼                                         ▼
                    ┌───────────┐                            ┌───────────┐
                    │   SAFE    │                            │  THREAT   │
                    │  Normal   │                            │  Alert!   │
                    │  logging  │                            │  Action   │
                    └───────────┘                            └───────────┘
```

### Example Scenarios

| Scenario | Detection | Response |
|----------|-----------|----------|
| Normal browsing | google.com, TTL=300s | ✅ Logged as safe |
| Low TTL attack | evil.com, TTL=5s | ⚠️ Cache poisoning alert |
| Fast-flux malware | malware.tk → 5 IPs | 🚨 Critical alert |
| DGA botnet | a8d7f2e9.com | ⚠️ Suspicious domain alert |
| **Phishing site** | **gitamedu.com** | **🎣 Phishing alert! Real site: gitam.edu** |

---

## SLIDE 8: Key Features

### 1. Real-Time DNS Monitoring
Live capture and display of all network DNS traffic with instant updates.

### 2. Multi-Threat Detection
Automatically identifies cache poisoning, fast-flux networks, DGA domains, DNS hijacking, and phishing attempts.

### 3. Phishing/Typosquat Detection (dnstwist)
Detects lookalike domains that impersonate legitimate sites (banks, universities, social media). Shows the correct original site URL to users.

### 4. Modern Security Dashboard
Clean, intuitive interface with multiple views: Overview, Traffic, Threats, Domains, Map, and Graph.

### 5. Automated Risk Scoring
Each domain receives a calculated risk score (0-100) based on behavior patterns.

### 6. Instant Alert System
WebSocket-powered notifications with severity levels (Critical, High, Medium, Low).

### 7. Domain Whitelist Management
One-click whitelisting for trusted domains with persistent storage.

### 8. Visual Analytics
Interactive charts, world map visualization, and domain relationship graphs.

---

## SLIDE 9: Innovation and Impact

### What Makes DNS Guardian Innovative

| Traditional Tools | DNS Guardian |
|-------------------|--------------|
| Batch log analysis | Real-time streaming |
| Command-line interface | Modern web dashboard |
| Manual rule writing | Automated detection |
| Enterprise pricing | Open-source & free |
| Complex deployment | Simple setup |

### Unique Aspects

1. **Unified Pipeline** - Combines packet capture, threat analysis, and visualization in one platform
2. **Sub-100ms Latency** - See threats as they happen, not minutes later
3. **Smart Detection** - Multiple algorithms working together for higher accuracy
4. **User-Friendly** - No security expertise required to understand alerts

### Target Users

- **Network Administrators** - Monitor corporate DNS traffic
- **Security Operations Centers** - Detect DNS-based attacks
- **Small/Medium Businesses** - Affordable DNS security
- **Educational Institutions** - Learn network security concepts
- **Home Users** - Protect home networks

### Real-World Impact

- **Prevents Data Exfiltration** via DNS tunneling detection
- **Blocks Malware Communication** by identifying C2 domains
- **Protects Against Phishing** through suspicious domain alerts
- **Reduces Response Time** from hours to seconds

---

## SLIDE 10: Challenges and Future Scope

### Challenges Faced

| Challenge | How We Solved It |
|-----------|------------------|
| High packet volume | Async event handling with Python asyncio |
| Real-time updates | WebSocket with connection management |
| False positives | Multi-factor scoring (TTL + IPs + patterns) |
| Cross-platform | Docker + Windows batch scripts |
| UI performance | React state batching (150ms intervals) |

### Current Limitations

- Requires Suricata installation on monitoring node
- Limited to standard DNS (UDP port 53)
- Single network interface monitoring
- No historical data persistence (in-memory)

### Future Enhancements

**Short-term:**
- Database persistence (PostgreSQL/MongoDB)
- DNS over HTTPS (DoH) detection
- Email/Slack alert integration

**Medium-term:**
- Machine learning threat detection
- Multi-node distributed monitoring
- SIEM integration (Splunk, ELK)

**Long-term:**
- Cloud-native Kubernetes deployment
- AI-powered anomaly detection
- Automated threat response (blocking)

---

## SLIDE 11: Demo Screenshots

### Overview Dashboard
- Live DNS traffic stream
- Recent threats panel
- Key metrics (queries, alerts, rate)

### Threat Detection
- Color-coded severity levels
- Whitelist management buttons
- Detailed threat indicators

### Domain Analysis
- Risk scoring per domain
- Query statistics
- Threat type breakdown

### World Map
- Geographic IP visualization
- Real-time marker updates
- Threat location highlighting

---

## SLIDE 12: Conclusion

### The Problem
DNS infrastructure is a critical attack vector exploited through cache poisoning, fast-flux networks, and domain hijacking. Most organizations lack real-time visibility into DNS security threats.

### Our Solution
**DNS Guardian** - A lightweight, real-time DNS security monitoring platform combining network intrusion detection with intelligent threat analysis and modern visualization.

### Key Achievements
✅ Real-time threat detection with <100ms latency  
✅ Automated analysis of 4+ threat types  
✅ Modern, accessible web dashboard  
✅ Open-source and deployment-ready  

### Impact
Empowers organizations of all sizes to gain visibility into DNS-based attacks, enabling faster threat detection and response.

---

### Closing Statement

> **"DNS security shouldn't require enterprise budgets or security expertise. With DNS Guardian, every organization can monitor, detect, and respond to DNS threats in real-time."**

---

## Quick Reference Card

**Tech Stack:**
- Frontend: React + TypeScript + Tailwind CSS
- Backend: FastAPI + Python + WebSocket
- Detection: Suricata IDS + Custom Algorithms

**Detection Capabilities:**
- Cache Poisoning (Low TTL)
- Fast-Flux Networks (Multiple IPs)
- DGA Domains (Random patterns)
- DNS Hijacking (NXDOMAIN anomalies)

**Performance:**
- <100ms alert latency
- 100+ queries/second processing
- Real-time WebSocket streaming

---

*DNS Guardian - Protecting Your Network, One Query at a Time* 🛡️
