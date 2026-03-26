# 🪟 DNS Security Monitor - Windows Setup Guide

## ✅ Prerequisites Check

Before starting, make sure you have:

- **Python 3.8+** - [Download](https://www.python.org/downloads/)
- **Node.js 16+** - [Download](https://nodejs.org/)
- **Git** (optional) - [Download](https://git-scm.com/)

### Verify Installation

Open PowerShell and run:

```powershell
python --version     # Should be 3.8 or higher
node --version       # Should be 16 or higher
npm --version        # Should be 8 or higher
```

## 🚀 Quick Start (Easiest Way)

### Option 1: Using Batch Files (Recommended for Windows)

1. **Open PowerShell or Command Prompt** in the project root folder
2. **Double-click or run:**

```cmd
START_WINDOWS.bat
```

This automatically:
- Creates Python virtual environment (if needed)
- Installs all dependencies
- Starts Backend on http://localhost:8000
- Starts Frontend on http://localhost:5173

Then in a **new terminal**, run traffic generator:

```cmd
cd scripts
start.bat
```

### Option 2: Manual Setup (Step-by-Step)

#### Step 1: Backend Setup

```powershell
# Navigate to backend
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start the server
python main.py

# Output: Uvicorn running on http://0.0.0.0:8000
```

#### Step 2: Frontend Setup (New PowerShell Window)

```powershell
# Navigate to frontend
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev

# Output: Local: http://localhost:5173/
```

#### Step 3: Traffic Generator (New PowerShell Window)

```powershell
# Navigate to scripts
cd scripts

# Install dnspython
pip install dnspython

# Run traffic generator
python generate_dns_traffic.py
```

## 🌐 Access Dashboard

Open your browser:

```
http://localhost:5173
```

You should see:
- ✅ Live DNS queries streaming in
- ✅ Real-time threat alerts
- ✅ Domain analysis with risk scores

---

## 🔧 Windows-Specific Tips

### PowerShell Commands Reference

```powershell
# Navigate to folder
cd "path\to\folder"

# Activate virtual environment
venv\Scripts\activate

# Deactivate virtual environment
deactivate

# Run Python script
python script.py

# Run Node command
npm run dev

# Kill process on port (if stuck)
netstat -ano | findstr :8000
taskkill /PID <PID> /F
```

### Common Issues

#### Issue: "python is not recognized"
**Solution:**
```powershell
# Use full path or reinstall Python with "Add to PATH" checked
# Or use:
py --version
py -m venv venv
```

#### Issue: "venv\Scripts\activate not found"
**Solution:**
```powershell
# Make sure you're in the backend directory
cd backend
python -m venv venv  # Create it first
venv\Scripts\activate
```

#### Issue: "npm: command not found"
**Solution:**
- Reinstall Node.js
- Check if installed: `node --version`
- Restart PowerShell/Command Prompt

#### Issue: "Port 8000 already in use"
**Solution:**
```powershell
# Find process on port 8000
netstat -ano | findstr :8000

# Kill it (replace PID with actual number)
taskkill /PID <PID> /F
```

#### Issue: Vite error with tsconfig.node.json
**Solution:** Already fixed! The file should exist now.

---

## 📝 Testing Locally (Without VPS)

To test locally without Suricata, the backend will try to read from `test_eve.json`:

```bash
# Backend will automatically use test_eve.json if eve.json not found
```

The test data includes:
- Normal DNS queries (google.com, example.com)
- Suspicious domains (d94ea7d8db472ea.com, dga-malware.ml)
- Fast-flux domains (4 different IPs)

---

## 🎯 What to Expect

### Dashboard Output

You'll see:
- **TOTAL QUERIES**: Count of DNS queries
- **THREAT ALERTS**: Number of detected threats
- **ALERT RATE**: Percentage of alerts vs total queries
- **LIVE LOGS**: Terminal-style event stream
- **TOP DOMAINS**: Risk-scored domain list
- **ALERTS PANEL**: Real-time threat alerts

### Sample Alerts

```
[INFO]  google.com
        TTL: 300s
        RISK: 0/100 ✓ (Green)

[ALERT] d94ea7d8db472ea.com
        Low TTL (45s) detected!
        RISK: 65/100 ⚠️ (Yellow)

[ALERT] fast-flux.com
        4 different IPs detected!
        RISK: 92/100 🚨 (Red)
```

---

## 🔗 Connecting to Your VPS

If you want to monitor DNS from your VPS on your Windows machine:

### Edit Frontend Config

Edit `frontend/src/App.tsx` and change:

```typescript
// Line ~30 (in connectWebSocket):
const wsUrl = `ws://your-vps-ip:8000/ws/logs`;  // Change localhost to your VPS IP
```

Then run the frontend on Windows pointing to your VPS backend.

---

## 🖼️ Frontend Features Explained

### Dashboard Tab
- **Total Queries**: All DNS queries captured
- **Threat Alerts**: Detected threats
- **Alert Rate**: % of queries that triggered alerts
- **Query Types**: Breakdown by A, AAAA, MX, etc.

### Live Logs Tab
- Terminal-style event viewer
- Real-time DNS traffic
- Color-coded: Green (INFO), Red (ALERT)
- Shows domain, IPs, TTL, response codes

### Domain Analysis Tab
- Top 10 domains by risk score
- Risk score 0-100 (red = high risk)
- IP count per domain
- TTL analysis
- Fast-flux detection

### Alerts Tab
- Real-time threat notifications
- Severity levels: info, warning, critical
- Alert reasons and timestamps
- Auto-updates as threats detected

---

## 📊 Performance on Windows

Expected performance:
- **CPU**: 5-15% (single core)
- **RAM**: 150-250MB total (backend + frontend)
- **Disk**: ~5MB per 50,000 events

Your Windows machine should handle this easily.

---

## 🚀 Next Steps

1. **Start with Quick Start** - Use `START_WINDOWS.bat`
2. **Watch Dashboard** - Monitor live events
3. **Generate Traffic** - Run `scripts/start.bat`
4. **See Alerts** - Query suspicious domains
5. **Deploy to VPS** - Follow VPS_SETUP_GUIDE.md when ready

---

## 📞 Troubleshooting Checklist

- [ ] Python 3.8+ installed and in PATH
- [ ] Node.js 16+ installed and in PATH
- [ ] backend/venv exists after running start.bat
- [ ] Frontend starting without errors
- [ ] Can access http://localhost:5173
- [ ] Backend health check: curl http://localhost:8000/health
- [ ] Traffic generator running
- [ ] Events appearing in dashboard

---

## 💡 Pro Tips for Windows Users

1. **Use Windows Terminal** - Better than Command Prompt
2. **Pin PowerShell Folders** - Right-click folder → "Open PowerShell here"
3. **Use VSCode** - F5 to debug Python/TypeScript
4. **Keep Batch Files** - Easy one-click startup
5. **Monitor Disk Space** - eve.json grows with events

---

## 🎓 Understanding the Data Flow

```
DNS Traffic (from VPS or test_eve.json)
         ↓
Backend reads eve.json
         ↓
DNSDetector analyzes for threats
         ↓
WebSocket broadcasts to Frontend
         ↓
React Dashboard updates in real-time
```

---

## ✨ Features You'll See Working

✅ **Real-Time Updates** - Watch events arrive instantly
✅ **Threat Detection** - See alerts as they happen
✅ **Risk Scoring** - Domain risk levels 0-100
✅ **Live Logs** - Terminal-style event stream
✅ **Domain Analytics** - IP tracking and TTL analysis
✅ **Alert Severity** - Color-coded threat levels

---

**Ready to monitor DNS on Windows?**

Start with: `START_WINDOWS.bat` 🎉
