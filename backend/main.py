#!/usr/bin/env python3
"""
DNS Security Monitoring Platform - Backend
Real-time DNS traffic analysis with threat detection
"""
import json
import asyncio
import re
import os
from datetime import datetime
from typing import List, Dict, Any
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from contextlib import asynccontextmanager
import aiofiles

# Data Models
class DNSLog(BaseModel):
    timestamp: str
    domain: str
    src_ip: str
    dest_ip: str
    query_type: str
    ttl: int
    response_code: str
    alert_level: str
    alert_reason: str

class AlertData(BaseModel):
    timestamp: str
    domain: str
    alert_type: str
    severity: str
    message: str
    data: Dict[str, Any]

# Detection Rules
class DNSDetector:
    LOW_TTL_THRESHOLD = 60
    FAST_FLUX_IPS_THRESHOLD = 3

    def __init__(self):
        self.domain_ips_history: Dict[str, List[str]] = {}
        self.suspicious_patterns = [
            r'^[a-z0-9]{20,}\.',
            r'\.tk$',
            r'\.ml$',
            r'^dga-',
            r'update.*\.',
        ]

    def detect_cache_poisoning(self, ttl: int) -> tuple[bool, str]:
        if ttl < self.LOW_TTL_THRESHOLD and ttl > 0:
            return True, "Low TTL detected - possible cache poisoning"
        return False, ""

    def detect_fast_flux(self, domain: str, answers: List[str]) -> tuple[bool, str]:
        """Detect fast-flux: domain resolving to multiple IPs"""
        if not answers:
            return False, ""

        # Filter out duplicates
        unique_ips = list(set(answers))
        if len(unique_ips) >= self.FAST_FLUX_IPS_THRESHOLD:
            self.domain_ips_history[domain] = unique_ips
            return True, f"Fast-flux detected: {len(unique_ips)} IPs"
        return False, ""

    def detect_suspicious_domain(self, domain: str) -> tuple[bool, str]:
        for pattern in self.suspicious_patterns:
            if re.search(pattern, domain.lower()):
                return True, f"Suspicious domain pattern: {pattern}"
        return False, ""

    def detect_dns_hijacking(self, response_code: str) -> tuple[bool, str]:
        if response_code == "NXDOMAIN":
            return True, "NXDOMAIN - Possible DNS hijacking"
        return False, ""

    def analyze_dns_event(self, event: Dict) -> tuple[str, str, str]:
        """Analyze DNS event and return alert_level, reason, severity"""
        domain = event.get('domain', '')
        ttl = event.get('ttl', 0)
        response_code = event.get('response_code', '')
        answers = event.get('answers', [])

        alerts = []
        severity = "info"

        # Check each threat
        is_cache_poison, msg = self.detect_cache_poisoning(ttl)
        if is_cache_poison:
            alerts.append(msg)
            severity = "warning"

        is_fast_flux, msg = self.detect_fast_flux(domain, answers)
        if is_fast_flux:
            alerts.append(msg)
            severity = "critical"

        is_suspicious, msg = self.detect_suspicious_domain(domain)
        if is_suspicious:
            alerts.append(msg)
            severity = "warning"

        is_hijack, msg = self.detect_dns_hijacking(response_code)
        if is_hijack:
            alerts.append(msg)
            severity = "warning"

        if alerts:
            return "alert", " | ".join(alerts), severity
        return "normal", "Clean DNS query", "info"

detector = DNSDetector()
last_position = 0

# WebSocket Connection Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass

manager = ConnectionManager()
log_watch_task = None

async def watch_suricata_logs():
    """Watch eve.json for new DNS events"""
    global last_position

    # Check for eve.json in multiple locations
    eve_file = None
    possible_paths = [
        "./eve.json",
        "/var/log/suricata/eve.json",
        "C:\\ProgramData\\Suricata\\logs\\eve.json",
    ]

    for path in possible_paths:
        if os.path.exists(path):
            eve_file = path
            break

    if not eve_file:
        print(f"Eve.json not found. Will wait for: {possible_paths[0]}")
        eve_file = possible_paths[0]

    print(f"Watching for DNS logs in: {eve_file}")

    while True:
        try:
            if not os.path.exists(eve_file):
                await asyncio.sleep(2)
                continue

            async with aiofiles.open(eve_file, 'r') as f:
                await f.seek(last_position)

                async for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        event = json.loads(line)

                        if event.get('event_type') != 'dns':
                            continue

                        dns_data = event.get('dns', {})
                        domain = dns_data.get('rrname', 'unknown')
                        query_type = dns_data.get('type', 'unknown')
                        response_code = dns_data.get('rcode', 'NOERROR')
                        ttl = dns_data.get('ttl', 0)
                        src_ip = event.get('src_ip', 'unknown')
                        dest_ip = event.get('dest_ip', 'unknown')
                        timestamp = event.get('timestamp', datetime.now().isoformat())
                        answers = dns_data.get('answers', [])

                        # Analyze threat
                        alert_level, alert_reason, severity = detector.analyze_dns_event({
                            'domain': domain,
                            'ttl': ttl,
                            'src_ip': src_ip,
                            'response_code': response_code,
                            'query_type': query_type,
                            'answers': answers
                        })

                        log_entry = {
                            'timestamp': timestamp,
                            'domain': domain,
                            'src_ip': src_ip,
                            'dest_ip': dest_ip,
                            'query_type': query_type,
                            'ttl': ttl,
                            'response_code': response_code,
                            'alert_level': alert_level,
                            'alert_reason': alert_reason,
                            'severity': severity,
                            'answers': answers,
                            'raw_event': event
                        }

                        # Broadcast to clients
                        await manager.broadcast(log_entry)

                    except json.JSONDecodeError:
                        continue

                # Update position
                last_position = await f.tell()

            # Small delay before next check
            await asyncio.sleep(0.5)

        except Exception as e:
            print(f"Error watching logs: {e}")
            await asyncio.sleep(2)

@asynccontextmanager
async def lifespan(app: FastAPI):
    global log_watch_task
    log_watch_task = asyncio.create_task(watch_suricata_logs())
    print("DNS log watcher started")
    yield
    if log_watch_task:
        log_watch_task.cancel()
    print("DNS log watcher stopped")

app = FastAPI(
    title="DNS Security Monitoring Platform",
    description="Real-time DNS threat detection",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {
        "service": "DNS Security Monitoring Platform",
        "status": "running",
        "endpoints": {
            "health": "/health",
            "websocket": "/ws/logs"
        }
    }

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "active_connections": len(manager.active_connections)
    }

@app.websocket("/ws/logs")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9000)
