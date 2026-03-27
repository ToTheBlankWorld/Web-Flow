
#!/usr/bin/env python3
"""
DNS Security Monitoring Platform - Backend
Real-time DNS traffic capture, analysis, and threat detection.

Captures REAL DNS traffic on your machine via:
  1. Scapy packet sniffer (if Npcap installed)
  2. Windows DNS cache monitor (always works)
  3. Active DNS resolver (enriches with full record data)
  4. eve.json watcher (for Suricata / testing fallback)
"""
import json
import asyncio
import re
import os
import math
import hashlib
from datetime import datetime
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import defaultdict, deque
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from contextlib import asynccontextmanager
import aiofiles

from dns_capture import DNSCaptureEngine, CapturedDNSEvent, HAS_DNSPYTHON
from phishing_detector import check_phishing_domain, find_matching_legitimate_domain, get_common_typosquats


# ─── Data Models ───────────────────────────────────────────────────────────────

class ThreatAlert(BaseModel):
    id: str
    timestamp: str
    domain: str
    threat_type: str
    severity: str
    confidence: float
    description: str
    indicators: Dict[str, Any] = {}
    src_ip: str = ""
    dest_ip: str = ""
    recommended_action: str = ""
    phishing_info: Optional[Dict[str, Any]] = None  # For phishing alerts


# ─── Advanced Detection Engine ─────────────────────────────────────────────────

class DNSDetector:
    """Advanced DNS threat detection with multiple heuristics"""

    def __init__(self):
        self.domain_ip_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.domain_ip_timestamps: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.domain_ttl_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=50))
        self.domain_ns_history: Dict[str, Set[str]] = defaultdict(set)
        self.known_legitimate_ns: Set[str] = {
            "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
            "208.67.222.222", "208.67.220.220", "9.9.9.9",
        }
        self.domain_query_freq: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self.base_domain_subdomains: Dict[str, Set[str]] = defaultdict(set)
        self.alert_cooldown: Dict[str, datetime] = {}

        # ── Whitelist of known legitimate base domains ──
        # CDNs, analytics, cloud providers, OS services, browsers, etc.
        # Subdomains of these will NOT trigger DGA/tunneling/fast-flux
        self.whitelisted_domains: Set[str] = {
            # CDNs
            "akamai.net", "akamaized.net", "akamaihd.net", "akadns.net",
            "cloudfront.net", "cloudflare.com", "cloudflare-dns.com",
            "fastly.net", "fastlylb.net", "edgecastcdn.net",
            "azureedge.net", "azurefd.net", "msecnd.net",
            "cdn77.org", "stackpathdns.com", "limelight.com",
            "cdninstagram.com", "fbcdn.net",
            # Analytics / Tracking
            "adobestats.io", "demdex.net", "omtrdc.net", "2o7.net",
            "google-analytics.com", "googletagmanager.com",
            "doubleclick.net", "googlesyndication.com",
            "googleadservices.com", "googleusercontent.com",
            "hotjar.com", "mixpanel.com", "segment.io", "segment.com",
            "amplitude.com", "fullstory.com", "newrelic.com",
            "nr-data.net", "sentry.io",
            # Cloud providers
            "amazonaws.com", "aws.amazon.com", "awsstatic.com",
            "azure.com", "azure.net", "windows.net", "microsoftonline.com",
            "googleapis.com", "gstatic.com", "google.com", "google.co.in",
            "googlevideo.com", "gvt1.com", "gvt2.com",
            "1e100.net",  # Google infra
            # Microsoft / Windows
            "microsoft.com", "msn.com", "live.com", "outlook.com",
            "office.com", "office365.com", "office.net",
            "windowsupdate.com", "windows.com", "bing.com",
            "msftconnecttest.com", "msftncsi.com",
            "login.microsoftonline.com", "sharepoint.com",
            "skype.com", "teams.microsoft.com",
            # Social / Common
            "facebook.com", "fbsbx.com", "instagram.com",
            "twitter.com", "x.com", "twimg.com",
            "linkedin.com", "licdn.com",
            "youtube.com", "ytimg.com", "yt3.ggpht.com",
            "reddit.com", "redd.it", "redditstatic.com",
            "tiktok.com", "tiktokcdn.com",
            "whatsapp.com", "whatsapp.net",
            "discord.com", "discord.gg", "discordapp.com",
            "snapchat.com", "snap.com",
            "pinterest.com", "pinimg.com",
            # Dev / Tech
            "github.com", "github.io", "githubusercontent.com",
            "gitlab.com", "bitbucket.org",
            "stackoverflow.com", "stackexchange.com",
            "npmjs.com", "npmjs.org", "yarnpkg.com",
            "docker.com", "docker.io",
            "pypi.org", "pythonhosted.org",
            # Ecommerce / Services
            "amazon.com", "amazon.in", "amazonses.com",
            "apple.com", "icloud.com", "apple-dns.net",
            "netflix.com", "nflxvideo.net", "nflxext.com",
            "spotify.com", "scdn.co",
            "paypal.com", "paypalobjects.com",
            "shopify.com",
            # Hosting / DNS
            "hstatic.io", "haravan.com",
            "wp.com", "wordpress.com", "gravatar.com",
            "squarespace.com", "wixsite.com", "wix.com",
            "godaddy.com", "namecheap.com",
            "dynect.net", "nsone.net", "route53.amazonaws.com",
            "dnsmadeeasy.com", "ultradns.com",
            # Security / Anti-virus
            "symantec.com", "norton.com", "mcafee.com",
            "kaspersky.com", "avast.com", "avg.com",
            "malwarebytes.com", "virustotal.com",
            # Email / Communication
            "sendgrid.net", "mailchimp.com", "mailgun.org",
            "smtp.google.com", "gmail.com",
            "zoho.com", "protonmail.com",
            # Telemetry / System
            "trafficmanager.net", "digicert.com", "verisign.com",
            "letsencrypt.org", "globalsign.com",
            "crashlytics.com", "app-measurement.com",
            "appsflyer.com", "adjust.com", "branch.io",
            # Indian sites (user is likely in India)
            "flipkart.com", "myntra.com", "swiggy.com",
            "zomato.com", "paytm.com", "razorpay.com",
            "jio.com", "airtel.in",
        }

        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.gq',
            '.top', '.xyz', '.club', '.work', '.date',
            '.racing', '.download', '.win', '.bid',
            '.stream', '.gdn', '.icu', '.buzz',
        }

        self.malicious_patterns = [
            r'(cmd|shell|exec|eval|payload)',
            r'(phish|spoof|fake|scam)',
            r'(malware|trojan|virus|worm)',
            r'(keylog|stealer|ransomware)',
        ]

    def _get_base_domain(self, domain: str) -> str:
        parts = domain.rstrip('.').split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return domain

    def _is_whitelisted(self, domain: str) -> bool:
        """Check if domain or its base domain is in the whitelist"""
        dl = domain.lower().rstrip('.')
        # Check exact match
        if dl in self.whitelisted_domains:
            return True
        # Check if it's a subdomain of a whitelisted domain
        for wd in self.whitelisted_domains:
            if dl.endswith('.' + wd):
                return True
        return False

    def _calculate_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        freq = defaultdict(int)
        for c in s:
            freq[c] += 1
        length = len(s)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    def _is_dga_domain(self, domain: str) -> Tuple[bool, float]:
        # Only check the SECOND-LEVEL domain label (e.g. "xk3jf9" in "xk3jf9.com")
        # NOT random subdomains of legit domains (e.g. "abc123.adobestats.io")
        parts = domain.rstrip('.').split('.')
        if len(parts) < 2:
            return False, 0.0
        # The base SLD label
        base = parts[-2] if len(parts) >= 2 else parts[0]
        if len(base) < 6:
            return False, 0.0

        entropy = self._calculate_entropy(base)
        vowels = sum(1 for c in base.lower() if c in 'aeiou')
        digits = sum(1 for c in base if c.isdigit())
        total = len(base)

        score = 0.0
        # Need HIGH entropy to flag
        if entropy > 3.8: score += 0.2
        if entropy > 4.2: score += 0.25
        # Very long random-looking labels
        if len(base) > 20: score += 0.15
        if len(base) > 30: score += 0.15
        if total > 0:
            vowel_ratio = vowels / total
            if vowel_ratio < 0.1: score += 0.15
        if digits > 0 and (total - digits) > 0:
            digit_ratio = digits / total
            if 0.3 < digit_ratio < 0.7: score += 0.15

        max_cons = 0
        cur = 0
        for c in base.lower():
            if c in 'bcdfghjklmnpqrstvwxyz':
                cur += 1
                max_cons = max(max_cons, cur)
            else:
                cur = 0
        if max_cons >= 5: score += 0.15

        return score >= 0.55, min(score, 1.0)

    def detect_fast_flux(self, domain, answers, timestamp):
        if not answers:
            return None
        now = datetime.fromisoformat(
            timestamp.replace('+0000', '+00:00').replace('Z', '+00:00')
        ) if 'T' in timestamp else datetime.now()

        for ip in answers:
            self.domain_ip_history[domain].append(ip)
            self.domain_ip_timestamps[domain].append(now)

        # Need substantial history before flagging
        if len(self.domain_ip_history[domain]) < 8:
            return None

        unique_ips = set(self.domain_ip_history[domain])
        total = len(self.domain_ip_history[domain])
        diversity = len(unique_ips) / total if total > 0 else 0

        timestamps = list(self.domain_ip_timestamps[domain])
        span = (timestamps[-1] - timestamps[0]).total_seconds() if len(timestamps) >= 2 else 0

        # Need at least 2 minutes of observation AND 8+ unique IPs
        # CDNs typically have 2-6 IPs, fast-flux has 8+
        if span < 120:
            return None
        rate = len(unique_ips) / (span / 60) if span > 0 else 0

        if len(unique_ips) >= 8 and diversity > 0.6 and rate > 3:
            conf = min(0.5 + len(unique_ips) * 0.03 + diversity * 0.2, 0.95)
            return ThreatAlert(
                id=hashlib.md5(f"ff-{domain}-{now.isoformat()}".encode()).hexdigest()[:12],
                timestamp=timestamp, domain=domain,
                threat_type="fast_flux", severity="critical", confidence=conf,
                description=f"Fast-flux network: {len(unique_ips)} unique IPs in {span/60:.1f} min",
                indicators={"unique_ips": list(unique_ips)[:10], "ip_diversity": round(diversity, 3),
                            "observation_window_sec": round(span)},
                recommended_action="Block domain and investigate IPs for botnet activity",
            )
        return None

    def detect_cache_poisoning(self, domain, ttl, answers, response_code, dest_ip):
        if ttl <= 0:
            return None
        self.domain_ttl_history[domain].append(ttl)
        ttl_list = list(self.domain_ttl_history[domain])
        if len(ttl_list) < 3:
            return None

        avg = sum(ttl_list[:-1]) / len(ttl_list[:-1])
        cur = ttl_list[-1]
        indicators = {}
        score = 0.0

        if avg > 0 and cur < avg * 0.1 and avg > 120:
            score += 0.4
            indicators["ttl_drop"] = f"{avg:.0f}s -> {cur}s"
        if cur < 10 and dest_ip not in self.known_legitimate_ns:
            score += 0.3
            indicators["low_ttl_unknown_resolver"] = f"TTL={cur}s via {dest_ip}"
        if len(ttl_list) >= 8:
            var = sum((t - avg) ** 2 for t in ttl_list) / len(ttl_list)
            sd = math.sqrt(var)
            if sd > avg * 0.7 and avg > 60:
                score += 0.25
                indicators["ttl_variance"] = f"std={sd:.1f} avg={avg:.1f}"

        if score >= 0.5:
            return ThreatAlert(
                id=hashlib.md5(f"cp-{domain}-{cur}".encode()).hexdigest()[:12],
                timestamp=datetime.now().isoformat(), domain=domain,
                threat_type="cache_poisoning",
                severity="critical" if score >= 0.6 else "high",
                confidence=min(score, 0.95),
                description=f"Cache poisoning: TTL anomaly for {domain}",
                indicators=indicators,
                recommended_action="Flush DNS cache, verify against authoritative NS",
            )
        return None

    def detect_dga(self, domain):
        is_dga, conf = self._is_dga_domain(domain)
        if is_dga:
            base = domain.rstrip('.').split('.')[0]
            return ThreatAlert(
                id=hashlib.md5(f"dga-{domain}".encode()).hexdigest()[:12],
                timestamp=datetime.now().isoformat(), domain=domain,
                threat_type="dga_domain",
                severity="high" if conf > 0.7 else "medium",
                confidence=conf,
                description=f"DGA domain detected: {domain}",
                indicators={"entropy": round(self._calculate_entropy(base), 3), "length": len(base)},
                recommended_action="Block domain and scan source for malware",
            )
        return None

    def detect_suspicious_tld(self, domain):
        dl = domain.lower().rstrip('.')
        for tld in self.suspicious_tlds:
            if dl.endswith(tld):
                return ThreatAlert(
                    id=hashlib.md5(f"tld-{domain}".encode()).hexdigest()[:12],
                    timestamp=datetime.now().isoformat(), domain=domain,
                    threat_type="suspicious_tld", severity="medium", confidence=0.4,
                    description=f"Abused TLD: {tld}",
                    indicators={"tld": tld},
                    recommended_action="Check domain reputation",
                )
        return None

    def detect_dns_tunneling(self, domain, query_type, src_ip):
        base = self._get_base_domain(domain)
        now = datetime.now()
        sub = domain.replace(base, '').rstrip('.')
        if sub:
            self.base_domain_subdomains[base].add(sub)
        self.domain_query_freq[base].append(now)

        indicators = {}
        score = 0.0
        usubs = len(self.base_domain_subdomains[base])
        # Need MANY unique subdomains before flagging (analytics services easily hit 10-20)
        if usubs > 40: score += 0.3; indicators["unique_subdomains"] = usubs
        if usubs > 80: score += 0.2

        recent = [t for t in self.domain_query_freq[base] if (now - t).total_seconds() < 60]
        if len(recent) > 50: score += 0.3; indicators["queries_per_minute"] = len(recent)

        if sub and len(sub) > 50:
            score += 0.2
            ent = self._calculate_entropy(sub.replace('.', ''))
            if ent > 4.0: score += 0.15; indicators["subdomain_entropy"] = round(ent, 3)
            indicators["subdomain_length"] = len(sub)
        if query_type == "TXT" and score > 0.2: score += 0.15

        if score >= 0.55:
            return ThreatAlert(
                id=hashlib.md5(f"tun-{base}-{now.isoformat()}".encode()).hexdigest()[:12],
                timestamp=now.isoformat(), domain=domain,
                threat_type="dns_tunneling",
                severity="critical" if score >= 0.7 else "high",
                confidence=min(score, 0.95),
                description=f"DNS tunneling via {base}",
                indicators=indicators, src_ip=src_ip,
                recommended_action="Block domain, investigate source for data exfiltration",
            )
        return None

    def detect_rogue_nameserver(self, domain, dest_ip, response_code, answers):
        self.domain_ns_history[domain].add(dest_ip)
        indicators = {}
        score = 0.0
        if dest_ip not in self.known_legitimate_ns and dest_ip != "system":
            score += 0.15
            indicators["non_standard_resolver"] = dest_ip
        if len(self.domain_ns_history[domain]) > 5:
            score += 0.2
            indicators["resolver_count"] = len(self.domain_ns_history[domain])
        if response_code in ("SERVFAIL", "REFUSED") and dest_ip not in self.known_legitimate_ns:
            score += 0.35
            indicators["error_response"] = response_code

        if score >= 0.5:
            return ThreatAlert(
                id=hashlib.md5(f"rogue-{domain}-{dest_ip}".encode()).hexdigest()[:12],
                timestamp=datetime.now().isoformat(), domain=domain,
                threat_type="rogue_nameserver",
                severity="high" if score >= 0.5 else "medium",
                confidence=min(score, 0.9),
                description=f"Rogue nameserver for {domain}",
                indicators=indicators,
                recommended_action="Verify DNS resolver, check for MITM",
            )
        return None

    def detect_malicious_pattern(self, domain):
        dl = domain.lower()
        for p in self.malicious_patterns:
            m = re.search(p, dl)
            if m:
                return ThreatAlert(
                    id=hashlib.md5(f"mal-{domain}".encode()).hexdigest()[:12],
                    timestamp=datetime.now().isoformat(), domain=domain,
                    threat_type="malicious_domain", severity="high", confidence=0.7,
                    description=f"Malicious keyword: '{m.group()}'",
                    indicators={"pattern": m.group()},
                    recommended_action="Block immediately and scan host",
                )
        return None

    def detect_phishing(self, domain):
        """Detect typosquatting/phishing domains using pattern matching"""
        match = find_matching_legitimate_domain(domain)
        if match:
            legit_domain, org_name, score = match
            # Don't alert on the legitimate domain itself
            base = domain.lower().rstrip('.')
            parts = base.split('.')
            if len(parts) >= 2:
                base_check = '.'.join(parts[-2:]) if len(parts) == 2 else '.'.join(parts[-3:]) if parts[-2] in ('co', 'ac', 'gov') else '.'.join(parts[-2:])
                if base_check == legit_domain:
                    return None
            
            return ThreatAlert(
                id=hashlib.md5(f"phish-{domain}".encode()).hexdigest()[:12],
                timestamp=datetime.now().isoformat(), domain=domain,
                threat_type="phishing_typosquat", 
                severity="critical" if score > 0.8 else "high",
                confidence=score,
                description=f"⚠️ PHISHING ALERT: This looks like a fake version of {legit_domain}",
                indicators={
                    "original_domain": legit_domain,
                    "original_org": org_name,
                    "similarity": round(score, 3),
                },
                recommended_action=f"DO NOT enter credentials! The real site is {legit_domain} ({org_name})",
                phishing_info={
                    "is_phishing": True,
                    "original_domain": legit_domain,
                    "original_org": org_name,
                    "confidence": score,
                }
            )
        return None

    def _should_alert(self, key, cooldown=30):
        now = datetime.now()
        if key in self.alert_cooldown:
            if (now - self.alert_cooldown[key]).total_seconds() < cooldown:
                return False
        self.alert_cooldown[key] = now
        return True

    def analyze(self, event: Dict) -> Tuple[str, str, str, List[ThreatAlert]]:
        domain = event.get('domain', '')
        ttl = event.get('ttl', 0)
        rcode = event.get('response_code', '')
        answers = event.get('answers', [])
        src = event.get('src_ip', '')
        dst = event.get('dest_ip', '')
        qtype = event.get('query_type', '')
        ts = event.get('timestamp', datetime.now().isoformat())

        # Skip ALL detection for whitelisted domains (CDNs, analytics, cloud, etc.)
        if self._is_whitelisted(domain):
            return "normal", "", "info", []

        threats = []

        # Priority 1: Phishing/typosquatting detection (most critical)
        checks = [
            ("phish", self.detect_phishing(domain)),
        ]

        # Priority 2: Malicious pattern check and suspicious TLD
        checks.extend([
            ("mal", self.detect_malicious_pattern(domain)),
            ("tld", self.detect_suspicious_tld(domain)),
        ])

        # Priority 3: Heuristic-based detections
        checks.extend([
            ("dga", self.detect_dga(domain)),
            ("ff", self.detect_fast_flux(domain, answers, ts)),
            ("cp", self.detect_cache_poisoning(domain, ttl, answers, rcode, dst)),
            ("tun", self.detect_dns_tunneling(domain, qtype, src)),
            ("rogue", self.detect_rogue_nameserver(domain, dst, rcode, answers)),
        ])

        for name, alert in checks:
            if alert and self._should_alert(f"{name}-{domain}", cooldown=60):
                alert.src_ip = alert.src_ip or src
                alert.dest_ip = alert.dest_ip or dst
                threats.append(alert)

        if threats:
            sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            worst = max(threats, key=lambda t: sev_order.get(t.severity, 0))
            reasons = " | ".join(t.description for t in threats)
            return "alert", reasons, worst.severity, threats

        return "normal", "", "info", []


# ─── Global State ──────────────────────────────────────────────────────────────

detector = DNSDetector()
capture_engine = DNSCaptureEngine()

stats_data = {
    "total_queries": 0,
    "total_alerts": 0,
    "threats_by_type": defaultdict(int),
    "queries_by_type": defaultdict(int),
    "queries_by_response": defaultdict(int),
    "unique_domains": set(),
    "unique_src_ips": set(),
    "recent_queries_per_min": deque(maxlen=600),
    "start_time": datetime.now().isoformat(),
    "capture_methods": [],
}

recent_logs: deque = deque(maxlen=500)
recent_alerts: deque = deque(maxlen=200)
domain_records: Dict[str, Dict] = {}  # domain -> {A: [...], AAAA: [...], ...}
# Time-windowed dedup: domain:type:source → last-seen epoch.
# Same event is suppressed for 30 s; after that it can fire again.
recent_event_keys: Dict[str, float] = {}
_DEDUP_WINDOW = 30.0  # seconds

# GeoIP cache: ip → {lat, lon, country, city, isp, ...}
_geoip_cache: Dict[str, Dict] = {}

# Validation in-flight tracker so we don't run parallel checks for the same domain
_validating: Set[str] = set()


# ─── WebSocket Connection Manager ─────────────────────────────────────────────

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        # Send recent history
        for log in list(recent_logs)[-50:]:
            try:
                await websocket.send_json(log)
            except:
                break

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        disconnected = []
        for conn in self.active_connections:
            try:
                await conn.send_json(message)
            except:
                disconnected.append(conn)
        for c in disconnected:
            self.disconnect(c)


manager = ConnectionManager()


# ─── Event Processing ─────────────────────────────────────────────────────────

async def process_dns_event(event: CapturedDNSEvent):
    """Process a single DNS event from any capture source"""
    domain = event.domain
    if not domain or domain == "unknown":
        return

    # Time-windowed dedup: same domain+type+source is suppressed for _DEDUP_WINDOW seconds
    import time as _t
    _now = _t.time()
    dedup_key = f"{domain}:{event.query_type}:{event.source}"
    last_seen = recent_event_keys.get(dedup_key, 0)
    if _now - last_seen < _DEDUP_WINDOW:
        # Still update records silently but don't re-broadcast
        if domain in domain_records and event.answers and event.query_type in domain_records[domain]:
            for ans in event.answers:
                if ans and ans not in domain_records[domain][event.query_type]:
                    domain_records[domain][event.query_type].append(ans)
        return
    recent_event_keys[dedup_key] = _now
    # Prune stale keys periodically to cap memory
    if len(recent_event_keys) > 4000:
        cutoff = _now - _DEDUP_WINDOW
        for k in [k for k, v in recent_event_keys.items() if v < cutoff]:
            del recent_event_keys[k]

    # Update stats
    stats_data["total_queries"] += 1
    stats_data["queries_by_type"][event.query_type] += 1
    stats_data["queries_by_response"][event.response_code] += 1
    stats_data["unique_domains"].add(domain)
    stats_data["unique_src_ips"].add(event.src_ip)
    stats_data["recent_queries_per_min"].append(datetime.now())

    # Track domain records
    if domain not in domain_records:
        domain_records[domain] = {
            "A": [], "AAAA": [], "CNAME": [], "NS": [], "MX": [], "TXT": [],
            "first_seen": event.timestamp, "last_seen": event.timestamp,
            "query_count": 0, "sources": set(),
        }
    dr = domain_records[domain]
    dr["last_seen"] = event.timestamp
    dr["query_count"] += 1
    dr["sources"].add(event.source)
    if event.answers and event.query_type in dr:
        existing = dr[event.query_type]
        for ans in event.answers:
            if ans and ans not in existing:
                existing.append(ans)

    # Run threat analysis
    alert_level, alert_reason, severity, threats = detector.analyze({
        'domain': domain,
        'ttl': event.ttl,
        'src_ip': event.src_ip,
        'dest_ip': event.dest_ip,
        'response_code': event.response_code,
        'query_type': event.query_type,
        'answers': event.answers,
        'timestamp': event.timestamp,
    })

    # Build log entry
    log_entry = {
        'type': 'dns_log',
        'timestamp': event.timestamp,
        'domain': domain,
        'src_ip': event.src_ip,
        'dest_ip': event.dest_ip,
        'query_type': event.query_type,
        'ttl': event.ttl,
        'response_code': event.response_code,
        'alert_level': alert_level,
        'alert_reason': alert_reason,
        'severity': severity,
        'answers': event.answers,
        'threat_type': threats[0].threat_type if threats else "",
        'confidence': threats[0].confidence if threats else 0.0,
        'source': event.source,
        'is_authoritative': event.is_authoritative,
    }

    recent_logs.append(log_entry)
    await manager.broadcast(log_entry)

    # Broadcast threat alerts
    for threat in threats:
        stats_data["total_alerts"] += 1
        stats_data["threats_by_type"][threat.threat_type] += 1
        alert_dict = {'type': 'threat_alert', 'alert': threat.dict()}
        recent_alerts.append(alert_dict)
        await manager.broadcast(alert_dict)

    # Kick off background authoritative validation for A records
    if event.query_type == 'A' and event.answers and domain not in _validating:
        asyncio.create_task(_auto_validate(domain, list(event.answers)))


# ─── Authoritative DNS Validation ─────────────────────────────────────────────

async def _auto_validate(domain: str, cached_ips: List[str]):
    """Query 8.8.8.8 directly (bypasses local cache) and compare with cached IPs.
    If they differ → potential cache poisoning; flush DNS cache and notify the user."""
    _validating.add(domain)
    try:
        auth_ips = await asyncio.to_thread(_resolve_via_google, domain)
        if not auth_ips:
            return  # Cannot determine — skip

        cached_set = set(cached_ips)
        auth_set   = set(auth_ips)
        is_safe    = bool(cached_set & auth_set) or not cached_set

        # Notify: validation complete
        await manager.broadcast({
            'type': 'dns_validated',
            'domain': domain,
            'status': 'safe' if is_safe else 'poisoned',
            'cached_ips': list(cached_set),
            'auth_ips':   list(auth_set),
            'changed_ips': list(cached_set - auth_set),
        })

        if not is_safe:
            # Flush the local DNS cache so the next request gets the real record
            import subprocess as _sp
            try:
                _sp.run(['ipconfig', '/flushdns'], capture_output=True, timeout=4)
            except Exception:
                pass
            await manager.broadcast({
                'type': 'dns_fixed',
                'domain': domain,
                'message': (
                    f'DNS cache poisoning detected for {domain}. '
                    f'Expected {list(auth_set)} but cache had {list(cached_set - auth_set)}. '
                    'Cache has been flushed — you are safe to continue.'
                ),
            })
    except Exception:
        pass
    finally:
        _validating.discard(domain)


def _resolve_via_google(domain: str) -> List[str]:
    """Synchronous helper: resolve *domain* A record via 8.8.8.8 (runs in a thread)."""
    if not HAS_DNSPYTHON:
        return []
    try:
        import dns.resolver as _dres
        r = _dres.Resolver()
        r.nameservers = ['8.8.8.8', '8.8.4.4']
        r.timeout  = 3
        r.lifetime = 5
        answers = r.resolve(domain, 'A')
        return [rdata.to_text() for rdata in answers]  # type: ignore[union-attr]
    except Exception:
        return []


# ─── GeoIP lookup ─────────────────────────────────────────────────────────────

def _geoip_lookup(ip: str) -> Optional[Dict]:
    """Blocking helper called via asyncio.to_thread. Fetches ip-api.com/json/{ip}."""
    if not ip or ip in ('127.0.0.1', '0.0.0.0', '::1'):
        return None
    if ip in _geoip_cache:
        return _geoip_cache[ip]
    import urllib.request as _ur
    try:
        url = (f"http://ip-api.com/json/{ip}"
               f"?fields=status,country,countryCode,regionName,city,lat,lon,isp,org,query")
        with _ur.urlopen(url, timeout=4) as resp:
            data = json.loads(resp.read().decode())
        if data.get('status') == 'success':
            _geoip_cache[ip] = data
            return data
    except Exception:
        pass
    return None


# ─── Event Queue Consumer ─────────────────────────────────────────────────────

async def event_consumer(queue: asyncio.Queue):
    """Consume events from the capture engine"""
    while True:
        try:
            event = await queue.get()
            await process_dns_event(event)
        except Exception as e:
            print(f"[Event Consumer] Error: {e}")


# ─── Eve.json Watcher (fallback for testing/Suricata) ────────────────────────

async def watch_eve_json(queue: asyncio.Queue):
    """Watch eve.json for testing / Suricata integration"""
    last_pos = 0
    possible = ["./eve.json", "/var/log/suricata/eve.json"]
    eve_file = None

    for p in possible:
        if os.path.exists(p):
            eve_file = p
            break

    if not eve_file:
        return  # No eve.json, that's fine

    print(f"[Eve.json] Also watching: {eve_file}")

    while True:
        try:
            if not os.path.exists(eve_file):
                await asyncio.sleep(2)
                continue

            async with aiofiles.open(eve_file, 'r') as f:
                await f.seek(last_pos)
                async for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                        if event.get('event_type') != 'dns':
                            continue

                        dns_data = event.get('dns', {})
                        answers_raw = dns_data.get('answers', [])
                        answers = []
                        for a in answers_raw:
                            if isinstance(a, dict):
                                answers.append(a.get('rdata', str(a)))
                            else:
                                answers.append(str(a))

                        captured = CapturedDNSEvent(
                            timestamp=event.get('timestamp', datetime.now().isoformat()),
                            domain=dns_data.get('rrname', 'unknown'),
                            query_type=dns_data.get('rrtype', dns_data.get('type', 'A')),
                            src_ip=event.get('src_ip', 'unknown'),
                            dest_ip=event.get('dest_ip', 'unknown'),
                            ttl=dns_data.get('ttl', 0),
                            response_code=dns_data.get('rcode', 'NOERROR'),
                            answers=answers,
                            source="eve.json",
                        )
                        await queue.put(captured)

                    except json.JSONDecodeError:
                        continue

                last_pos = await f.tell()
            await asyncio.sleep(0.5)

        except Exception as e:
            print(f"[Eve.json] Error: {e}")
            await asyncio.sleep(2)


# ─── Demo / Simulated Events Fallback ─────────────────────────────────────────

async def demo_events_loop(queue: asyncio.Queue):
    """Generate simulated DNS traffic when real capture produces nothing after 13 s."""
    import random
    try:
        from generate_events import (
            LEGITIMATE_DOMAINS, create_event, generate_dga_domain,
            generate_fast_flux_event, generate_cache_poison_event,
            generate_tunneling_event, generate_rogue_ns_event,
            generate_suspicious_tld_event, generate_malicious_keyword_event,
        )
    except ImportError:
        print("[Demo] generate_events.py not found, demo mode disabled")
        return

    # Give real capture 13 s to produce at least 3 events
    await asyncio.sleep(8)
    baseline = stats_data["total_queries"]
    await asyncio.sleep(5)
    if stats_data["total_queries"] - baseline >= 3:
        print("[Demo] Real DNS capture is active — demo mode staying off")
        return

    print("[Demo] No real DNS events detected — activating simulated traffic")
    if "simulated" not in stats_data["capture_methods"]:
        stats_data["capture_methods"].append("simulated")

    attack_generators = [
        generate_fast_flux_event,
        generate_cache_poison_event,
        generate_tunneling_event,
        generate_rogue_ns_event,
        generate_suspicious_tld_event,
        generate_malicious_keyword_event,
        lambda: create_event(
            generate_dga_domain(), "A", random.randint(30, 120), "NOERROR",
            [f"185.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,254)}"]
        ),
    ]

    while True:
        try:
            if random.random() < 0.72:
                domain, qtype, ttl, ips = random.choice(LEGITIMATE_DOMAINS)
                eve_event = create_event(domain, qtype, ttl, "NOERROR", ips)
            else:
                eve_event = random.choice(attack_generators)()

            dns_data = eve_event.get('dns', {})
            answers_raw = dns_data.get('answers', [])
            answers = [str(a) if not isinstance(a, dict) else a.get('rdata', '') for a in answers_raw]

            event = CapturedDNSEvent(
                timestamp=datetime.utcnow().isoformat() + "Z",
                domain=dns_data.get('rrname', 'unknown'),
                query_type=dns_data.get('rrtype', 'A'),
                src_ip=eve_event.get('src_ip', '192.168.1.100'),
                dest_ip=eve_event.get('dest_ip', '8.8.8.8'),
                ttl=dns_data.get('ttl', 0),
                response_code=dns_data.get('rcode', 'NOERROR'),
                answers=answers,
                source="simulated",
            )
            await queue.put(event)
        except Exception:
            pass

        await asyncio.sleep(random.uniform(0.4, 1.8))


# ─── App Lifecycle ─────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    import time
    startup_start = time.time()
    print("\n" + "="*60, flush=True)
    print("DNS SECURITY MONITORING PLATFORM - STARTING", flush=True)
    print("="*60, flush=True)

    event_queue = asyncio.Queue(maxsize=1000)

    # Start consumer
    consumer_task = asyncio.create_task(event_consumer(event_queue))
    print("✓ Event consumer started", flush=True)

    # Watch eve.json for testing / Suricata
    eve_task = asyncio.create_task(watch_eve_json(event_queue))
    print("✓ Eve.json watcher started", flush=True)

    # Simulated events fallback (activates after 13 s if real capture produces nothing)
    demo_task = asyncio.create_task(demo_events_loop(event_queue))

    # DNS capture engine — started as a background task AFTER yield so it can
    # NEVER block server startup regardless of what happens inside start().
    # Any blocking call (subprocess, time.sleep, network) in start() would stall
    # the event loop if awaited here; a create_task keeps it fully non-blocking.
    bg_capture_tasks: List[asyncio.Task] = []

    async def _start_capture_bg():
        try:
            tasks = await asyncio.wait_for(capture_engine.start(event_queue), timeout=20)
            bg_capture_tasks.extend(tasks)
            stats_data["capture_methods"] = capture_engine.capture_methods
            caps = capture_engine.get_capabilities()
            print("\n" + "-"*60, flush=True)
            print("DNS CAPTURE ACTIVE:", flush=True)
            print(f"   Methods:   {', '.join(capture_engine.capture_methods)}", flush=True)
            print(f"   Scapy:     {'✓' if caps['scapy'] else '✗'}", flush=True)
            print(f"   DNSPython: {'✓' if caps['dnspython'] else '✗'}", flush=True)
            print(f"   DNS Cache: {'✓' if caps['cache_monitor'] else '✗'}", flush=True)
            print("-"*60, flush=True)
        except asyncio.TimeoutError:
            stats_data["capture_methods"] = ["timeout"]
            print("[Capture] Timed out — using simulated traffic", flush=True)
        except Exception as e:
            stats_data["capture_methods"] = ["error"]
            print(f"[Capture] Error: {e} — using simulated traffic", flush=True)

    capture_init_task = asyncio.create_task(_start_capture_bg())

    print("-"*60, flush=True)
    print(f"Dashboard:  http://localhost:5173", flush=True)
    print(f"API:        http://localhost:9000", flush=True)
    print(f"Health:     http://localhost:9000/health", flush=True)
    print(f"Started in: {time.time() - startup_start:.2f}s", flush=True)
    print("="*60 + "\n", flush=True)

    yield  # ← SERVER IS LIVE HERE — capture initializes in background

    print("\nShutting down DNS Guardian...", flush=True)
    capture_engine.stop()
    capture_init_task.cancel()
    consumer_task.cancel()
    eve_task.cancel()
    demo_task.cancel()
    for t in bg_capture_tasks:
        t.cancel()
    print("DNS Guardian stopped\n", flush=True)


# ─── FastAPI App ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="DNS Security Monitoring Platform",
    description="Real-time DNS traffic capture, analysis, and threat detection",
    version="2.0.0",
    lifespan=lifespan,
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
        "version": "2.0.0",
        "status": "running",
        "capture_methods": stats_data["capture_methods"],
        "endpoints": {
            "health": "/health",
            "stats": "/api/stats",
            "domains": "/api/domains",
            "records": "/api/records/{domain}",
            "validate": "/api/validate/{domain}",
            "websocket": "/ws/logs",
        }
    }


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "active_connections": len(manager.active_connections),
        "capture_methods": stats_data["capture_methods"],
    }


@app.get("/api/stats")
async def get_stats():
    now = datetime.now()
    recent = [t for t in stats_data["recent_queries_per_min"]
              if (now - t).total_seconds() < 60]
    return {
        "total_queries": stats_data["total_queries"],
        "total_alerts": stats_data["total_alerts"],
        "queries_per_minute": len(recent),
        "unique_domains": len(stats_data["unique_domains"]),
        "unique_sources": len(stats_data["unique_src_ips"]),
        "active_connections": len(manager.active_connections),
        "threats_by_type": dict(stats_data["threats_by_type"]),
        "queries_by_type": dict(stats_data["queries_by_type"]),
        "queries_by_response": dict(stats_data["queries_by_response"]),
        "alert_rate": round(
            (stats_data["total_alerts"] / stats_data["total_queries"] * 100)
            if stats_data["total_queries"] > 0 else 0, 2
        ),
        "capture_methods": stats_data["capture_methods"],
        "uptime_since": stats_data["start_time"],
    }


@app.get("/api/alerts")
async def get_alerts():
    return {"alerts": list(recent_alerts)}


@app.get("/api/domains")
async def get_domains():
    """Get all tracked domains with their records"""
    result = {}
    for domain, info in list(domain_records.items())[:100]:
        result[domain] = {
            "A": info.get("A", []),
            "AAAA": info.get("AAAA", []),
            "CNAME": info.get("CNAME", []),
            "NS": info.get("NS", []),
            "MX": info.get("MX", []),
            "TXT": info.get("TXT", []),
            "first_seen": info.get("first_seen", ""),
            "last_seen": info.get("last_seen", ""),
            "query_count": info.get("query_count", 0),
            "sources": list(info.get("sources", set())),
        }
    return {"domains": result, "total": len(domain_records)}


@app.get("/api/records/{domain}")
async def get_domain_records(domain: str):
    """Get full DNS records for a specific domain (active resolution)"""
    events = await capture_engine.resolve_domain_full(domain)
    records = {}
    for ev in events:
        records[ev.query_type] = {
            "answers": ev.answers,
            "ttl": ev.ttl,
            "response_code": ev.response_code,
            "source": ev.source,
        }

    # Also get cached data
    cached = domain_records.get(domain, {})

    return {
        "domain": domain,
        "live_records": records,
        "cached_records": {
            k: v for k, v in cached.items()
            if k in ["A", "AAAA", "CNAME", "NS", "MX", "TXT"] and v
        },
        "query_count": cached.get("query_count", 0),
        "first_seen": cached.get("first_seen", ""),
        "last_seen": cached.get("last_seen", ""),
    }


@app.get("/api/validate/{domain}")
async def validate_domain(domain: str):
    """Validate cached vs authoritative DNS response"""
    result = await capture_engine.validate_domain(domain)
    return result


@app.get("/api/geoip")
async def geoip_batch(ips: str):
    """Return geolocation for up to 20 comma-separated IPs.
    Uses ip-api.com (free, no key needed). Results are in-memory cached."""
    ip_list = [ip.strip() for ip in ips.split(",") if ip.strip()][:20]
    results = await asyncio.gather(
        *[asyncio.to_thread(_geoip_lookup, ip) for ip in ip_list]
    )
    return {"results": [r for r in results if r]}


@app.get("/api/phishing/{domain}")
async def check_phishing(domain: str):
    """
    Check if a domain is a potential phishing/typosquatting domain.
    Uses dnstwist-style detection to identify lookalike domains.
    
    Returns:
    - is_phishing: bool
    - original_domain: The legitimate domain being spoofed
    - original_org: Organization name
    - confidence: Detection confidence (0-1)
    - fuzzer_type: Type of typosquatting technique used
    """
    result = await check_phishing_domain(domain)
    return result


@app.get("/api/typosquats/{domain}")
async def get_typosquats(domain: str):
    """
    Generate common typosquat variations for a domain.
    Useful for proactive protection - check if any of these exist.
    """
    variations = get_common_typosquats(domain)
    return {
        "domain": domain,
        "variations": variations,
        "count": len(variations)
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
    import sys

    # Force line-buffered stdout so prints appear immediately in any terminal/CMD
    try:
        getattr(sys.stdout, "reconfigure")(line_buffering=True)
    except Exception:
        pass

    # ── Request administrator privileges for live ETW DNS capture ──────────────
    if sys.platform == "win32":
        import ctypes
        try:
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            is_admin = False

        if not is_admin:
            print("\n" + "="*60, flush=True)
            print(" LIVE DNS CAPTURE — ADMINISTRATOR ACCESS REQUIRED", flush=True)
            print("="*60, flush=True)
            print(" Requesting elevation via Windows UAC...", flush=True)
            print(" Click 'Yes' on the UAC prompt to enable live DNS tracking.", flush=True)
            print("="*60 + "\n", flush=True)
            # Re-launch this script as admin with -u (unbuffered) flag
            script_path = os.path.abspath(__file__)
            work_dir = os.path.dirname(script_path)
            ret = ctypes.windll.shell32.ShellExecuteW(
                None, "runas",
                sys.executable,
                f'-u "{script_path}"',
                work_dir,
                1,  # SW_SHOWNORMAL
            )
            # ShellExecuteW returns >32 on success
            if ret > 32:
                sys.exit(0)
            else:
                print("UAC elevation failed or was denied — continuing without admin.", flush=True)
                print("Live ETW DNS capture will be unavailable.\n", flush=True)

    port = int(os.environ.get("PORT", 9000))

    print("\n" + "="*60)
    print(" DNS SECURITY MONITORING PLATFORM - BACKEND SERVER")
    print("="*60)
    print(f" Starting server on port {port}...")
    print("="*60 + "\n")

    try:
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=port,
            log_level="info",
            access_log=False,
        )
    except KeyboardInterrupt:
        print("\n\n✓ Server stopped by user")
        sys.exit(0)
