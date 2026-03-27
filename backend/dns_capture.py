#!/usr/bin/env python3
"""
DNS Capture Module - Real-time DNS traffic monitoring on Windows
Multiple capture methods with automatic fallback:
  1. Scapy packet sniffer (best: captures all DNS packets, needs Npcap + admin)
  2. Windows DNS cache monitor (reliable: polls ipconfig /displaydns, no admin needed)
  3. Active DNS resolver (always works: resolves domains via dnspython)
"""
import asyncio
import json
import socket
import struct
import subprocess
import re
import os
import platform
import threading
import time
from datetime import datetime
from typing import Dict, List, Set, Optional, Callable, Any
from collections import defaultdict
from dataclasses import dataclass, field

# Try importing optional dependencies
try:
    import dns.resolver
    import dns.rdatatype
    import dns.name
    import dns.query
    import dns.zone
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    from scapy.all import sniff, DNS, DNSQR, DNSRR, IP, UDP
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


# ─── Data Structures ──────────────────────────────────────────────────────────

RECORD_TYPE_MAP = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 257: "CAA",
}

RECORD_TYPE_REVERSE = {v: k for k, v in RECORD_TYPE_MAP.items()}


@dataclass
class CapturedDNSEvent:
    """Represents a captured DNS event from any source"""
    timestamp: str
    domain: str
    query_type: str   # A, AAAA, CNAME, NS, MX, TXT
    src_ip: str
    dest_ip: str
    ttl: int
    response_code: str  # NOERROR, NXDOMAIN, SERVFAIL, REFUSED
    answers: List[str]
    source: str  # "sniffer", "cache", "resolver"
    is_authoritative: bool = False
    nameserver: str = ""


# ─── Windows DNS Cache Monitor ────────────────────────────────────────────────

class WindowsDNSCacheMonitor:
    """Monitors Windows DNS client cache for new entries"""

    # How long (seconds) before the same domain+type+answer can fire again.
    # 90 s means: if you visit a domain, it appears immediately; visiting the
    # same domain again within 90 s won't spam duplicates, but will show up
    # again after that window expires (e.g. when the user revisits a site).
    _DEDUP_TTL = 90

    def __init__(self):
        self._seen_entries: Dict[str, float] = {}  # key → last-seen epoch
        self.local_ip = self._get_local_ip()
        self._cached_dns_server: Optional[str] = None

    def _get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def _get_default_dns_server(self) -> str:
        """Get the system's configured DNS server (cached).
        Uses 'netsh' (instant, built-in) instead of PowerShell (slow cold-start)."""
        if self._cached_dns_server:
            return self._cached_dns_server

        # Try netsh first (built-in Windows command, starts instantly)
        try:
            result = subprocess.run(
                ["netsh", "interface", "ip", "show", "dns"],
                capture_output=True, text=True, timeout=3,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            for line in result.stdout.split('\n'):
                # Look for lines like "  DNS Servers:  192.168.1.1"
                m = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if m:
                    ip = m.group(1)
                    self._cached_dns_server = ip
                    return ip
        except Exception:
            pass

        self._cached_dns_server = "8.8.8.8"
        return "8.8.8.8"

    def poll_cache(self) -> List[CapturedDNSEvent]:
        """Poll Windows DNS cache using ipconfig /displaydns.
        Avoids PowerShell which has a slow cold-start and can hang on timeout kill."""
        return self._poll_cache_ipconfig()

    def _poll_cache_ipconfig(self) -> List[CapturedDNSEvent]:
        """Fallback: parse ipconfig /displaydns output"""
        events = []
        try:
            result = subprocess.run(
                ["ipconfig", "/displaydns"],
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )

            dns_server = self._get_default_dns_server()
            current = {}

            for line in result.stdout.split('\n'):
                line = line.strip()

                if 'Record Name' in line or 'Nom de l' in line:
                    if current.get("domain"):
                        ev = self._build_event_from_ipconfig(current, dns_server)
                        if ev:
                            events.append(ev)
                    val = line.split(':', 1)[-1].strip().rstrip('.')
                    current = {"domain": val}

                elif ('Record Type' in line or 'Type' in line) and 'record_type' not in current:
                    val = line.split(':', 1)[-1].strip()
                    try:
                        current["record_type"] = int(val)
                    except ValueError:
                        current["record_type"] = 1

                elif 'Time To Live' in line or 'Dur' in line:
                    val = line.split(':', 1)[-1].strip()
                    try:
                        current["ttl"] = int(val)
                    except ValueError:
                        current["ttl"] = 0

                elif ('A (Host) Record' in line or 'Host) Record' in line or
                     'AAAA' in line or 'CNAME' in line):
                    val = line.split(':', 1)[-1].strip()
                    if val:
                        current["answer"] = val

            # Last entry
            if current.get("domain"):
                ev = self._build_event_from_ipconfig(current, dns_server)
                if ev:
                    events.append(ev)

        except Exception as e:
            print(f"[DNS Cache ipconfig] Error: {e}")

        return events

    def _build_event_from_ipconfig(self, data: dict, dns_server: str) -> Optional[CapturedDNSEvent]:
        domain = data.get("domain", "").strip()
        if not domain or self._should_skip(domain):
            return None

        record_type_num = data.get("record_type", 1)
        entry_key = f"{domain}:{record_type_num}:{data.get('answer', '')}"
        now = time.time()
        last = self._seen_entries.get(entry_key, 0)
        if now - last < self._DEDUP_TTL:
            return None  # Same entry seen recently — skip
        self._seen_entries[entry_key] = now
        # Prune expired entries every ~500 polls to stop unbounded growth
        if len(self._seen_entries) > 5000:
            cutoff = now - self._DEDUP_TTL
            self._seen_entries = {k: v for k, v in self._seen_entries.items() if v > cutoff}

        record_type = RECORD_TYPE_MAP.get(record_type_num, "A")
        answer = data.get("answer", "")

        return CapturedDNSEvent(
            timestamp=datetime.utcnow().isoformat() + "Z",
            domain=domain,
            query_type=record_type,
            src_ip=self.local_ip,
            dest_ip=dns_server,
            ttl=data.get("ttl", 0),
            response_code="NOERROR",
            answers=[answer] if answer else [],
            source="cache",
        )

    def _should_skip(self, domain: str) -> bool:
        """Skip internal/system domains"""
        skip_patterns = [
            'localhost', '.local', '_dns', '_tcp', '_udp', '_msdcs',
            'in-addr.arpa', 'ip6.arpa', '_kerberos', '_ldap',
            'wpad', 'isatap', 'teredo',
        ]
        domain_lower = domain.lower()
        if len(domain_lower) < 3:
            return True
        for pattern in skip_patterns:
            if pattern in domain_lower:
                return True
        return False

    @property
    def seen_entries(self) -> Set[str]:
        """Back-compat: return current live keys as a set."""
        return set(self._seen_entries.keys())

    def reset(self):
        """Reset seen entries to re-capture everything"""
        self._seen_entries.clear()


# ─── Active DNS Resolver ──────────────────────────────────────────────────────

class ActiveDNSResolver:
    """Actively resolves domains to get full record details (A, AAAA, CNAME, NS, MX)
    Also validates authoritative vs cached responses."""

    RECORD_TYPES = ["A", "AAAA", "CNAME", "NS", "MX", "TXT"]

    def __init__(self):
        self.local_ip = "127.0.0.1"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            self.local_ip = s.getsockname()[0]
            s.close()
        except:
            pass

    def resolve_domain(self, domain: str, record_types: List[str] = None,
                       nameserver: str = None) -> List[CapturedDNSEvent]:
        """Resolve a domain for specified record types"""
        if not HAS_DNSPYTHON:
            return self._resolve_socket(domain)

        if record_types is None:
            record_types = self.RECORD_TYPES

        events = []
        resolver = dns.resolver.Resolver()
        if nameserver:
            resolver.nameservers = [nameserver]
        resolver.timeout = 3
        resolver.lifetime = 5

        for rtype in record_types:
            try:
                result = resolver.resolve(domain, rtype)
                answers = []
                ttl = result.rrset.ttl if result.rrset else 0

                for rdata in result:
                    if rtype == "MX":
                        answers.append(f"{rdata.preference} {rdata.exchange}")
                    elif rtype == "NS":
                        answers.append(str(rdata.target))
                    elif rtype == "CNAME":
                        answers.append(str(rdata.target))
                    elif rtype == "TXT":
                        answers.append(' '.join(s.decode() for s in rdata.strings))
                    else:
                        answers.append(str(rdata))

                ns_used = nameserver or (resolver.nameservers[0] if resolver.nameservers else "system")

                events.append(CapturedDNSEvent(
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    domain=domain,
                    query_type=rtype,
                    src_ip=self.local_ip,
                    dest_ip=ns_used,
                    ttl=ttl,
                    response_code="NOERROR",
                    answers=answers,
                    source="resolver",
                    is_authoritative=nameserver is not None,
                    nameserver=ns_used,
                ))

            except dns.resolver.NXDOMAIN:
                events.append(CapturedDNSEvent(
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    domain=domain,
                    query_type=rtype,
                    src_ip=self.local_ip,
                    dest_ip=nameserver or "system",
                    ttl=0,
                    response_code="NXDOMAIN",
                    answers=[],
                    source="resolver",
                ))
            except dns.resolver.NoAnswer:
                continue
            except dns.resolver.NoNameservers:
                events.append(CapturedDNSEvent(
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    domain=domain,
                    query_type=rtype,
                    src_ip=self.local_ip,
                    dest_ip=nameserver or "system",
                    ttl=0,
                    response_code="SERVFAIL",
                    answers=[],
                    source="resolver",
                ))
            except Exception:
                continue

        return events

    def _resolve_socket(self, domain: str) -> List[CapturedDNSEvent]:
        """Fallback resolver using socket (no dnspython)"""
        events = []
        try:
            ips = socket.getaddrinfo(domain, None)
            answers_v4 = list(set(addr[4][0] for addr in ips if addr[0] == socket.AF_INET))
            answers_v6 = list(set(addr[4][0] for addr in ips if addr[0] == socket.AF_INET6))

            if answers_v4:
                events.append(CapturedDNSEvent(
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    domain=domain,
                    query_type="A",
                    src_ip=self.local_ip,
                    dest_ip="system",
                    ttl=0,
                    response_code="NOERROR",
                    answers=answers_v4,
                    source="resolver",
                ))
            if answers_v6:
                events.append(CapturedDNSEvent(
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    domain=domain,
                    query_type="AAAA",
                    src_ip=self.local_ip,
                    dest_ip="system",
                    ttl=0,
                    response_code="NOERROR",
                    answers=answers_v6,
                    source="resolver",
                ))
        except socket.gaierror:
            events.append(CapturedDNSEvent(
                timestamp=datetime.utcnow().isoformat() + "Z",
                domain=domain,
                query_type="A",
                src_ip=self.local_ip,
                dest_ip="system",
                ttl=0,
                response_code="NXDOMAIN",
                answers=[],
                source="resolver",
            ))
        return events

    def get_authoritative_ns(self, domain: str) -> List[str]:
        """Get authoritative nameservers for a domain"""
        if not HAS_DNSPYTHON:
            return []
        try:
            # Walk up the domain to find NS records
            parts = domain.split('.')
            for i in range(len(parts) - 1):
                check = '.'.join(parts[i:])
                try:
                    result = dns.resolver.resolve(check, 'NS')
                    ns_list = []
                    for rdata in result:
                        try:
                            ns_ips = dns.resolver.resolve(str(rdata.target), 'A')
                            for ip in ns_ips:
                                ns_list.append(str(ip))
                        except:
                            pass
                    if ns_list:
                        return ns_list
                except:
                    continue
        except:
            pass
        return []

    def validate_authoritative(self, domain: str) -> Dict[str, Any]:
        """Compare cached vs authoritative DNS response"""
        result = {
            "domain": domain,
            "cached": {},
            "authoritative": {},
            "match": True,
            "warnings": [],
        }

        if not HAS_DNSPYTHON:
            return result

        # Get cached response (default resolver)
        cached_events = self.resolve_domain(domain, ["A", "AAAA"])
        for ev in cached_events:
            result["cached"][ev.query_type] = {
                "answers": ev.answers,
                "ttl": ev.ttl,
                "resolver": ev.dest_ip,
            }

        # Get authoritative nameservers
        auth_ns = self.get_authoritative_ns(domain)
        if not auth_ns:
            result["warnings"].append("Could not determine authoritative nameservers")
            return result

        # Query authoritative directly
        for ns_ip in auth_ns[:2]:  # Try first 2 NS
            try:
                auth_events = self.resolve_domain(domain, ["A", "AAAA"], nameserver=ns_ip)
                for ev in auth_events:
                    result["authoritative"][ev.query_type] = {
                        "answers": ev.answers,
                        "ttl": ev.ttl,
                        "nameserver": ns_ip,
                    }
                break
            except:
                continue

        # Compare
        for rtype in ["A", "AAAA"]:
            cached_ans = set(result["cached"].get(rtype, {}).get("answers", []))
            auth_ans = set(result["authoritative"].get(rtype, {}).get("answers", []))

            if cached_ans and auth_ans and cached_ans != auth_ans:
                result["match"] = False
                result["warnings"].append(
                    f"{rtype} mismatch: cached={list(cached_ans)} vs authoritative={list(auth_ans)}"
                )

        return result


# ─── Scapy Packet Sniffer ────────────────────────────────────────────────────

class ScapyDNSSniffer:
    """Real-time DNS packet capture using Scapy (requires Npcap on Windows)"""

    def __init__(self, callback: Callable[[CapturedDNSEvent], None]):
        self.callback = callback
        self.running = False
        self.thread = None
        self.local_ip = "127.0.0.1"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            self.local_ip = s.getsockname()[0]
            s.close()
        except:
            pass

    def _process_packet(self, pkt):
        """Process a captured DNS packet"""
        try:
            if not pkt.haslayer(DNS):
                return

            dns_layer = pkt[DNS]
            ip_layer = pkt[IP] if pkt.haslayer(IP) else None

            src_ip = str(ip_layer.src) if ip_layer else "unknown"
            dest_ip = str(ip_layer.dst) if ip_layer else "unknown"

            # Process DNS response
            if dns_layer.qr == 1 and dns_layer.ancount > 0:
                # Get the query name
                if dns_layer.qd:
                    domain = dns_layer.qd.qname.decode().rstrip('.')
                    qtype_num = dns_layer.qd.qtype
                    query_type = RECORD_TYPE_MAP.get(qtype_num, f"TYPE{qtype_num}")
                else:
                    return

                # Determine rcode
                rcode_map = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL",
                             3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
                rcode = rcode_map.get(dns_layer.rcode, f"RCODE{dns_layer.rcode}")

                # Extract answers
                answers = []
                ttl = 0
                for i in range(dns_layer.ancount):
                    try:
                        rr = dns_layer.an[i]
                        if hasattr(rr, 'rdata'):
                            answers.append(str(rr.rdata))
                        if hasattr(rr, 'ttl'):
                            ttl = rr.ttl
                    except:
                        pass

                event = CapturedDNSEvent(
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    domain=domain,
                    query_type=query_type,
                    src_ip=src_ip,
                    dest_ip=dest_ip,
                    ttl=ttl,
                    response_code=rcode,
                    answers=answers,
                    source="sniffer",
                )
                self.callback(event)

            # Also capture DNS queries (no answer yet)
            elif dns_layer.qr == 0 and dns_layer.qd:
                domain = dns_layer.qd.qname.decode().rstrip('.')
                qtype_num = dns_layer.qd.qtype
                query_type = RECORD_TYPE_MAP.get(qtype_num, f"TYPE{qtype_num}")

                event = CapturedDNSEvent(
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    domain=domain,
                    query_type=query_type,
                    src_ip=src_ip,
                    dest_ip=dest_ip,
                    ttl=0,
                    response_code="QUERY",
                    answers=[],
                    source="sniffer",
                )
                self.callback(event)

        except Exception as e:
            pass  # Silent fail on individual packet parse errors

    def start(self):
        """Start packet capture in background thread"""
        if not HAS_SCAPY:
            return False

        def _sniff_thread():
            try:
                self.running = True
                sniff(filter="udp port 53", prn=self._process_packet,
                      store=0, stop_filter=lambda _: not self.running)
            except Exception as e:
                print(f"[Scapy] Sniffer error: {e}")
                self.running = False

        self.thread = threading.Thread(target=_sniff_thread, daemon=True)
        self.thread.start()
        return True

    def stop(self):
        self.running = False


# ─── ETW Live DNS Monitor ─────────────────────────────────────────────────────

class ETWDNSMonitor:
    """Real-time DNS monitoring via Windows ETW (Event Tracing for Windows).

    Reads Microsoft-Windows-DNS-Client/Operational log which fires an event
    for every DNS query (Event 3008) and every response (Event 3020).
    Requires the log to be enabled — the class tries to enable it (needs admin).
    """

    _LOG = "Microsoft-Windows-DNS-Client/Operational"

    # PowerShell script: enables the log, then streams events as compact JSON
    _PS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$L = 'Microsoft-Windows-DNS-Client/Operational'

# Enable log (needs admin; silently ignored if no permission)
try {
    $cfg = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration($L)
    if (-not $cfg.IsEnabled) { $cfg.IsEnabled = $true; $cfg.SaveChanges() }
} catch {}

# Verify access — exit 1 if not available so Python can detect the failure
# Use Get-WinEvent -ListLog instead of -MaxEvents 1 so newly-enabled empty logs don't cause false exit
try { $log = Get-WinEvent -ListLog $L -ErrorAction Stop; if (-not $log.IsEnabled) { exit 1 } } catch { exit 1 }

$last = [DateTime]::UtcNow
while ($true) {
    try {
        $evts = Get-WinEvent -FilterHashtable @{ LogName=$L; StartTime=$last } -ErrorAction SilentlyContinue
        if ($evts) {
            foreach ($e in ($evts | Sort-Object TimeCreated)) {
                $u = $e.TimeCreated.ToUniversalTime()
                if ($u -ge $last) { $last = $u.AddMilliseconds(1) }
                $p = $e.Properties
                if ($p.Count -lt 1) { continue }
                $nm = [string]$p[0].Value
                if (-not $nm) { continue }
                $tp = 1;  if ($p.Count -gt 1) { try { $tp = [int]$p[1].Value  } catch {} }
                $st = 0;  if ($p.Count -gt 4) { try { $st = [int]$p[4].Value  } catch {} }
                $rs = ''; if ($p.Count -gt 5) { $rs = [string]$p[5].Value }
                [PSCustomObject]@{t=$u.ToString('o');id=[int]$e.Id;n=$nm;tp=$tp;s=$st;r=$rs} | ConvertTo-Json -Compress
                [Console]::Out.Flush()
            }
        }
    } catch {}
    Start-Sleep -Milliseconds 500
}
"""

    def __init__(self, callback: Callable[[CapturedDNSEvent], None]):
        self.callback = callback
        self.running = False
        self.process: Optional[subprocess.Popen] = None
        self.thread: Optional[threading.Thread] = None
        self.local_ip = "127.0.0.1"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            self.local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            pass

    def start(self) -> bool:
        """Start live ETW DNS monitoring. Returns True if the log is available."""
        if platform.system() != "Windows":
            return False
        try:
            self.process = subprocess.Popen(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", self._PS_SCRIPT],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            # Give PowerShell ~1.5 s to start and either print events or exit 1
            # (This method is called via asyncio.to_thread — time.sleep is safe here)
            time.sleep(1.5)
            if self.process.poll() is not None:
                return False  # Exited immediately — log not available / no admin
            self.running = True
            self.thread = threading.Thread(target=self._reader, daemon=True)
            self.thread.start()
            return True
        except Exception as e:
            print(f"[ETW] Startup error: {e}")
            return False

    def _reader(self):
        """Background thread: reads JSON lines from the PowerShell process."""
        try:
            for line in self.process.stdout:
                if not self.running:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    name = str(d.get("n", "")).strip().rstrip(".")
                    if not name:
                        continue

                    type_num = int(d.get("tp", 1))
                    record_type = RECORD_TYPE_MAP.get(type_num, "A")
                    event_id = int(d.get("id", 0))
                    status = int(d.get("s", 0))
                    results_raw = str(d.get("r", ""))

                    if status in (9003, 9501):
                        rcode = "NXDOMAIN"
                    elif status != 0:
                        rcode = "SERVFAIL"
                    elif event_id == 3008:   # query fired, no answer yet
                        rcode = "QUERY"
                    else:
                        rcode = "NOERROR"

                    # Results field may be "ip1;ip2" or "ip1\nip2"
                    answers = [a.strip() for a in re.split(r"[;\n]", results_raw) if a.strip()] if results_raw else []

                    self.callback(CapturedDNSEvent(
                        timestamp=d.get("t", datetime.utcnow().isoformat() + "Z"),
                        domain=name,
                        query_type=record_type,
                        src_ip=self.local_ip,
                        dest_ip="",
                        ttl=0,
                        response_code=rcode,
                        answers=answers,
                        source="etw",
                    ))
                except Exception:
                    pass
        except Exception as e:
            print(f"[ETW] Reader error: {e}")
        finally:
            self.running = False

    def stop(self):
        self.running = False
        if self.process:
            try:
                self.process.terminate()
            except Exception:
                pass


# ─── Unified DNS Capture Engine ───────────────────────────────────────────────

class DNSCaptureEngine:
    """Unified DNS capture that combines all methods"""

    def __init__(self):
        self.cache_monitor = WindowsDNSCacheMonitor()
        self.resolver = ActiveDNSResolver()
        self.scapy_sniffer: Optional[ScapyDNSSniffer] = None
        self.etw_monitor: Optional[ETWDNSMonitor] = None
        self.event_queue: asyncio.Queue = None
        self.capture_methods: List[str] = []
        self._live_capture_running = False  # True when ETW or Scapy is active

    def get_capabilities(self) -> Dict[str, bool]:
        return {
            "scapy": HAS_SCAPY,
            "dnspython": HAS_DNSPYTHON,
            "cache_monitor": platform.system() == "Windows",
            "etw": platform.system() == "Windows",
        }

    async def start(self, event_queue: asyncio.Queue):
        """Start all available capture methods"""
        import time
        self.event_queue = event_queue
        caps = self.get_capabilities()

        print("[DNS Capture] Initializing capture engine...", flush=True)

        # 1. ETW live monitor — started in background to avoid blocking the event loop.
        #    ETWDNSMonitor.start() calls time.sleep(1.5); wrapping with asyncio.to_thread
        #    keeps that sleep in a thread pool and returns immediately to the caller.
        tasks = []
        if caps["etw"]:
            print("[DNS Capture] ETW live DNS monitor initializing (background)...", flush=True)
            tasks.append(asyncio.create_task(self._init_etw_background()))

        # 2. Try Scapy packet sniffer (needs Npcap + admin) — only if ETW not on Windows
        if caps["scapy"] and not caps["etw"] and not self._live_capture_running:
            step_start = time.time()
            try:
                self.scapy_sniffer = ScapyDNSSniffer(self._on_live_event)
                if self.scapy_sniffer.start():
                    self.capture_methods.append("sniffer")
                    self._live_capture_running = True
                    print(f"[DNS Capture] ✓ Scapy packet sniffer active ({time.time() - step_start:.2f}s)", flush=True)
            except Exception as e:
                print(f"[DNS Capture] ✗ Scapy failed: {e} ({time.time() - step_start:.2f}s)", flush=True)

        # 3. DNS cache monitor (always available on Windows, near-real-time)
        if caps["cache_monitor"]:
            self.capture_methods.append("cache")
            print("[DNS Capture] ✓ DNS cache monitor queued (1-second polling)", flush=True)

        # 4. Active resolver for enrichment
        self.capture_methods.append("resolver")
        print(f"[DNS Capture] ✓ Active methods: {', '.join(self.capture_methods)}", flush=True)

        if "cache" in self.capture_methods:
            tasks.append(asyncio.create_task(self._cache_monitor_loop()))
        if not self._live_capture_running:
            tasks.append(asyncio.create_task(self._active_resolver_loop()))

        return tasks

    def _on_live_event(self, event: CapturedDNSEvent):
        """Callback from ETW monitor or Scapy sniffer (runs in a thread)."""
        if self.event_queue:
            try:
                self.event_queue.put_nowait(event)
            except asyncio.QueueFull:
                pass

    async def _init_etw_background(self):
        """Initialize ETW in a thread pool so time.sleep inside ETWDNSMonitor.start()
        does not block the asyncio event loop."""
        import time as _time
        step_start = _time.time()
        try:
            etw = ETWDNSMonitor(self._on_live_event)
            success = await asyncio.to_thread(etw.start)
            if success:
                self.etw_monitor = etw
                self._live_capture_running = True
                self.capture_methods.append("etw-live")
                print(f"[DNS Capture] ✓ ETW live DNS monitor active ({_time.time() - step_start:.2f}s)", flush=True)
            else:
                print(f"[DNS Capture] ✗ ETW unavailable (run as admin to enable) ({_time.time() - step_start:.2f}s)", flush=True)
        except Exception as e:
            print(f"[DNS Capture] ✗ ETW failed: {e} ({_time.time() - step_start:.2f}s)", flush=True)

    async def _cache_monitor_loop(self):
        """Periodically poll Windows DNS cache"""
        # Defer baseline to first poll - don't block startup
        enriched_domains: Set[str] = set()
        first_poll = True

        while True:
            try:
                events = await asyncio.to_thread(self.cache_monitor.poll_cache)
                
                # On first poll, mark all as baseline (don't emit old cached entries)
                if first_poll:
                    print(f"[DNS Cache] ✓ Baseline: {len(self.cache_monitor.seen_entries)} existing entries marked")
                    first_poll = False
                    await asyncio.sleep(1)
                    continue
                
                for event in events:
                    if self.event_queue:
                        await self.event_queue.put(event)

                        # Only enrich ONCE per domain, not every poll
                        if (HAS_DNSPYTHON and event.query_type == "A"
                                and event.domain not in enriched_domains):
                            enriched_domains.add(event.domain)
                            try:
                                enrichment = await asyncio.to_thread(
                                    self.resolver.resolve_domain,
                                    event.domain,
                                    ["AAAA", "CNAME", "NS", "MX"]
                                )
                                for enriched in enrichment:
                                    if enriched.answers:  # Only emit if there's actual data
                                        await self.event_queue.put(enriched)
                            except Exception:
                                pass

            except Exception as e:
                print(f"[DNS Cache] Poll error: {e}")

            await asyncio.sleep(0.5)  # Poll every 500 ms for near-real-time capture

    async def _active_resolver_loop(self):
        """Actively resolve domains discovered in cache to get full record details.
        Only runs when scapy sniffer is NOT active (to avoid duplicates)."""
        resolved_domains: Set[str] = set()

        while True:
            try:
                # Find new domains from cache that haven't been fully resolved
                new_domains = set()
                for entry_key in list(self.cache_monitor.seen_entries):
                    domain = entry_key.split(':')[0]
                    if domain not in resolved_domains and not self.cache_monitor._should_skip(domain):
                        new_domains.add(domain)

                # Resolve max 3 new domains per cycle to avoid flooding
                for domain in list(new_domains)[:3]:
                    resolved_domains.add(domain)
                    try:
                        events = await asyncio.to_thread(
                            self.resolver.resolve_domain,
                            domain,
                            ["A", "AAAA", "NS", "MX"]  # Skip CNAME/TXT to reduce noise
                        )
                        for event in events:
                            if self.event_queue and event.answers:
                                await self.event_queue.put(event)
                    except Exception:
                        pass

            except Exception as e:
                print(f"[Resolver] Error: {e}")

            await asyncio.sleep(8)  # Slower cycle to reduce event flood

    async def validate_domain(self, domain: str) -> Dict:
        """Validate a domain (cached vs authoritative)"""
        return await asyncio.to_thread(self.resolver.validate_authoritative, domain)

    async def resolve_domain_full(self, domain: str) -> List[CapturedDNSEvent]:
        """Get full resolution for a domain"""
        return await asyncio.to_thread(
            self.resolver.resolve_domain, domain,
            ["A", "AAAA", "CNAME", "NS", "MX", "TXT"]
        )

    def stop(self):
        if self.etw_monitor:
            self.etw_monitor.stop()
        if self.scapy_sniffer:
            self.scapy_sniffer.stop()
