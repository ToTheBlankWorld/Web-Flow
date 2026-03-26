#!/usr/bin/env python3
"""Generate continuous DNS traffic for testing"""
import json
import time
import asyncio
from datetime import datetime
import random

DNS_QUERIES = [
    ("google.com", 300),
    ("github.com", 300),
    ("stackoverflow.com", 300),
    ("example.com", 25),  # Low TTL triggers alert
    ("test-malware.tk", 60),  # Suspicious TLD
    ("dga-malware.com", 45),  # DGA pattern
    ("fast-flux.com", 10),  # Fast flux (multiple IPs)
    ("amazon.com", 300),
    ("facebook.com", 300),
    ("d94ea7d8db472ea.com", 60),  # Random subdomain
]

def generate_dns_event(domain, ttl, src_ip="192.168.1.100"):
    """Generate a realistic DNS event"""
    timestamp = datetime.utcnow().isoformat(timespec='microseconds') + "+0000"
    flow_id = random.randint(1000000000, 9999999999)
    src_port = random.randint(50000, 65000)

    # Some domains resolve to multiple IPs (fast-flux)
    if "fast-flux" in domain:
        answers = [f"192.168.1.{random.randint(1, 254)}" for _ in range(random.randint(2, 4))]
    else:
        answers = ["192.168.1.1"]

    event = {
        "timestamp": timestamp,
        "flow_id": flow_id,
        "in_iface": "eth0",
        "event_type": "dns",
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": "8.8.8.8",
        "dest_port": 53,
        "proto": "UDP",
        "dns": {
            "type": "query",
            "id": random.randint(1, 65535),
            "rrname": domain,
            "rrtype": "A",
            "rcode": "NOERROR",
            "ttl": ttl,
            "answers": answers
        }
    }
    return event

def append_to_eve():
    """Continuously append DNS events to eve.json"""
    eve_file = "eve.json"

    print(f"Starting DNS traffic generator...")
    print(f"Writing to {eve_file}")

    try:
        while True:
            domain, ttl = random.choice(DNS_QUERIES)
            event = generate_dns_event(domain, ttl)

            # Append to eve.json
            with open(eve_file, 'a') as f:
                f.write(json.dumps(event) + '\n')
                f.flush()

            print(f"[{datetime.now().strftime('%H:%M:%S')}] Generated: {domain} (TTL: {ttl})")

            # Wait 1-2 seconds between events
            time.sleep(random.uniform(1, 2))
    except KeyboardInterrupt:
        print("\nStopped")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    append_to_eve()
