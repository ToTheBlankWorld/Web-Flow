#!/usr/bin/env python3
"""Generate continuous DNS traffic for local testing"""
import json
import time
import random
from datetime import datetime

DNS_QUERIES = [
    ("google.com", 300),
    ("github.com", 300),
    ("stackoverflow.com", 60),  # Low TTL trigger
    ("example.com", 25),  # Very low TTL
    ("test-malware.tk", 60),  # Suspicious TLD
    ("dga-command.ml", 45),  # DGA pattern
    ("fast-flux-botnet.com", 10),  # Fast flux
    ("amazon.com", 300),
    ("cloudflare.com", 300),
    ("random-subdomain-12345.xyz", 60),  # Random subdomain
]

def generate_event(domain, ttl):
    """Generate a realistic DNS event"""
    timestamp = datetime.utcnow().isoformat() + "+0000"

    # Fast-flux domains get multiple IPs
    if "fast-flux" in domain:
        answers = [f"192.168.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(random.randint(3, 6))]
    else:
        answers = [f"8.8.{random.randint(1,255)}.{random.randint(1,254)}"]

    event = {
        "timestamp": timestamp,
        "flow_id": random.randint(1000000000, 9999999999),
        "in_iface": "eth0",
        "event_type": "dns",
        "src_ip": f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
        "src_port": random.randint(50000, 65000),
        "dest_ip": "8.8.8.8",
        "dest_port": 53,
        "proto": "UDP",
        "dns": {
            "type": "query",
            "id": random.randint(1, 65535),
            "rrname": domain,
            "rrtype": "A",
            "rcode": "NOERROR" if random.random() > 0.1 else "NXDOMAIN",
            "ttl": ttl,
            "answers": answers
        }
    }
    return event

def main():
    eve_file = "eve.json"

    print(f"DNS Traffic Generator")
    print(f"Writing to: {eve_file}")
    print(f"Press Ctrl+C to stop\n")

    try:
        while True:
            domain, ttl = random.choice(DNS_QUERIES)
            event = generate_event(domain, ttl)

            # Append to eve.json
            with open(eve_file, 'a') as f:
                f.write(json.dumps(event) + '\n')
                f.flush()

            print(f"[{datetime.now().strftime('%H:%M:%S')}] {domain:30s} TTL:{ttl:3d} Answers:{len(event['dns']['answers'])}")

            # Random delay between 0.5-2 seconds
            time.sleep(random.uniform(0.5, 2))

    except KeyboardInterrupt:
        print("\n\nGenerator stopped")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
