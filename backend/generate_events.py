#!/usr/bin/env python3
"""
DNS Event Generator - Realistic attack traffic simulation
Generates both benign and malicious DNS events for testing
"""
import json
import time
import random
import string
import math
from datetime import datetime

# ─── Benign Traffic ────────────────────────────────────────────────────────────

LEGITIMATE_DOMAINS = [
    ("google.com", "A", 300, ["142.250.80.46"]),
    ("www.google.com", "A", 300, ["142.250.80.46"]),
    ("github.com", "A", 300, ["140.82.121.3"]),
    ("stackoverflow.com", "A", 300, ["151.101.1.69"]),
    ("amazon.com", "A", 60, ["205.251.242.103"]),
    ("cloudflare.com", "A", 300, ["104.16.132.229"]),
    ("microsoft.com", "A", 300, ["20.70.246.20"]),
    ("youtube.com", "A", 300, ["142.250.80.78"]),
    ("facebook.com", "A", 300, ["157.240.1.35"]),
    ("twitter.com", "A", 300, ["104.244.42.65"]),
    ("netflix.com", "A", 60, ["54.237.226.164"]),
    ("reddit.com", "A", 300, ["151.101.1.140"]),
    ("wikipedia.org", "A", 600, ["208.80.154.224"]),
    ("mail.google.com", "CNAME", 300, ["142.250.80.17"]),
    ("outlook.com", "MX", 300, ["40.97.164.146"]),
    ("gmail.com", "MX", 3600, ["142.250.115.27"]),
    ("ns1.google.com", "NS", 3600, ["216.239.32.10"]),
    ("ns1.cloudflare.com", "NS", 3600, ["173.245.58.51"]),
    ("_dmarc.google.com", "TXT", 3600, ["v=DMARC1; p=reject"]),
    ("dns.google", "AAAA", 300, ["2001:4860:4860::8888"]),
]

# ─── Attack Scenarios ──────────────────────────────────────────────────────────

def generate_dga_domain():
    """Generate realistic DGA (Domain Generation Algorithm) domains"""
    patterns = [
        # Random alphanumeric (common DGA)
        lambda: ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(12, 30))),
        # Consonant-heavy (another DGA pattern)
        lambda: ''.join(random.choices('bcdfghjklmnpqrstvwxz', k=random.randint(10, 20))),
        # Mixed with some vowels
        lambda: ''.join(random.choices(string.ascii_lowercase, k=random.randint(15, 25))),
    ]
    tlds = ['.com', '.net', '.org', '.info', '.biz']
    name = random.choice(patterns)()
    return name + random.choice(tlds)


def generate_fast_flux_event(domain="botnet-c2-server.com"):
    """Generate fast-flux events (different IPs each time)"""
    answers = [
        f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        for _ in range(random.randint(3, 8))
    ]
    return create_event(domain, "A", random.randint(5, 30), "NOERROR", answers,
                       dest_ip="8.8.8.8")


def generate_cache_poison_event():
    """Generate cache poisoning events (TTL anomalies)"""
    targets = ["bankofamerica.com", "paypal.com", "chase.com", "wellsfargo.com"]
    domain = random.choice(targets)
    # Poisoned response: very low TTL + non-standard resolver
    return create_event(domain, "A", random.randint(1, 15), "NOERROR",
                       [f"185.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,254)}"],
                       dest_ip=f"10.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,254)}")


def generate_tunneling_event(base_domain="exfil-data.com"):
    """Generate DNS tunneling events (encoded data in subdomains)"""
    # Simulate base64-encoded data in subdomain
    encoded = ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(30, 60)))
    subdomain = '.'.join([encoded[i:i+12] for i in range(0, len(encoded), 12)])
    domain = f"{subdomain}.{base_domain}"
    query_type = random.choice(["TXT", "A", "CNAME"])
    return create_event(domain, query_type, 0, "NOERROR", ["127.0.0.1"],
                       src_ip=f"192.168.1.{random.randint(100, 200)}")


def generate_rogue_ns_event():
    """Generate rogue nameserver events"""
    domains = ["company-internal.com", "secure-login.net", "api-gateway.io"]
    domain = random.choice(domains)
    rogue_ip = f"10.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,254)}"
    response = random.choice(["SERVFAIL", "REFUSED", "NOERROR"])
    return create_event(domain, "A", random.randint(30, 120), response,
                       [f"192.168.{random.randint(1,255)}.{random.randint(1,254)}"],
                       dest_ip=rogue_ip)


def generate_suspicious_tld_event():
    """Generate events with suspicious TLDs"""
    names = ["free-prize", "login-verify", "account-update", "security-check", "prize-winner"]
    tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club"]
    domain = random.choice(names) + random.choice(tlds)
    return create_event(domain, "A", random.randint(30, 120), "NOERROR",
                       [f"185.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,254)}"])


def generate_malicious_keyword_event():
    """Generate events with malicious keywords"""
    domains = [
        "download-payload.com", "cmd-shell-access.net",
        "phishing-login.com", "malware-distribution.xyz",
        "keylogger-install.top", "ransomware-decrypt.com",
    ]
    domain = random.choice(domains)
    return create_event(domain, "A", 60, "NOERROR",
                       [f"45.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,254)}"])


# ─── Event Builder ─────────────────────────────────────────────────────────────

def create_event(domain, query_type="A", ttl=300, rcode="NOERROR",
                 answers=None, src_ip=None, dest_ip=None):
    """Build a realistic Suricata-format DNS event"""
    if answers is None:
        answers = [f"8.8.{random.randint(1,255)}.{random.randint(1,254)}"]
    if src_ip is None:
        src_ip = f"192.168.{random.randint(1,10)}.{random.randint(1,254)}"
    if dest_ip is None:
        dest_ip = random.choice(["8.8.8.8", "8.8.4.4", "1.1.1.1"])

    return {
        "timestamp": datetime.utcnow().isoformat() + "+0000",
        "flow_id": random.randint(1000000000, 9999999999),
        "in_iface": "eth0",
        "event_type": "dns",
        "src_ip": src_ip,
        "src_port": random.randint(50000, 65000),
        "dest_ip": dest_ip,
        "dest_port": 53,
        "proto": "UDP",
        "dns": {
            "type": "query",
            "id": random.randint(1, 65535),
            "rrname": domain,
            "rrtype": query_type,
            "rcode": rcode,
            "ttl": ttl,
            "answers": answers,
        }
    }


# ─── Main Loop ─────────────────────────────────────────────────────────────────

def main():
    eve_file = "eve.json"
    print("DNS Traffic Generator v2.0")
    print(f"Writing to: {eve_file}")
    print("Press Ctrl+C to stop\n")
    print("Traffic mix: 70% legitimate, 30% attack scenarios\n")

    attack_generators = [
        ("DGA Domain", lambda: create_event(generate_dga_domain(), "A", random.randint(30, 120), "NOERROR",
                                            [f"185.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,254)}"])),
        ("Fast-Flux", generate_fast_flux_event),
        ("Cache Poisoning", generate_cache_poison_event),
        ("DNS Tunneling", generate_tunneling_event),
        ("Rogue Nameserver", generate_rogue_ns_event),
        ("Suspicious TLD", generate_suspicious_tld_event),
        ("Malicious Keywords", generate_malicious_keyword_event),
    ]

    count = 0
    try:
        while True:
            # 70% legitimate, 30% attacks
            if random.random() < 0.7:
                domain, qtype, ttl, ips = random.choice(LEGITIMATE_DOMAINS)
                event = create_event(domain, qtype, ttl, "NOERROR", ips)
                label = "LEGIT"
            else:
                attack_name, generator = random.choice(attack_generators)
                event = generator()
                label = attack_name.upper()

            with open(eve_file, 'a') as f:
                f.write(json.dumps(event) + '\n')
                f.flush()

            domain = event['dns']['rrname']
            ttl = event['dns']['ttl']
            qtype = event['dns']['rrtype']
            count += 1

            color = "\033[92m" if label == "LEGIT" else "\033[91m"
            reset = "\033[0m"
            print(f"{color}[{count:>5}] [{datetime.now().strftime('%H:%M:%S')}] {label:<20} {qtype:<6} {domain:<45} TTL:{ttl}{reset}")

            time.sleep(random.uniform(0.3, 1.5))

    except KeyboardInterrupt:
        print(f"\n\nStopped. Generated {count} events.")


if __name__ == "__main__":
    main()
