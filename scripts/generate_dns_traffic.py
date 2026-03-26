#!/usr/bin/env python3
"""
DNS Traffic Generation Script using dnspython
Generates various DNS queries for Suricata to capture
"""

import dns.resolver
import random
import time
from datetime import datetime

def generate_dns_traffic():
    """Generate DNS traffic for monitoring"""

    # Configuration
    domains = [
        "google.com",
        "github.com",
        "stackoverflow.com",
        "example.com",
        "cloudflare.com",
        "amazon.com",
        "reddit.com",
        "wikipedia.org",
        "youtube.com",
        "facebook.com",
        # Suspicious domains for testing detection
        "aaaaaa-random-suspicious.tk",
        "dga-malware.ml",
        "fast-flux-test.com",
        "update-system-NOW.com",
        "d94ea7d8db472ea.com",
    ]

    query_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    dns_servers = ["8.8.8.8", "1.1.1.1", "8.8.4.4", "9.9.9.9"]

    resolver = dns.resolver.Resolver()

    counter = 0

    print("[*] DNS Traffic Generator - dnspython Method")
    print("[*] Generating DNS queries...")
    print("")

    try:
        while True:
            counter += 1

            # Random selection
            domain = random.choice(domains)
            query_type = random.choice(query_types)
            dns_server = random.choice(dns_servers)

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{timestamp}] Query #{counter}: {query_type} record for {domain} (via {dns_server})")

            try:
                # Set nameserver
                resolver.nameservers = [dns_server]

                # Set timeout
                resolver.timeout = 5

                # Query
                answer = resolver.resolve(domain, query_type)

                print(f"    ✓ Response received ({len(answer)} records)")

            except dns.resolver.NXDOMAIN:
                print(f"    ⚠ NXDOMAIN - Domain not found")

            except dns.resolver.NoAnswer:
                print(f"    ⚠ No Answer - Query type not available")

            except dns.exception.Timeout:
                print(f"    ✗ Timeout - No response from server")

            except Exception as e:
                print(f"    ✗ Error: {str(e)}")

            # Random delay between 1-3 seconds
            sleep_time = random.uniform(1, 3)
            time.sleep(sleep_time)

    except KeyboardInterrupt:
        print("\n[*] Generator stopped by user")
        print(f"[*] Total queries generated: {counter}")


if __name__ == "__main__":
    try:
        generate_dns_traffic()
    except Exception as e:
        print(f"[!] Fatal error: {e}")
