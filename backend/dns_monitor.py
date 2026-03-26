#!/usr/bin/env python3
"""Windows DNS Monitor - Logs DNS queries from Windows DNS Client"""
import json
import subprocess
import re
from datetime import datetime
import time

EVE_FILE = "eve.json"

def get_dns_cache():
    """Get DNS cache entries from Windows"""
    try:
        result = subprocess.run(
            ['ipconfig', '/displaydns'],
            capture_output=True,
            text=True
        )
        return result.stdout
    except:
        return ""

def parse_dns_cache(cache_output):
    """Parse ipconfig /displaydns output"""
    domains = {}
    current_domain = None

    for line in cache_output.split('\n'):
        if 'Record Name' in line:
            current_domain = line.split(':')[1].strip().rstrip('.')
        elif 'Record Type' in line and current_domain:
            record_type = line.split(':')[1].strip()
            if record_type == 'A':
                if current_domain not in domains:
                    domains[current_domain] = {'ips': [], 'type': 'A'}

    return domains

def log_dns_event(domain, ip='8.8.8.8'):
    """Write DNS event to eve.json"""
    try:
        event = {
            "timestamp": datetime.utcnow().isoformat() + "+0000",
            "flow_id": hash(domain) & 0x7FFFFFFF,
            "in_iface": "eth0",
            "event_type": "dns",
            "src_ip": "192.168.x.x",
            "src_port": 53,
            "dest_ip": ip,
            "dest_port": 53,
            "proto": "UDP",
            "dns": {
                "type": "query",
                "id": hash(domain) % 65535,
                "rrname": domain,
                "rrtype": "A",
                "rcode": "NOERROR",
                "ttl": 300,
                "answers": [ip]
            }
        }

        with open(EVE_FILE, 'a') as f:
            f.write(json.dumps(event) + '\n')
            f.flush()

        print(f"[{datetime.now().strftime('%H:%M:%S')}] {domain}")

    except Exception as e:
        print(f"Error: {e}")

def monitor_dns():
    """Monitor DNS by checking Windows DNS client cache"""
    print("Windows DNS Monitor")
    print(f"Logging DNS queries to: {EVE_FILE}")
    print("Monitoring DNS client cache...")
    print()

    seen_domains = set()
    check_count = 0

    while True:
        try:
            cache_output = get_dns_cache()
            domains = parse_dns_cache(cache_output)

            for domain in domains.keys():
                if domain and domain not in seen_domains and len(domain) > 2:
                    # Filter out Windows internal domains
                    if not any(x in domain.lower() for x in ['localhost', 'invalid', '_', 'local', 'mcast']):
                        log_dns_event(domain)
                        seen_domains.add(domain)

            check_count += 1
            if check_count % 10 == 0:
                print(f"[Monitor] Checked DNS cache {check_count} times, found {len(seen_domains)} domains")

            time.sleep(2)  # Check every 2 seconds

        except KeyboardInterrupt:
            print("\nStopped")
            break
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(2)

if __name__ == "__main__":
    monitor_dns()
