#!/bin/bash
# DNS Traffic Generation Script - Using nslookup
# This script generates DNS query traffic for Suricata to capture

echo "[*] DNS Traffic Generator - nslookup Method"
echo "[*] Generating queries every 2 seconds..."
echo ""

# List of domains to test
DOMAINS=(
    "google.com"
    "github.com"
    "stackoverflow.com"
    "example.com"
    "cloudflare.com"
    "amazon.com"
    "reddit.com"
    "wikipedia.org"
    "youtube.com"
    "facebook.com"
    "aaa-random-suspicious.tk"
    "dga-malware.ml"
    "fast-flux-test.com"
)

# DNS servers to query
DNS_SERVERS=(
    "8.8.8.8"       # Google DNS
    "1.1.1.1"       # Cloudflare DNS
    "8.8.4.4"       # Google DNS Secondary
)

COUNTER=0

while true; do
    # Pick random domain
    DOMAIN=${DOMAINS[$RANDOM % ${#DOMAINS[@]}]}

    # Pick random DNS server
    DNS_SERVER=${DNS_SERVERS[$RANDOM % ${#DNS_SERVERS[@]}]}

    # Increment counter
    COUNTER=$((COUNTER + 1))

    # Generate query
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] Query #$COUNTER: $DOMAIN (via $DNS_SERVER)"

    # Run nslookup and suppress output
    nslookup $DOMAIN $DNS_SERVER > /dev/null 2>&1

    # Wait 2 seconds
    sleep 2
done
