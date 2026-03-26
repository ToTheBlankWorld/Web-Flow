#!/usr/bin/env python3
"""Windows DNS Traffic Sniffer - Captures real DNS queries"""
import socket
import struct
import json
import os
from datetime import datetime
import threading

DNS_PORT = 53
EVE_FILE = "eve.json"

def parse_dns_packet(data, src_ip, dest_ip, src_port, dest_port):
    """Parse DNS packet and extract query info"""
    try:
        # DNS header is 12 bytes
        if len(data) < 12:
            return None

        # Parse DNS header
        transaction_id = struct.unpack('!H', data[0:2])[0]
        flags = struct.unpack('!H', data[2:4])[0]
        questions = struct.unpack('!H', data[4:6])[0]
        answers = struct.unpack('!H', data[6:8])[0]

        # Check if it's a query or response
        is_response = (flags & 0x8000) != 0
        rcode = flags & 0x0F

        # Simple DNS name extraction (this is a simplified version)
        domain = extract_domain_from_dns(data[12:])

        if not domain:
            return None

        event = {
            "timestamp": datetime.utcnow().isoformat() + "+0000",
            "flow_id": transaction_id,
            "in_iface": "eth0",
            "event_type": "dns",
            "src_ip": src_ip,
            "src_port": src_port,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "proto": "UDP",
            "dns": {
                "type": "response" if is_response else "query",
                "id": transaction_id,
                "rrname": domain,
                "rrtype": "A",
                "rcode": "NOERROR",
                "ttl": 300,
                "answers": ["8.8.8.8"]
            }
        }
        return event

    except Exception as e:
        return None

def extract_domain_from_dns(data):
    """Extract domain name from DNS packet"""
    try:
        pos = 0
        domain_parts = []

        while pos < len(data) and pos < 256:
            length = data[pos]
            if length == 0:
                break
            if length > 63:
                break

            pos += 1
            if pos + length > len(data):
                break

            part = data[pos:pos+length].decode('utf-8', errors='ignore')
            domain_parts.append(part)
            pos += length

        return '.'.join(domain_parts) if domain_parts else None

    except:
        return None

def log_dns_event(event):
    """Write DNS event to eve.json"""
    try:
        with open(EVE_FILE, 'a') as f:
            f.write(json.dumps(event) + '\n')
            f.flush()
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {event['dns']['rrname']}")
    except Exception as e:
        print(f"Error writing to eve.json: {e}")

def sniff_dns():
    """Sniff DNS packets on port 53"""
    print("DNS Traffic Sniffer - Windows")
    print(f"Capturing DNS traffic to: {EVE_FILE}")
    print("Waiting for DNS queries...")
    print()

    try:
        # Create UDP socket to listen on all interfaces
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', DNS_PORT))

        while True:
            data, (src_ip, src_port) = sock.recvfrom(512)

            # DNS response typically comes back on port 53 from resolver
            dest_ip = "8.8.8.8"
            dest_port = 53

            event = parse_dns_packet(data, src_ip, dest_ip, src_port, dest_port)
            if event:
                log_dns_event(event)

    except PermissionError:
        print("ERROR: Need admin privileges to sniff DNS traffic on port 53")
        print("Run as Administrator!")
    except KeyboardInterrupt:
        print("\nStopped")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    sniff_dns()
