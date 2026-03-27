"""
DNS Twist Integration - Phishing/Typosquatting Detection
Uses dnstwist to detect lookalike domains for phishing detection.

When a suspicious domain is detected (e.g., cache poisoning), this module
finds similar legitimate domains to alert users about potential phishing.
"""

import asyncio
import subprocess
import json
import re
from typing import List, Dict, Optional, Tuple
from functools import lru_cache
from datetime import datetime, timedelta

# Common legitimate domains that we want to protect
# Maps base domain to organization name
PROTECTED_DOMAINS = {
    # Education
    "gitam.edu": "GITAM University",
    "iitb.ac.in": "IIT Bombay",
    "iitd.ac.in": "IIT Delhi",
    "iisc.ac.in": "IISc Bangalore",
    "bits-pilani.ac.in": "BITS Pilani",
    "vit.ac.in": "VIT University",
    "manipal.edu": "Manipal University",
    "amity.edu": "Amity University",
    
    # Banking - India
    "sbi.co.in": "State Bank of India",
    "hdfcbank.com": "HDFC Bank",
    "icicibank.com": "ICICI Bank",
    "axisbank.com": "Axis Bank",
    "kotak.com": "Kotak Mahindra Bank",
    "pnb.co.in": "Punjab National Bank",
    
    # Banking - Global
    "chase.com": "JPMorgan Chase",
    "bankofamerica.com": "Bank of America",
    "wellsfargo.com": "Wells Fargo",
    "citi.com": "Citibank",
    "hsbc.com": "HSBC",
    
    # Payment/Finance
    "paypal.com": "PayPal",
    "paytm.com": "Paytm",
    "razorpay.com": "Razorpay",
    "phonepe.com": "PhonePe",
    "gpay.com": "Google Pay",
    "stripe.com": "Stripe",
    
    # Tech Giants
    "google.com": "Google",
    "microsoft.com": "Microsoft",
    "apple.com": "Apple",
    "amazon.com": "Amazon",
    "facebook.com": "Meta/Facebook",
    "instagram.com": "Instagram",
    "twitter.com": "Twitter/X",
    "linkedin.com": "LinkedIn",
    "github.com": "GitHub",
    
    # E-commerce India
    "flipkart.com": "Flipkart",
    "myntra.com": "Myntra",
    "swiggy.com": "Swiggy",
    "zomato.com": "Zomato",
    "amazon.in": "Amazon India",
    "bigbasket.com": "BigBasket",
    "nykaa.com": "Nykaa",
    
    # Government
    "gov.in": "Government of India",
    "nic.in": "National Informatics Centre",
    "irctc.co.in": "IRCTC Railways",
    "incometax.gov.in": "Income Tax India",
}

# Cache for dnstwist results (domain -> (timestamp, results))
_twist_cache: Dict[str, Tuple[datetime, List[Dict]]] = {}
CACHE_TTL = timedelta(hours=1)


def _extract_base_domain(domain: str) -> str:
    """Extract base domain from full domain (removes subdomains)"""
    parts = domain.lower().rstrip('.').split('.')
    if len(parts) >= 2:
        # Handle .co.in, .ac.in, .gov.in type TLDs
        if len(parts) >= 3 and parts[-2] in ('co', 'ac', 'gov', 'org', 'edu', 'net'):
            return '.'.join(parts[-3:])
        return '.'.join(parts[-2:])
    return domain


def _similarity_score(domain1: str, domain2: str) -> float:
    """Calculate similarity between two domains (0-1)"""
    d1 = domain1.lower().replace('.', '')
    d2 = domain2.lower().replace('.', '')
    
    if d1 == d2:
        return 1.0
    
    # Levenshtein-like simple distance
    max_len = max(len(d1), len(d2))
    if max_len == 0:
        return 0.0
    
    matches = sum(c1 == c2 for c1, c2 in zip(d1, d2))
    return matches / max_len


def find_matching_legitimate_domain(suspicious_domain: str) -> Optional[Tuple[str, str, float]]:
    """
    Check if a suspicious domain looks like a typosquat of a protected domain.
    
    Returns: (legitimate_domain, org_name, similarity_score) or None
    """
    base = _extract_base_domain(suspicious_domain)
    sus_clean = base.replace('.', '').replace('-', '')
    
    best_match = None
    best_score = 0.0
    
    for legit_domain, org_name in PROTECTED_DOMAINS.items():
        legit_clean = legit_domain.replace('.', '').replace('-', '')
        
        # Skip if this IS the legitimate domain (exact match)
        if base.lower() == legit_domain.lower():
            return None
        
        # Direct similarity
        score = _similarity_score(sus_clean, legit_clean)
        
        # Check for common typosquatting patterns
        patterns = [
            (sus_clean, legit_clean),  # Direct match
            (sus_clean.replace('0', 'o'), legit_clean),  # 0 -> o
            (sus_clean.replace('1', 'l'), legit_clean),  # 1 -> l
            (sus_clean.replace('1', 'i'), legit_clean),  # 1 -> i
            (sus_clean.replace('rn', 'm'), legit_clean),  # rn -> m
            (sus_clean.replace('vv', 'w'), legit_clean),  # vv -> w
        ]
        
        for sus_var, leg_var in patterns:
            if sus_var == leg_var:
                score = 0.95
                break
        
        # Check if it contains the legitimate domain name
        if legit_clean in sus_clean or sus_clean in legit_clean:
            score = max(score, 0.8)
        
        if score > best_score and score >= 0.6:
            best_score = score
            best_match = (legit_domain, org_name, score)
    
    return best_match


async def run_dnstwist(domain: str, timeout: int = 30) -> List[Dict]:
    """
    Run dnstwist on a domain to find lookalike domains.
    
    Returns list of lookalike domains with their details.
    """
    # Check cache first
    if domain in _twist_cache:
        cached_time, cached_results = _twist_cache[domain]
        if datetime.now() - cached_time < CACHE_TTL:
            return cached_results
    
    try:
        # Run dnstwist with JSON output
        proc = await asyncio.create_subprocess_exec(
            'python', '-m', 'dnstwist',
            '--format', 'json',
            '--registered',  # Only show registered domains
            domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=timeout
        )
        
        if proc.returncode == 0 and stdout:
            results = json.loads(stdout.decode())
            # Filter to only include active/registered domains
            active = [
                r for r in results 
                if r.get('dns_a') or r.get('dns_aaaa') or r.get('dns_mx')
            ]
            _twist_cache[domain] = (datetime.now(), active)
            return active
        
    except asyncio.TimeoutError:
        print(f"[dnstwist] Timeout scanning {domain}")
    except FileNotFoundError:
        print("[dnstwist] dnstwist not installed or not in PATH")
    except json.JSONDecodeError:
        print(f"[dnstwist] Invalid JSON output for {domain}")
    except Exception as e:
        print(f"[dnstwist] Error scanning {domain}: {e}")
    
    return []


async def check_phishing_domain(domain: str) -> Dict:
    """
    Check if a domain is potentially a phishing/typosquat domain.
    
    Returns detection result with:
    - is_phishing: bool
    - original_domain: str (legitimate domain being spoofed)
    - original_org: str (organization name)
    - confidence: float
    - fuzzer_type: str (type of typosquat)
    - details: dict (additional info)
    """
    result = {
        "domain": domain,
        "is_phishing": False,
        "original_domain": None,
        "original_org": None,
        "confidence": 0.0,
        "fuzzer_type": None,
        "details": {}
    }
    
    # Quick check against known protected domains
    match = find_matching_legitimate_domain(domain)
    if match:
        legit_domain, org_name, score = match
        
        # Skip if it's actually the legitimate domain
        base = _extract_base_domain(domain)
        if base == legit_domain:
            return result
        
        result.update({
            "is_phishing": True,
            "original_domain": legit_domain,
            "original_org": org_name,
            "confidence": score,
            "fuzzer_type": "lookalike",
            "details": {
                "detected_by": "pattern_matching",
                "similarity": round(score, 3)
            }
        })
        return result
    
    # For unknown domains, try running dnstwist to find if this domain
    # appears in the permutation list of any protected domain
    base = _extract_base_domain(domain)
    
    # Check if this domain could be a typosquat of a protected domain
    for legit_domain, org_name in PROTECTED_DOMAINS.items():
        twist_results = await run_dnstwist(legit_domain)
        
        for perm in twist_results:
            if perm.get('domain', '').lower() == base.lower():
                result.update({
                    "is_phishing": True,
                    "original_domain": legit_domain,
                    "original_org": org_name,
                    "confidence": 0.85,
                    "fuzzer_type": perm.get('fuzzer', 'unknown'),
                    "details": {
                        "detected_by": "dnstwist",
                        "dns_a": perm.get('dns_a', []),
                        "dns_mx": perm.get('dns_mx', []),
                    }
                })
                return result
    
    return result


def get_common_typosquats(domain: str) -> List[str]:
    """
    Generate common typosquat variations of a domain without running dnstwist.
    Useful for quick inline checks.
    """
    base = domain.lower().rstrip('.')
    parts = base.split('.')
    if len(parts) < 2:
        return []
    
    name = parts[0]
    tld = '.'.join(parts[1:])
    
    variations = []
    
    # Character substitutions
    subs = {
        'o': '0', '0': 'o',
        'l': '1', '1': 'l', 'i': '1',
        'a': '4', '4': 'a',
        'e': '3', '3': 'e',
        's': '5', '5': 's',
        'm': 'rn', 'rn': 'm',
        'w': 'vv', 'vv': 'w',
    }
    
    for old, new in subs.items():
        if old in name:
            variations.append(name.replace(old, new) + '.' + tld)
    
    # Missing character
    for i in range(len(name)):
        variations.append(name[:i] + name[i+1:] + '.' + tld)
    
    # Adjacent swap
    for i in range(len(name) - 1):
        swapped = name[:i] + name[i+1] + name[i] + name[i+2:]
        variations.append(swapped + '.' + tld)
    
    # Double character
    for i in range(len(name)):
        variations.append(name[:i] + name[i] + name[i:] + '.' + tld)
    
    # Different TLD
    alt_tlds = ['.com', '.net', '.org', '.co', '.io', '.in', '.edu']
    for alt in alt_tlds:
        if alt != '.' + tld:
            variations.append(name + alt)
    
    return list(set(variations))[:50]


# Quick test
if __name__ == "__main__":
    import asyncio
    
    async def test():
        # Test pattern matching
        test_domains = [
            "gitamedu.com",      # Typosquat of gitam.edu
            "g1tam.edu",         # 1 instead of i
            "paypall.com",       # Double l
            "amazom.com",        # m instead of n
            "flipkart.com",      # Legitimate
            "google.com",        # Legitimate
            "g00gle.com",        # 0s instead of o
            "faceb00k.com",      # 0s instead of o
        ]
        
        for domain in test_domains:
            result = await check_phishing_domain(domain)
            if result["is_phishing"]:
                print(f"⚠️  {domain}")
                print(f"   → Original: {result['original_domain']} ({result['original_org']})")
                print(f"   → Confidence: {result['confidence']:.0%}")
                print(f"   → Type: {result['fuzzer_type']}")
            else:
                print(f"✓  {domain} - OK")
            print()
    
    asyncio.run(test())
