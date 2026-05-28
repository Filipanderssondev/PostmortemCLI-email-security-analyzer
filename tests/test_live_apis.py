#!/usr/bin/env python3
"""
tests/test_live_apis.py
Live API connectivity test — requires network access and API keys.

Usage:
    export $(grep -v '^#' ~/.postmortemcli/.env | grep -v '^$' | xargs)
    python3 tests/test_live_apis.py

Note: Run from project root directory.
"""

import sys
import os
import dns.resolver

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.analyzer import (
    _urlhaus, _malwarebazaar, _threatfox,
    _abuseipdb, _virustotal_url, _virustotal_hash,
    _google_safe_browsing, _dnsbl
)

PASS = "\033[92m[OK  ]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
INFO = "\033[94m[INFO]\033[0m"

results = []

def check(name, ok, detail=''):
    symbol = PASS if ok else FAIL
    print(f"{symbol} {name:<30} {detail}")
    results.append((name, ok))


print()
print("=== PostmortemCLI — Live API Test ===")
print()

# 1. Spamhaus ZEN
try:
    dns.resolver.resolve('2.0.0.127.zen.spamhaus.org', 'A', lifetime=5)
    check('Spamhaus ZEN', True, 'listed IP 127.0.0.2 detected correctly')
except Exception as e:
    check('Spamhaus ZEN', False, str(e))

# 2. Spamhaus DBL
try:
    dns.resolver.resolve('test.dbl.spamhaus.org', 'A', lifetime=5)
    check('Spamhaus DBL', True, 'reachable')
except Exception as e:
    check('Spamhaus DBL', False, str(e))

# 3. URLhaus — known malware URL
try:
    r = _urlhaus('http://182.127.81.175:38715/bin.sh')
    check('URLhaus', r, f'known malware URL hit={r}')
except Exception as e:
    check('URLhaus', False, str(e))

# 4. MalwareBazaar — API connectivity (hash_not_found is a valid response)
try:
    import requests
    key = os.environ.get('ABUSE_CH_API_KEY', '')
    r = requests.post(
        'https://mb-api.abuse.ch/api/v1/',
        data={'query': 'get_info', 'hash': 'a' * 64},
        headers={'Auth-Key': key} if key else {},
        timeout=5
    )
    ok = r.status_code == 200 and r.json().get('query_status') in ('ok', 'hash_not_found', 'no_results')
    check('MalwareBazaar', ok, f'status={r.json().get("query_status")}')
except Exception as e:
    check('MalwareBazaar', False, str(e))

# 5. ThreatFox — IOC lookup
try:
    import requests
    key = os.environ.get('ABUSE_CH_API_KEY', '')
    r = requests.post(
        'https://threatfox-api.abuse.ch/api/v1/',
        json={'query': 'search_ioc', 'search_term': '195.123.226.84'},
        headers={'Auth-Key': key} if key else {},
        timeout=5
    )
    ok = r.status_code == 200 and r.json().get('query_status') in ('ok', 'no_results', 'no_result')
    check('ThreatFox', ok, f'status={r.json().get("query_status")}')
except Exception as e:
    check('ThreatFox', False, str(e))

# 6. AbuseIPDB
try:
    score = _abuseipdb('8.8.8.8')
    check('AbuseIPDB', score != -1, f'score={score}/100 for 8.8.8.8')
except Exception as e:
    check('AbuseIPDB', False, str(e))

# 7. VirusTotal URL
try:
    r = _virustotal_url('https://www.google.com')
    check('VirusTotal URL', r is not None, f'engines={r.get("total") if r else "N/A"}')
except Exception as e:
    check('VirusTotal URL', False, str(e))

# 8. VirusTotal hash
try:
    r = _virustotal_hash('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f')
    check('VirusTotal hash', r is not None, f'engines={r.get("total") if r else "N/A"}')
except Exception as e:
    check('VirusTotal hash', False, str(e))

# 9. Google Safe Browsing
try:
    r = _google_safe_browsing(['https://www.google.com'])
    check('Google SafeBrowsing', r is not None, '0 threats for google.com')
except Exception as e:
    check('Google SafeBrowsing', False, str(e))

# EmailRep — pending approval
print(f"{INFO} {'EmailRep':<30} pending manual approval from emailrep.io")

# Summary
print()
passed = sum(1 for _, ok in results if ok)
failed = sum(1 for _, ok in results if not ok)
total  = len(results)

print(f"{'='*56}")
print(f"  Results: {passed}/{total} passed", end="")
if failed:
    print(f"  |  {failed} FAILED:")
    for name, ok in results:
        if not ok:
            print(f"    ✗  {name}")
else:
    print("  — all sources reachable")
print(f"{'='*56}")
print()

sys.exit(0 if failed == 0 else 1)