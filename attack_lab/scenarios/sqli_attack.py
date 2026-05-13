"""
attack_lab/scenarios/sqli_attack.py
=====================================
SQL Injection Attack Simulator

Sends realistic SQLi payloads to vulnerable target endpoints.
Triggers: Signature Engine (regex rules) + XSS rule variants.
MITRE: T1190 — Exploit Public-Facing Application
"""
import time
import random
import logging
import urllib.request
import urllib.parse
import urllib.error
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from attack_lab.utils.payload_generator import PayloadGenerator

log = logging.getLogger("sentinel.attack_lab.sqli")

def run(target: str = "127.0.0.1", port: int = 5001,
        count: int = 30, delay: float = 0.3, verbose: bool = True) -> dict:
    base = f"http://{target}:{port}"
    results = {"sent": 0, "errors": 0, "payloads_used": []}
    pg = PayloadGenerator()

    endpoints = [
        ("/login",  "user", pg.SQL_PAYLOADS),
        ("/search", "q",    pg.SQL_PAYLOADS),
        ("/",       "search", pg.SQL_PAYLOADS),
        ("/",       "q",    pg.XSS_PAYLOADS),
        ("/",       "cmd",  pg.CMD_PAYLOADS),
    ]

    if verbose:
        log.info(f"[SQLi] Starting SQLi/XSS attack → {base} | {count} requests")

    for i in range(count):
        endpoint, param, payloads = random.choice(endpoints)
        payload = random.choice(payloads)
        encoded = urllib.parse.quote(payload)
        url = f"{base}{endpoint}?{param}={encoded}"

        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": random.choice([
                    "sqlmap/1.7.8#stable",
                    "Mozilla/5.0 (compatible; Googlebot)",
                    "python-requests/2.28.0",
                    "curl/7.85.0",
                ])
            })
            urllib.request.urlopen(req, timeout=2)
            results["sent"] += 1
            results["payloads_used"].append(payload[:30])
            if verbose:
                log.info(f"[SQLi]   → {endpoint}?{param}={payload[:30]}...")
        except urllib.error.HTTPError:
            results["sent"] += 1  # 4xx/5xx is fine — IDS saw the packet
        except Exception as e:
            results["errors"] += 1
            log.debug(f"[SQLi] Error: {e}")

        time.sleep(delay)

    if verbose:
        log.info(f"[SQLi] Done: {results['sent']} sent, {results['errors']} errors")
    return results
