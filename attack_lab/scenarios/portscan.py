"""
attack_lab/scenarios/portscan.py
==================================
Professional Port Scan Attack Simulator

Simulates:
  1. TCP SYN Scan (half-open / stealth scan)
  2. Full TCP Connect Scan
  3. Aggressive Multi-port Scan

Uses both Scapy (for raw SYN packets) and socket (for connect scan).
Spoofed source ports randomized for realism.

⚠️  FOR LOCALHOST LAB USE ONLY
"""

import time
import socket
import random
import logging
import threading

log = logging.getLogger("sentinel.attack_lab.portscan")

# Safety: only allow localhost/private targets
ALLOWED_TARGETS = ["127.0.0.1", "localhost", "192.168."]


def _safety_check(target: str):
    allowed = any(target.startswith(a) or target == a for a in ALLOWED_TARGETS)
    if not allowed:
        raise ValueError(f"[SAFETY] Target {target} is not localhost/private. Blocked.")


# =========================================================
# TCP Connect Scan (no Scapy required)
# =========================================================
def tcp_connect_scan(target: str = "127.0.0.1",
                     ports: list = None,
                     delay: float = 0.01,
                     verbose: bool = True) -> dict:
    """
    Full TCP connect scan. IDS detects via:
    - Large number of connection attempts to different ports
    - RST responses
    - Port scan heuristic (unique_dst_ports > threshold)
    """
    _safety_check(target)

    if ports is None:
        # CICIDS-style scan: mix of common + sequential ports
        ports = list(range(1, 1025)) + [1433, 3306, 3389, 5432, 6379, 8080, 8443, 27017]
        random.shuffle(ports)

    results = {"open": [], "closed": [], "filtered": [], "total_scanned": 0}

    if verbose:
        log.info(f"[PortScan] Starting TCP connect scan → {target} ({len(ports)} ports)")

    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            result = s.connect_ex((target, port))
            s.close()
            if result == 0:
                results["open"].append(port)
                if verbose:
                    log.info(f"[PortScan]   OPEN: {target}:{port}")
            else:
                results["closed"].append(port)
        except Exception:
            results["filtered"].append(port)
        finally:
            results["total_scanned"] += 1

        time.sleep(delay)

    if verbose:
        log.info(f"[PortScan] Scan complete: {len(results['open'])} open, "
                 f"{len(results['closed'])} closed, "
                 f"{len(results['filtered'])} filtered")

    return results


# =========================================================
# SYN Scan (requires Scapy + admin/npcap)
# =========================================================
def syn_scan(target: str = "127.0.0.1",
             ports: list = None,
             count: int = 200,
             delay: float = 0.005,
             verbose: bool = True) -> dict:
    """
    Raw SYN scan using Scapy. Sends SYN packets without completing handshake.
    IDS detects via:
    - High SYN count with no ACK responses
    - Unique destination ports exceeding threshold
    - Port scan ML model activation
    """
    _safety_check(target)

    try:
        from scapy.all import IP, TCP, sr1, conf
        conf.verb = 0
    except ImportError:
        log.warning("[PortScan] Scapy not available, falling back to connect scan")
        return tcp_connect_scan(target, ports, delay, verbose)

    if ports is None:
        ports = random.sample(range(1, 10000), min(count, 9999))

    results = {"open": [], "closed": [], "total_sent": 0}

    if verbose:
        log.info(f"[PortScan] Starting SYN scan → {target} ({len(ports)} ports)")

    for port in ports:
        try:
            pkt = IP(dst=target) / TCP(
                dport=port,
                sport=random.randint(1024, 65534),
                flags="S",
                seq=random.randint(1000, 999999)
            )
            resp = sr1(pkt, timeout=0.1, verbose=0)
            if resp and resp.haslayer(TCP):
                if resp[TCP].flags == 0x12:  # SYN-ACK → port open
                    results["open"].append(port)
                    # Send RST to be polite
                    from scapy.all import send
                    send(IP(dst=target) / TCP(dport=port, flags="R"), verbose=0)
                elif resp[TCP].flags & 0x04:  # RST → port closed
                    results["closed"].append(port)
        except Exception as e:
            log.debug(f"[PortScan] SYN error on port {port}: {e}")
        finally:
            results["total_sent"] += 1

        time.sleep(delay)

    if verbose:
        log.info(f"[PortScan] SYN scan complete: {len(results['open'])} open")
    return results


# =========================================================
# Aggressive Scan (high speed for ML detection)
# =========================================================
def aggressive_scan(target: str = "127.0.0.1",
                    port_count: int = 500,
                    threads: int = 20,
                    verbose: bool = True) -> dict:
    """
    Multi-threaded aggressive scan designed to trigger ML detection.
    Scans many ports quickly → generates CICIDS-compatible flow features.
    """
    _safety_check(target)

    ports = list(range(1, port_count + 1))
    random.shuffle(ports)
    results = {"scanned": 0, "open": []}
    lock = threading.Lock()

    def scan_chunk(chunk):
        for port in chunk:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.05)
                if s.connect_ex((target, port)) == 0:
                    with lock:
                        results["open"].append(port)
                s.close()
            except Exception:
                pass
            finally:
                with lock:
                    results["scanned"] += 1

    chunk_size = len(ports) // threads + 1
    chunks = [ports[i:i+chunk_size] for i in range(0, len(ports), chunk_size)]

    if verbose:
        log.info(f"[PortScan] Aggressive scan → {target} | {port_count} ports | {threads} threads")

    workers = []
    for chunk in chunks:
        t = threading.Thread(target=scan_chunk, args=(chunk,))
        t.daemon = True
        t.start()
        workers.append(t)

    for w in workers:
        w.join(timeout=30)

    if verbose:
        log.info(f"[PortScan] Aggressive scan done: {results['scanned']} scanned, "
                 f"{len(results['open'])} open")
    return results


def run(mode: str = "connect", target: str = "127.0.0.1",
        port_count: int = 200, verbose: bool = True):
    """Entry point for attack launcher."""
    if mode == "syn":
        return syn_scan(target, count=port_count, verbose=verbose)
    elif mode == "aggressive":
        return aggressive_scan(target, port_count=port_count, verbose=verbose)
    else:
        ports = list(range(1, port_count + 1))
        random.shuffle(ports)
        return tcp_connect_scan(target, ports=ports[:port_count], verbose=verbose)
