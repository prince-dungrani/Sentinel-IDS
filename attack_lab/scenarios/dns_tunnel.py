"""
attack_lab/scenarios/dns_tunnel.py
=====================================
DNS Tunneling Simulator — generates suspicious oversized DNS queries
MITRE: T1071.004 — DNS Application Layer Protocol
"""
import time, random, logging, socket
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from attack_lab.utils.payload_generator import PayloadGenerator
log = logging.getLogger("sentinel.attack_lab.dns")

def run(target="127.0.0.1", count=30, delay=0.5, verbose=True):
    pg = PayloadGenerator()
    results = {"sent": 0, "errors": 0}
    if verbose:
        log.info(f"[DNSTunnel] Generating {count} suspicious DNS-like queries")

    try:
        from scapy.all import DNS, DNSQR, IP, UDP, send, conf
        conf.verb = 0

        for _ in range(count):
            query = pg.generate_dns_tunnel_query()
            # Send raw UDP to port 53 (will be sniffed by IDS)
            pkt = IP(dst=target) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=query))
            send(pkt, verbose=0)
            results["sent"] += 1
            if verbose:
                log.info(f"[DNSTunnel]   Query: {query[:50]}...")
            time.sleep(delay)
    except ImportError:
        log.warning("[DNSTunnel] Scapy not available — simulating via socket")
        for _ in range(count):
            try:
                # Fallback: send UDP data to port 53
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                query = pg.generate_dns_tunnel_query().encode()
                s.sendto(query, (target, 53))
                s.close()
                results["sent"] += 1
            except Exception as e:
                results["errors"] += 1
            time.sleep(delay)

    if verbose:
        log.info(f"[DNSTunnel] Done: {results['sent']} queries sent")
    return results
