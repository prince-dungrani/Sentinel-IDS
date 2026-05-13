"""
attack_lab/launcher.py
=======================
Sentinel-IDS Attack Lab — Professional Attack Orchestrator

CLI and programmatic interface for launching attack scenarios.
Can be used standalone or called via Flask API (attack_lab.html).

Usage:
  python attack_lab/launcher.py --attack portscan --mode aggressive --count 300
  python attack_lab/launcher.py --attack ddos --mode syn --count 500
  python attack_lab/launcher.py --attack all --target 127.0.0.1
  python attack_lab/launcher.py --attack sqli --count 50

⚠️  FOR EDUCATIONAL LAB USE ONLY — LOCALHOST TARGETS ONLY
"""

import sys
import os
import time
import logging
import argparse
import threading
import json
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s][%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("sentinel.attack_lab")

# =========================================================
# Safety: only allow localhost targets
# =========================================================
SAFE_TARGETS = ["127.0.0.1", "localhost"]

def _safety_check(target: str):
    if not any(target == t or target.startswith("192.168.") for t in SAFE_TARGETS):
        print(f"\n⛔ [SAFETY BLOCK] Target '{target}' is NOT allowed.")
        print("   Only localhost (127.0.0.1) or private IPs are permitted.")
        sys.exit(1)


# =========================================================
# Attack Registry
# =========================================================
ATTACKS = {
    "portscan":    "attack_lab.scenarios.portscan",
    "synflood":    "attack_lab.scenarios.syn_flood",
    "ddos":        "attack_lab.scenarios.syn_flood",
    "sqli":        "attack_lab.scenarios.sqli_attack",
    "bruteforce":  "attack_lab.scenarios.brute_force",
    "dns":         "attack_lab.scenarios.dns_tunnel",
    "slowloris":   "attack_lab.scenarios.slowloris",
}

# =========================================================
# Session Log (for dashboard API)
# =========================================================
_session_log = []


def _log_session(attack: str, result: dict, duration: float):
    _session_log.append({
        "timestamp":   datetime.now().isoformat(),
        "attack_type": attack,
        "result":      result,
        "duration":    round(duration, 2),
    })
    if len(_session_log) > 100:
        _session_log.pop(0)


def get_session_log():
    return list(_session_log)


# =========================================================
# Core Launch Function
# =========================================================
def launch(attack: str, target: str = "127.0.0.1",
           mode: str = "default", count: int = 200,
           port: int = 5001, duration: int = 30,
           verbose: bool = True) -> dict:
    """
    Launch a single attack scenario.

    Args:
        attack:   Attack name (portscan/synflood/sqli/bruteforce/dns/slowloris)
        target:   Target IP (must be localhost or private)
        mode:     Attack mode (syn/connect/aggressive/http)
        count:    Number of packets/requests
        port:     Target port
        duration: Duration in seconds (for slowloris)
        verbose:  Print progress

    Returns:
        dict with results
    """
    _safety_check(target)

    attack = attack.lower().strip()
    if attack not in ATTACKS:
        return {"error": f"Unknown attack: {attack}. Valid: {list(ATTACKS.keys())}"}

    module_name = ATTACKS[attack]
    log.info(f"\n{'='*55}")
    log.info(f"  🚨 LAUNCHING: {attack.upper()}")
    log.info(f"  Target: {target}:{port} | Mode: {mode} | Count: {count}")
    log.info(f"{'='*55}")

    start = time.time()
    result = {}

    try:
        import importlib
        module = importlib.import_module(module_name)

        if attack == "portscan":
            result = module.run(mode=mode, target=target, port_count=count, verbose=verbose)
        elif attack in ("synflood", "ddos"):
            result = module.run(mode=mode, target=target, port=port, count=count, verbose=verbose)
        elif attack == "sqli":
            result = module.run(target=target, port=port, count=count, verbose=verbose)
        elif attack == "bruteforce":
            result = module.run(target=target, port=port, count=count, verbose=verbose)
        elif attack == "dns":
            result = module.run(target=target, count=count, verbose=verbose)
        elif attack == "slowloris":
            result = module.run(target=target, port=port, connections=min(count, 100),
                                duration=duration, verbose=verbose)

        elapsed = time.time() - start
        result["attack"] = attack
        result["mode"] = mode
        result["target"] = target
        result["duration_s"] = round(elapsed, 2)
        result["timestamp"] = datetime.now().isoformat()

        _log_session(attack, result, elapsed)

        log.info(f"\n✅ {attack.upper()} complete in {elapsed:.2f}s | Result: {result}")

    except Exception as e:
        result = {"error": str(e), "attack": attack}
        log.error(f"[Launcher] Attack failed: {e}")

    return result


def launch_all(target: str = "127.0.0.1", port: int = 5001,
               verbose: bool = True) -> dict:
    """Launch all attack scenarios sequentially."""
    _safety_check(target)

    log.info("\n🔥 LAUNCHING ALL ATTACK SCENARIOS")
    log.info(f"   Target: {target}:{port}")
    log.info("=" * 55)

    results = {}

    scenarios = [
        ("portscan",   {"mode": "connect", "count": 100}),
        ("sqli",       {"count": 20}),
        ("bruteforce", {"count": 30}),
        ("synflood",   {"mode": "syn",  "count": 200}),
        ("dns",        {"count": 15}),
        ("slowloris",  {"count": 20, "duration": 10}),
    ]

    for attack, kwargs in scenarios:
        log.info(f"\n[{attack.upper()}] Starting...")
        result = launch(attack, target=target, port=port, verbose=verbose, **kwargs)
        results[attack] = result
        time.sleep(1)

    log.info("\n✅ ALL ATTACKS COMPLETE")
    return results


# =========================================================
# CLI Entry Point
# =========================================================
def main():
    parser = argparse.ArgumentParser(
        description="Sentinel-IDS Attack Lab Launcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python attack_lab/launcher.py --attack portscan --mode aggressive --count 300
  python attack_lab/launcher.py --attack synflood --count 500
  python attack_lab/launcher.py --attack sqli --count 50
  python attack_lab/launcher.py --attack all
        """
    )
    parser.add_argument("--attack",   default="all",      help="Attack type (portscan/synflood/sqli/bruteforce/dns/slowloris/all)")
    parser.add_argument("--target",   default="127.0.0.1",help="Target IP (localhost only)")
    parser.add_argument("--port",     default=5001, type=int, help="Target port")
    parser.add_argument("--mode",     default="connect",  help="Attack mode (connect/syn/aggressive/http)")
    parser.add_argument("--count",    default=200,  type=int, help="Number of packets/requests")
    parser.add_argument("--duration", default=30,   type=int, help="Duration in seconds (slowloris)")
    parser.add_argument("--quiet",    action="store_true",    help="Suppress verbose output")

    args = parser.parse_args()

    print("\n" + "=" * 55)
    print("  🛡️  SENTINEL-IDS ATTACK LAB")
    print("  ⚠️   FOR EDUCATIONAL/LAB USE ONLY")
    print("  Target validation: LOCALHOST ONLY")
    print("=" * 55 + "\n")

    _safety_check(args.target)

    if args.attack == "all":
        launch_all(target=args.target, port=args.port, verbose=not args.quiet)
    else:
        launch(
            attack=args.attack,
            target=args.target,
            mode=args.mode,
            count=args.count,
            port=args.port,
            duration=args.duration,
            verbose=not args.quiet,
        )


if __name__ == "__main__":
    main()
