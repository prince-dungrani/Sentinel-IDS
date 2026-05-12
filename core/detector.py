"""
core/detector.py
================
Sentinel-IDS — Triple-Engine Detection Pipeline

Detection Engines:
  A. Signature Engine  — JSON rules + Suricata rule compatibility
  B. Heuristic Engine  — Behavior-based anomaly detection
  C. ML Engine         — Hybrid RandomForest + IsolationForest

Flow:
  features -> [Engine A] -> [Engine B] -> [Engine C] -> AlertManager -> log
"""

import os
import time
import json
import re
import uuid
import logging
from datetime import datetime
from collections import defaultdict

from core.alert_manager import AlertManager
from core import ml_engine

log = logging.getLogger("sentinel.detector")

# =========================================================
# Rule File Paths
# =========================================================
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RULES_FILE = os.path.join(BASE_DIR, "data", "rules.json")
SURICATA_FILE = os.path.join(BASE_DIR, "data", "suricata.rules")
CONFIG_FILE = os.path.join(BASE_DIR, "config", "config.json")

# =========================================================
# Rule Storage (module-level for process-lifetime caching)
# =========================================================
RULES = []
_last_rules_mtime = 0.0

# =========================================================
# Global AlertManager instance (per-process singleton)
# =========================================================
_alert_manager = AlertManager(
    rate_limit_window=10,
    max_alerts_per_window=5,
    escalation_threshold=3,
    escalation_window=60
)


# =========================================================
# Config Loader
# =========================================================
def _load_config() -> dict:
    try:
        with open(CONFIG_FILE) as f:
            return json.load(f)
    except Exception:
        return {
            "syn_flood_threshold": 50,
            "port_scan_threshold": 15,
            "icmp_flood_threshold": 30,
            "suspicious_ports": [22, 23, 445],
            "alert_rate_limit": 5,
        }


CONFIG = _load_config()


# =========================================================
# Suricata Rule Parser
# =========================================================
def _load_suricata_rules(filepath: str):
    """Parse Suricata-format .rules file into internal rule dict format."""
    if not os.path.exists(filepath):
        return []
    rules = []
    with open(filepath, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                header, options = line.split("(", 1)
                options = options.rstrip(")")
                parts = header.split()
                if len(parts) < 7:
                    continue

                protocol = parts[1].upper()
                dst_port_str = parts[6]

                rule = {
                    "name": "Suricata Rule",
                    "severity": "HIGH",
                    "group": "Suricata",
                    "protocol": protocol,
                    "threshold": 1,
                    "status": "enabled",
                }

                if dst_port_str.isdigit():
                    rule["port"] = int(dst_port_str)

                for opt in options.split(";"):
                    opt = opt.strip()
                    if not opt:
                        continue
                    if ":" in opt:
                        key, val = opt.split(":", 1)
                        key = key.strip()
                        val = val.strip().strip('"')
                        if key == "msg":
                            rule["name"] = val
                        elif key == "content":
                            rule["content"] = val
                        elif key == "sid":
                            rule["sid"] = val
                    elif opt == "nocase":
                        rule["nocase"] = True

                rules.append(rule)
            except Exception:
                pass
    return rules


# =========================================================
# Dynamic Rule Reloader (hot-reload without restart)
# =========================================================
def _reload_rules_if_needed():
    global RULES, _last_rules_mtime
    try:
        mtime = os.path.getmtime(RULES_FILE)
        if mtime > _last_rules_mtime:
            with open(RULES_FILE) as f:
                loaded = json.load(f)
            RULES = [r for r in loaded if r.get("status", "enabled").lower() != "disabled"]
            RULES += _load_suricata_rules(SURICATA_FILE)
            _last_rules_mtime = mtime
            log.info(f"[Detector] Rules hot-reloaded — {len(RULES)} rules active.")
    except Exception as e:
        log.debug(f"[Detector] Rule reload skipped: {e}")


# =========================================================
# Heuristic Flow Tracking State
# =========================================================
_packet_count: dict = defaultdict(int)
_port_access: dict = defaultdict(set)
_last_seen: dict = defaultdict(float)
_rule_hits: dict = defaultdict(int)

# Time window for heuristic analysis (seconds)
TIME_WINDOW = 10


# =========================================================
# Alert Object Factory
# =========================================================
def _create_alert(features: dict, attack_type: str, severity: str,
                  rule_name: str, engine_name: str) -> dict:
    """
    Create a standardized alert dict with all enterprise fields.
    """
    payload = str(features.get("payload", features.get("reassembled_payload", "")))
    preview = payload[:100] + "..." if len(payload) > 100 else payload

    return {
        "id": f"ALERT-{str(uuid.uuid4())[:8].upper()}",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "traffic_type": "MALICIOUS" if severity.upper() in ["HIGH", "CRITICAL"] else "SUSPICIOUS",
        "attack_type": attack_type,
        "severity": severity,
        "src_ip": features.get("src_ip", "Unknown"),
        "dst_ip": features.get("dst_ip", "Unknown"),
        "src_port": features.get("src_port", "*"),
        "dst_port": features.get("dst_port", "*"),
        "protocol": features.get("protocol", "Unknown"),
        "packet_size": features.get("packet_size", len(payload)),
        "flags": features.get("flags", ""),
        "status": "ACTIVE",
        "rule": rule_name,
        "payload_preview": preview,
        "engine": engine_name,
        # These fields are enriched by AlertManager:
        "risk_score": 0,
        "mitre_tactic": "",
        "mitre_technique": "",
        "mitre_technique_name": "",
        "hit_count": 1,
        "engines_triggered": [engine_name],
        "ml_confidence": 0.0,
        "ml_label": "N/A",
        "ml_top_features": [],
    }


# =========================================================
# Engine A — Signature Rule Matching
# =========================================================
def _match_rule(features: dict, rule: dict) -> bool:
    """Returns True if packet features match a given rule definition."""
    proto = features.get("protocol")
    dst_port = features.get("dst_port")

    if rule.get("protocol") and proto != rule["protocol"]:
        return False
    if "port" in rule and dst_port != rule["port"]:
        return False
    if "ports" in rule and dst_port not in rule["ports"]:
        return False

    target_field = rule.get("field", "payload")
    if target_field == "payload" and "reassembled_payload" in features:
        value = str(features["reassembled_payload"])
    else:
        value = str(features.get(target_field, ""))

    if "content" in rule:
        check = rule["content"].lower() if rule.get("nocase") else rule["content"]
        haystack = value.lower() if rule.get("nocase") else value
        if check not in haystack:
            return False

    if "regex" in rule:
        flags = re.IGNORECASE if rule.get("nocase") else 0
        if not re.search(rule["regex"], value, flags):
            return False

    if "length_gt" in rule and len(value) <= rule["length_gt"]:
        return False

    return True


def _run_signature_engine(features: dict) -> list:
    """Engine A: Match features against all loaded rules."""
    alerts = []
    for rule in RULES:
        if _match_rule(features, rule):
            _rule_hits[rule["name"]] += 1
            if _rule_hits[rule["name"]] >= rule.get("threshold", 1):
                alert = _create_alert(
                    features,
                    rule.get("group", "Signature"),
                    rule.get("severity", "MEDIUM"),
                    rule["name"],
                    "Signature Engine"
                )
                alerts.append(alert)
    return alerts


# =========================================================
# Engine B — Heuristic Behavior Analysis
# =========================================================
def _run_heuristic_engine(features: dict) -> list:
    """Engine B: Detect behavioral anomalies through flow analysis."""
    alerts = []
    src_ip = features.get("src_ip", "Unknown")
    dst_port = features.get("dst_port")
    flags = features.get("flags", "")
    now = time.time()

    syn_thresh = CONFIG.get("syn_flood_threshold", 50)
    port_thresh = CONFIG.get("port_scan_threshold", 15)
    susp_ports = CONFIG.get("suspicious_ports", [22, 23, 445])

    # Reset flow counters after time window
    if now - _last_seen[src_ip] > TIME_WINDOW:
        _packet_count[src_ip] = 0
        _port_access[src_ip].clear()

    _last_seen[src_ip] = now
    _packet_count[src_ip] += 1
    if dst_port:
        _port_access[src_ip].add(dst_port)

    # SYN Flood Detection
    if _packet_count[src_ip] > syn_thresh and flags == "S":
        alerts.append(_create_alert(features, "SYN Flood", "HIGH",
                                    "Possible SYN Flood", "Heuristic Engine"))

    # Port Scan Detection
    if len(_port_access[src_ip]) > port_thresh:
        alerts.append(_create_alert(features, "Port Scan", "MEDIUM",
                                    "Possible Port Scan", "Heuristic Engine"))

    # Suspicious Port Access
    if dst_port in susp_ports:
        alerts.append(_create_alert(features, "Suspicious Access", "HIGH",
                                    f"Access to sensitive port {dst_port}",
                                    "Heuristic Engine"))

    # DNS Tunneling Detection
    if dst_port == 53:
        dns_query = features.get("dns_query", "")
        if len(dns_query) > 50:
            alerts.append(_create_alert(features, "DNS Tunneling", "MEDIUM",
                                        "DNS query length anomaly", "Heuristic Engine"))

    return alerts


# =========================================================
# Engine C — ML Inference
# =========================================================
def _run_ml_engine(features: dict) -> tuple[list, dict]:
    """
    Engine C: Run ML inference and generate alert if triggered.
    Returns (alerts_list, ml_result_dict).
    ml_result is passed to AlertManager for confidence fusion.
    """
    try:
        ml_result = ml_engine.predict(features)
    except Exception as e:
        log.debug(f"[Detector] ML prediction error: {e}")
        return [], {"ml_triggered": False, "ml_confidence": 0.0}

    alerts = []
    if ml_result.get("ml_triggered"):
        label = ml_result.get("ml_label", "ML Anomaly")
        confidence = ml_result.get("ml_confidence", 0.0)

        # Map confidence to severity
        if confidence >= 0.90:
            severity = "CRITICAL"
        elif confidence >= 0.75:
            severity = "HIGH"
        elif confidence >= 0.60:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        alert = _create_alert(
            features,
            f"ML: {label}",
            severity,
            f"ML Prediction ({confidence:.0%} confidence)",
            "ML Engine"
        )
        alert["ml_confidence"] = confidence
        alert["ml_label"] = label
        alert["ml_top_features"] = ml_result.get("top_features", [])
        alerts.append(alert)

    return alerts, ml_result


# =========================================================
# Main Detection Entry Point
# =========================================================
def detect(features: dict) -> list:
    """
    Run all three detection engines and return fully enriched alerts.

    Args:
        features: Parsed packet feature dictionary from protocol_parser.py

    Returns:
        List of enriched alert dicts ready for logging
    """
    _reload_rules_if_needed()

    candidate_alerts = []

    # --- Engine A: Signature ---
    candidate_alerts.extend(_run_signature_engine(features))

    # --- Engine B: Heuristic ---
    candidate_alerts.extend(_run_heuristic_engine(features))

    # --- Engine C: ML ---
    ml_alerts, ml_result = _run_ml_engine(features)
    candidate_alerts.extend(ml_alerts)

    # --- AlertManager: Enrich, Rate-Limit, Score, Escalate ---
    final_alerts = []
    for alert in candidate_alerts:
        enriched = _alert_manager.process(alert, ml_result=ml_result)
        if enriched is not None:
            final_alerts.append(enriched)

    return final_alerts