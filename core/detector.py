"""
core/detector.py
================
Sentinel-IDS — Triple-Engine Detection Pipeline

Pipeline:
  Flow features → Engine A (Signature) → Engine B (Heuristic) → Engine C (ML) → AlertManager

Engine C now uses the enterprise multi-model ML infrastructure:
  - core/ml_engine.py (orchestrator)
  - core/model_router.py (routing)
  - core/model_registry.py (model loading)
  - core/feature_mapper.py (CICIDS feature extraction)
  - core/model_validator.py (compatibility checks)
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

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RULES_FILE  = os.path.join(BASE_DIR, "data", "rules.json")
CONFIG_FILE = os.path.join(BASE_DIR, "config", "config.json")

RULES: list = []
_last_rules_mtime: float = 0.0

_alert_manager = AlertManager(
    rate_limit_window=10,
    max_alerts_per_window=5,
    escalation_threshold=3,
    escalation_window=60
)

# Initialize ML models at startup (non-blocking)
def _init_ml():
    try:
        from core.model_registry import get_registry
        registry = get_registry()
        if not registry._loaded:
            registry.initialize()
    except Exception as e:
        log.error(f"[Detector] ML initialization error: {e}")

_init_ml()


def _load_config() -> dict:
    try:
        with open(CONFIG_FILE) as f:
            return json.load(f)
    except Exception:
        return {
            "syn_flood_threshold": 50,
            "port_scan_threshold": 15,
            "suspicious_ports": [22, 23, 445],
        }

CONFIG = _load_config()


def _reload_rules_if_needed():
    global RULES, _last_rules_mtime
    try:
        mtime = os.path.getmtime(RULES_FILE)
        if mtime > _last_rules_mtime:
            with open(RULES_FILE) as f:
                loaded = json.load(f)
            RULES = [r for r in loaded if r.get("status", "enabled").lower() != "disabled"]
            _last_rules_mtime = mtime
            log.info(f"[Detector] Rules reloaded — {len(RULES)} active rules")
    except Exception as e:
        log.debug(f"[Detector] Rule reload skipped: {e}")


# =========================================================
# Heuristic state
# =========================================================
_packet_count: dict = defaultdict(int)
_port_access: dict  = defaultdict(set)
_last_seen: dict    = defaultdict(float)
_rule_hits: dict    = defaultdict(int)
TIME_WINDOW = 10


# =========================================================
# Alert Factory
# =========================================================
def _create_alert(features: dict, attack_type: str, severity: str,
                  rule_name: str, engine_name: str) -> dict:
    payload = str(features.get("reassembled_payload", features.get("payload", "")))
    preview = payload[:120] + "..." if len(payload) > 120 else payload
    return {
        "id":              f"ALERT-{str(uuid.uuid4())[:8].upper()}",
        "timestamp":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "traffic_type":    "MALICIOUS" if severity.upper() in ["HIGH", "CRITICAL"] else "SUSPICIOUS",
        "attack_type":     attack_type,
        "severity":        severity,
        "src_ip":          features.get("src_ip", "Unknown"),
        "dst_ip":          features.get("dst_ip", "Unknown"),
        "src_port":        features.get("src_port", "*"),
        "dst_port":        features.get("dst_port", "*"),
        "protocol":        features.get("protocol", "Unknown"),
        "packet_size":     features.get("packet_size", len(payload)),
        "flags":           features.get("flags", ""),
        "status":          "ACTIVE",
        "rule":            rule_name,
        "payload_preview": preview,
        "engine":          engine_name,
        "risk_score":      0,
        "mitre_tactic":    "",
        "mitre_technique": "",
        "mitre_technique_name": "",
        "hit_count":       1,
        "engines_triggered": [engine_name],
        "ml_confidence":   0.0,
        "ml_label":        "N/A",
        "ml_top_features": [],
    }


# =========================================================
# Engine A — Signature
# =========================================================
def _match_rule(features: dict, rule: dict) -> bool:
    proto    = features.get("protocol")
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
        check   = rule["content"].lower() if rule.get("nocase") else rule["content"]
        haystack = value.lower() if rule.get("nocase") else value
        if check not in haystack:
            return False

    if "regex" in rule:
        flags_r = re.IGNORECASE if rule.get("nocase") else 0
        if not re.search(rule["regex"], value, flags_r):
            return False

    if "length_gt" in rule and len(value) <= rule["length_gt"]:
        return False

    return True


def _run_signature_engine(features: dict) -> list:
    alerts = []
    for rule in RULES:
        if _match_rule(features, rule):
            _rule_hits[rule["name"]] += 1
            if _rule_hits[rule["name"]] >= rule.get("threshold", 1):
                alerts.append(_create_alert(
                    features,
                    rule.get("group", "Signature"),
                    rule.get("severity", "MEDIUM"),
                    rule["name"],
                    "Signature Engine"
                ))
    return alerts


# =========================================================
# Engine B — Heuristic
# =========================================================
def _run_heuristic_engine(features: dict) -> list:
    alerts = []
    src_ip   = features.get("src_ip", "Unknown")
    dst_port = features.get("dst_port")
    flags    = features.get("flags", "")
    now      = time.time()

    syn_thresh  = CONFIG.get("syn_flood_threshold", 50)
    port_thresh = CONFIG.get("port_scan_threshold", 15)
    susp_ports  = CONFIG.get("suspicious_ports", [22, 23, 445])

    if now - _last_seen[src_ip] > TIME_WINDOW:
        _packet_count[src_ip] = 0
        _port_access[src_ip].clear()

    _last_seen[src_ip] = now
    _packet_count[src_ip] += 1
    if dst_port:
        _port_access[src_ip].add(dst_port)

    if _packet_count[src_ip] > syn_thresh and flags == "S":
        alerts.append(_create_alert(features, "SYN Flood", "HIGH",
                                    "Possible SYN Flood", "Heuristic Engine"))

    if len(_port_access[src_ip]) > port_thresh:
        alerts.append(_create_alert(features, "Port Scan", "MEDIUM",
                                    "Possible Port Scan", "Heuristic Engine"))

    if dst_port in susp_ports:
        alerts.append(_create_alert(features, "Suspicious Access", "HIGH",
                                    f"Access to sensitive port {dst_port}",
                                    "Heuristic Engine"))

    if dst_port == 53:
        dns_q = features.get("dns_query", "")
        if len(dns_q) > 50:
            alerts.append(_create_alert(features, "DNS Tunneling", "MEDIUM",
                                        "DNS query length anomaly", "Heuristic Engine"))

    return alerts


# =========================================================
# Engine C — ML (uses enriched flow from flow_manager)
# =========================================================
def _run_ml_engine(features: dict) -> tuple:
    """
    Run ML prediction on the enriched flow dict.
    features here = the flow dict returned by flow_manager.update_flow()
    """
    try:
        ml_result = ml_engine.predict(features)
    except Exception as e:
        log.debug(f"[Detector] ML predict error: {e}")
        return [], {"ml_triggered": False, "ml_confidence": 0.0}

    alerts = []
    if ml_result.get("ml_triggered"):
        label      = ml_result.get("ml_label", "ML Anomaly")
        confidence = ml_result.get("ml_confidence", 0.0)
        model_used = ml_result.get("model_used", "ML Engine")

        if confidence >= 0.90:   severity = "CRITICAL"
        elif confidence >= 0.75: severity = "HIGH"
        elif confidence >= 0.60: severity = "MEDIUM"
        else:                    severity = "LOW"

        alert = _create_alert(
            features,
            f"ML: {label}",
            severity,
            f"ML Prediction ({confidence:.0%} confidence) via {model_used}",
            "ML Engine"
        )
        alert["ml_confidence"]   = confidence
        alert["ml_label"]        = label
        alert["ml_top_features"] = ml_result.get("top_features", [])
        alerts.append(alert)

    return alerts, ml_result


# =========================================================
# Main Entry Point
# =========================================================
def detect(features: dict) -> list:
    """
    Run all three detection engines on packet/flow features.
    Returns list of enriched, rate-limited, risk-scored alert dicts.
    """
    _reload_rules_if_needed()

    candidates = []
    candidates.extend(_run_signature_engine(features))
    candidates.extend(_run_heuristic_engine(features))

    ml_alerts, ml_result = _run_ml_engine(features)
    candidates.extend(ml_alerts)

    final = []
    for alert in candidates:
        enriched = _alert_manager.process(alert, ml_result=ml_result)
        if enriched is not None:
            final.append(enriched)

    return final