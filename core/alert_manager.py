"""
core/alert_manager.py
=====================
Enterprise Alert Manager — Professional Rate Limiting, Risk Scoring,
Repeat Attacker Escalation, and Multi-Engine Confidence Fusion.

Key responsibilities:
  1. Rate-limit duplicate alerts to prevent log flooding
  2. Track repeat attackers and escalate severity automatically
  3. Compute a normalized Risk Score (0-100) for every alert
  4. Fuse confidence signals from multiple detection engines
  5. Map every alert to a MITRE ATT&CK Tactic + Technique
"""

import time
import logging
from collections import defaultdict

log = logging.getLogger("sentinel.alert_manager")

# =========================================================
# MITRE ATT&CK Mapping Table
# Maps (attack_type, rule_name) keywords -> (Tactic, Technique ID, Technique Name)
# =========================================================
MITRE_MAP = [
    (["sql", "sqli", "injection"],          "Initial Access",           "T1190", "Exploit Public-Facing Application"),
    (["xss", "cross-site"],                 "Initial Access",           "T1189", "Drive-by Compromise"),
    (["command injection", "cmd", "shell"], "Execution",                "T1059", "Command and Scripting Interpreter"),
    (["port scan", "scan"],                 "Discovery",                "T1046", "Network Service Discovery"),
    (["suspicious access", "ssh", "telnet","smb"], "Lateral Movement", "T1021", "Remote Services"),
    (["syn flood", "dos", "ddos", "flood"], "Impact",                   "T1499", "Endpoint Denial of Service"),
    (["dns tunnel", "dns"],                 "Command and Control",      "T1071", "Application Layer Protocol"),
    (["brute", "auth"],                     "Credential Access",        "T1110", "Brute Force"),
    (["beacon", "c2"],                      "Command and Control",      "T1071", "Application Layer Protocol"),
    (["exfil", "data"],                     "Exfiltration",             "T1041", "Exfiltration Over C2 Channel"),
]

# Severity tier -> base risk score
SEVERITY_BASE = {
    "CRITICAL": 85,
    "HIGH":     65,
    "MEDIUM":   40,
    "LOW":      15,
    "INFO":     5,
}

# Escalation ladder
ESCALATION = {
    "LOW":      "MEDIUM",
    "MEDIUM":   "HIGH",
    "HIGH":     "CRITICAL",
    "CRITICAL": "CRITICAL",
}


class AlertManager:
    """
    Enterprise-grade alert manager with rate limiting, escalation,
    risk scoring, and MITRE ATT&CK mapping.
    """

    def __init__(self,
                 rate_limit_window: int = 10,
                 max_alerts_per_window: int = 5,
                 escalation_threshold: int = 3,
                 escalation_window: int = 60):
        """
        Args:
            rate_limit_window:   Seconds to enforce per-alert rate limit
            max_alerts_per_window: Max same alerts from same IP per window
            escalation_threshold: Hit count before escalating severity
            escalation_window:    Seconds to track hits for escalation
        """
        # Rate limit state: key=(attack_type, src_ip) -> [timestamps]
        self._rate_history: dict = defaultdict(list)

        # Escalation state: key=src_ip -> {attack_type: [timestamps]}
        self._escalation_hits: dict = defaultdict(lambda: defaultdict(list))

        # Repeat attacker total tracking
        self._attacker_scores: dict = defaultdict(int)

        self.rate_limit_window = rate_limit_window
        self.max_alerts = max_alerts_per_window
        self.escalation_threshold = escalation_threshold
        self.escalation_window = escalation_window

    # --------------------------------------------------
    # Public API
    # --------------------------------------------------
    def process(self, alert: dict, ml_result: dict = None) -> dict | None:
        """
        Process a candidate alert through the enterprise pipeline:
          1. Check rate limit
          2. Apply MITRE mapping
          3. Escalate severity if repeat attacker
          4. Calculate risk score
          5. Fuse ML confidence

        Returns enriched alert dict, or None if rate-limited.
        """
        src_ip = alert.get("src_ip", "Unknown")
        attack_type = alert.get("attack_type", "Unknown")
        rule = alert.get("rule", "")
        now = time.time()

        # --- Rate Limit Check ---
        rate_key = (attack_type, src_ip)
        self._rate_history[rate_key] = [
            t for t in self._rate_history[rate_key]
            if now - t < self.rate_limit_window
        ]
        if len(self._rate_history[rate_key]) >= self.max_alerts:
            return None  # Suppressed
        self._rate_history[rate_key].append(now)

        # --- Escalation Tracking ---
        esc_key = f"{attack_type}_{src_ip}"
        self._escalation_hits[src_ip][attack_type] = [
            t for t in self._escalation_hits[src_ip][attack_type]
            if now - t < self.escalation_window
        ]
        self._escalation_hits[src_ip][attack_type].append(now)
        hit_count = len(self._escalation_hits[src_ip][attack_type])

        original_severity = alert.get("severity", "MEDIUM").upper()
        severity = original_severity
        escalated_from = None

        # Escalate if hit_count exceeds threshold(s)
        escalations_needed = hit_count // self.escalation_threshold
        for _ in range(min(escalations_needed, 2)):  # max 2 escalation steps
            new_sev = ESCALATION.get(severity, severity)
            if new_sev != severity:
                escalated_from = severity
                severity = new_sev

        # --- MITRE Mapping ---
        mitre_tactic, mitre_technique, mitre_technique_name = self._map_mitre(attack_type, rule)

        # --- Risk Score Calculation ---
        base_score = SEVERITY_BASE.get(severity, 40)
        frequency_bonus = min(hit_count * 3, 15)  # max +15
        attacker_history_bonus = min(self._attacker_scores[src_ip] // 10, 10)  # max +10

        # ML fusion bonus
        ml_confidence = 0.0
        ml_bonus = 0
        if ml_result and ml_result.get("ml_triggered"):
            ml_confidence = float(ml_result.get("ml_confidence", 0.0))
            ml_bonus = int(ml_confidence * 10)  # max +10

        risk_score = min(100, base_score + frequency_bonus + attacker_history_bonus + ml_bonus)

        # Track this attacker's total risk contribution
        self._attacker_scores[src_ip] += risk_score // 10

        # --- Determine engines triggered ---
        engines = [alert.get("engine", "Signature Engine")]
        if ml_result and ml_result.get("ml_triggered"):
            engines.append("ML Engine")

        # Multi-engine agreement bonus (for display, already baked into score)
        if len(engines) > 1:
            risk_score = min(100, risk_score + 5)

        # --- Enrich the alert ---
        alert["severity"] = severity
        alert["traffic_type"] = "MALICIOUS" if severity in ["HIGH", "CRITICAL"] else "SUSPICIOUS"
        alert["risk_score"] = risk_score
        alert["mitre_tactic"] = mitre_tactic
        alert["mitre_technique"] = mitre_technique
        alert["mitre_technique_name"] = mitre_technique_name
        alert["hit_count"] = hit_count
        alert["engines_triggered"] = engines
        alert["ml_confidence"] = round(ml_confidence, 4)
        alert["ml_label"] = ml_result.get("ml_label", "N/A") if ml_result else "N/A"
        alert["ml_top_features"] = ml_result.get("top_features", []) if ml_result else []

        if escalated_from:
            alert["escalated_from"] = escalated_from

        return alert

    def should_alert(self, alert: dict) -> bool:
        """Legacy compatibility shim — wraps process() for old callers."""
        return self.process(alert) is not None

    # --------------------------------------------------
    # Internal Helpers
    # --------------------------------------------------
    def _map_mitre(self, attack_type: str, rule: str) -> tuple:
        """Return (tactic, technique_id, technique_name) for this alert."""
        combined = f"{attack_type} {rule}".lower()
        for keywords, tactic, technique_id, technique_name in MITRE_MAP:
            if any(kw in combined for kw in keywords):
                return tactic, technique_id, technique_name
        return "Discovery", "T1046", "Network Service Discovery"