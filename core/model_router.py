"""
core/model_router.py
=====================
Intelligent Traffic-to-Model Router

Analyzes live flow features and decides which ML model(s) to run.
Supports simultaneous execution of multiple models.

Routing logic:
  PortScan signals:
    - Many unique destination ports from same source
    - Low packet counts per connection
    - RST/SYN without ACK
    - Scan-like inter-arrival patterns

  DDoS signals:
    - High packet rate
    - SYN flood behavior (high SYN count, low ACK count)
    - Volumetric flows (many packets, high bytes/s)
    - Short flow duration with many packets
"""

import logging
from typing import List, Dict, Any

log = logging.getLogger("sentinel.model_router")


class RoutingDecision:
    """Encapsulates routing result for a single flow."""

    def __init__(self):
        self.models_to_run: List[str] = []   # list of model_ids to execute
        self.signals: Dict[str, Any] = {}    # detected signals for debugging
        self.confidence: float = 0.0


def route(flow: dict) -> RoutingDecision:
    """
    Analyze flow features and return a RoutingDecision specifying
    which model(s) to run.

    Args:
        flow: Enriched flow dict from flow_manager.py

    Returns:
        RoutingDecision with models_to_run list
    """
    decision = RoutingDecision()

    dst_port  = int(flow.get("dst_port", 0) or 0)
    protocol  = str(flow.get("protocol", "TCP")).upper()
    flags     = str(flow.get("flags", ""))
    fwd_pkts  = int(flow.get("fwd_packets", 1) or 1)
    bwd_pkts  = int(flow.get("bwd_packets", 0) or 0)
    syn_count = int(flow.get("syn_count", 0) or 0)
    ack_count = int(flow.get("ack_count", 0) or 0)
    total_pkts = fwd_pkts + bwd_pkts

    # Flow-level aggregates
    unique_ports = int(flow.get("unique_dst_ports", 0) or 0)  # set by flow_manager
    flow_duration_us = float(flow.get("flow_duration_us", 1) or 1)
    flow_duration_s = flow_duration_us / 1_000_000 if flow_duration_us > 0 else 0.001
    flow_pkts_s = total_pkts / flow_duration_s

    # =========================================================
    # Signal 1: PortScan Detection Heuristics
    # =========================================================
    portscan_score = 0

    # Many unique ports probed by this source
    if unique_ports >= 5:
        portscan_score += 3
        decision.signals["unique_ports"] = unique_ports

    # SYN without ACK (half-open scan)
    if "S" in flags and "A" not in flags:
        portscan_score += 2
        decision.signals["syn_no_ack"] = True

    # Very few packets per flow (characteristic of port scanners)
    if fwd_pkts <= 3 and bwd_pkts == 0:
        portscan_score += 2
        decision.signals["minimal_packets"] = True

    # RST response (closed port)
    if "R" in flags:
        portscan_score += 1
        decision.signals["rst_seen"] = True

    # =========================================================
    # Signal 2: DDoS Detection Heuristics
    # =========================================================
    ddos_score = 0

    # Very high packet rate
    if flow_pkts_s > 100:
        ddos_score += 3
        decision.signals["high_pps"] = round(flow_pkts_s, 1)

    # SYN flood: many SYN packets, few ACK packets
    if syn_count > 10 and ack_count < syn_count * 0.1:
        ddos_score += 3
        decision.signals["syn_flood_ratio"] = f"{syn_count}:{ack_count}"

    # High total packet count in short time
    if total_pkts > 50 and flow_duration_s < 5:
        ddos_score += 2
        decision.signals["burst_packets"] = total_pkts

    # UDP flood (high packet rate with UDP)
    if protocol == "UDP" and flow_pkts_s > 50:
        ddos_score += 2
        decision.signals["udp_flood"] = True

    # =========================================================
    # Routing Decisions (can route to MULTIPLE models)
    # =========================================================
    PORTSCAN_THRESHOLD = 3
    DDOS_THRESHOLD = 3

    if portscan_score >= PORTSCAN_THRESHOLD:
        decision.models_to_run.append("portscan_v1")
        decision.signals["portscan_score"] = portscan_score

    if ddos_score >= DDOS_THRESHOLD:
        decision.models_to_run.append("ddos_v1")
        decision.signals["ddos_score"] = ddos_score

    # If no specific routing, run both models on all traffic above
    # minimum packet threshold (let ML decide)
    if not decision.models_to_run and total_pkts >= 5:
        decision.models_to_run = ["portscan_v1", "ddos_v1"]
        decision.signals["default_routing"] = True

    if decision.models_to_run:
        log.debug(f"[Router] Routing to {decision.models_to_run} | signals={decision.signals}")

    return decision
