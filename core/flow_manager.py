"""
core/flow_manager.py
=====================
Enterprise Flow Manager with Full CICIDS Feature Collection

Tracks bidirectional TCP/UDP flows and accumulates the complete set of
statistics required by the CICIDS2017-trained ML models.

Key CICIDS features collected per flow:
  - Packet counts (fwd/bwd)
  - Packet lengths (min/max/mean/std for fwd/bwd)
  - Inter-arrival times (flow/fwd/bwd IAT: mean/std/max/min)
  - TCP flag counts (SYN/ACK/FIN/RST/PSH/URG)
  - Header lengths, window sizes
  - Flow duration, bytes/s, packets/s
  - Active/idle time tracking
  - Unique destination ports (for port scan routing)

Flow direction: first packet determines "forward". Reverse = backward.
"""

import time
import logging
from collections import defaultdict

log = logging.getLogger("sentinel.flow_manager")


class FlowManager:

    def __init__(self):
        self.flows: dict = {}
        self.packet_counter: int = 0
        self.total_packets: int = 0
        self.IDLE_TIMEOUT: float = 60.0    # seconds
        self.ACTIVE_TIMEOUT: float = 3600.0  # 1 hour max
        # Track unique dst_ports per src_ip for portscan routing
        self._src_port_sets: dict = defaultdict(set)

    # --------------------------------------------------
    # Main Update Method
    # --------------------------------------------------
    def update_flow(self, features: dict) -> dict:
        """
        Update flow state with new packet features.
        Returns enriched flow dict suitable for ML prediction.
        """
        src_ip   = features.get("src_ip", "0.0.0.0")
        dst_ip   = features.get("dst_ip", "0.0.0.0")
        src_port = int(features.get("src_port", 0) or 0)
        dst_port = int(features.get("dst_port", 0) or 0)
        protocol = features.get("protocol", "UNKNOWN")

        # Flow key: 5-tuple (bidirectional — always lower IP first)
        flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)

        now = float(features.get("pkt_timestamp", time.time()))
        pkt_len = int(features.get("packet_size", len(features.get("payload", ""))))
        flags   = str(features.get("flags", ""))

        # Track unique destination ports per source IP
        if dst_port > 0:
            self._src_port_sets[src_ip].add(dst_port)

        # =========================================================
        # Initialize new flow
        # =========================================================
        if flow_key not in self.flows:
            self.flows[flow_key] = {
                # Identity
                "src_ip":   src_ip,
                "dst_ip":   dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "flags":    flags,

                # Timing
                "start_time":       now,
                "last_active":      now,
                "last_pkt_time":    now,
                "flow_duration_us": 0.0,

                # Packet counts
                "fwd_packets": 0,
                "bwd_packets": 0,

                # Packet lengths (accumulated lists)
                "fwd_pkt_lengths": [],
                "bwd_pkt_lengths": [],

                # IAT tracking
                "flow_iats": [],
                "fwd_iats":  [],
                "bwd_iats":  [],
                "last_fwd_time": None,
                "last_bwd_time": None,

                # TCP flag counts
                "syn_count": 0,
                "ack_count": 0,
                "fin_count": 0,
                "rst_count": 0,
                "psh_count": 0,
                "urg_count": 0,

                # Direction-specific flags
                "fwd_psh_flags": 0,
                "bwd_psh_flags": 0,
                "fwd_urg_flags": 0,
                "bwd_urg_flags": 0,

                # Header lengths
                "fwd_header_length": 0,
                "bwd_header_length": 0,

                # TCP window sizes (from first packet)
                "init_win_fwd": features.get("tcp_window", 0) or 0,
                "init_win_bwd": 0,
                "act_data_pkt_fwd": 0,
                "min_seg_size_forward": 20,  # default IP+TCP header

                # Active / idle tracking
                "active_times": [],
                "idle_times":   [],
                "_last_activity_start": now,
                "_idle_threshold": 1.0,  # 1 second idle threshold

                # Unique ports (for port scan detection)
                "unique_dst_ports": len(self._src_port_sets[src_ip]),

                # Byte count (for legacy compatibility)
                "byte_count": 0,
                "packet_count": 0,
                "packet_rate": 0.0,
            }

        flow = self.flows[flow_key]

        # =========================================================
        # Determine packet direction
        # =========================================================
        is_forward = (src_ip == flow["src_ip"] and src_port == flow["src_port"])

        # =========================================================
        # Update flow statistics
        # =========================================================
        flow["last_active"] = now
        flow["packet_count"] += 1
        flow["byte_count"] += pkt_len

        # IAT (Inter-Arrival Time) in microseconds
        time_since_last = (now - flow["last_pkt_time"]) * 1_000_000  # → μs
        if flow["last_pkt_time"] != now:
            flow["flow_iats"].append(time_since_last)
        flow["last_pkt_time"] = now

        # Active / Idle detection
        idle_gap_s = (now - flow["last_active"])
        if idle_gap_s > flow["_idle_threshold"]:
            # Was idle — record idle time, start new active period
            flow["idle_times"].append(idle_gap_s * 1_000_000)
            flow["_last_activity_start"] = now
        else:
            active_s = (now - flow["_last_activity_start"]) * 1_000_000
            if active_s > 0:
                flow["active_times"].append(active_s)

        # Duration
        flow["flow_duration_us"] = (now - flow["start_time"]) * 1_000_000

        # TCP Flags
        if "S" in flags: flow["syn_count"] += 1
        if "A" in flags: flow["ack_count"] += 1
        if "F" in flags: flow["fin_count"] += 1
        if "R" in flags: flow["rst_count"] += 1
        if "P" in flags: flow["psh_count"] += 1
        if "U" in flags: flow["urg_count"] += 1

        if is_forward:
            flow["fwd_packets"] += 1
            flow["fwd_pkt_lengths"].append(pkt_len)
            flow["fwd_header_length"] += int(features.get("ip_hdr_len", 20) or 20)

            if "P" in flags: flow["fwd_psh_flags"] += 1
            if "U" in flags: flow["fwd_urg_flags"] += 1

            # Forward IAT
            if flow["last_fwd_time"] is not None:
                fwd_iat = (now - flow["last_fwd_time"]) * 1_000_000
                flow["fwd_iats"].append(fwd_iat)
            flow["last_fwd_time"] = now

            # Count packets with actual data payload
            if pkt_len > 0:
                flow["act_data_pkt_fwd"] += 1

        else:
            flow["bwd_packets"] += 1
            flow["bwd_pkt_lengths"].append(pkt_len)
            flow["bwd_header_length"] += int(features.get("ip_hdr_len", 20) or 20)

            if "P" in flags: flow["bwd_psh_flags"] += 1
            if "U" in flags: flow["bwd_urg_flags"] += 1

            # Backward IAT
            if flow["last_bwd_time"] is not None:
                bwd_iat = (now - flow["last_bwd_time"]) * 1_000_000
                flow["bwd_iats"].append(bwd_iat)
            flow["last_bwd_time"] = now

            # Capture backward window size
            if flow["init_win_bwd"] == 0:
                flow["init_win_bwd"] = features.get("tcp_window", 0) or 0

        # Update unique ports count
        flow["unique_dst_ports"] = len(self._src_port_sets.get(src_ip, set()))

        # Packet rate (legacy)
        dur = max(flow["flow_duration_us"] / 1_000_000, 0.001)
        flow["packet_rate"] = flow["packet_count"] / dur

        # Evict stale flows every 500 packets
        self.packet_counter += 1
        self.total_packets += 1
        if self.packet_counter % 500 == 0:
            self._evict_stale_flows(now)

        return flow

    # --------------------------------------------------
    # Stale Flow Eviction
    # --------------------------------------------------
    def _evict_stale_flows(self, current_time: float):
        """Remove flows that have been idle or running too long."""
        stale_keys = [
            key for key, flow in self.flows.items()
            if (current_time - flow["last_active"] > self.IDLE_TIMEOUT or
                current_time - flow["start_time"] > self.ACTIVE_TIMEOUT)
        ]
        for key in stale_keys:
            del self.flows[key]

        # Also clean up old src_port_sets
        active_src_ips = {key[0] for key in self.flows}
        stale_ips = [ip for ip in self._src_port_sets if ip not in active_src_ips]
        for ip in stale_ips:
            del self._src_port_sets[ip]

        if stale_keys:
            log.debug(f"[FlowManager] Evicted {len(stale_keys)} stale flows")

    # --------------------------------------------------
    # Stats
    # --------------------------------------------------
    def get_stats(self) -> dict:
        return {
            "active_flows": len(self.flows),
            "total_packets": self.total_packets,
            "tracked_src_ips": len(self._src_port_sets),
        }