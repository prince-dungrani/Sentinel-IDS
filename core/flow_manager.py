import time
from collections import defaultdict

class FlowManager:

    def __init__(self):
        self.flows = defaultdict(dict)
        self.packet_counter = 0
        self.IDLE_TIMEOUT = 60      # seconds
        self.ACTIVE_TIMEOUT = 3600  # 1 hour maximum flow duration

    def update_flow(self, features):
        
        # We need a fallback if features missing expected keys
        flow_key = (
            features.get("src_ip", "0.0.0.0"),
            features.get("dst_ip", "0.0.0.0"),
            features.get("src_port", 0),
            features.get("dst_port", 0),
            features.get("protocol", "UNKNOWN")
        )

        # Allow passing timestamp from packet to maintain accuracy
        now = features.get("timestamp", time.time())

        if flow_key not in self.flows:
            self.flows[flow_key] = {
                "start_time": now,
                "packet_count": 0,
                "byte_count": 0,
                "syn_count": 0,
                "rst_count": 0,
                "last_active": now
            }

        flow = self.flows[flow_key]

        flow["packet_count"] += 1
        flow["byte_count"] += len(features.get("payload", ""))
        flow["last_active"] = now

        flags = features.get("flags", "")
        if "S" in flags:
            flow["syn_count"] += 1
        if "R" in flags:
            flow["rst_count"] += 1

        duration = now - flow["start_time"]
        flow["packet_rate"] = flow["packet_count"] / max(duration, 1)

        self.packet_counter += 1
        
        # Evict stale flows every 1000 packets to prevent OOM Memory Leaks
        if self.packet_counter % 1000 == 0:
            self._evict_stale_flows(now)

        return flow

    def _evict_stale_flows(self, current_time):
        
        stale_keys = []
        for key, flow in self.flows.items():
            
            idle_time = current_time - flow["last_active"]
            active_time = current_time - flow["start_time"]
            
            if idle_time > self.IDLE_TIMEOUT or active_time > self.ACTIVE_TIMEOUT:
                stale_keys.append(key)
                
        for key in stale_keys:
            del self.flows[key]