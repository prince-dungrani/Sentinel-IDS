from collections import defaultdict

class TCPTracker:

    def __init__(self):
        self.tcp_states = {}
        # Stores payload chunks ordered by sequence number
        self.stream_buffers = defaultdict(dict)
        self.expected_seq = {}

    def update_state(self, features):
        if features.get("protocol") != "TCP":
            return None

        # Standardizing directionality: Client -> Server
        key = (
            features.get("src_ip"),
            features.get("dst_ip"),
            features.get("src_port"),
            features.get("dst_port")
        )

        flags = str(features.get("flags", ""))
        seq = features.get("seq", 0)
        payload = features.get("payload", "")

        # State Machine Transition
        if "S" in flags and "A" not in flags:
            self.tcp_states[key] = "SYN_SENT"
            # Initialize Expected Sequence (ISN + 1)
            self.expected_seq[key] = seq + 1
            
        elif "S" in flags and "A" in flags:
            self.tcp_states[key] = "SYN_ACK"
            
        elif "A" in flags and self.tcp_states.get(key) in ["SYN_SENT", "SYN_ACK"]:
            self.tcp_states[key] = "ESTABLISHED"
            
        elif "F" in flags or "R" in flags:
            self.tcp_states[key] = "CLOSED"
            # Clean up buffer memory on close
            if key in self.stream_buffers:
                del self.stream_buffers[key]
            if key in self.expected_seq:
                del self.expected_seq[key]

        # Basic Stream Reassembly Buffer
        if payload and self.tcp_states.get(key) == "ESTABLISHED":
            # Add payload to buffer indexed by sequence number
            self.stream_buffers[key][seq] = payload
            
            # Simple reassembly attempt (concatenate contiguous chunks)
            # In a production IDS, this would handle overlaps (Ptacek & Newsham)
            assembled_stream = ""
            sorted_seqs = sorted(self.stream_buffers[key].keys())
            
            for s in sorted_seqs:
                assembled_stream += self.stream_buffers[key][s]
                
            # Expose the reassembled stream for detection engine
            features["reassembled_payload"] = assembled_stream

        return self.tcp_states.get(key, "UNKNOWN")