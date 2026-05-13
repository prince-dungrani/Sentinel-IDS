"""
core/feature_mapper.py
=======================
CICIDS Feature Mapper

Converts live packet flow features (from flow_manager.py and protocol_parser.py)
into the exact 78-feature (PortScan) and 64-feature (DDoS) vectors that the
CICIDS2017-trained models expect.

Feature name reference: model_metadata.json → "feature_names"

Key insight: CICIDS features are FLOW-LEVEL statistics, not per-packet values.
The flow_manager.py must accumulate these statistics over the flow lifetime.

All missing values default to 0.0. NaN/Inf values are sanitized.
"""

import logging
import math

log = logging.getLogger("sentinel.feature_mapper")

# =========================================================
# CICIDS Feature Definitions (ordered exactly as model expects)
# =========================================================

# PortScan model: 78 features
PORTSCAN_FEATURES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean",
    "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
    "URG Flag Count", "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio",
    "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Fwd Header Length.1",  # duplicate of Fwd Header Length in CICIDS
    "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets",
    "Subflow Bwd Bytes", "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "act_data_pkt_fwd", "min_seg_size_forward",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]

# DDoS model: 64 features (no FIN/RST/PSH/ACK/URG/CWE/ECE counts,
# no Fwd Header Length, no bulk features, no Down/Up Ratio separately)
DDOS_FEATURES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean",
    "Packet Length Std", "Packet Length Variance", "SYN Flag Count",
    "ACK Flag Count", "Down/Up Ratio", "Average Packet Size",
    "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets",
    "Subflow Bwd Bytes", "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "act_data_pkt_fwd", "min_seg_size_forward",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]


def _safe(val, default=0.0):
    """Return float value, replacing None/NaN/Inf with default."""
    try:
        v = float(val)
        if math.isnan(v) or math.isinf(v):
            return default
        return v
    except (TypeError, ValueError):
        return default


def _std(values: list) -> float:
    """Compute standard deviation of a list of floats."""
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    variance = sum((x - mean) ** 2 for x in values) / n
    return math.sqrt(variance)


def _mean(values: list) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


# =========================================================
# Core Feature Extraction
# =========================================================
def extract_cicids_features(flow: dict) -> dict:
    """
    Extract all CICIDS-compatible features from a live flow statistics dict.

    The flow dict comes from flow_manager.py and contains accumulated
    per-flow statistics. This function computes all derived features.

    Returns a flat dict mapping CICIDS feature name → float value.
    """
    # --- Basic flow info ---
    dst_port = _safe(flow.get("dst_port", 0))
    duration_us = _safe(flow.get("flow_duration_us", 0))  # microseconds
    duration_s = duration_us / 1_000_000 if duration_us > 0 else 0.001

    # --- Packet counts ---
    fwd_pkts = _safe(flow.get("fwd_packets", 0))
    bwd_pkts = _safe(flow.get("bwd_packets", 0))
    total_pkts = fwd_pkts + bwd_pkts

    # --- Packet lengths ---
    fwd_lens = [_safe(x) for x in flow.get("fwd_pkt_lengths", [])]
    bwd_lens = [_safe(x) for x in flow.get("bwd_pkt_lengths", [])]
    all_lens = fwd_lens + bwd_lens

    fwd_len_total = sum(fwd_lens)
    bwd_len_total = sum(bwd_lens)
    total_bytes = fwd_len_total + bwd_len_total

    fwd_len_max  = max(fwd_lens) if fwd_lens else 0.0
    fwd_len_min  = min(fwd_lens) if fwd_lens else 0.0
    fwd_len_mean = _mean(fwd_lens)
    fwd_len_std  = _std(fwd_lens)

    bwd_len_max  = max(bwd_lens) if bwd_lens else 0.0
    bwd_len_min  = min(bwd_lens) if bwd_lens else 0.0
    bwd_len_mean = _mean(bwd_lens)
    bwd_len_std  = _std(bwd_lens)

    pkt_len_max  = max(all_lens) if all_lens else 0.0
    pkt_len_min  = min(all_lens) if all_lens else 0.0
    pkt_len_mean = _mean(all_lens)
    pkt_len_std  = _std(all_lens)
    pkt_len_var  = pkt_len_std ** 2

    # --- Rates ---
    flow_bytes_s = total_bytes / duration_s
    flow_pkts_s  = total_pkts / duration_s
    fwd_pkts_s   = fwd_pkts / duration_s
    bwd_pkts_s   = bwd_pkts / duration_s

    # --- Inter-Arrival Times ---
    flow_iats = [_safe(x) for x in flow.get("flow_iats", [])]
    fwd_iats  = [_safe(x) for x in flow.get("fwd_iats", [])]
    bwd_iats  = [_safe(x) for x in flow.get("bwd_iats", [])]

    flow_iat_mean = _mean(flow_iats)
    flow_iat_std  = _std(flow_iats)
    flow_iat_max  = max(flow_iats) if flow_iats else 0.0
    flow_iat_min  = min(flow_iats) if flow_iats else 0.0

    fwd_iat_total = sum(fwd_iats)
    fwd_iat_mean  = _mean(fwd_iats)
    fwd_iat_std   = _std(fwd_iats)
    fwd_iat_max   = max(fwd_iats) if fwd_iats else 0.0
    fwd_iat_min   = min(fwd_iats) if fwd_iats else 0.0

    bwd_iat_total = sum(bwd_iats)
    bwd_iat_mean  = _mean(bwd_iats)
    bwd_iat_std   = _std(bwd_iats)
    bwd_iat_max   = max(bwd_iats) if bwd_iats else 0.0
    bwd_iat_min   = min(bwd_iats) if bwd_iats else 0.0

    # --- TCP Flags ---
    flags_str = str(flow.get("flags_seen", ""))
    syn_count = _safe(flow.get("syn_count", flags_str.count("S")))
    ack_count = _safe(flow.get("ack_count", flags_str.count("A")))
    fin_count = _safe(flow.get("fin_count", flags_str.count("F")))
    rst_count = _safe(flow.get("rst_count", flags_str.count("R")))
    psh_count = _safe(flow.get("psh_count", flags_str.count("P")))
    urg_count = _safe(flow.get("urg_count", flags_str.count("U")))

    fwd_psh = _safe(flow.get("fwd_psh_flags", 0))
    bwd_psh = _safe(flow.get("bwd_psh_flags", 0))
    fwd_urg = _safe(flow.get("fwd_urg_flags", 0))
    bwd_urg = _safe(flow.get("bwd_urg_flags", 0))

    # --- Header lengths ---
    fwd_hdr_len = _safe(flow.get("fwd_header_length", fwd_pkts * 20))
    bwd_hdr_len = _safe(flow.get("bwd_header_length", bwd_pkts * 20))

    # --- Derived ---
    down_up_ratio = bwd_pkts / fwd_pkts if fwd_pkts > 0 else 0.0
    avg_pkt_size  = total_bytes / total_pkts if total_pkts > 0 else 0.0
    avg_fwd_seg   = fwd_len_mean
    avg_bwd_seg   = bwd_len_mean

    # --- Window sizes (from TCP handshake) ---
    init_win_fwd = _safe(flow.get("init_win_fwd", 0))
    init_win_bwd = _safe(flow.get("init_win_bwd", 0))
    act_data_fwd = _safe(flow.get("act_data_pkt_fwd", 0))
    min_seg_fwd  = _safe(flow.get("min_seg_size_forward", 0))

    # --- Active / Idle times ---
    active_times = [_safe(x) for x in flow.get("active_times", [])]
    idle_times   = [_safe(x) for x in flow.get("idle_times", [])]

    active_mean = _mean(active_times)
    active_std  = _std(active_times)
    active_max  = max(active_times) if active_times else 0.0
    active_min  = min(active_times) if active_times else 0.0

    idle_mean = _mean(idle_times)
    idle_std  = _std(idle_times)
    idle_max  = max(idle_times) if idle_times else 0.0
    idle_min  = min(idle_times) if idle_times else 0.0

    # Subflow features (simplified: same as full flow)
    subflow_fwd_pkts  = fwd_pkts
    subflow_fwd_bytes = fwd_len_total
    subflow_bwd_pkts  = bwd_pkts
    subflow_bwd_bytes = bwd_len_total

    # =========================================================
    # Return all features as a flat dict (CICIDS names as keys)
    # =========================================================
    return {
        "Destination Port":           dst_port,
        "Flow Duration":              duration_us,
        "Total Fwd Packets":          fwd_pkts,
        "Total Backward Packets":     bwd_pkts,
        "Total Length of Fwd Packets": fwd_len_total,
        "Total Length of Bwd Packets": bwd_len_total,
        "Fwd Packet Length Max":      fwd_len_max,
        "Fwd Packet Length Min":      fwd_len_min,
        "Fwd Packet Length Mean":     fwd_len_mean,
        "Fwd Packet Length Std":      fwd_len_std,
        "Bwd Packet Length Max":      bwd_len_max,
        "Bwd Packet Length Min":      bwd_len_min,
        "Bwd Packet Length Mean":     bwd_len_mean,
        "Bwd Packet Length Std":      bwd_len_std,
        "Flow Bytes/s":               flow_bytes_s,
        "Flow Packets/s":             flow_pkts_s,
        "Flow IAT Mean":              flow_iat_mean,
        "Flow IAT Std":               flow_iat_std,
        "Flow IAT Max":               flow_iat_max,
        "Flow IAT Min":               flow_iat_min,
        "Fwd IAT Total":              fwd_iat_total,
        "Fwd IAT Mean":               fwd_iat_mean,
        "Fwd IAT Std":                fwd_iat_std,
        "Fwd IAT Max":                fwd_iat_max,
        "Fwd IAT Min":                fwd_iat_min,
        "Bwd IAT Total":              bwd_iat_total,
        "Bwd IAT Mean":               bwd_iat_mean,
        "Bwd IAT Std":                bwd_iat_std,
        "Bwd IAT Max":                bwd_iat_max,
        "Bwd IAT Min":                bwd_iat_min,
        "Fwd PSH Flags":              fwd_psh,
        "Bwd PSH Flags":              bwd_psh,
        "Fwd URG Flags":              fwd_urg,
        "Bwd URG Flags":              bwd_urg,
        "Fwd Header Length":          fwd_hdr_len,
        "Bwd Header Length":          bwd_hdr_len,
        "Fwd Packets/s":              fwd_pkts_s,
        "Bwd Packets/s":              bwd_pkts_s,
        "Min Packet Length":          pkt_len_min,
        "Max Packet Length":          pkt_len_max,
        "Packet Length Mean":         pkt_len_mean,
        "Packet Length Std":          pkt_len_std,
        "Packet Length Variance":     pkt_len_var,
        "FIN Flag Count":             fin_count,
        "SYN Flag Count":             syn_count,
        "RST Flag Count":             rst_count,
        "PSH Flag Count":             psh_count,
        "ACK Flag Count":             ack_count,
        "URG Flag Count":             urg_count,
        "CWE Flag Count":             0.0,
        "ECE Flag Count":             0.0,
        "Down/Up Ratio":              down_up_ratio,
        "Average Packet Size":        avg_pkt_size,
        "Avg Fwd Segment Size":       avg_fwd_seg,
        "Avg Bwd Segment Size":       avg_bwd_seg,
        "Fwd Header Length.1":        fwd_hdr_len,
        "Fwd Avg Bytes/Bulk":         0.0,
        "Fwd Avg Packets/Bulk":       0.0,
        "Fwd Avg Bulk Rate":          0.0,
        "Bwd Avg Bytes/Bulk":         0.0,
        "Bwd Avg Packets/Bulk":       0.0,
        "Bwd Avg Bulk Rate":          0.0,
        "Subflow Fwd Packets":        subflow_fwd_pkts,
        "Subflow Fwd Bytes":          subflow_fwd_bytes,
        "Subflow Bwd Packets":        subflow_bwd_pkts,
        "Subflow Bwd Bytes":          subflow_bwd_bytes,
        "Init_Win_bytes_forward":     init_win_fwd,
        "Init_Win_bytes_backward":    init_win_bwd,
        "act_data_pkt_fwd":           act_data_fwd,
        "min_seg_size_forward":       min_seg_fwd,
        "Active Mean":                active_mean,
        "Active Std":                 active_std,
        "Active Max":                 active_max,
        "Active Min":                 active_min,
        "Idle Mean":                  idle_mean,
        "Idle Std":                   idle_std,
        "Idle Max":                   idle_max,
        "Idle Min":                   idle_min,
    }


def build_feature_vector(flow: dict, feature_names: list):
    """
    Build a numpy feature vector from a flow dict using an ordered list
    of CICIDS feature names. Returns (numpy_array, feature_dict).
    """
    try:
        import numpy as np
        cicids = extract_cicids_features(flow)
        vector = [_safe(cicids.get(name, 0.0)) for name in feature_names]
        arr = np.array(vector, dtype=np.float64).reshape(1, -1)
        # Sanitize
        arr = np.nan_to_num(arr, nan=0.0, posinf=1e9, neginf=-1e9)
        return arr, cicids
    except Exception as e:
        log.error(f"[FeatureMapper] Failed to build feature vector: {e}")
        return None, {}
