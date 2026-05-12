"""
core/ml_engine.py
=================
Enterprise ML Inference Engine — Engine C

This module integrates the pre-trained RandomForestClassifier and
IsolationForest models into the live packet analysis pipeline.

Prediction Logic:
    final_score = (alpha * rf_confidence) + (beta * iso_score)
    If final_score >= confidence_threshold -> ALERT

Designed with graceful degradation: if models fail to load due to
version incompatibilities, the engine logs a warning and disables
itself without crashing the IDS pipeline.
"""

import os
import json
import logging
import numpy as np
from collections import OrderedDict

# --- Module-level logger ---
log = logging.getLogger("sentinel.ml_engine")

# =========================================================
# CONSTANTS — CICIDS2017 Feature Vector
# The model was trained on these 20 features, extracted in order.
# =========================================================
FEATURE_NAMES = [
    "dst_port",         # Destination Port
    "protocol_num",     # Protocol number (6=TCP, 17=UDP, 1=ICMP)
    "packet_size",      # Total packet length
    "header_length",    # IP header length
    "flags_num",        # TCP flags as bitmask integer
    "ttl",              # Time-to-live
    "src_port",         # Source port
    "flow_packets",     # Packets in this flow
    "flow_bytes",       # Total bytes in flow
    "psh_flag",         # PSH flag (1 or 0)
    "syn_flag",         # SYN flag (1 or 0)
    "ack_flag",         # ACK flag (1 or 0)
    "fin_flag",         # FIN flag (1 or 0)
    "rst_flag",         # RST flag (1 or 0)
    "urg_flag",         # URG flag (1 or 0)
    "payload_length",   # Length of payload
    "inter_arrival",    # Avg inter-arrival time in flow
    "tcp_state_num",    # TCP state encoded (0=NONE,1=SYN,2=EST,3=FIN)
    "flow_duration",    # Duration of flow in seconds
    "packet_rate",      # Packets per second in flow
]

# Protocol string -> number mapping
PROTO_MAP = {"TCP": 6, "UDP": 17, "ICMP": 1}

# TCP flags string -> bitmask
FLAGS_MAP = {
    "S": 0x02, "A": 0x10, "F": 0x01, "R": 0x04,
    "P": 0x08, "U": 0x20, "SA": 0x12, "AP": 0x18,
    "AF": 0x11, "PA": 0x18, "FA": 0x01
}

# TCP state string -> int
STATE_MAP = {"NONE": 0, "SYN": 1, "SYN_ACK": 1, "ESTABLISHED": 2, "FIN": 3, "CLOSED": 3}

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ML_CONFIG_PATH = os.path.join(BASE_DIR, "config", "ml_config.json")

# =========================================================
# LRU Cache for recent ML predictions (avoids re-scoring same flow)
# =========================================================
class LRUPredictionCache:
    def __init__(self, max_size: int = 500):
        self._cache = OrderedDict()
        self._max = max_size

    def get(self, key):
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]
        return None

    def set(self, key, value):
        self._cache[key] = value
        self._cache.move_to_end(key)
        if len(self._cache) > self._max:
            self._cache.popitem(last=False)


# =========================================================
# Main ML Engine Class
# =========================================================
class MLEngine:
    """
    Enterprise ML Inference Engine.

    Loads RandomForest (supervised) and IsolationForest (unsupervised)
    models and fuses their scores using configurable alpha/beta weights.
    Supports live config reload without engine restart.
    """

    def __init__(self):
        self.rf_model = None
        self.iso_model = None
        self.scaler = None
        self.enabled = False
        self.config = {}
        self._prediction_cache = LRUPredictionCache(max_size=1000)
        self._config_mtime = 0

        # Load config and models
        self._load_config()
        self._load_models()

    # --------------------------------------------------
    # Configuration Management
    # --------------------------------------------------
    def _load_config(self):
        """Load or hot-reload ML config from ml_config.json."""
        try:
            mtime = os.path.getmtime(ML_CONFIG_PATH)
            if mtime > self._config_mtime:
                with open(ML_CONFIG_PATH, "r") as f:
                    self.config = json.load(f)
                self._config_mtime = mtime
        except Exception as e:
            log.warning(f"[MLEngine] Could not load ml_config.json: {e}. Using defaults.")
            self.config = {
                "alpha": 0.6, "beta": 0.4,
                "anomaly_threshold": 0.5,
                "confidence_threshold": 0.65,
                "ml_enabled": True,
                "top_features_count": 5
            }

    def _reload_config_if_needed(self):
        """Check if config file was modified and reload if so."""
        try:
            mtime = os.path.getmtime(ML_CONFIG_PATH)
            if mtime > self._config_mtime:
                self._load_config()
        except Exception:
            pass

    # --------------------------------------------------
    # Model Loading (with graceful degradation)
    # --------------------------------------------------
    def _load_models(self):
        """
        Attempt to load pre-trained models.
        If loading fails (e.g., version mismatch), disable ML engine
        gracefully — the IDS continues with Signature + Heuristic engines.
        """
        try:
            import joblib  # type: ignore
            rf_path = os.path.join(BASE_DIR, "rf_model.joblib")
            iso_path = os.path.join(BASE_DIR, "iso_model.joblib")
            scaler_path = os.path.join(BASE_DIR, "scaler.joblib")

            if not all(os.path.exists(p) for p in [rf_path, iso_path, scaler_path]):
                log.warning("[MLEngine] Model files not found. ML Engine disabled.")
                return

            self.rf_model = joblib.load(rf_path)
            self.iso_model = joblib.load(iso_path)
            self.scaler = joblib.load(scaler_path)
            self.enabled = True
            log.info("[MLEngine] ✓ All models loaded successfully. ML Engine ACTIVE.")

        except ImportError:
            log.warning("[MLEngine] joblib not installed. ML Engine disabled.")
        except Exception as e:
            log.warning(f"[MLEngine] Model load failed ({type(e).__name__}): {e}. ML Engine disabled.")

    # --------------------------------------------------
    # Feature Engineering
    # --------------------------------------------------
    def _build_feature_vector(self, features: dict) -> np.ndarray:
        """
        Converts a live packet features dict into the 20-dimensional
        feature vector expected by the trained CICIDS models.

        All missing fields default to 0 to prevent crashes.
        """
        flags_str = str(features.get("flags", ""))
        flags_bitmask = FLAGS_MAP.get(flags_str.upper(), 0)
        proto_str = str(features.get("protocol", "TCP")).upper()
        proto_num = PROTO_MAP.get(proto_str, 6)
        tcp_state = str(features.get("tcp_state", "NONE")).upper()
        tcp_state_num = STATE_MAP.get(tcp_state, 0)

        # Parse individual flag bits
        syn = 1 if "S" in flags_str else 0
        ack = 1 if "A" in flags_str else 0
        fin = 1 if "F" in flags_str else 0
        rst = 1 if "R" in flags_str else 0
        psh = 1 if "P" in flags_str else 0
        urg = 1 if "U" in flags_str else 0

        payload = str(features.get("payload", features.get("reassembled_payload", "")))
        flow_bytes = features.get("flow_bytes", features.get("packet_size", 0))
        flow_packets = features.get("flow_packets", 1)
        flow_duration = features.get("flow_duration", 0.0)
        packet_rate = (flow_packets / flow_duration) if flow_duration > 0 else 0

        vector = [
            float(features.get("dst_port", 0)),
            float(proto_num),
            float(features.get("packet_size", 0)),
            float(features.get("header_length", 20)),
            float(flags_bitmask),
            float(features.get("ttl", 64)),
            float(features.get("src_port", 0)),
            float(flow_packets),
            float(flow_bytes),
            float(psh),
            float(syn),
            float(ack),
            float(fin),
            float(rst),
            float(urg),
            float(len(payload)),
            float(features.get("inter_arrival", 0.0)),
            float(tcp_state_num),
            float(flow_duration),
            float(packet_rate),
        ]

        return np.array(vector, dtype=np.float64).reshape(1, -1)

    # --------------------------------------------------
    # Core Prediction
    # --------------------------------------------------
    def predict(self, features: dict) -> dict:
        """
        Run ML inference on a packet's features.

        Returns a result dict:
        {
            "ml_triggered": bool,
            "ml_confidence": float (0.0 to 1.0),
            "ml_label": str,
            "rf_score": float,
            "iso_score": float,
            "final_score": float,
            "top_features": list of (feature_name, value) tuples,
            "ml_engine": "ML Engine",
        }
        """
        # Reload config if file changed (hot-reload support)
        self._reload_config_if_needed()

        if not self.enabled or not self.config.get("ml_enabled", True):
            return {"ml_triggered": False, "ml_confidence": 0.0, "ml_label": "N/A",
                    "rf_score": 0.0, "iso_score": 0.0, "final_score": 0.0,
                    "top_features": [], "ml_engine": "ML Engine (Disabled)"}

        # Build cache key from flow tuple
        cache_key = (
            features.get("src_ip"), features.get("dst_ip"),
            features.get("src_port"), features.get("dst_port"),
            features.get("flags")
        )
        cached = self._prediction_cache.get(cache_key)
        if cached:
            return cached

        try:
            raw_vector = self._build_feature_vector(features)

            # Handle scaler dimension mismatch gracefully
            if self.scaler is not None:
                scaler_features = self.scaler.mean_.shape[0]
                if raw_vector.shape[1] != scaler_features:
                    # Pad or truncate to match scaler's expected input
                    if raw_vector.shape[1] < scaler_features:
                        pad = np.zeros((1, scaler_features - raw_vector.shape[1]))
                        raw_vector = np.hstack([raw_vector, pad])
                    else:
                        raw_vector = raw_vector[:, :scaler_features]
                scaled = self.scaler.transform(raw_vector)
            else:
                scaled = raw_vector

            # === RandomForest (Supervised) ===
            rf_proba = self.rf_model.predict_proba(scaled)[0]
            rf_classes = self.rf_model.classes_
            # Probability of ATTACK class (non-BENIGN)
            benign_idx = list(rf_classes).index("BENIGN") if "BENIGN" in rf_classes else 0
            rf_score = 1.0 - rf_proba[benign_idx]
            rf_label = rf_classes[np.argmax(rf_proba)]

            # === IsolationForest (Unsupervised Anomaly) ===
            iso_raw = self.iso_model.decision_function(scaled)[0]
            # Normalize: decision_function returns negative for anomalies
            # Map to 0-1 range where 1 = most anomalous
            iso_score = max(0.0, min(1.0, (-iso_raw + 0.5)))

            # === Hybrid Fusion Score ===
            alpha = float(self.config.get("alpha", 0.6))
            beta = float(self.config.get("beta", 0.4))
            final_score = (alpha * rf_score) + (beta * iso_score)

            # === Explainability — Top Features (RF feature importances) ===
            top_n = int(self.config.get("top_features_count", 5))
            top_features = []
            if hasattr(self.rf_model, "feature_importances_"):
                importances = self.rf_model.feature_importances_
                # Map to available features (may differ in length)
                n = min(len(importances), len(FEATURE_NAMES))
                pairs = list(zip(FEATURE_NAMES[:n], importances[:n]))
                pairs.sort(key=lambda x: x[1], reverse=True)
                top_features = [(name, round(float(val), 4)) for name, val in pairs[:top_n]]

            confidence_threshold = float(self.config.get("confidence_threshold", 0.65))
            ml_triggered = final_score >= confidence_threshold

            result = {
                "ml_triggered": ml_triggered,
                "ml_confidence": round(final_score, 4),
                "ml_label": rf_label if ml_triggered else "BENIGN",
                "rf_score": round(rf_score, 4),
                "iso_score": round(iso_score, 4),
                "final_score": round(final_score, 4),
                "top_features": top_features,
                "ml_engine": "ML Engine",
            }

            self._prediction_cache.set(cache_key, result)
            return result

        except Exception as e:
            log.debug(f"[MLEngine] Prediction error: {e}")
            return {"ml_triggered": False, "ml_confidence": 0.0, "ml_label": "Error",
                    "rf_score": 0.0, "iso_score": 0.0, "final_score": 0.0,
                    "top_features": [], "ml_engine": "ML Engine (Error)"}


# Module-level singleton — one engine per process
_engine_instance = None


def get_engine() -> MLEngine:
    """Return the module-level MLEngine singleton."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = MLEngine()
    return _engine_instance


def predict(features: dict) -> dict:
    """Convenience function for calling ML inference."""
    return get_engine().predict(features)
