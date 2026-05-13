"""
core/ml_engine.py
==================
Enterprise Multi-Model Hybrid ML Engine

Orchestrates the complete ML detection pipeline:
  1. Load flow features via feature_mapper.py
  2. Route traffic via model_router.py
  3. Run each routed model (RF + IsolationForest fusion)
  4. Aggregate results with risk scoring
  5. Return structured ML result for alert_manager.py

Fusion Formula:
  Final Score = (alpha × RF_confidence) + (beta × IsoForest_anomaly_score)
  Alert if Final Score >= confidence_threshold

Failsafe:
  - Each model prediction wrapped in try/except
  - Failed models auto-disabled via ModelRegistry
  - IDS never stops on ML failure
"""

import os
import json
import logging
import time
from functools import lru_cache
from typing import Optional

from core.model_registry import get_registry
from core.model_router import route
from core.feature_mapper import build_feature_vector
from core.model_validator import validate_feature_vector

log = logging.getLogger("sentinel.ml_engine")

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ML_CONFIG_PATH = os.path.join(BASE_DIR, "config", "ml_config.json")

# Failure counter per model — auto-disable after N consecutive failures
_failure_counts: dict = {}
MAX_FAILURES = 5

# =========================================================
# Config Loader (hot-reload on each call if file changed)
# =========================================================
_config_mtime = 0.0
_config_cache: dict = {}


def _load_config() -> dict:
    global _config_mtime, _config_cache
    try:
        mtime = os.path.getmtime(ML_CONFIG_PATH)
        if mtime > _config_mtime:
            with open(ML_CONFIG_PATH) as f:
                _config_cache = json.load(f)
            _config_mtime = mtime
    except Exception:
        pass
    return _config_cache or {
        "alpha": 0.7, "beta": 0.3,
        "confidence_threshold": 0.60,
        "anomaly_threshold": 0.50,
        "ml_enabled": True,
        "portscan_enabled": True,
        "ddos_enabled": True,
        "min_flow_packets_for_ml": 3,
    }


# =========================================================
# Single-Model Prediction Engine
# =========================================================
def _run_single_model(bundle, feature_vector) -> dict:
    """
    Run RF + IsolationForest on a feature vector for one ModelBundle.
    Returns a prediction result dict.
    """
    result = {
        "model_id": bundle.model_id,
        "attack_type": bundle.attack_type,
        "rf_proba": 0.0,
        "iso_score": 0.0,
        "fusion_score": 0.0,
        "triggered": False,
        "label": "BENIGN",
        "top_features": [],
    }

    cfg = _load_config()
    alpha = float(cfg.get("alpha", 0.7))
    beta  = float(cfg.get("beta", 0.3))
    conf_threshold = float(cfg.get("confidence_threshold", 0.60))

    try:
        import numpy as np

        # Scale features
        X_scaled = bundle.scaler.transform(feature_vector)

        # --- RandomForest prediction ---
        rf_proba_all = bundle.rf_model.predict_proba(X_scaled)[0]
        # Index 1 = attack class probability
        rf_proba = float(rf_proba_all[1]) if len(rf_proba_all) > 1 else float(rf_proba_all[0])

        # --- IsolationForest anomaly score ---
        # decision_function returns negative anomaly score: lower = more anomalous
        iso_raw = bundle.iso_model.decision_function(X_scaled)[0]
        # Normalize to [0, 1] where 1 = most anomalous
        iso_score = float(max(0.0, min(1.0, (0.5 - iso_raw))))

        # --- Fusion ---
        fusion_score = alpha * rf_proba + beta * iso_score

        result["rf_proba"]     = round(rf_proba, 4)
        result["iso_score"]    = round(iso_score, 4)
        result["fusion_score"] = round(fusion_score, 4)

        # --- Trigger decision ---
        if fusion_score >= conf_threshold:
            result["triggered"] = True
            result["label"] = bundle.attack_type

            # --- Explainability: top N features ---
            try:
                if hasattr(bundle.rf_model, "feature_importances_"):
                    importances = bundle.rf_model.feature_importances_
                    n_top = int(cfg.get("top_features_count", 5))
                    top_indices = importances.argsort()[::-1][:n_top]
                    result["top_features"] = [
                        {
                            "feature": bundle.feature_names[i],
                            "importance": round(float(importances[i]), 4),
                        }
                        for i in top_indices
                        if i < len(bundle.feature_names)
                    ]
            except Exception:
                pass

        log.debug(f"[MLEngine][{bundle.model_id}] "
                  f"RF={rf_proba:.3f} ISO={iso_score:.3f} "
                  f"Fusion={fusion_score:.3f} Triggered={result['triggered']}")

    except Exception as e:
        log.error(f"[MLEngine][{bundle.model_id}] Prediction error: {e}")
        raise  # Let caller handle failure counting

    return result


# =========================================================
# Main Detection Entry Point
# =========================================================
def predict(flow: dict) -> dict:
    """
    Run the full ML detection pipeline on a flow dict.

    Returns:
        {
          "ml_triggered": bool,
          "ml_label": str,
          "ml_confidence": float,   ← highest fusion score
          "anomaly_score": float,
          "models_run": list,
          "per_model": dict,        ← results keyed by model_id
          "top_features": list,
          "routing_signals": dict,
        }
    """
    empty = {
        "ml_triggered": False, "ml_label": "N/A",
        "ml_confidence": 0.0, "anomaly_score": 0.0,
        "models_run": [], "per_model": {}, "top_features": [],
        "routing_signals": {},
    }

    cfg = _load_config()

    # Global ML kill switch
    if not cfg.get("ml_enabled", True):
        return empty

    # Minimum packet threshold — don't waste ML on single packets
    min_pkts = int(cfg.get("min_flow_packets_for_ml", 3))
    fwd_pkts = int(flow.get("fwd_packets", 0) or 0)
    bwd_pkts = int(flow.get("bwd_packets", 0) or 0)
    if (fwd_pkts + bwd_pkts) < min_pkts:
        return empty

    registry = get_registry()
    if not registry._loaded:
        registry.initialize()

    ready_bundles = registry.get_ready_bundles()
    if not ready_bundles:
        return empty

    # =========================================================
    # Step 1: Route traffic to appropriate models
    # =========================================================
    routing = route(flow)
    models_to_run = routing.models_to_run

    # Apply per-model enable flags from config
    if not cfg.get("portscan_enabled", True):
        models_to_run = [m for m in models_to_run if "portscan" not in m]
    if not cfg.get("ddos_enabled", True):
        models_to_run = [m for m in models_to_run if "ddos" not in m]

    if not models_to_run:
        return empty

    # =========================================================
    # Step 2: Build feature vectors and run each model
    # =========================================================
    best_result = None
    per_model = {}
    models_actually_run = []

    for model_id in models_to_run:
        bundle = ready_bundles.get(model_id)
        if not bundle:
            continue

        # Build feature vector for this model
        feature_vector, _ = build_feature_vector(flow, bundle.feature_names)
        if feature_vector is None:
            log.warning(f"[MLEngine][{model_id}] Feature vector construction failed")
            continue

        # Validate feature vector shape
        ok, reason = validate_feature_vector(feature_vector, bundle.feature_count, model_id)
        if not ok:
            log.warning(f"[MLEngine][{model_id}] Feature validation failed: {reason}")
            continue

        # Run the model with failure counting
        try:
            result = _run_single_model(bundle, feature_vector)
            per_model[model_id] = result
            models_actually_run.append(model_id)
            _failure_counts[model_id] = 0  # reset on success

            # Track the highest-confidence triggered result
            if result["triggered"]:
                if best_result is None or result["fusion_score"] > best_result["fusion_score"]:
                    best_result = result

        except Exception as e:
            _failure_counts[model_id] = _failure_counts.get(model_id, 0) + 1
            log.error(f"[MLEngine][{model_id}] Error #{_failure_counts[model_id]}: {e}")
            if _failure_counts[model_id] >= MAX_FAILURES:
                registry.disable_model(model_id, f"Disabled after {MAX_FAILURES} consecutive errors")
            continue

    # =========================================================
    # Step 3: Aggregate final result
    # =========================================================
    if best_result:
        # Multi-model agreement bonus
        triggered_models = [m for m, r in per_model.items() if r.get("triggered")]
        if len(triggered_models) > 1:
            best_result["fusion_score"] = min(1.0, best_result["fusion_score"] + 0.05)

        return {
            "ml_triggered":  True,
            "ml_label":      best_result["label"],
            "ml_confidence": best_result["fusion_score"],
            "anomaly_score": best_result["iso_score"],
            "rf_confidence": best_result["rf_proba"],
            "model_used":    best_result["model_id"],
            "models_run":    models_actually_run,
            "per_model":     per_model,
            "top_features":  best_result.get("top_features", []),
            "routing_signals": routing.signals,
        }

    return {
        "ml_triggered":  False,
        "ml_label":      "BENIGN",
        "ml_confidence": max((r["fusion_score"] for r in per_model.values()), default=0.0),
        "anomaly_score": max((r["iso_score"] for r in per_model.values()), default=0.0),
        "models_run":    models_actually_run,
        "per_model":     per_model,
        "top_features":  [],
        "routing_signals": routing.signals,
    }
