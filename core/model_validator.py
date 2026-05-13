"""
core/model_validator.py
========================
Enterprise Model Compatibility Validator

Validates sklearn/numpy/Python version compatibility BEFORE any model is
loaded. Prevents ImportError crashes that occur when .joblib files were
trained with a different environment than the current runtime.

This module is the PRIMARY DEFENSE against:
    ImportError: numpy.core.multiarray failed to import

Rules:
  - Major + minor sklearn version must match (e.g. 1.6.x is OK for 1.6.1)
  - numpy major version must match (2.x for 2.x trained models)
  - Graceful warning + disable if mismatch — NEVER crash
"""

import sys
import os
import json
import logging
from typing import Tuple

log = logging.getLogger("sentinel.model_validator")

# =========================================================
# Runtime Version Cache (imported once)
# =========================================================
_RUNTIME_VERSIONS = {}

def _get_runtime_versions() -> dict:
    global _RUNTIME_VERSIONS
    if _RUNTIME_VERSIONS:
        return _RUNTIME_VERSIONS

    versions = {
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "python_major_minor": f"{sys.version_info.major}.{sys.version_info.minor}",
        "sklearn": "N/A",
        "numpy": "N/A",
        "joblib": "N/A",
    }

    try:
        import sklearn
        versions["sklearn"] = sklearn.__version__
    except ImportError:
        pass

    try:
        import numpy as np
        versions["numpy"] = np.__version__
    except ImportError:
        pass

    try:
        import joblib
        versions["joblib"] = joblib.__version__
    except ImportError:
        pass

    _RUNTIME_VERSIONS = versions
    log.info(f"[Validator] Runtime: Python={versions['python']} "
             f"sklearn={versions['sklearn']} numpy={versions['numpy']}")
    return versions


def _version_major_minor(ver_str: str) -> Tuple[int, int]:
    """Extract (major, minor) from version string like '1.6.1' → (1, 6)."""
    try:
        parts = str(ver_str).split(".")
        return int(parts[0]), int(parts[1])
    except Exception:
        return -1, -1


def _version_major(ver_str: str) -> int:
    try:
        return int(str(ver_str).split(".")[0])
    except Exception:
        return -1


# =========================================================
# Public API
# =========================================================
def validate_environment() -> dict:
    """
    Validate that sklearn and numpy are importable in the current environment.
    Returns a status dict.
    """
    result = {"ok": True, "errors": [], "warnings": [], "versions": {}}
    rv = _get_runtime_versions()
    result["versions"] = rv

    if rv["sklearn"] == "N/A":
        result["ok"] = False
        result["errors"].append("scikit-learn is not installed or not importable")

    if rv["numpy"] == "N/A":
        result["ok"] = False
        result["errors"].append("numpy is not installed or not importable")

    if not result["ok"]:
        log.error(f"[Validator] Environment check FAILED: {result['errors']}")
    else:
        log.info("[Validator] ✓ Environment check passed")

    return result


def validate_model_compatibility(metadata: dict, model_id: str) -> Tuple[bool, str]:
    """
    Compare the model's training environment (from metadata.json)
    against the current runtime. Returns (is_compatible, reason).

    Compatibility rules:
      - sklearn: major.minor must match  (1.6.x ↔ 1.6.y is OK)
      - numpy:   major version must match (2.x ↔ 2.y is OK)
      - Python:  major.minor should match (warning only, not fatal)
    """
    rv = _get_runtime_versions()

    # --- sklearn check (CRITICAL) ---
    model_sklearn = str(metadata.get("sklearn_version", "0.0"))
    rt_sklearn = rv["sklearn"]

    if rt_sklearn == "N/A":
        return False, "scikit-learn not available in runtime"

    model_sk_mm = _version_major_minor(model_sklearn)
    rt_sk_mm = _version_major_minor(rt_sklearn)

    if model_sk_mm != rt_sk_mm:
        reason = (f"sklearn version mismatch: model trained with {model_sklearn}, "
                  f"runtime has {rt_sklearn}. Major.minor must match.")
        log.error(f"[Validator][{model_id}] INCOMPATIBLE — {reason}")
        return False, reason

    # --- numpy check (CRITICAL) ---
    model_numpy = str(metadata.get("numpy_version", "0"))
    rt_numpy = rv["numpy"]

    if rt_numpy == "N/A":
        return False, "numpy not available in runtime"

    if _version_major(model_numpy) != _version_major(rt_numpy):
        reason = (f"numpy major version mismatch: model trained with {model_numpy}, "
                  f"runtime has {rt_numpy}. Major version must match.")
        log.error(f"[Validator][{model_id}] INCOMPATIBLE — {reason}")
        return False, reason

    # --- Python version check (WARNING only) ---
    model_python = str(metadata.get("python_version", "0.0"))
    rt_python = rv["python_major_minor"]

    if _version_major_minor(model_python) != _version_major_minor(rt_python):
        log.warning(f"[Validator][{model_id}] Python version difference: "
                    f"model={model_python} runtime={rt_python}. This may cause issues.")

    log.info(f"[Validator][{model_id}] ✓ Compatibility check passed "
             f"(sklearn={rt_sklearn} numpy={rt_numpy})")
    return True, "OK"


def validate_feature_vector(feature_vector, expected_count: int, model_id: str) -> Tuple[bool, str]:
    """
    Validate a numpy feature vector before passing it to a model.
    Checks: shape, NaN, Infinity, feature count match.
    """
    try:
        import numpy as np

        if feature_vector is None:
            return False, "feature_vector is None"

        shape = feature_vector.shape
        if len(shape) != 2:
            return False, f"Expected 2D array, got shape {shape}"

        actual_count = shape[1]
        if actual_count != expected_count:
            return False, (f"Feature count mismatch: model expects {expected_count}, "
                           f"got {actual_count}")

        if np.any(np.isnan(feature_vector)):
            log.warning(f"[Validator][{model_id}] NaN values in feature vector — replacing with 0")
            feature_vector[:] = np.nan_to_num(feature_vector, nan=0.0)

        if np.any(np.isinf(feature_vector)):
            log.warning(f"[Validator][{model_id}] Inf values in feature vector — clipping")
            feature_vector[:] = np.clip(feature_vector, -1e9, 1e9)

        return True, "OK"

    except Exception as e:
        return False, f"Feature validation error: {e}"


def load_metadata(metadata_path: str) -> dict:
    """Safely load and return model_metadata.json content."""
    try:
        with open(metadata_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        log.error(f"[Validator] metadata file not found: {metadata_path}")
        return {}
    except json.JSONDecodeError as e:
        log.error(f"[Validator] metadata JSON parse error: {e}")
        return {}
