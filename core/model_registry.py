"""
core/model_registry.py
=======================
Enterprise Model Registry

Loads all ML models defined in config/model_registry.json.
Each model is validated for version compatibility before loading.
Failed models are isolated — other models and the core IDS continue.

Architecture:
  ModelRegistry (singleton) → {model_id → ModelBundle}
  ModelBundle: rf_model, iso_model, scaler, metadata, feature_names, status
"""

import os
import json
import logging
from dataclasses import dataclass, field
from typing import Dict, Optional, Any

from core.model_validator import (
    validate_environment,
    validate_model_compatibility,
    load_metadata,
)

log = logging.getLogger("sentinel.model_registry")

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REGISTRY_CONFIG = os.path.join(BASE_DIR, "config", "model_registry.json")


@dataclass
class ModelBundle:
    """All artifacts for a single detection model."""
    model_id: str
    attack_type: str
    name: str
    status: str               # "active" | "disabled" | "error"
    error_reason: str = ""
    rf_model: Any = None
    iso_model: Any = None
    scaler: Any = None
    metadata: dict = field(default_factory=dict)
    feature_names: list = field(default_factory=list)
    feature_count: int = 0

    @property
    def is_ready(self) -> bool:
        return (self.status == "active" and
                self.rf_model is not None and
                self.iso_model is not None and
                self.scaler is not None and
                len(self.feature_names) > 0)


class ModelRegistry:
    """
    Singleton registry that loads, validates, and exposes all ML models.
    Each model is independently fault-isolated.
    """

    _instance: Optional["ModelRegistry"] = None

    def __init__(self):
        self._bundles: Dict[str, ModelBundle] = {}
        self._env_ok = False
        self._loaded = False

    @classmethod
    def get_instance(cls) -> "ModelRegistry":
        if cls._instance is None:
            cls._instance = ModelRegistry()
        return cls._instance

    # --------------------------------------------------
    # Initialization
    # --------------------------------------------------
    def initialize(self):
        """Load and validate all models from registry config. Call once at startup."""
        if self._loaded:
            return

        log.info("[Registry] Initializing ML model registry...")

        # Step 1: Validate the runtime environment first
        env = validate_environment()
        self._env_ok = env["ok"]
        if not self._env_ok:
            log.error(f"[Registry] Environment validation FAILED: {env['errors']}")
            log.warning("[Registry] All ML models disabled. IDS continues with rule/heuristic engines.")
            self._loaded = True
            return

        # Step 2: Load registry config
        try:
            with open(REGISTRY_CONFIG, "r") as f:
                config = json.load(f)
        except Exception as e:
            log.error(f"[Registry] Cannot read model_registry.json: {e}")
            self._loaded = True
            return

        # Step 3: Load each model independently
        for entry in config.get("models", []):
            model_id = entry.get("id", "unknown")
            if entry.get("status", "active") != "active":
                log.info(f"[Registry] Skipping inactive model: {model_id}")
                continue
            self._load_model(model_id, entry)

        active = sum(1 for b in self._bundles.values() if b.is_ready)
        log.info(f"[Registry] ✓ Initialization complete. {active}/{len(self._bundles)} models ready.")
        self._loaded = True

    def _load_model(self, model_id: str, entry: dict):
        """Load a single model bundle. Failures are isolated."""
        attack_type = entry.get("attack_type", "Unknown")
        bundle = ModelBundle(
            model_id=model_id,
            attack_type=attack_type,
            name=entry.get("name", model_id),
            status="error",
        )

        try:
            import joblib

            model_dir = os.path.join(BASE_DIR, entry["model_dir"])
            meta_path = os.path.join(model_dir, entry.get("metadata", "model_metadata.json"))

            # 1. Load metadata
            metadata = load_metadata(meta_path)
            if not metadata:
                raise ValueError(f"Cannot load metadata from {meta_path}")
            bundle.metadata = metadata

            # 2. Version compatibility check
            compatible, reason = validate_model_compatibility(metadata, model_id)
            if not compatible:
                bundle.error_reason = reason
                log.error(f"[Registry][{model_id}] DISABLED — {reason}")
                self._bundles[model_id] = bundle
                return

            # 3. Load feature names from metadata
            bundle.feature_names = metadata.get("feature_names", [])
            bundle.feature_count = len(bundle.feature_names)
            if bundle.feature_count == 0:
                raise ValueError("No feature names found in metadata")

            # 4. Load models
            rf_path     = os.path.join(model_dir, entry.get("rf_model", "rf_model.joblib"))
            iso_path    = os.path.join(model_dir, entry.get("iso_model", "iso_model.joblib"))
            scaler_path = os.path.join(model_dir, entry.get("scaler", "scaler.joblib"))

            for path in [rf_path, iso_path, scaler_path]:
                if not os.path.exists(path):
                    raise FileNotFoundError(f"Model file not found: {path}")

            bundle.rf_model  = joblib.load(rf_path)
            bundle.iso_model = joblib.load(iso_path)
            bundle.scaler    = joblib.load(scaler_path)

            # 5. Validate scaler feature count
            if hasattr(bundle.scaler, "mean_"):
                scaler_n = bundle.scaler.mean_.shape[0]
                if scaler_n != bundle.feature_count:
                    raise ValueError(
                        f"Scaler expects {scaler_n} features but metadata says {bundle.feature_count}"
                    )

            bundle.status = "active"
            log.info(f"[Registry][{model_id}] ✓ Loaded — {bundle.name} "
                     f"({bundle.feature_count} features, attack={attack_type})")

        except Exception as e:
            bundle.status = "error"
            bundle.error_reason = str(e)
            log.error(f"[Registry][{model_id}] FAILED to load: {e}")

        self._bundles[model_id] = bundle

    # --------------------------------------------------
    # Public Accessors
    # --------------------------------------------------
    def get_bundle(self, model_id: str) -> Optional[ModelBundle]:
        return self._bundles.get(model_id)

    def get_all_bundles(self) -> Dict[str, ModelBundle]:
        return dict(self._bundles)

    def get_ready_bundles(self) -> Dict[str, ModelBundle]:
        return {k: v for k, v in self._bundles.items() if v.is_ready}

    def get_bundle_for_attack(self, attack_type: str) -> Optional[ModelBundle]:
        """Find a ready bundle matching the given attack type."""
        for bundle in self._bundles.values():
            if bundle.is_ready and bundle.attack_type.lower() == attack_type.lower():
                return bundle
        return None

    def get_status_summary(self) -> list:
        """Return list of status dicts for the dashboard."""
        return [
            {
                "id": b.model_id,
                "name": b.name,
                "attack_type": b.attack_type,
                "status": b.status,
                "ready": b.is_ready,
                "feature_count": b.feature_count,
                "error": b.error_reason,
                "sklearn_version": b.metadata.get("sklearn_version", "N/A"),
                "training_date": b.metadata.get("training_date", "N/A"),
            }
            for b in self._bundles.values()
        ]

    def disable_model(self, model_id: str, reason: str = "Runtime error"):
        """Disable a model at runtime after repeated failures."""
        if model_id in self._bundles:
            self._bundles[model_id].status = "error"
            self._bundles[model_id].error_reason = reason
            log.warning(f"[Registry][{model_id}] Model DISABLED at runtime: {reason}")


# Module-level convenience
def get_registry() -> ModelRegistry:
    return ModelRegistry.get_instance()
