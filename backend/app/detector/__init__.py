"""Detector engine package."""

from app.detector.validator import validate_target_url, SSRFValidationError
from app.detector.prober import probe_service, ProbeResult
from app.detector.rules import HealthStatusRule, Elevated5xxRule, LatencyThresholdRule
from app.detector.evaluator import evaluate_service_health, DetectionReport
from app.detector.lifecycle import process_detection_lifecycle
from app.detector.runner import run_evaluation_for_service, run_evaluation_for_workspace

__all__ = [
    "validate_target_url",
    "SSRFValidationError",
    "probe_service",
    "ProbeResult",
    "HealthStatusRule",
    "Elevated5xxRule",
    "LatencyThresholdRule",
    "evaluate_service_health",
    "DetectionReport",
    "process_detection_lifecycle",
    "run_evaluation_for_service",
    "run_evaluation_for_workspace",
]
