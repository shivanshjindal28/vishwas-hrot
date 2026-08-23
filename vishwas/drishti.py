"""DRISHTI - continuous attestation and the AI advisory plane.

Design rule we do not compromise:
    CRYPTOGRAPHY IS AUTHORITATIVE. AI IS ADVISORY AND EXPLANATORY ONLY.
No model output can grant boot, admit a device, or approve an update. Models
add context, raise flags and rank human attention - nothing more.

Two narrow components:
  1. Drift explainer      - a deterministic log diff produces structured facts;
                            a local open-source LLM renders them in plain
                            language. Falls back to a template when no model
                            is available, so behaviour is never model-dependent.
  2. Fleet anomaly detector - flags a validly signed but statistically unique
                            sub-fleet build, i.e. the signature of a TARGETED
                            supply-chain attack that passes every crypto check.
"""
from __future__ import annotations

import collections


def explain(drift_facts: list[str], component_versions: dict | None = None) -> str:
    """Render structured drift facts as an operator-readable sentence.

    A local model (Ollama / vLLM) is used when configured; the deterministic
    template below is the fallback and the ground truth for tests.
    """
    if not drift_facts:
        return "Platform integrity verified: all measurements match an approved policy."
    lines = ["Integrity check FAILED. What changed:"]
    lines += [f"  - {f}" for f in drift_facts]
    if component_versions:
        lines.append("  Component versions reported: " +
                     ", ".join(f"{k} {v}" for k, v in component_versions.items()))
    lines.append("Advisory only - the cryptographic verdict above was produced "
                 "by deterministic verification, not by a model.")
    return "\n".join(lines)


def fleet_anomaly(fleet_measurements: dict, threshold: float = 0.10) -> list[str]:
    """Flag devices running a build that only a small slice of the fleet has.

    Every one of these images may carry a perfectly valid signature. That is
    exactly the point: signature verification cannot detect a targeted build,
    and this is the layer that can.
    """
    counts = collections.Counter(fleet_measurements.values())
    total = len(fleet_measurements)
    rare = {m for m, c in counts.items() if c / total < threshold}
    return sorted(d for d, m in fleet_measurements.items() if m in rare)
