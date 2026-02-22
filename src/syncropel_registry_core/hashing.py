"""4-level hash computation for patterns — standalone, no registry dependency.

Implements the same algorithm as Runner Core (src/hashing.rs) and
syncropel-registry (registry/services/hash_service.py):

Canonical JSON format per level:
- L3 (Intent):     {"in":"<shape>","out":"<shape>"}
- L2 (Flow):       {"in":"<shape>","out":"<shape>","p":"<primitive>"}
- L1 (Structural): {"in":"<shape>","op":"<operation>","out":"<shape>","p":"<primitive>"}
- L0 (Exact):      L1 + ,"params":{...} with sorted keys

Sequence hash: sha256(hash1 + "," + hash2 + ...)
Full 64-character SHA-256 hex output (no truncation).
"""

from __future__ import annotations

import hashlib
import json


def _sha256(data: str) -> str:
    """Compute full SHA-256 hex digest (64 characters)."""
    return hashlib.sha256(data.encode()).hexdigest()


def _operation_or_primitive(effect: dict) -> str:
    """Get operation name, falling back to lowercase primitive."""
    op = effect.get("operation")
    if op:
        return op
    return effect["primitive"].lower()


def hash_effect(effect: dict, level: int) -> str:
    """Hash a single effect dict at a given level.

    Args:
        effect: Dict with keys: primitive, input_shape, output_shape,
                and optionally operation, parameters.
        level: 0=Exact, 1=Structural, 2=Flow, 3=Intent.

    Returns:
        64-character hex SHA-256 hash.
    """
    in_shape = effect["input_shape"]
    out_shape = effect["output_shape"]
    primitive = effect["primitive"]

    if level == 3:
        canonical = f'{{"in":"{in_shape}","out":"{out_shape}"}}'
    elif level == 2:
        canonical = f'{{"in":"{in_shape}","out":"{out_shape}","p":"{primitive}"}}'
    elif level == 1:
        op = _operation_or_primitive(effect)
        canonical = f'{{"in":"{in_shape}","op":"{op}","out":"{out_shape}","p":"{primitive}"}}'
    else:  # L0
        op = _operation_or_primitive(effect)
        params = effect.get("parameters", {})
        params_keys = sorted(params.keys())
        params_json = ",".join(
            f'"{k}":{json.dumps(params[k], separators=(",", ":"), sort_keys=True)}'
            for k in params_keys
        )
        canonical = (
            f'{{"in":"{in_shape}","op":"{op}","out":"{out_shape}",'
            f'"p":"{primitive}","params":{{{params_json}}}}}'
        )

    return _sha256(canonical)


def hash_effect_sequence(effects: list[dict], level: int) -> str:
    """Hash a sequence of effects at a given level.

    sha256(hash1 + "," + hash2 + ...)

    Args:
        effects: Effect dicts in topological order.
        level: 0=Exact, 1=Structural, 2=Flow, 3=Intent.

    Returns:
        64-character hex SHA-256 hash.
    """
    effect_hashes = [hash_effect(e, level) for e in effects]
    combined = ",".join(effect_hashes)
    return _sha256(combined)


def compute_hashes(effects: list[dict]) -> tuple[str, str, str, str]:
    """Compute 4-level hashes for a list of effects.

    Returns:
        Tuple of (hash_l0, hash_l1, hash_l2, hash_l3)
    """
    return (
        hash_effect_sequence(effects, level=0),
        hash_effect_sequence(effects, level=1),
        hash_effect_sequence(effects, level=2),
        hash_effect_sequence(effects, level=3),
    )
