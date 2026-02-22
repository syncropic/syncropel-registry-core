"""Namespace resolution — pure functions implementing the 5-level hierarchy.

Spec reference: syncropel-spec/registry/04-namespace-resolution.md

All functions are pure (no class state, no DB access). The resolution
algorithm accepts callbacks to fetch namespaces and policies from any store.
"""

from __future__ import annotations

import fnmatch
import re
from typing import Callable

# ---------------------------------------------------------------------------
# Constants — Frozen Foundation compliance (F1, F2)
# ---------------------------------------------------------------------------

VALID_PRIMITIVES = {"GET", "PUT", "CALL", "MAP"}
VALID_SHAPES = {"VOID", "ONE", "OPTIONAL", "MANY", "KEYED"}
ALL_HASH_LEVELS = ["L0", "L1", "L2", "L3"]

LEVELS = ("DEFAULT", "ORG", "PROJECT", "ENV", "JOB")

# Namespace ID regex — spec §2.1
_NS_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*(/[a-z0-9][a-z0-9_-]*)*$")
_BINDING_REF_RE = re.compile(r"^@[a-z][a-z0-9_-]*$")

# Limits — spec §2.1
MAX_NS_ID_LENGTH = 256
MAX_SEGMENT_LENGTH = 63
MAX_SEGMENTS = 4  # user-defined (excluding implicit DEFAULT)

# ---------------------------------------------------------------------------
# DEFAULT namespace configuration — spec §3.2
# ---------------------------------------------------------------------------

DEFAULT_CAPABILITY: dict = {
    "primitives": ["GET", "PUT", "CALL", "MAP"],
    "shapes": ["VOID", "ONE", "OPTIONAL", "MANY", "KEYED"],
    "operations": ["*"],
    "resources": ["/*"],
    "max_effects": 1000,
    "max_depth": 50,
}

DEFAULT_DENY: dict = {"rules": []}

DEFAULT_BUDGET: dict = {
    "compute_usd": 0.10,
    "latency_ms": 60000,
    "quality_floor": 0.0,
    "risk_ceiling": 1.0,
}

DEFAULT_BINDINGS: dict = {
    "@wikipedia": {
        "concrete_path": "/document/wikipedia",
        "binding_type": "INVOCABLE",
        "scoped": False,
        "description": "Wikipedia article lookup",
    },
    "@weather": {
        "concrete_path": "/document/weather",
        "binding_type": "INVOCABLE",
        "scoped": False,
        "description": "Weather information service",
    },
    "@files": {
        "concrete_path": "/local/data",
        "binding_type": "CONTENT",
        "scoped": True,
        "description": "Local file access (scoped to namespace home)",
    },
    "@scratch": {
        "concrete_path": "/local/scratch",
        "binding_type": "WRITABLE",
        "scoped": True,
        "description": "Scratch space for temporary data",
    },
    "@sim": {
        "concrete_path": "/sim",
        "binding_type": "ANY",
        "scoped": True,
        "description": "Simulation environment",
    },
}

DEFAULT_DEFAULTS: dict = {
    "dial": 0.5,
    "timeout_seconds": 300,
    "max_cost_usd": 0.10,
    "preferred_runner_labels": [],
}

DEFAULT_VARIABLES: dict = {
    "LOG_LEVEL": {"type": "ENV", "value": "info"},
}

# ---------------------------------------------------------------------------
# Validation — spec §2
# ---------------------------------------------------------------------------


def validate_namespace_id(ns_id: str) -> None:
    """Validate a namespace ID per spec §2.2.

    Raises ValueError with spec error codes on failure.
    """
    if not ns_id:
        raise ValueError("NAMESPACE_ID_INVALID: namespace ID must not be empty")

    if len(ns_id) > MAX_NS_ID_LENGTH:
        raise ValueError("NAMESPACE_ID_TOO_LONG: maximum 256 characters")

    if ns_id == "default":
        return  # Reserved, always valid

    if not _NS_ID_RE.match(ns_id):
        raise ValueError(
            "NAMESPACE_ID_INVALID: must match ^[a-z0-9][a-z0-9_-]*(/[a-z0-9][a-z0-9_-]*)*$"
        )

    segments = ns_id.split("/")
    if len(segments) > MAX_SEGMENTS:
        raise ValueError(
            "NAMESPACE_ID_TOO_DEEP: maximum 4 segments (org/project/env/job)"
        )

    for segment in segments:
        if len(segment) > MAX_SEGMENT_LENGTH:
            raise ValueError(
                "NAMESPACE_SEGMENT_TOO_LONG: each segment maximum 63 characters"
            )


# ---------------------------------------------------------------------------
# Derivation — spec §1.2, §1.3
# ---------------------------------------------------------------------------


def derive_parent_id(ns_id: str) -> str | None:
    """Derive the parent namespace ID from a given ID.

    "default" → None, ORG → "default", deeper → remove last segment.
    """
    if ns_id == "default":
        return None
    segments = ns_id.split("/")
    if len(segments) == 1:
        return "default"
    return "/".join(segments[:-1])


def derive_level(ns_id: str) -> str:
    """Derive the hierarchy level from a namespace ID.

    "default" → DEFAULT, 1 seg → ORG, 2 → PROJECT, 3 → ENV, 4 → JOB.
    """
    if ns_id == "default":
        return "DEFAULT"
    segments = ns_id.split("/")
    n = len(segments)
    if n == 1:
        return "ORG"
    if n == 2:
        return "PROJECT"
    if n == 3:
        return "ENV"
    if n == 4:
        return "JOB"
    raise ValueError(f"NAMESPACE_ID_TOO_DEEP: {n} segments exceeds maximum 4")


# ---------------------------------------------------------------------------
# Pattern subsumption — spec §5.1
# ---------------------------------------------------------------------------


def pattern_subsumes(parent_pat: str, child_pat: str) -> bool:
    """Check if parent pattern subsumes child pattern.

    A parent pattern p subsumes child pattern c if every string matched
    by c is also matched by p.
    """
    if parent_pat == "*":
        return True
    if parent_pat == "/*":
        return child_pat.startswith("/")
    # If parent ends with /* then child must share the prefix
    if parent_pat.endswith("/*"):
        prefix = parent_pat[:-1]  # e.g. "/sync/" from "/sync/*"
        if child_pat.startswith(prefix):
            return True
        # Also check if child is an exact match of the prefix without trailing /
        if child_pat == parent_pat[:-2]:
            return True
    if parent_pat.endswith(".*"):
        prefix = parent_pat[:-1]  # e.g. "db." from "db.*"
        if child_pat.startswith(prefix):
            return True
        if child_pat == parent_pat[:-2]:
            return True
    # Exact match
    if parent_pat == child_pat:
        return True
    # Use fnmatch as last resort
    return fnmatch.fnmatch(child_pat, parent_pat)


# ---------------------------------------------------------------------------
# Composition rules — spec §5
# ---------------------------------------------------------------------------


def intersect_capability(parent: dict, child: dict) -> dict:
    """Capability intersection — spec §5.1.

    Set intersection for primitives/shapes, pattern intersection for
    operations/resources, min for max_effects/max_depth.
    """
    parent_prims = set(parent.get("primitives", []))
    child_prims = set(child.get("primitives", []))
    parent_shapes = set(parent.get("shapes", []))
    child_shapes = set(child.get("shapes", []))

    return {
        "primitives": sorted(parent_prims & child_prims),
        "shapes": sorted(parent_shapes & child_shapes),
        "operations": _pattern_intersect(
            parent.get("operations", []), child.get("operations", [])
        ),
        "resources": _pattern_intersect(
            parent.get("resources", []), child.get("resources", [])
        ),
        "max_effects": min(
            parent.get("max_effects", 1000), child.get("max_effects", 1000)
        ),
        "max_depth": min(parent.get("max_depth", 50), child.get("max_depth", 50)),
    }


def _pattern_intersect(
    parent_patterns: list[str], child_patterns: list[str]
) -> list[str]:
    """Return child patterns subsumed by at least one parent pattern."""
    result = []
    for c in child_patterns:
        for p in parent_patterns:
            if pattern_subsumes(p, c):
                result.append(c)
                break
    return result


def union_deny(parent_deny: dict, child_deny: dict) -> dict:
    """Deny rule union — spec §5.4. Forbid-wins: concatenate rules."""
    parent_rules = parent_deny.get("rules", [])
    child_rules = child_deny.get("rules", [])
    return {"rules": parent_rules + child_rules}


def restrict_budget(parent: dict, child: dict) -> dict:
    """Budget restriction — spec §5.2. Tighter bound wins per dimension."""
    return {
        "compute_usd": min(
            parent.get("compute_usd", 0.10), child.get("compute_usd", 0.10)
        ),
        "latency_ms": min(
            parent.get("latency_ms", 60000), child.get("latency_ms", 60000)
        ),
        "quality_floor": max(
            parent.get("quality_floor", 0.0), child.get("quality_floor", 0.0)
        ),
        "risk_ceiling": min(
            parent.get("risk_ceiling", 1.0), child.get("risk_ceiling", 1.0)
        ),
    }


def overlay_bindings(parent: dict, child: dict) -> dict:
    """Binding overlay — spec §5.6. Child wins on key conflict."""
    result = dict(parent)
    if child:
        result.update(child)
    return result


def merge_variables(effective: dict, child_vars: dict | None) -> dict:
    """Variable merge — spec §5.7. Type-segregated, child overrides parent."""
    if not child_vars:
        return effective

    env_vars = dict(effective.get("env_vars", {}))
    secret_vars = dict(effective.get("secret_vars", {}))
    vault_vars = dict(effective.get("vault_vars", {}))

    for key, var in child_vars.items():
        if isinstance(var, dict):
            var_type = var.get("type", "ENV").upper()
            var_value = var.get("value", "")
        else:
            var_type = "ENV"
            var_value = str(var)

        if var_type == "ENV":
            env_vars[key] = var_value
        elif var_type == "SECRET":
            secret_vars[key] = var_value
        elif var_type == "VAULT":
            vault_vars[key] = var_value

    effective["env_vars"] = env_vars
    effective["secret_vars"] = secret_vars
    effective["vault_vars"] = vault_vars
    return effective


def override_defaults(parent: dict, child: dict) -> dict:
    """Default override — spec §5.8. Child overrides parent on non-null fields."""
    result = dict(parent)
    for key in ("dial", "timeout_seconds", "max_cost_usd", "preferred_runner_labels"):
        val = child.get(key)
        if val is not None:
            result[key] = val
    return result


def resolve_binding(binding: dict, namespace_id: str) -> str:
    """Resolve a single binding to its concrete VFS path — spec §7.3."""
    path = binding.get("concrete_path", "")
    if binding.get("scoped", False):
        return "/home/" + namespace_id + "/" + path.lstrip("/")
    return path


# ---------------------------------------------------------------------------
# Resolution algorithm — spec §4
# ---------------------------------------------------------------------------


def build_ancestor_chain(
    ns_id: str,
    get_ns: Callable[[str], dict | None],
) -> list[dict]:
    """Build ordered chain from DEFAULT (root) to target — spec §4.1.

    *get_ns* is a callback: ``get_ns(namespace_id) -> dict | None``.
    Returns list of namespace dicts, root first.
    """
    chain: list[dict] = []
    visited: set[str] = set()
    current_id: str | None = ns_id

    while current_id is not None:
        if current_id in visited:
            raise ValueError(f"NAMESPACE_CYCLE_DETECTED: cycle at {current_id}")
        visited.add(current_id)

        ns = get_ns(current_id)
        if ns is None:
            raise ValueError(f"NAMESPACE_NOT_FOUND: {current_id}")

        chain.insert(0, ns)  # prepend so root ends up first
        current_id = ns.get("parent_id") or derive_parent_id(current_id)

    # Ensure DEFAULT is always root
    if not chain or chain[0].get("id") != "default":
        default_ns = get_ns("default")
        if default_ns is None:
            raise ValueError("NAMESPACE_DEFAULT_MISSING: registry invariant violated")
        chain.insert(0, default_ns)

    return chain


def resolve_namespace(
    ns_id: str,
    get_ns: Callable[[str], dict | None],
    get_policy: Callable[[str], dict | None],
) -> dict:
    """Resolve a namespace ID to its effective configuration — spec §4.2.

    Returns an EffectiveNamespace dict matching spec §10.
    """
    chain = build_ancestor_chain(ns_id, get_ns)

    effective: dict = {
        "namespace_id": ns_id,
        "chain": [ns["id"] for ns in chain],
        "capability": None,
        "deny": {"rules": []},
        "budget": None,
        "dial_ceiling": None,
        "hash_access": None,
        "bindings": {},
        "env_vars": {},
        "secret_vars": {},
        "vault_vars": {},
        "defaults": None,
    }

    for level_ns in chain:
        effective = _compose(effective, level_ns, get_policy)

    # Resolve scoped bindings
    resolved_bindings: dict = {}
    for ref, binding in effective.get("bindings", {}).items():
        if isinstance(binding, dict):
            resolved_bindings[ref] = resolve_binding(binding, ns_id)
        else:
            resolved_bindings[ref] = binding
    effective["bindings"] = resolved_bindings

    return effective


def _compose(
    effective: dict, level_ns: dict, get_policy: Callable[[str], dict | None]
) -> dict:
    """Apply one level's config onto the running effective state — spec §4.3."""
    policy = get_policy(level_ns["id"])

    # Parse JSON fields from namespace if stored as strings
    ns_bindings = _parse_json_field(level_ns.get("bindings_json") or level_ns.get("bindings"))
    ns_variables = _parse_json_field(level_ns.get("variables_json") or level_ns.get("variables"))
    ns_defaults = _parse_json_field(level_ns.get("config_json") or level_ns.get("defaults"))

    if effective["capability"] is None:
        # First level (DEFAULT): initialize
        if policy:
            effective["capability"] = policy.get("capability", DEFAULT_CAPABILITY)
            effective["deny"] = policy.get("deny", {"rules": []})
            effective["budget"] = policy.get("budget", DEFAULT_BUDGET)
            effective["dial_ceiling"] = policy.get("dial_ceiling", 1.0)
            effective["hash_access"] = policy.get("hash_access", list(ALL_HASH_LEVELS))
        else:
            effective["capability"] = dict(DEFAULT_CAPABILITY)
            effective["deny"] = {"rules": []}
            effective["budget"] = dict(DEFAULT_BUDGET)
            effective["dial_ceiling"] = 1.0
            effective["hash_access"] = list(ALL_HASH_LEVELS)

        if ns_defaults:
            effective["defaults"] = dict(ns_defaults)
        else:
            effective["defaults"] = dict(DEFAULT_DEFAULTS)
    elif policy is not None:
        # Subsequent levels: compose via monotonic narrowing
        if "capability" in policy:
            effective["capability"] = intersect_capability(
                effective["capability"], policy["capability"]
            )
        if "deny" in policy:
            effective["deny"] = union_deny(effective["deny"], policy["deny"])
        if "budget" in policy:
            effective["budget"] = restrict_budget(effective["budget"], policy["budget"])
        if "dial_ceiling" in policy:
            effective["dial_ceiling"] = min(
                effective["dial_ceiling"], policy["dial_ceiling"]
            )
        if "hash_access" in policy:
            effective["hash_access"] = sorted(
                set(effective["hash_access"]) & set(policy["hash_access"])
            )

        # Defaults: child overrides parent
        if ns_defaults and effective["defaults"]:
            effective["defaults"] = override_defaults(effective["defaults"], ns_defaults)
        elif ns_defaults:
            effective["defaults"] = dict(ns_defaults)

    # Bindings: overlay (child wins on key conflict)
    if ns_bindings:
        effective["bindings"] = overlay_bindings(
            effective.get("bindings", {}), ns_bindings
        )

    # Variables: child overrides parent on key conflict
    effective = merge_variables(effective, ns_variables)

    return effective


def _parse_json_field(val) -> dict | None:
    """Parse a JSON string field or return dict as-is."""
    import json as _json

    if val is None:
        return None
    if isinstance(val, dict):
        return val
    if isinstance(val, str):
        try:
            parsed = _json.loads(val)
            return parsed if isinstance(parsed, dict) else None
        except (ValueError, TypeError):
            return None
    return None
