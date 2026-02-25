"""Pure governance validation checks (3-9).

These checks are synchronous and stateless — they operate on in-memory
data structures only. Checks 1, 2, and 10 require store access and remain
in the registry's GovernanceValidatorService.

The ConsentEdge is represented as a simple protocol (any object with
from_namespace, to_namespace, and active attributes).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any

from syncropel_registry_core.constants import _any_glob_match
from syncropel_registry_core.models.governance import (
    DenialKind,
    GovernanceResultType,
)
from syncropel_registry_core.models.sct import (
    GovernanceTier,
    SessionCapabilityToken,
)

# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass
class GovernanceCheckError:
    """A single governance check failure or warning."""

    check_number: int  # 1-10
    check_name: str
    kind: DenialKind
    detail: str
    effect_index: int | None = None
    severity: str = "error"  # "error" or "warning"

    def to_dict(self) -> dict:
        return {
            "check_number": self.check_number,
            "check_name": self.check_name,
            "kind": self.kind.value,
            "detail": self.detail,
            "effect_index": self.effect_index,
            "severity": self.severity,
        }


@dataclass
class GovernanceValidationResult:
    """Aggregate result of running governance checks on a trace."""

    valid: bool = True
    errors: list[GovernanceCheckError] = field(default_factory=list)
    warnings: list[GovernanceCheckError] = field(default_factory=list)
    result_type: GovernanceResultType = GovernanceResultType.ALLOWED
    denial_kind: DenialKind | None = None
    sct_hash: str = ""
    governance_tier: GovernanceTier = GovernanceTier.STANDARD
    hitl_request_id: str | None = None
    checks_passed: list[int] = field(default_factory=list)
    checks_failed: list[int] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "errors": [e.to_dict() for e in self.errors],
            "warnings": [w.to_dict() for w in self.warnings],
            "result_type": self.result_type.value,
            "denial_kind": self.denial_kind.value if self.denial_kind else None,
            "sct_hash": self.sct_hash,
            "governance_tier": self.governance_tier.value,
            "hitl_request_id": self.hitl_request_id,
            "checks_passed": self.checks_passed,
            "checks_failed": self.checks_failed,
        }

    @classmethod
    def denied(
        cls,
        kind: DenialKind,
        errors: list[GovernanceCheckError],
        sct_hash: str = "",
        governance_tier: GovernanceTier = GovernanceTier.STANDARD,
        warnings: list[GovernanceCheckError] | None = None,
    ) -> GovernanceValidationResult:
        """Convenience constructor for a denied result."""
        failed_checks = sorted({e.check_number for e in errors})
        return cls(
            valid=False,
            errors=errors,
            warnings=warnings or [],
            result_type=GovernanceResultType.DENIED,
            denial_kind=kind,
            sct_hash=sct_hash,
            governance_tier=governance_tier,
            checks_failed=failed_checks,
        )


# ---------------------------------------------------------------------------
# Pure governance checks (3-9)
# ---------------------------------------------------------------------------


def check_3_capability(
    trace_effects: list[dict],
    sct: SessionCapabilityToken,
    errors: list[GovernanceCheckError],
    warnings: list[GovernanceCheckError],
) -> None:
    """Check 3: Capability envelope enforcement.

    3a: Primitive must be in capability.primitives (empty set = all allowed)
    3b: Shape must be in capability.shapes (empty set = all allowed)
    3c: Operation must match capability.operations via glob (empty = all)
    3d: Resource must match capability.resources via glob (empty = all)
    """
    cap = sct.capability

    for idx, effect in enumerate(trace_effects):
        primitive = effect.get("primitive", "")
        shape = effect.get("shape", "")
        operation = effect.get("operation", "")
        resource = effect.get("resource", "")

        # 3a: Primitive check
        if cap.primitives and primitive not in cap.primitives:
            errors.append(
                GovernanceCheckError(
                    check_number=3,
                    check_name="capability.primitives",
                    kind=DenialKind.CAPABILITY_VIOLATION,
                    detail=(f"Primitive '{primitive}' not in allowed set {sorted(cap.primitives)}"),
                    effect_index=idx,
                )
            )

        # 3b: Shape check
        if cap.shapes and shape not in cap.shapes:
            errors.append(
                GovernanceCheckError(
                    check_number=3,
                    check_name="capability.shapes",
                    kind=DenialKind.CAPABILITY_VIOLATION,
                    detail=(f"Shape '{shape}' not in allowed set {sorted(cap.shapes)}"),
                    effect_index=idx,
                )
            )

        # 3c: Operation check (empty operations list = all allowed)
        if cap.operations and operation:
            if not _any_glob_match(cap.operations, operation):
                errors.append(
                    GovernanceCheckError(
                        check_number=3,
                        check_name="capability.operations",
                        kind=DenialKind.CAPABILITY_VIOLATION,
                        detail=(
                            f"Operation '{operation}' does not match any "
                            f"allowed pattern {cap.operations}"
                        ),
                        effect_index=idx,
                    )
                )

        # 3d: Resource check (empty resources list = all allowed)
        if cap.resources and resource:
            if not _any_glob_match(cap.resources, resource):
                errors.append(
                    GovernanceCheckError(
                        check_number=3,
                        check_name="capability.resources",
                        kind=DenialKind.CAPABILITY_VIOLATION,
                        detail=(
                            f"Resource '{resource}' does not match any "
                            f"allowed pattern {cap.resources}"
                        ),
                        effect_index=idx,
                    )
                )


def check_4_deny(
    trace_effects: list[dict],
    sct: SessionCapabilityToken,
    errors: list[GovernanceCheckError],
    warnings: list[GovernanceCheckError],
) -> None:
    """Check 4: Deny constraint enforcement.

    No effect may match any deny constraint in the SCT.
    """
    for idx, effect in enumerate(trace_effects):
        primitive = effect.get("primitive", "")
        shape = effect.get("shape", "")
        resource = effect.get("resource", "")

        if sct.deny.matches(sct.principal_did, primitive, shape, resource):
            errors.append(
                GovernanceCheckError(
                    check_number=4,
                    check_name="deny_constraint",
                    kind=DenialKind.DENY_CONSTRAINT,
                    detail=(
                        f"Effect {primitive} {shape} on '{resource}' matches a deny constraint"
                    ),
                    effect_index=idx,
                )
            )


def check_5_budget_session(
    trace_effects: list[dict],
    sct: SessionCapabilityToken,
    errors: list[GovernanceCheckError],
    warnings: list[GovernanceCheckError],
) -> None:
    """Check 5: Budget session ceiling (aggregate compute/latency).

    - Sum of estimated_cost across effects <= budget.compute (0 = unlimited)
    - Sum of estimated_latency across effects <= budget.latency (0 = unlimited)
    """
    budget = sct.budget

    total_cost = Decimal("0")
    total_latency = Decimal("0")

    for effect in trace_effects:
        total_cost += _to_decimal(effect.get("estimated_cost", "0"))
        total_latency += _to_decimal(effect.get("estimated_latency", "0"))

    # Compute budget check (aggregate, 0 = unlimited)
    if budget.compute > Decimal("0") and total_cost > budget.compute:
        errors.append(
            GovernanceCheckError(
                check_number=5,
                check_name="budget.compute",
                kind=DenialKind.BUDGET_EXCEEDED,
                detail=(
                    f"Total estimated cost {total_cost} exceeds compute budget {budget.compute}"
                ),
                effect_index=None,
            )
        )

    # Latency budget check (aggregate, 0 = unlimited)
    if budget.latency > Decimal("0") and total_latency > budget.latency:
        errors.append(
            GovernanceCheckError(
                check_number=5,
                check_name="budget.latency",
                kind=DenialKind.BUDGET_EXCEEDED,
                detail=(
                    f"Total estimated latency {total_latency}ms exceeds "
                    f"latency budget {budget.latency}ms"
                ),
                effect_index=None,
            )
        )

    # Budget utilization warnings (> 80%)
    if budget.compute > Decimal("0"):
        utilization = total_cost / budget.compute
        if utilization > Decimal("0.8") and total_cost <= budget.compute:
            warnings.append(
                GovernanceCheckError(
                    check_number=5,
                    check_name="budget.compute",
                    kind=DenialKind.BUDGET_EXCEEDED,
                    detail=(
                        f"Compute budget utilization at "
                        f"{utilization * 100:.0f}% "
                        f"({total_cost}/{budget.compute})"
                    ),
                    effect_index=None,
                    severity="warning",
                )
            )


def check_6_dial(
    sct: SessionCapabilityToken,
    dial_position: Decimal | None,
    errors: list[GovernanceCheckError],
) -> None:
    """Check 6: Dial position <= SCT dial ceiling."""
    if dial_position is not None:
        if dial_position > sct.dial_ceiling:
            errors.append(
                GovernanceCheckError(
                    check_number=6,
                    check_name="dial_ceiling",
                    kind=DenialKind.DIAL_CEILING_EXCEEDED,
                    detail=(
                        f"Dial position {dial_position} exceeds SCT dial ceiling {sct.dial_ceiling}"
                    ),
                    effect_index=None,
                )
            )


def check_7_hash_level(
    sct: SessionCapabilityToken,
    requested_hash_level: str | None,
    errors: list[GovernanceCheckError],
) -> None:
    """Check 7: Hash level access.

    Verify that the requested hash level is in the SCT's hash_access set.
    L0 is always local-only and must never leave the namespace (F8).
    """
    if requested_hash_level is None:
        return

    if requested_hash_level not in sct.hash_access:
        errors.append(
            GovernanceCheckError(
                check_number=7,
                check_name="hash_level_access",
                kind=DenialKind.CAPABILITY_VIOLATION,
                detail=(
                    f"Hash level '{requested_hash_level}' not in SCT "
                    f"hash_access {sorted(sct.hash_access)}"
                ),
            )
        )


def check_8_budget_guard(
    trace_effects: list[dict],
    sct: SessionCapabilityToken,
    errors: list[GovernanceCheckError],
    warnings: list[GovernanceCheckError],
) -> None:
    """Check 8: Budget guard — per-effect quality floor and risk ceiling.

    - Per-effect quality >= budget.quality (quality floor)
    - Per-effect risk <= budget.risk (risk ceiling)
    """
    budget = sct.budget

    for idx, effect in enumerate(trace_effects):
        quality = _to_decimal(effect.get("quality", "1"))
        risk = _to_decimal(effect.get("risk", "0"))

        # Quality floor check (per-effect)
        if budget.quality > Decimal("0") and quality < budget.quality:
            errors.append(
                GovernanceCheckError(
                    check_number=8,
                    check_name="budget.quality",
                    kind=DenialKind.BUDGET_EXCEEDED,
                    detail=(
                        f"Effect quality {quality} is below budget quality floor {budget.quality}"
                    ),
                    effect_index=idx,
                )
            )

        # Risk ceiling check (per-effect)
        if risk > budget.risk:
            errors.append(
                GovernanceCheckError(
                    check_number=8,
                    check_name="budget.risk",
                    kind=DenialKind.BUDGET_EXCEEDED,
                    detail=(f"Effect risk {risk} exceeds budget risk ceiling {budget.risk}"),
                    effect_index=idx,
                )
            )


def check_9b_output_constraints(
    trace_effects: list[dict],
    sct: SessionCapabilityToken,
    errors: list[GovernanceCheckError],
    warnings: list[GovernanceCheckError],
) -> None:
    """9b: Output constraints enforcement."""
    oc = sct.output_constraints
    if oc is None:
        return

    for idx, effect in enumerate(trace_effects):
        output_shape = effect.get("output_shape", effect.get("shape", ""))
        resource = effect.get("resource", "")

        # max_many_cardinality check
        if oc.max_many_cardinality is not None and output_shape == "MANY":
            cardinality = effect.get("output_cardinality", 0)
            if isinstance(cardinality, str):
                try:
                    cardinality = int(cardinality)
                except (ValueError, TypeError):
                    cardinality = 0
            if cardinality > oc.max_many_cardinality:
                errors.append(
                    GovernanceCheckError(
                        check_number=9,
                        check_name="output_constraints.max_many_cardinality",
                        kind=DenialKind.SHAPE_CONSTRAINT_VIOLATION,
                        detail=(
                            f"MANY output cardinality {cardinality} exceeds "
                            f"limit {oc.max_many_cardinality}"
                        ),
                        effect_index=idx,
                    )
                )

        # deny_shapes_on_resources check
        if resource and oc.deny_shapes_on_resources:
            for denied_shape, resource_patterns in oc.deny_shapes_on_resources:
                if output_shape == denied_shape and _any_glob_match(resource_patterns, resource):
                    errors.append(
                        GovernanceCheckError(
                            check_number=9,
                            check_name="output_constraints.deny_shapes_on_resources",
                            kind=DenialKind.SHAPE_CONSTRAINT_VIOLATION,
                            detail=(f"Shape '{denied_shape}' is denied on resource '{resource}'"),
                            effect_index=idx,
                        )
                    )


def check_9c_lineage_integrity(
    trace_effects: list[dict],
    errors: list[GovernanceCheckError],
    warnings: list[GovernanceCheckError],
) -> None:
    """9c: Lineage integrity check.

    Each effect that claims a content_hash must have a non-empty value.
    Effects without a content_hash field are assumed to be new (pass).
    """
    for idx, effect in enumerate(trace_effects):
        content_hash = effect.get("content_hash")
        # Only check if the field is explicitly present but empty
        if content_hash is not None and content_hash == "":
            errors.append(
                GovernanceCheckError(
                    check_number=9,
                    check_name="lineage_integrity",
                    kind=DenialKind.LINEAGE_INTEGRITY_FAILURE,
                    detail=(
                        f"Effect at index {idx} has an empty content_hash, "
                        f"indicating broken lineage"
                    ),
                    effect_index=idx,
                )
            )


def check_9d_federation_consent(
    trace_effects: list[dict],
    sct: SessionCapabilityToken,
    consent_edges: list[Any] | None,
    errors: list[GovernanceCheckError],
    warnings: list[GovernanceCheckError],
) -> None:
    """9d: Federation consent check.

    Any effect targeting a cross-namespace sync:// resource requires a
    matching consent edge from the target namespace to the SCT's namespace.

    consent_edges should be objects with from_namespace, to_namespace,
    and active attributes.
    """
    sct_namespace = sct.namespace
    if not sct_namespace:
        return

    for idx, effect in enumerate(trace_effects):
        resource = effect.get("resource", "")
        if not resource:
            continue

        target_namespace = _extract_namespace_from_resource(resource)
        if target_namespace is None:
            continue

        if target_namespace == sct_namespace:
            continue

        # Cross-namespace access: require a consent edge
        if not _has_consent_edge(
            consent_edges,
            target_namespace,
            sct_namespace,
        ):
            errors.append(
                GovernanceCheckError(
                    check_number=9,
                    check_name="federation_consent",
                    kind=DenialKind.FEDERATION_CONSENT_DENIED,
                    detail=(
                        f"Cross-namespace access to '{resource}' "
                        f"(namespace '{target_namespace}') requires a "
                        f"consent edge from '{target_namespace}' to "
                        f"'{sct_namespace}'"
                    ),
                    effect_index=idx,
                )
            )


def validate_checks_3_to_9(
    trace_effects: list[dict],
    sct: SessionCapabilityToken,
    dial_position: Decimal | None = None,
    requested_hash_level: str | None = None,
    consent_edges: list[Any] | None = None,
) -> GovernanceValidationResult:
    """Run pure governance checks 3-9 and return aggregate result.

    This is a convenience function for running all pure checks at once.
    Checks 1, 2, and 10 require store access and are not included.
    """
    errors: list[GovernanceCheckError] = []
    warnings: list[GovernanceCheckError] = []
    checks_passed: list[int] = []
    checks_failed: list[int] = []

    sct_hash = sct.content_hash()
    governance_tier = sct.governance_tier

    # Check 3: Capability
    cap_before = len(errors)
    check_3_capability(trace_effects, sct, errors, warnings)
    (checks_passed if len(errors) == cap_before else checks_failed).append(3)

    # Check 4: Deny
    deny_before = len(errors)
    check_4_deny(trace_effects, sct, errors, warnings)
    (checks_passed if len(errors) == deny_before else checks_failed).append(4)

    # Check 5: Budget session
    budget_before = len(errors)
    check_5_budget_session(trace_effects, sct, errors, warnings)
    (checks_passed if len(errors) == budget_before else checks_failed).append(5)

    # Check 6: Dial
    dial_before = len(errors)
    check_6_dial(sct, dial_position, errors)
    (checks_passed if len(errors) == dial_before else checks_failed).append(6)

    # Check 7: Hash level
    hash_before = len(errors)
    check_7_hash_level(sct, requested_hash_level, errors)
    (checks_passed if len(errors) == hash_before else checks_failed).append(7)

    # Check 8: Budget guard
    guard_before = len(errors)
    check_8_budget_guard(trace_effects, sct, errors, warnings)
    (checks_passed if len(errors) == guard_before else checks_failed).append(8)

    # Check 9: Structural (9a: max_effects + sub-checks 9b-9d)
    struct_before = len(errors)
    cap = sct.capability
    if len(trace_effects) > cap.max_effects:
        errors.append(
            GovernanceCheckError(
                check_number=9,
                check_name="structural.max_effects",
                kind=DenialKind.CAPABILITY_VIOLATION,
                detail=(
                    f"Trace has {len(trace_effects)} effects, "
                    f"exceeding max_effects limit of {cap.max_effects}"
                ),
                effect_index=None,
            )
        )
    check_9b_output_constraints(trace_effects, sct, errors, warnings)
    check_9c_lineage_integrity(trace_effects, errors, warnings)
    check_9d_federation_consent(trace_effects, sct, consent_edges, errors, warnings)
    (checks_passed if len(errors) == struct_before else checks_failed).append(9)

    if errors:
        primary_kind = errors[0].kind
        return GovernanceValidationResult(
            valid=False,
            errors=errors,
            warnings=warnings,
            result_type=GovernanceResultType.DENIED,
            denial_kind=primary_kind,
            sct_hash=sct_hash,
            governance_tier=governance_tier,
            checks_passed=sorted(checks_passed),
            checks_failed=sorted(set(checks_failed)),
        )

    return GovernanceValidationResult(
        valid=True,
        errors=[],
        warnings=warnings,
        result_type=GovernanceResultType.ALLOWED,
        sct_hash=sct_hash,
        governance_tier=governance_tier,
        checks_passed=sorted(checks_passed),
        checks_failed=[],
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _to_decimal(value) -> Decimal:
    """Safely convert a value to Decimal."""
    if isinstance(value, Decimal):
        return value
    try:
        return Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        return Decimal("0")


def _extract_namespace_from_resource(resource: str) -> str | None:
    """Extract the namespace from a sync:// resource URI.

    sync:// URIs have the form: sync://<namespace>/<path>
    e.g. sync://acme/analytics/data -> namespace "acme"

    Returns the namespace string, or None if the resource is not a sync:// URI.
    """
    if not resource.startswith("sync://"):
        return None

    path = resource[len("sync://") :]
    if not path:
        return None

    parts = path.split("/")
    if not parts or not parts[0]:
        return None

    return parts[0]


def _has_consent_edge(
    consent_edges: list[Any] | None,
    from_namespace: str,
    to_namespace: str,
) -> bool:
    """Check whether a consent edge exists from one namespace to another."""
    if not consent_edges:
        return False
    for edge in consent_edges:
        if (
            edge.from_namespace == from_namespace
            and edge.to_namespace == to_namespace
            and edge.active
        ):
            return True
    return False
