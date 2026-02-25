"""Pure SCT computation helpers — extracted from registry sct_service.py.

These are the synchronous, store-independent helpers used during SCT
computation. The async compute_sct() orchestrator remains in the registry.
"""

from __future__ import annotations

from decimal import Decimal
from fnmatch import fnmatch

from syncropel_registry_core.models.sct import (
    BudgetEnvelope,
    CapabilityEnvelope,
    DenyConstraint,
)
from syncropel_registry_core.trust import GovernanceTrustScore


def resolve_namespace_hierarchy(namespace: str) -> list[str]:
    """Walk DEFAULT -> ORG -> PROJECT -> ENV -> JOB.

    e.g., "acme/analytics/prod" -> ["default", "acme", "acme/analytics", "acme/analytics/prod"]
    """
    chain = ["default"]
    if not namespace or namespace == "default":
        return chain

    parts = namespace.split("/")
    for i in range(len(parts)):
        chain.append("/".join(parts[: i + 1]))
    return chain


def intersect_capabilities(policies: list) -> CapabilityEnvelope:
    """Intersect capability envelopes from all policies in the hierarchy.

    Each policy must have a ``capability`` attribute that is a
    CapabilityEnvelope.
    """
    if not policies:
        return CapabilityEnvelope()

    result = policies[0].capability
    for policy in policies[1:]:
        result = result.intersect(policy.capability)
    return result


def collect_deny_constraints(
    policies: list,
    principal_did: str,
) -> list[DenyConstraint]:
    """Gather deny constraints from all namespace levels.

    Each policy must have a ``deny_constraints`` attribute that is a
    list of DenyConstraint objects.
    """
    constraints = []
    for policy in policies:
        for dc in policy.deny_constraints:
            if fnmatch(principal_did, dc.principal_pattern):
                constraints.append(dc)
    return constraints


def apply_principal_overrides(
    policies: list,
    principal_did: str,
    capability: CapabilityEnvelope,
) -> CapabilityEnvelope:
    """Apply principal-specific overrides (further intersection).

    Each policy must have a ``principals`` attribute with objects that
    have ``match``, ``primitives``, ``operations``, and ``resources``
    attributes.
    """
    for policy in policies:
        for override in policy.principals:
            if fnmatch(principal_did, override.match):
                override_envelope = CapabilityEnvelope(
                    primitives=set(override.primitives)
                    if override.primitives
                    else capability.primitives,
                    shapes=capability.shapes,
                    operations=override.operations
                    if override.operations
                    else capability.operations,
                    resources=override.resources if override.resources else capability.resources,
                    max_effects=capability.max_effects,
                    max_depth=capability.max_depth,
                )
                capability = capability.intersect(override_envelope)
    return capability


def compute_dial_ceiling(
    sa_config,
    namespace_policies: list,
    trust_score: Decimal,
    budget_ratio: Decimal,
) -> Decimal:
    """Compute dial ceiling as min of all constraints.

    sa_config may be None. If provided, must have a ``max_dial`` attribute.
    Each policy must have a ``dial_ceiling`` attribute.
    """
    ceilings = [Decimal("1")]

    # SA identity constraint
    if sa_config:
        ceilings.append(Decimal(str(sa_config.max_dial)))

    # Namespace constraints
    for policy in namespace_policies:
        ceilings.append(policy.dial_ceiling)

    # Trust-derived ceiling
    ceilings.append(GovernanceTrustScore.trust_to_dial_ceiling(trust_score))

    # Budget constraint: if budget is mostly spent, lower dial ceiling
    if budget_ratio < Decimal("0.1"):
        ceilings.append(Decimal("0.3333"))  # REPLAY only
    elif budget_ratio < Decimal("0.25"):
        ceilings.append(Decimal("0.5"))  # up to ADAPT
    elif budget_ratio < Decimal("0.5"):
        ceilings.append(Decimal("0.6667"))  # up to EXPLORE

    return min(ceilings)


def build_budget_envelope(
    policies: list,
    sa_config=None,
) -> BudgetEnvelope:
    """Compose budget from namespace hierarchy (tighter bound wins).

    Each policy must have budget_compute, budget_latency, budget_quality,
    budget_risk attributes. sa_config, if provided, must have the same.
    """
    budget = BudgetEnvelope()

    for policy in policies:
        policy_budget = BudgetEnvelope(
            compute=policy.budget_compute,
            latency=policy.budget_latency,
            quality=policy.budget_quality,
            risk=policy.budget_risk,
        )
        budget = budget.restrict(policy_budget)

    if sa_config:
        sa_budget = BudgetEnvelope(
            compute=Decimal(str(sa_config.budget_compute)),
            latency=Decimal(str(sa_config.budget_latency)),
            quality=Decimal(str(sa_config.budget_quality)),
            risk=Decimal(str(sa_config.budget_risk)),
        )
        budget = budget.restrict(sa_budget)

    return budget


def dial_zone_to_hash_access(
    dial_ceiling: Decimal,
    policies: list,
) -> set[str]:
    """Map dial zone to accessible hash levels, intersected with namespace consent.

    Each policy, if it has a ``hash_access`` attribute, provides a list
    of allowed hash levels.
    """
    # Dial-based access
    if dial_ceiling < Decimal("0.3333"):
        dial_access = {"L0"}
    elif dial_ceiling < Decimal("0.5"):
        dial_access = {"L0", "L1"}
    elif dial_ceiling < Decimal("0.6667"):
        dial_access = {"L0", "L1", "L2"}
    else:
        dial_access = {"L0", "L1", "L2", "L3"}

    # Intersect with namespace federation consent
    namespace_access = None
    for policy in policies:
        if policy.hash_access:
            ns_set = set(policy.hash_access) | {"L0"}  # L0 always local
            if namespace_access is None:
                namespace_access = ns_set
            else:
                namespace_access &= ns_set

    if namespace_access:
        return dial_access & namespace_access
    return dial_access
