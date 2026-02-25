"""Session Capability Token (SCT) — primary governance primitive.

An SCT is a cryptographically signed token computed once at session creation.
It carries all governance constraints: capabilities, budget, dial ceiling,
trust score, and hash access levels. The runner uses the SCT for every
governance check — no runtime database lookups required.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum

from syncropel_registry_core.constants import _any_glob_match


class PrincipalType(StrEnum):
    """Type of principal requesting a session."""

    USER = "USER"
    SERVICE = "SERVICE"
    RUNNER = "RUNNER"
    ANONYMOUS = "ANONYMOUS"


class GovernanceTier(StrEnum):
    """Governance tier determines enforcement level."""

    STANDARD = "STANDARD"
    ELEVATED = "ELEVATED"


class HashLevel(StrEnum):
    """Four-level content-addressed hashing for privacy-preserving transfer."""

    L0 = "L0"  # Exact (all params) — never leaves local
    L1 = "L1"  # Structural (ops + shapes, no params)
    L2 = "L2"  # Flow (primitives + shapes)
    L3 = "L3"  # Intent (effects only)


@dataclass
class QuadMetrics:
    """Four-dimensional cost model."""

    compute: Decimal = Decimal("0")  # USD
    latency: Decimal = Decimal("0")  # milliseconds
    quality: Decimal = Decimal("0")  # quality score [0, 1]
    risk: Decimal = Decimal("0")  # risk score [0, 1]

    def to_dict(self) -> dict:
        return {
            "compute": str(self.compute),
            "latency": str(self.latency),
            "quality": str(self.quality),
            "risk": str(self.risk),
        }

    @classmethod
    def from_dict(cls, data: dict) -> QuadMetrics:
        if not data:
            return cls()
        return cls(
            compute=Decimal(str(data.get("compute", "0"))),
            latency=Decimal(str(data.get("latency", "0"))),
            quality=Decimal(str(data.get("quality", "0"))),
            risk=Decimal(str(data.get("risk", "0"))),
        )


@dataclass
class CapabilityEnvelope:
    """Defines what effects a session is allowed to execute.

    Capabilities compose via set intersection — narrowing only, never widening.
    """

    primitives: set[str] = field(default_factory=lambda: {"GET", "PUT", "CALL", "MAP"})
    shapes: set[str] = field(default_factory=lambda: {"VOID", "ONE", "OPTIONAL", "MANY", "KEYED"})
    operations: list[str] = field(default_factory=list)  # glob patterns
    resources: list[str] = field(default_factory=list)  # VFS glob patterns
    max_effects: int = 1000
    max_depth: int = 20

    def contains(self, primitive: str, shape: str, operation: str = "", resource: str = "") -> bool:
        """Check if this envelope allows the given effect parameters."""
        if primitive not in self.primitives:
            return False
        if shape not in self.shapes:
            return False
        if self.operations and operation:
            if not _any_glob_match(self.operations, operation):
                return False
        if self.resources and resource:
            if not _any_glob_match(self.resources, resource):
                return False
        return True

    def intersect(self, other: CapabilityEnvelope) -> CapabilityEnvelope:
        """Compute the intersection of two capability envelopes."""
        return CapabilityEnvelope(
            primitives=self.primitives & other.primitives,
            shapes=self.shapes & other.shapes,
            operations=_intersect_patterns(self.operations, other.operations),
            resources=_intersect_patterns(self.resources, other.resources),
            max_effects=min(self.max_effects, other.max_effects),
            max_depth=min(self.max_depth, other.max_depth),
        )

    def to_dict(self) -> dict:
        return {
            "primitives": sorted(self.primitives),
            "shapes": sorted(self.shapes),
            "operations": self.operations,
            "resources": self.resources,
            "max_effects": self.max_effects,
            "max_depth": self.max_depth,
        }

    @classmethod
    def from_dict(cls, data: dict) -> CapabilityEnvelope:
        if not data:
            return cls()
        return cls(
            primitives=set(data.get("primitives", ["GET", "PUT", "CALL", "MAP"])),
            shapes=set(data.get("shapes", ["VOID", "ONE", "OPTIONAL", "MANY", "KEYED"])),
            operations=data.get("operations", []),
            resources=data.get("resources", []),
            max_effects=data.get("max_effects", 1000),
            max_depth=data.get("max_depth", 20),
        )


@dataclass
class DenyConstraint:
    """A structural deny rule baked into the SCT."""

    principal_pattern: str = "*"
    resources: list[str] = field(default_factory=list)
    primitives_on_resources: list[tuple[str, list[str]]] = field(default_factory=list)
    shapes_on_resources: list[tuple[str, list[str]]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "principal_pattern": self.principal_pattern,
            "resources": self.resources,
            "primitives_on_resources": [
                {"primitive": p, "resources": r} for p, r in self.primitives_on_resources
            ],
            "shapes_on_resources": [
                {"shape": s, "resources": r} for s, r in self.shapes_on_resources
            ],
        }

    @classmethod
    def from_dict(cls, data: dict) -> DenyConstraint:
        if not data:
            return cls()
        por = [
            (item["primitive"], item["resources"])
            for item in data.get("primitives_on_resources", [])
        ]
        sor = [(item["shape"], item["resources"]) for item in data.get("shapes_on_resources", [])]
        return cls(
            principal_pattern=data.get("principal_pattern", "*"),
            resources=data.get("resources", []),
            primitives_on_resources=por,
            shapes_on_resources=sor,
        )


@dataclass
class DenyEnvelope:
    """Collection of deny constraints applied after capability intersection."""

    constraints: list[DenyConstraint] = field(default_factory=list)

    def matches(self, principal_did: str, primitive: str, shape: str, resource: str) -> bool:
        """Check if any deny constraint matches the given effect parameters."""
        from fnmatch import fnmatch

        for c in self.constraints:
            if not fnmatch(principal_did, c.principal_pattern):
                continue
            # Check resource-level deny
            if c.resources and _any_glob_match(c.resources, resource):
                return True
            # Check primitive-on-resource deny
            for p, resources in c.primitives_on_resources:
                if p == primitive and _any_glob_match(resources, resource):
                    return True
            # Check shape-on-resource deny
            for s, resources in c.shapes_on_resources:
                if s == shape and _any_glob_match(resources, resource):
                    return True
        return False

    def to_dict(self) -> dict:
        return {"constraints": [c.to_dict() for c in self.constraints]}

    @classmethod
    def from_dict(cls, data: dict) -> DenyEnvelope:
        if not data:
            return cls()
        return cls(constraints=[DenyConstraint.from_dict(c) for c in data.get("constraints", [])])


@dataclass
class BudgetEnvelope:
    """Four-dimensional budget for a session using QuadMetrics."""

    compute: Decimal = Decimal("0")  # USD ceiling (0 = unlimited)
    latency: Decimal = Decimal("0")  # milliseconds ceiling (0 = unlimited)
    quality: Decimal = Decimal("0")  # quality floor [0, 1]
    risk: Decimal = Decimal("1")  # risk ceiling [0, 1]
    spent_compute: Decimal = Decimal("0")
    spent_latency: Decimal = Decimal("0")

    def can_afford(self, cost: QuadMetrics) -> bool:
        """Check if budget can afford the given cost."""
        if self.compute > 0 and self.spent_compute + cost.compute > self.compute:
            return False
        if self.latency > 0 and self.spent_latency + cost.latency > self.latency:
            return False
        if cost.quality < self.quality:
            return False
        if cost.risk > self.risk:
            return False
        return True

    def remaining(self) -> QuadMetrics:
        """Return remaining budget as QuadMetrics."""
        return QuadMetrics(
            compute=max(self.compute - self.spent_compute, Decimal("0")),
            latency=max(self.latency - self.spent_latency, Decimal("0")),
            quality=self.quality,
            risk=self.risk,
        )

    def restrict(self, other: BudgetEnvelope) -> BudgetEnvelope:
        """Return a tighter budget envelope (intersection)."""
        return BudgetEnvelope(
            compute=min(self.compute, other.compute)
            if self.compute > 0 and other.compute > 0
            else max(self.compute, other.compute),
            latency=min(self.latency, other.latency)
            if self.latency > 0 and other.latency > 0
            else max(self.latency, other.latency),
            quality=max(self.quality, other.quality),
            risk=min(self.risk, other.risk),
        )

    def to_dict(self) -> dict:
        return {
            "compute": str(self.compute),
            "latency": str(self.latency),
            "quality": str(self.quality),
            "risk": str(self.risk),
            "spent_compute": str(self.spent_compute),
            "spent_latency": str(self.spent_latency),
        }

    @classmethod
    def from_dict(cls, data: dict) -> BudgetEnvelope:
        if not data:
            return cls()
        return cls(
            compute=Decimal(str(data.get("compute", "0"))),
            latency=Decimal(str(data.get("latency", "0"))),
            quality=Decimal(str(data.get("quality", "0"))),
            risk=Decimal(str(data.get("risk", "1"))),
            spent_compute=Decimal(str(data.get("spent_compute", "0"))),
            spent_latency=Decimal(str(data.get("spent_latency", "0"))),
        )


@dataclass
class OutputConstraints:
    """Constraints on output shapes for data exfiltration control."""

    max_many_cardinality: int | None = None
    deny_shapes_on_resources: list[tuple[str, list[str]]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "max_many_cardinality": self.max_many_cardinality,
            "deny_shapes_on_resources": [
                {"shape": s, "resources": r} for s, r in self.deny_shapes_on_resources
            ],
        }

    @classmethod
    def from_dict(cls, data: dict) -> OutputConstraints:
        if not data:
            return cls()
        dsor = [
            (item["shape"], item["resources"]) for item in data.get("deny_shapes_on_resources", [])
        ]
        return cls(
            max_many_cardinality=data.get("max_many_cardinality"),
            deny_shapes_on_resources=dsor,
        )


@dataclass
class CrossNamespaceGrant:
    """Permission to access resources in another namespace."""

    target_namespace: str = ""
    capability: CapabilityEnvelope = field(default_factory=CapabilityEnvelope)
    hash_levels: set[str] = field(default_factory=set)
    expires_at: str | None = None
    budget: BudgetEnvelope | None = None
    issuer_signature: str = ""

    def to_dict(self) -> dict:
        return {
            "target_namespace": self.target_namespace,
            "capability": self.capability.to_dict(),
            "hash_levels": sorted(self.hash_levels),
            "expires_at": self.expires_at,
            "budget": self.budget.to_dict() if self.budget else None,
            "issuer_signature": self.issuer_signature,
        }

    @classmethod
    def from_dict(cls, data: dict) -> CrossNamespaceGrant:
        if not data:
            return cls()
        budget_data = data.get("budget")
        return cls(
            target_namespace=data.get("target_namespace", ""),
            capability=CapabilityEnvelope.from_dict(data.get("capability", {})),
            hash_levels=set(data.get("hash_levels", [])),
            expires_at=data.get("expires_at"),
            budget=BudgetEnvelope.from_dict(budget_data) if budget_data else None,
            issuer_signature=data.get("issuer_signature", ""),
        )


@dataclass
class SessionCapabilityToken:
    """The SCT — carries all governance constraints for a session.

    Content-addressed via content_hash(). Once issued, immutable.
    """

    # Identity
    principal_did: str = ""
    principal_type: PrincipalType = PrincipalType.ANONYMOUS

    # Capability
    capability: CapabilityEnvelope = field(default_factory=CapabilityEnvelope)
    deny: DenyEnvelope = field(default_factory=DenyEnvelope)

    # Budget
    budget: BudgetEnvelope = field(default_factory=BudgetEnvelope)

    # Dial
    dial_ceiling: Decimal = Decimal("1")
    governance_tier: GovernanceTier = GovernanceTier.STANDARD

    # Trust
    trust_score: Decimal = Decimal("0.47")
    trust_freshness: Decimal = Decimal("1")

    # Visibility
    hash_access: set[str] = field(default_factory=lambda: {"L0", "L1", "L2", "L3"})

    # Scope
    namespace: str = ""
    cross_namespace_grants: list[CrossNamespaceGrant] = field(default_factory=list)

    # Structural limits
    max_effects: int = 1000
    max_depth: int = 20
    output_constraints: OutputConstraints | None = None

    # Validity
    issued_at: str = ""
    expires_at: str = ""
    policy_version: str = ""

    # Authority
    issuer_did: str = ""

    # Revocation tracking
    revoked: bool = False
    revoked_at: str | None = None

    # Delegation
    parent_sct_hash: str | None = None
    delegation_chain: list[str] = field(default_factory=list)

    # Cryptographic signing (excluded from content hash)
    issuer_signature: str = ""  # Base64-encoded Ed25519 signature
    principal_key: str = ""  # Hex-encoded Ed25519 public key (optional)

    def content_hash(self) -> str:
        """Compute deterministic content hash of this SCT."""
        canonical = json.dumps(self._canonical_dict(), sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def is_valid(self) -> bool:
        """Check if the SCT is currently valid (not expired, not revoked)."""
        if self.revoked:
            return False
        if not self.expires_at:
            return False
        now = datetime.now(UTC).isoformat()
        return now < self.expires_at

    def is_revoked(self) -> bool:
        return self.revoked

    def _canonical_dict(self) -> dict:
        """Produce a canonical dict for hashing (excludes mutable fields)."""
        return {
            "principal_did": self.principal_did,
            "principal_type": self.principal_type.value,
            "capability": self.capability.to_dict(),
            "deny": self.deny.to_dict(),
            "budget": {
                "compute": str(self.budget.compute),
                "latency": str(self.budget.latency),
                "quality": str(self.budget.quality),
                "risk": str(self.budget.risk),
            },
            "dial_ceiling": str(self.dial_ceiling),
            "governance_tier": self.governance_tier.value,
            "trust_score": str(self.trust_score),
            "hash_access": sorted(self.hash_access),
            "namespace": self.namespace,
            "max_effects": self.max_effects,
            "max_depth": self.max_depth,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "policy_version": self.policy_version,
            "issuer_did": self.issuer_did,
            "parent_sct_hash": self.parent_sct_hash,
            "delegation_chain": self.delegation_chain,
        }

    def is_expired(self) -> bool:
        """Check if the SCT has expired (alias for time component of is_valid)."""
        if not self.expires_at:
            return True
        from datetime import datetime

        now = datetime.now(UTC).isoformat()
        return now >= self.expires_at

    def to_dict(self) -> dict:
        d = self._canonical_dict()
        d["trust_freshness"] = str(self.trust_freshness)
        d["cross_namespace_grants"] = [g.to_dict() for g in self.cross_namespace_grants]
        d["output_constraints"] = (
            self.output_constraints.to_dict() if self.output_constraints else None
        )
        d["revoked"] = self.revoked
        d["revoked_at"] = self.revoked_at
        d["content_hash"] = self.content_hash()
        d["issuer_signature"] = self.issuer_signature
        d["principal_key"] = self.principal_key
        return d

    @classmethod
    def from_dict(cls, data: dict) -> SessionCapabilityToken:
        if not data:
            return cls()
        oc = data.get("output_constraints")
        grants = [CrossNamespaceGrant.from_dict(g) for g in data.get("cross_namespace_grants", [])]
        return cls(
            principal_did=data.get("principal_did", ""),
            principal_type=PrincipalType(data.get("principal_type", "ANONYMOUS")),
            capability=CapabilityEnvelope.from_dict(data.get("capability", {})),
            deny=DenyEnvelope.from_dict(data.get("deny", {})),
            budget=BudgetEnvelope.from_dict(data.get("budget", {})),
            dial_ceiling=Decimal(str(data.get("dial_ceiling", "1"))),
            governance_tier=GovernanceTier(data.get("governance_tier", "STANDARD")),
            trust_score=Decimal(str(data.get("trust_score", "0.47"))),
            trust_freshness=Decimal(str(data.get("trust_freshness", "1"))),
            hash_access=set(data.get("hash_access", ["L0", "L1", "L2", "L3"])),
            namespace=data.get("namespace", ""),
            cross_namespace_grants=grants,
            max_effects=data.get("max_effects", 1000),
            max_depth=data.get("max_depth", 20),
            output_constraints=OutputConstraints.from_dict(oc) if oc else None,
            issued_at=data.get("issued_at", ""),
            expires_at=data.get("expires_at", ""),
            policy_version=data.get("policy_version", ""),
            issuer_did=data.get("issuer_did", ""),
            revoked=data.get("revoked", False),
            revoked_at=data.get("revoked_at"),
            parent_sct_hash=data.get("parent_sct_hash"),
            delegation_chain=data.get("delegation_chain", []),
            issuer_signature=data.get("issuer_signature", ""),
            principal_key=data.get("principal_key", ""),
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _intersect_patterns(a: list[str], b: list[str]) -> list[str]:
    """Intersect two pattern lists using subsumption.

    Returns b's patterns that are subsumed by at least one pattern in a,
    plus a's patterns subsumed by at least one in b (symmetric subsumption).
    If either list is empty, use the other (identity element).
    """
    if not a:
        return list(b)
    if not b:
        return list(a)
    from syncropel_registry_core.namespaces import pattern_subsumes

    result = []
    for pat_b in b:
        for pat_a in a:
            if pattern_subsumes(pat_a, pat_b):
                result.append(pat_b)
                break
    for pat_a in a:
        if pat_a not in result:
            for pat_b in b:
                if pattern_subsumes(pat_b, pat_a):
                    result.append(pat_a)
                    break
    return sorted(set(result))
