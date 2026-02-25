"""Governance v3 records: audit, lineage, observations.

Immutable records that form the governance audit trail. Every governance
decision references an SCT content hash, creating a universal linkage
between authorization and execution.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from enum import StrEnum

from syncropel_registry_core.models.sct import GovernanceTier, QuadMetrics


class AuditAction(StrEnum):
    """All auditable governance actions (37 canonical actions)."""

    # Policy decisions
    POLICY_ALLOW = "POLICY_ALLOW"
    POLICY_DENY = "POLICY_DENY"
    # Effect-level governance decisions
    EFFECT_ALLOWED = "EFFECT_ALLOWED"
    EFFECT_DENIED = "EFFECT_DENIED"
    # Session lifecycle
    SESSION_CREATED = "SESSION_CREATED"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    SESSION_COMPLETED = "SESSION_COMPLETED"
    SESSION_REVOKED = "SESSION_REVOKED"
    # Service account lifecycle
    SA_CREATED = "SA_CREATED"
    SA_AUTHENTICATED = "SA_AUTHENTICATED"
    SA_AUTH_FAILED = "SA_AUTH_FAILED"
    SA_KEY_ROTATED = "SA_KEY_ROTATED"
    SA_DEACTIVATED = "SA_DEACTIVATED"
    SA_REACTIVATED = "SA_REACTIVATED"
    # Policy management
    POLICY_SET = "POLICY_SET"
    POLICY_DELETED = "POLICY_DELETED"
    POLICY_UPDATED = "POLICY_UPDATED"
    # Federation
    FEDERATION_CONSENT_GRANTED = "FEDERATION_CONSENT_GRANTED"
    FEDERATION_CONSENT_REVOKED = "FEDERATION_CONSENT_REVOKED"
    FEDERATION_QUERY = "FEDERATION_QUERY"
    FEDERATION_SYNC = "FEDERATION_SYNC"
    # SCT lifecycle
    SCT_ISSUED = "SCT_ISSUED"
    SCT_RENEWED = "SCT_RENEWED"
    SCT_REVOKED = "SCT_REVOKED"
    SCT_DELEGATED = "SCT_DELEGATED"
    # Human-in-the-loop
    HITL_CREATED = "HITL_CREATED"
    HITL_APPROVAL_REQUESTED = "HITL_APPROVAL_REQUESTED"
    HITL_APPROVED = "HITL_APPROVED"
    HITL_REJECTED = "HITL_REJECTED"
    HITL_EXPIRED = "HITL_EXPIRED"
    HITL_TIMED_OUT = "HITL_TIMED_OUT"
    # CRL / Revocation
    CRL_ENTRY_ADDED = "CRL_ENTRY_ADDED"
    CRL_ENTRY_REMOVED = "CRL_ENTRY_REMOVED"
    # Trust
    TRUST_OBSERVATION_RECORDED = "TRUST_OBSERVATION_RECORDED"
    TRUST_SCORE_RECOMPUTED = "TRUST_SCORE_RECOMPUTED"
    # Settlement
    SETTLEMENT_EXECUTED = "SETTLEMENT_EXECUTED"
    SETTLEMENT_FAILED = "SETTLEMENT_FAILED"
    # Job governance
    JOB_GOVERNANCE_CHECK = "JOB_GOVERNANCE_CHECK"


class DenialKind(StrEnum):
    """Typed denial reasons matching the spec's DenialKind variants."""

    CAPABILITY_VIOLATION = "CapabilityViolation"
    BUDGET_EXCEEDED = "BudgetExceeded"
    DENY_CONSTRAINT = "DenyConstraint"
    DIAL_CEILING_EXCEEDED = "DialCeilingExceeded"
    SCT_EXPIRED = "SctExpired"
    SCT_REVOKED = "SctRevoked"
    POLICY_STALE = "PolicyStale"
    HITL_REQUIRED = "HitlRequired"
    LINEAGE_INTEGRITY_FAILURE = "LineageIntegrityFailure"
    FEDERATION_CONSENT_DENIED = "FederationConsentDenied"
    SHAPE_CONSTRAINT_VIOLATION = "ShapeConstraintViolation"


class GovernanceResultType(StrEnum):
    """The 4 governance result variants from the spec."""

    ALLOWED = "Allowed"
    DENIED = "Denied"
    ELEVATED_REQUIRED = "ElevatedRequired"
    HITL_REQUIRED = "HitlRequired"


@dataclass
class GovernanceDecision:
    """Result of a governance evaluation."""

    result_type: GovernanceResultType = GovernanceResultType.ALLOWED
    kind: DenialKind | None = None
    detail: str = ""  # human-readable reason
    effect_id: str = ""  # effect that triggered the decision
    sct_hash: str = ""  # SCT that authorized
    governance_tier: GovernanceTier | None = None
    evaluation_time_us: int = 0  # microseconds

    # Legacy compat
    @property
    def effect(self) -> str:
        return "ALLOW" if self.result_type == GovernanceResultType.ALLOWED else "DENY"

    def to_dict(self) -> dict:
        return {
            "type": self.result_type.value,
            "effect": self.effect,
            "kind": self.kind.value if self.kind else None,
            "detail": self.detail,
            "effect_id": self.effect_id,
            "sct_hash": self.sct_hash,
            "governance_tier": self.governance_tier.value if self.governance_tier else None,
            "evaluation_time_us": self.evaluation_time_us,
        }

    @classmethod
    def from_dict(cls, data: dict) -> GovernanceDecision:
        if not data:
            return cls()
        result_type = data.get("type") or data.get("result_type")
        kind = data.get("kind")
        gt = data.get("governance_tier")
        # Legacy compat: "effect" field maps to result_type
        if not result_type and data.get("effect"):
            result_type = "Allowed" if data["effect"] == "ALLOW" else "Denied"
        return cls(
            result_type=GovernanceResultType(result_type)
            if result_type
            else GovernanceResultType.ALLOWED,
            kind=DenialKind(kind) if kind else None,
            detail=data.get("detail", ""),
            effect_id=data.get("effect_id", ""),
            sct_hash=data.get("sct_hash", ""),
            governance_tier=GovernanceTier(gt) if gt else None,
            evaluation_time_us=data.get("evaluation_time_us", 0),
        )


@dataclass
class AuditRecord:
    """Immutable v3 audit record with SCT linkage."""

    id: str = ""
    timestamp: str = ""
    action: AuditAction = AuditAction.POLICY_ALLOW
    principal_did: str = ""
    org_id: str = ""
    namespace: str = ""
    resource: str | None = None
    dial_zone: str | None = None
    governance_tier: GovernanceTier | None = None
    decision: GovernanceDecision | None = None
    sct_hash: str | None = None
    policy_version: str | None = None
    detail: dict = field(default_factory=dict)
    session_id: str | None = None
    correlation_id: str | None = None
    cost: QuadMetrics | None = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "action": self.action.value,
            "principal_did": self.principal_did,
            "org_id": self.org_id,
            "namespace": self.namespace,
            "resource": self.resource,
            "dial_zone": self.dial_zone,
            "governance_tier": self.governance_tier.value if self.governance_tier else None,
            "decision": self.decision.to_dict() if self.decision else None,
            "sct_hash": self.sct_hash,
            "policy_version": self.policy_version,
            "detail": self.detail,
            "session_id": self.session_id,
            "correlation_id": self.correlation_id,
            "cost": self.cost.to_dict() if self.cost else None,
        }

    @classmethod
    def from_dict(cls, data: dict) -> AuditRecord:
        if not data:
            return cls()
        decision = data.get("decision")
        cost = data.get("cost")
        gt = data.get("governance_tier")
        return cls(
            id=data.get("id", ""),
            timestamp=data.get("timestamp", ""),
            action=AuditAction(data.get("action", "POLICY_ALLOW")),
            principal_did=data.get("principal_did", ""),
            org_id=data.get("org_id", ""),
            namespace=data.get("namespace", ""),
            resource=data.get("resource"),
            dial_zone=data.get("dial_zone"),
            governance_tier=GovernanceTier(gt) if gt else None,
            decision=GovernanceDecision.from_dict(decision) if decision else None,
            sct_hash=data.get("sct_hash"),
            policy_version=data.get("policy_version"),
            detail=data.get("detail", {}),
            session_id=data.get("session_id"),
            correlation_id=data.get("correlation_id"),
            cost=QuadMetrics.from_dict(cost) if cost else None,
        )


class DerivationType(StrEnum):
    """How an artifact was derived from its parents."""

    TRANSFORM = "TRANSFORM"
    COMBINE = "COMBINE"
    ADAPT = "ADAPT"
    GENERATE = "GENERATE"


@dataclass
class LineageRecord:
    """Provenance record linking artifacts to their derivation chain."""

    artifact_hash: str = ""
    owner_did: str = ""
    parent_hashes: list[str] = field(default_factory=list)
    derivation_type: DerivationType = DerivationType.TRANSFORM
    attribution_rate: Decimal = Decimal("0.10")
    trace_hash_l1: str = ""
    namespace: str = ""
    created_at: str = ""
    sct_hash: str = ""

    def to_dict(self) -> dict:
        return {
            "artifact_hash": self.artifact_hash,
            "owner_did": self.owner_did,
            "parent_hashes": self.parent_hashes,
            "derivation_type": self.derivation_type.value,
            "attribution_rate": str(self.attribution_rate),
            "trace_hash_l1": self.trace_hash_l1,
            "namespace": self.namespace,
            "created_at": self.created_at,
            "sct_hash": self.sct_hash,
        }

    @classmethod
    def from_dict(cls, data: dict) -> LineageRecord:
        if not data:
            return cls()
        return cls(
            artifact_hash=data.get("artifact_hash", ""),
            owner_did=data.get("owner_did", ""),
            parent_hashes=data.get("parent_hashes", []),
            derivation_type=DerivationType(data.get("derivation_type", "TRANSFORM")),
            attribution_rate=Decimal(str(data.get("attribution_rate", "0.10"))),
            trace_hash_l1=data.get("trace_hash_l1", ""),
            namespace=data.get("namespace", ""),
            created_at=data.get("created_at", ""),
            sct_hash=data.get("sct_hash", ""),
        )


class ObservationOutcome(StrEnum):
    """Outcome of an observed effect execution."""

    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    TIMEOUT = "TIMEOUT"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"


@dataclass
class ObservationRecord:
    """Governance observation feeding the trust engine."""

    id: str = ""
    principal_did: str = ""
    domain: str = ""
    effect_primitive: str = ""
    resource_path: str = ""
    dial_zone: str = ""
    outcome: ObservationOutcome = ObservationOutcome.SUCCESS
    quality_score: Decimal = Decimal("1")
    latency_ms: Decimal = Decimal("0")
    cost: QuadMetrics | None = None
    timestamp: str = ""
    sct_hash: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "principal_did": self.principal_did,
            "domain": self.domain,
            "effect_primitive": self.effect_primitive,
            "resource_path": self.resource_path,
            "dial_zone": self.dial_zone,
            "outcome": self.outcome.value,
            "quality_score": str(self.quality_score),
            "latency_ms": str(self.latency_ms),
            "cost": self.cost.to_dict() if self.cost else None,
            "timestamp": self.timestamp,
            "sct_hash": self.sct_hash,
        }

    @classmethod
    def from_dict(cls, data: dict) -> ObservationRecord:
        if not data:
            return cls()
        cost = data.get("cost")
        return cls(
            id=data.get("id", ""),
            principal_did=data.get("principal_did", ""),
            domain=data.get("domain", ""),
            effect_primitive=data.get("effect_primitive", ""),
            resource_path=data.get("resource_path", ""),
            dial_zone=data.get("dial_zone", ""),
            outcome=ObservationOutcome(data.get("outcome", "SUCCESS")),
            quality_score=Decimal(str(data.get("quality_score", "1"))),
            latency_ms=Decimal(str(data.get("latency_ms", "0"))),
            cost=QuadMetrics.from_dict(cost) if cost else None,
            timestamp=data.get("timestamp", ""),
            sct_hash=data.get("sct_hash", ""),
        )
