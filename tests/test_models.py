"""Tests for core governance models — SCT, envelopes, and governance records."""

from datetime import UTC, datetime, timedelta
from decimal import Decimal

from syncropel_registry_core.models.governance import (
    AuditAction,
    AuditRecord,
    DenialKind,
    DerivationType,
    GovernanceDecision,
    GovernanceResultType,
    LineageRecord,
    ObservationOutcome,
    ObservationRecord,
)
from syncropel_registry_core.models.sct import (
    BudgetEnvelope,
    CapabilityEnvelope,
    CrossNamespaceGrant,
    DenyConstraint,
    DenyEnvelope,
    OutputConstraints,
    PrincipalType,
    QuadMetrics,
    SessionCapabilityToken,
)


class TestQuadMetrics:
    def test_to_dict_roundtrip(self):
        qm = QuadMetrics(
            compute=Decimal("0.05"),
            latency=Decimal("100"),
            quality=Decimal("0.9"),
            risk=Decimal("0.1"),
        )
        d = qm.to_dict()
        restored = QuadMetrics.from_dict(d)
        assert restored.compute == qm.compute
        assert restored.latency == qm.latency
        assert restored.quality == qm.quality
        assert restored.risk == qm.risk

    def test_from_empty_dict(self):
        qm = QuadMetrics.from_dict({})
        assert qm.compute == Decimal("0")

    def test_from_none(self):
        qm = QuadMetrics.from_dict(None)
        assert qm.compute == Decimal("0")


class TestCapabilityEnvelope:
    def test_contains_allowed(self):
        cap = CapabilityEnvelope(
            primitives={"GET", "PUT"},
            shapes={"ONE", "MANY"},
            operations=["db.*"],
            resources=["/sync/*"],
        )
        assert cap.contains("GET", "ONE", "db.query", "/sync/db/table")

    def test_contains_primitive_denied(self):
        cap = CapabilityEnvelope(primitives={"GET"}, shapes={"ONE"})
        assert not cap.contains("PUT", "ONE")

    def test_contains_shape_denied(self):
        cap = CapabilityEnvelope(primitives={"GET"}, shapes={"ONE"})
        assert not cap.contains("GET", "MANY")

    def test_intersect(self):
        a = CapabilityEnvelope(primitives={"GET", "PUT"}, shapes={"ONE", "MANY"}, max_effects=1000)
        b = CapabilityEnvelope(primitives={"GET", "CALL"}, shapes={"ONE", "KEYED"}, max_effects=500)
        result = a.intersect(b)
        assert result.primitives == {"GET"}
        assert result.shapes == {"ONE"}
        assert result.max_effects == 500

    def test_to_dict_roundtrip(self):
        cap = CapabilityEnvelope(
            primitives={"GET", "PUT"},
            shapes={"ONE"},
            operations=["db.*"],
            resources=["/sync/*"],
            max_effects=500,
            max_depth=10,
        )
        d = cap.to_dict()
        restored = CapabilityEnvelope.from_dict(d)
        assert restored.primitives == cap.primitives
        assert restored.operations == cap.operations
        assert restored.max_effects == 500

    def test_from_empty(self):
        cap = CapabilityEnvelope.from_dict({})
        assert "GET" in cap.primitives  # defaults


class TestDenyEnvelope:
    def test_matches_resource(self):
        deny = DenyEnvelope(
            constraints=[DenyConstraint(principal_pattern="*", resources=["/admin/*"])]
        )
        assert deny.matches("did:user:1", "GET", "ONE", "/admin/settings")

    def test_no_match(self):
        deny = DenyEnvelope(
            constraints=[DenyConstraint(principal_pattern="*", resources=["/admin/*"])]
        )
        assert not deny.matches("did:user:1", "GET", "ONE", "/public/data")

    def test_principal_pattern_mismatch(self):
        deny = DenyEnvelope(
            constraints=[DenyConstraint(principal_pattern="did:sync:sa:*", resources=["/admin/*"])]
        )
        assert not deny.matches("did:sync:user:1", "GET", "ONE", "/admin/settings")

    def test_to_dict_roundtrip(self):
        deny = DenyEnvelope(
            constraints=[DenyConstraint(principal_pattern="*", resources=["/admin/*"])]
        )
        d = deny.to_dict()
        restored = DenyEnvelope.from_dict(d)
        assert len(restored.constraints) == 1
        assert restored.constraints[0].resources == ["/admin/*"]


class TestBudgetEnvelope:
    def test_can_afford(self):
        budget = BudgetEnvelope(compute=Decimal("1.0"), latency=Decimal("5000"))
        cost = QuadMetrics(compute=Decimal("0.5"), latency=Decimal("2000"))
        assert budget.can_afford(cost)

    def test_cannot_afford_compute(self):
        budget = BudgetEnvelope(compute=Decimal("1.0"), latency=Decimal("5000"))
        cost = QuadMetrics(compute=Decimal("1.5"), latency=Decimal("100"))
        assert not budget.can_afford(cost)

    def test_unlimited_compute_and_latency(self):
        """When compute=0 and latency=0, those dimensions are unlimited."""
        budget = BudgetEnvelope(compute=Decimal("0"), latency=Decimal("0"))
        cost = QuadMetrics(
            compute=Decimal("999"),
            latency=Decimal("999999"),
            quality=Decimal("0.5"),
            risk=Decimal("0.5"),
        )
        assert budget.can_afford(cost)

    def test_cannot_afford_risk_too_high(self):
        """Risk ceiling is enforced: cost risk > budget risk => denied."""
        budget = BudgetEnvelope(risk=Decimal("0.5"))
        cost = QuadMetrics(risk=Decimal("0.8"))
        assert not budget.can_afford(cost)

    def test_cannot_afford_quality_too_low(self):
        """Quality floor is enforced: cost quality < budget quality => denied."""
        budget = BudgetEnvelope(quality=Decimal("0.8"))
        cost = QuadMetrics(quality=Decimal("0.3"))
        assert not budget.can_afford(cost)

    def test_remaining(self):
        budget = BudgetEnvelope(
            compute=Decimal("1.0"),
            latency=Decimal("5000"),
            spent_compute=Decimal("0.3"),
            spent_latency=Decimal("2000"),
        )
        rem = budget.remaining()
        assert rem.compute == Decimal("0.7")
        assert rem.latency == Decimal("3000")

    def test_restrict(self):
        a = BudgetEnvelope(
            compute=Decimal("1.0"),
            latency=Decimal("5000"),
            quality=Decimal("0.5"),
            risk=Decimal("0.8"),
        )
        b = BudgetEnvelope(
            compute=Decimal("0.5"),
            latency=Decimal("3000"),
            quality=Decimal("0.7"),
            risk=Decimal("0.6"),
        )
        result = a.restrict(b)
        assert result.compute == Decimal("0.5")
        assert result.quality == Decimal("0.7")
        assert result.risk == Decimal("0.6")

    def test_to_dict_roundtrip(self):
        budget = BudgetEnvelope(compute=Decimal("1.0"), latency=Decimal("5000"))
        d = budget.to_dict()
        restored = BudgetEnvelope.from_dict(d)
        assert restored.compute == budget.compute


class TestSessionCapabilityToken:
    def _make_sct(self, **kwargs):
        now = datetime.now(UTC)
        defaults = {
            "principal_did": "did:sync:user:test",
            "principal_type": PrincipalType.USER,
            "namespace": "default",
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(hours=1)).isoformat(),
            "policy_version": "v1-abc123",
            "issuer_did": "did:sync:registry",
        }
        defaults.update(kwargs)
        return SessionCapabilityToken(**defaults)

    def test_content_hash_deterministic(self):
        sct = self._make_sct()
        assert sct.content_hash() == sct.content_hash()
        assert len(sct.content_hash()) == 64

    def test_content_hash_changes_with_data(self):
        sct1 = self._make_sct(principal_did="did:sync:user:a")
        sct2 = self._make_sct(principal_did="did:sync:user:b")
        assert sct1.content_hash() != sct2.content_hash()

    def test_is_valid(self):
        sct = self._make_sct()
        assert sct.is_valid()

    def test_is_valid_expired(self):
        past = datetime.now(UTC) - timedelta(hours=1)
        sct = self._make_sct(expires_at=past.isoformat())
        assert not sct.is_valid()

    def test_is_valid_revoked(self):
        sct = self._make_sct(revoked=True)
        assert not sct.is_valid()

    def test_is_expired(self):
        past = datetime.now(UTC) - timedelta(hours=1)
        sct = self._make_sct(expires_at=past.isoformat())
        assert sct.is_expired()

    def test_is_not_expired(self):
        sct = self._make_sct()
        assert not sct.is_expired()

    def test_to_dict_roundtrip(self):
        sct = self._make_sct(
            dial_ceiling=Decimal("0.6667"),
            trust_score=Decimal("0.85"),
        )
        d = sct.to_dict()
        restored = SessionCapabilityToken.from_dict(d)
        assert restored.principal_did == sct.principal_did
        assert restored.dial_ceiling == sct.dial_ceiling
        assert restored.trust_score == sct.trust_score
        assert restored.namespace == sct.namespace

    def test_from_empty(self):
        sct = SessionCapabilityToken.from_dict({})
        assert sct.principal_type == PrincipalType.ANONYMOUS

    def test_from_none(self):
        sct = SessionCapabilityToken.from_dict(None)
        assert sct.principal_type == PrincipalType.ANONYMOUS


class TestOutputConstraints:
    def test_to_dict_roundtrip(self):
        oc = OutputConstraints(
            max_many_cardinality=100,
            deny_shapes_on_resources=[("KEYED", ["/admin/*"])],
        )
        d = oc.to_dict()
        restored = OutputConstraints.from_dict(d)
        assert restored.max_many_cardinality == 100
        assert len(restored.deny_shapes_on_resources) == 1


class TestCrossNamespaceGrant:
    def test_to_dict_roundtrip(self):
        grant = CrossNamespaceGrant(
            target_namespace="acme/analytics",
            hash_levels={"L1", "L2"},
        )
        d = grant.to_dict()
        restored = CrossNamespaceGrant.from_dict(d)
        assert restored.target_namespace == "acme/analytics"
        assert restored.hash_levels == {"L1", "L2"}


# ---------------------------------------------------------------------------
# Governance models (models/governance.py)
# ---------------------------------------------------------------------------


class TestGovernanceDecision:
    def test_allowed_effect(self):
        d = GovernanceDecision(result_type=GovernanceResultType.ALLOWED)
        assert d.effect == "ALLOW"

    def test_denied_effect(self):
        d = GovernanceDecision(
            result_type=GovernanceResultType.DENIED,
            kind=DenialKind.BUDGET_EXCEEDED,
        )
        assert d.effect == "DENY"

    def test_elevated_required_effect(self):
        d = GovernanceDecision(result_type=GovernanceResultType.ELEVATED_REQUIRED)
        assert d.effect == "DENY"

    def test_hitl_required_effect(self):
        d = GovernanceDecision(result_type=GovernanceResultType.HITL_REQUIRED)
        assert d.effect == "DENY"

    def test_to_dict_roundtrip(self):
        d = GovernanceDecision(
            result_type=GovernanceResultType.DENIED,
            kind=DenialKind.CAPABILITY_VIOLATION,
            detail="Primitive not allowed",
        )
        data = d.to_dict()
        restored = GovernanceDecision.from_dict(data)
        assert restored.result_type == GovernanceResultType.DENIED
        assert restored.kind == DenialKind.CAPABILITY_VIOLATION

    def test_legacy_compat(self):
        restored = GovernanceDecision.from_dict({"effect": "ALLOW"})
        assert restored.result_type == GovernanceResultType.ALLOWED


class TestAuditRecord:
    def test_to_dict_roundtrip(self):
        record = AuditRecord(
            id="audit-001",
            action=AuditAction.SESSION_CREATED,
            principal_did="did:sync:user:test",
            org_id="acme",
            namespace="acme/analytics",
        )
        d = record.to_dict()
        restored = AuditRecord.from_dict(d)
        assert restored.action == AuditAction.SESSION_CREATED
        assert restored.org_id == "acme"


class TestLineageRecord:
    def test_to_dict_roundtrip(self):
        record = LineageRecord(
            artifact_hash="abc123" * 10 + "abcd",
            owner_did="did:sync:user:test",
            parent_hashes=["parent1"],
            derivation_type=DerivationType.COMBINE,
            attribution_rate=Decimal("0.15"),
        )
        d = record.to_dict()
        restored = LineageRecord.from_dict(d)
        assert restored.derivation_type == DerivationType.COMBINE
        assert restored.attribution_rate == Decimal("0.15")


class TestObservationRecord:
    def test_to_dict_roundtrip(self):
        record = ObservationRecord(
            id="obs-001",
            principal_did="did:sync:user:test",
            outcome=ObservationOutcome.SUCCESS,
            quality_score=Decimal("0.95"),
        )
        d = record.to_dict()
        restored = ObservationRecord.from_dict(d)
        assert restored.outcome == ObservationOutcome.SUCCESS
        assert restored.quality_score == Decimal("0.95")
