"""Tests for governance validation checks 3-9."""

from dataclasses import dataclass
from decimal import Decimal

from syncropel_registry_core.models.governance import (
    DenialKind,
    GovernanceResultType,
)
from syncropel_registry_core.models.sct import (
    BudgetEnvelope,
    CapabilityEnvelope,
    DenyConstraint,
    DenyEnvelope,
    OutputConstraints,
    SessionCapabilityToken,
)
from syncropel_registry_core.validators.governance import (
    GovernanceCheckError,
    GovernanceValidationResult,
    check_3_capability,
    check_4_deny,
    check_5_budget_session,
    check_6_dial,
    check_7_hash_level,
    check_8_budget_guard,
    check_9b_output_constraints,
    check_9c_lineage_integrity,
    check_9d_federation_consent,
    validate_checks_3_to_9,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_sct(**overrides) -> SessionCapabilityToken:
    """Create a permissive SCT for testing, with optional overrides."""
    defaults = dict(
        principal_did="did:sync:user:test",
        namespace="test-ns",
        capability=CapabilityEnvelope(
            primitives={"GET", "PUT", "CALL", "MAP"},
            shapes={"VOID", "ONE", "OPTIONAL", "MANY", "KEYED"},
            operations=[],
            resources=[],
            max_effects=1000,
            max_depth=20,
        ),
        deny=DenyEnvelope(),
        budget=BudgetEnvelope(
            compute=Decimal("0"),
            latency=Decimal("0"),
            quality=Decimal("0"),
            risk=Decimal("1"),
        ),
        dial_ceiling=Decimal("1"),
        hash_access={"L0", "L1", "L2", "L3"},
    )
    defaults.update(overrides)
    return SessionCapabilityToken(**defaults)


@dataclass
class ConsentEdge:
    """Simple consent edge for testing check_9d."""
    from_namespace: str
    to_namespace: str
    active: bool


# ---------------------------------------------------------------------------
# Check 3: Capability envelope
# ---------------------------------------------------------------------------


class TestCheck3Capability:
    """Test capability envelope enforcement."""

    def test_allowed_primitive_passes(self):
        sct = _make_sct(capability=CapabilityEnvelope(primitives={"GET", "CALL"}))
        effects = [{"primitive": "GET", "shape": "ONE"}]
        errors, warnings = [], []
        check_3_capability(effects, sct, errors, warnings)
        assert len(errors) == 0

    def test_disallowed_primitive_fails(self):
        sct = _make_sct(capability=CapabilityEnvelope(primitives={"GET"}))
        effects = [{"primitive": "PUT", "shape": "ONE"}]
        errors, warnings = [], []
        check_3_capability(effects, sct, errors, warnings)
        assert len(errors) == 1
        assert errors[0].check_number == 3
        assert errors[0].kind == DenialKind.CAPABILITY_VIOLATION
        assert "PUT" in errors[0].detail

    def test_shape_check(self):
        sct = _make_sct(capability=CapabilityEnvelope(shapes={"ONE", "VOID"}))
        effects = [{"primitive": "GET", "shape": "MANY"}]
        errors, warnings = [], []
        check_3_capability(effects, sct, errors, warnings)
        assert len(errors) == 1
        assert "MANY" in errors[0].detail

    def test_operation_glob_match(self):
        sct = _make_sct(capability=CapabilityEnvelope(operations=["db.*"]))
        effects = [{"primitive": "GET", "shape": "ONE", "operation": "db.query"}]
        errors, warnings = [], []
        check_3_capability(effects, sct, errors, warnings)
        assert len(errors) == 0

    def test_operation_glob_no_match(self):
        sct = _make_sct(capability=CapabilityEnvelope(operations=["db.*"]))
        effects = [{"primitive": "GET", "shape": "ONE", "operation": "llm.generate"}]
        errors, warnings = [], []
        check_3_capability(effects, sct, errors, warnings)
        assert len(errors) == 1
        assert "llm.generate" in errors[0].detail

    def test_resource_glob_match(self):
        sct = _make_sct(capability=CapabilityEnvelope(resources=["/sync/database/*"]))
        effects = [{"primitive": "GET", "shape": "ONE", "resource": "/sync/database/users"}]
        errors, warnings = [], []
        check_3_capability(effects, sct, errors, warnings)
        assert len(errors) == 0

    def test_resource_glob_no_match(self):
        sct = _make_sct(capability=CapabilityEnvelope(resources=["/sync/database/*"]))
        effects = [{"primitive": "GET", "shape": "ONE", "resource": "/exec/llm/gen"}]
        errors, warnings = [], []
        check_3_capability(effects, sct, errors, warnings)
        assert len(errors) == 1
        assert "/exec/llm/gen" in errors[0].detail

    def test_empty_primitives_allows_all(self):
        """Empty primitives set means all primitives are allowed."""
        sct = _make_sct(capability=CapabilityEnvelope(primitives=set()))
        effects = [{"primitive": "MAP", "shape": "MANY"}]
        errors, warnings = [], []
        check_3_capability(effects, sct, errors, warnings)
        assert len(errors) == 0

    def test_empty_operations_allows_all(self):
        """Empty operations list means all operations are allowed."""
        sct = _make_sct(capability=CapabilityEnvelope(operations=[]))
        effects = [{"primitive": "GET", "shape": "ONE", "operation": "anything"}]
        errors, warnings = [], []
        check_3_capability(effects, sct, errors, warnings)
        assert len(errors) == 0


# ---------------------------------------------------------------------------
# Check 4: Deny constraints
# ---------------------------------------------------------------------------


class TestCheck4Deny:
    """Test deny constraint enforcement."""

    def test_deny_matches_produces_error(self):
        deny = DenyEnvelope(constraints=[
            DenyConstraint(
                principal_pattern="*",
                resources=["/admin/*"],
            ),
        ])
        sct = _make_sct(deny=deny)
        effects = [{"primitive": "GET", "shape": "ONE", "resource": "/admin/secret"}]
        errors, warnings = [], []
        check_4_deny(effects, sct, errors, warnings)
        assert len(errors) == 1
        assert errors[0].kind == DenialKind.DENY_CONSTRAINT

    def test_no_deny_constraint_passes(self):
        sct = _make_sct(deny=DenyEnvelope())
        effects = [{"primitive": "GET", "shape": "ONE", "resource": "/sync/data"}]
        errors, warnings = [], []
        check_4_deny(effects, sct, errors, warnings)
        assert len(errors) == 0

    def test_deny_principal_pattern_mismatch(self):
        """Deny constraint with non-matching principal pattern should pass."""
        deny = DenyEnvelope(constraints=[
            DenyConstraint(
                principal_pattern="did:sync:sa:*",
                resources=["/admin/*"],
            ),
        ])
        # principal_did does NOT match "did:sync:sa:*"
        sct = _make_sct(
            principal_did="did:sync:user:alice",
            deny=deny,
        )
        effects = [{"primitive": "GET", "shape": "ONE", "resource": "/admin/secret"}]
        errors, warnings = [], []
        check_4_deny(effects, sct, errors, warnings)
        assert len(errors) == 0


# ---------------------------------------------------------------------------
# Check 5: Budget session
# ---------------------------------------------------------------------------


class TestCheck5BudgetSession:
    """Test budget session ceiling."""

    def test_within_budget_passes(self):
        sct = _make_sct(budget=BudgetEnvelope(compute=Decimal("100")))
        effects = [
            {"estimated_cost": "30"},
            {"estimated_cost": "20"},
        ]
        errors, warnings = [], []
        check_5_budget_session(effects, sct, errors, warnings)
        assert len(errors) == 0

    def test_exceeds_budget_fails(self):
        sct = _make_sct(budget=BudgetEnvelope(compute=Decimal("50")))
        effects = [
            {"estimated_cost": "30"},
            {"estimated_cost": "25"},
        ]
        errors, warnings = [], []
        check_5_budget_session(effects, sct, errors, warnings)
        assert len(errors) == 1
        assert errors[0].kind == DenialKind.BUDGET_EXCEEDED

    def test_unlimited_budget_passes(self):
        """compute=0 means unlimited — should always pass."""
        sct = _make_sct(budget=BudgetEnvelope(compute=Decimal("0")))
        effects = [{"estimated_cost": "999999"}]
        errors, warnings = [], []
        check_5_budget_session(effects, sct, errors, warnings)
        assert len(errors) == 0

    def test_budget_warning_above_80_percent(self):
        """Utilization above 80% should produce a warning (not an error)."""
        sct = _make_sct(budget=BudgetEnvelope(compute=Decimal("100")))
        effects = [{"estimated_cost": "85"}]
        errors, warnings = [], []
        check_5_budget_session(effects, sct, errors, warnings)
        assert len(errors) == 0
        assert len(warnings) == 1
        assert warnings[0].severity == "warning"
        assert warnings[0].kind == DenialKind.BUDGET_EXCEEDED

    def test_latency_budget_exceeded(self):
        sct = _make_sct(budget=BudgetEnvelope(latency=Decimal("1000")))
        effects = [{"estimated_latency": "600"}, {"estimated_latency": "500"}]
        errors, warnings = [], []
        check_5_budget_session(effects, sct, errors, warnings)
        assert len(errors) == 1
        assert "latency" in errors[0].detail.lower()


# ---------------------------------------------------------------------------
# Check 6: Dial ceiling
# ---------------------------------------------------------------------------


class TestCheck6Dial:
    """Test dial position vs SCT dial ceiling."""

    def test_within_ceiling_passes(self):
        sct = _make_sct(dial_ceiling=Decimal("0.6667"))
        errors = []
        check_6_dial(sct, Decimal("0.5"), errors)
        assert len(errors) == 0

    def test_exceeds_ceiling_fails(self):
        sct = _make_sct(dial_ceiling=Decimal("0.5"))
        errors = []
        check_6_dial(sct, Decimal("0.7"), errors)
        assert len(errors) == 1
        assert errors[0].kind == DenialKind.DIAL_CEILING_EXCEEDED

    def test_none_dial_position_passes(self):
        """None dial position should be silently accepted."""
        sct = _make_sct(dial_ceiling=Decimal("0.5"))
        errors = []
        check_6_dial(sct, None, errors)
        assert len(errors) == 0

    def test_equal_to_ceiling_passes(self):
        sct = _make_sct(dial_ceiling=Decimal("0.5"))
        errors = []
        check_6_dial(sct, Decimal("0.5"), errors)
        assert len(errors) == 0


# ---------------------------------------------------------------------------
# Check 7: Hash level access
# ---------------------------------------------------------------------------


class TestCheck7HashLevel:
    """Test hash level access check."""

    def test_in_hash_access_passes(self):
        sct = _make_sct(hash_access={"L0", "L1", "L2"})
        errors = []
        check_7_hash_level(sct, "L1", errors)
        assert len(errors) == 0

    def test_not_in_hash_access_fails(self):
        sct = _make_sct(hash_access={"L0", "L1"})
        errors = []
        check_7_hash_level(sct, "L3", errors)
        assert len(errors) == 1
        assert errors[0].kind == DenialKind.CAPABILITY_VIOLATION
        assert "L3" in errors[0].detail

    def test_none_hash_level_passes(self):
        """None hash level request should pass without error."""
        sct = _make_sct(hash_access={"L0"})
        errors = []
        check_7_hash_level(sct, None, errors)
        assert len(errors) == 0


# ---------------------------------------------------------------------------
# Check 8: Budget guard (quality floor / risk ceiling)
# ---------------------------------------------------------------------------


class TestCheck8BudgetGuard:
    """Test per-effect quality floor and risk ceiling."""

    def test_quality_above_floor_passes(self):
        sct = _make_sct(budget=BudgetEnvelope(quality=Decimal("0.5")))
        effects = [{"quality": "0.8", "risk": "0.1"}]
        errors, warnings = [], []
        check_8_budget_guard(effects, sct, errors, warnings)
        assert len(errors) == 0

    def test_quality_below_floor_fails(self):
        sct = _make_sct(budget=BudgetEnvelope(quality=Decimal("0.8")))
        effects = [{"quality": "0.5", "risk": "0.1"}]
        errors, warnings = [], []
        check_8_budget_guard(effects, sct, errors, warnings)
        assert len(errors) == 1
        assert errors[0].kind == DenialKind.BUDGET_EXCEEDED
        assert "quality" in errors[0].detail.lower()

    def test_risk_above_ceiling_fails(self):
        sct = _make_sct(budget=BudgetEnvelope(risk=Decimal("0.3")))
        effects = [{"quality": "1", "risk": "0.5"}]
        errors, warnings = [], []
        check_8_budget_guard(effects, sct, errors, warnings)
        assert len(errors) == 1
        assert "risk" in errors[0].detail.lower()

    def test_risk_within_ceiling_passes(self):
        sct = _make_sct(budget=BudgetEnvelope(risk=Decimal("0.5")))
        effects = [{"quality": "1", "risk": "0.3"}]
        errors, warnings = [], []
        check_8_budget_guard(effects, sct, errors, warnings)
        assert len(errors) == 0


# ---------------------------------------------------------------------------
# Check 9b: Output constraints
# ---------------------------------------------------------------------------


class TestCheck9bOutputConstraints:
    """Test output constraints enforcement."""

    def test_max_many_cardinality_exceeded(self):
        oc = OutputConstraints(max_many_cardinality=100)
        sct = _make_sct(output_constraints=oc)
        effects = [{"shape": "MANY", "output_cardinality": 200}]
        errors, warnings = [], []
        check_9b_output_constraints(effects, sct, errors, warnings)
        assert len(errors) == 1
        assert errors[0].kind == DenialKind.SHAPE_CONSTRAINT_VIOLATION
        assert "200" in errors[0].detail

    def test_max_many_cardinality_within_limit(self):
        oc = OutputConstraints(max_many_cardinality=100)
        sct = _make_sct(output_constraints=oc)
        effects = [{"shape": "MANY", "output_cardinality": 50}]
        errors, warnings = [], []
        check_9b_output_constraints(effects, sct, errors, warnings)
        assert len(errors) == 0

    def test_no_output_constraints_passes(self):
        sct = _make_sct(output_constraints=None)
        effects = [{"shape": "MANY", "output_cardinality": 9999}]
        errors, warnings = [], []
        check_9b_output_constraints(effects, sct, errors, warnings)
        assert len(errors) == 0

    def test_non_many_shape_not_checked(self):
        """max_many_cardinality only applies to MANY shapes."""
        oc = OutputConstraints(max_many_cardinality=10)
        sct = _make_sct(output_constraints=oc)
        effects = [{"shape": "ONE", "output_cardinality": 100}]
        errors, warnings = [], []
        check_9b_output_constraints(effects, sct, errors, warnings)
        assert len(errors) == 0


# ---------------------------------------------------------------------------
# Check 9c: Lineage integrity
# ---------------------------------------------------------------------------


class TestCheck9cLineageIntegrity:
    """Test lineage integrity check."""

    def test_empty_content_hash_fails(self):
        effects = [{"content_hash": ""}]
        errors, warnings = [], []
        check_9c_lineage_integrity(effects, errors, warnings)
        assert len(errors) == 1
        assert errors[0].kind == DenialKind.LINEAGE_INTEGRITY_FAILURE

    def test_valid_content_hash_passes(self):
        effects = [{"content_hash": "abcdef1234567890"}]
        errors, warnings = [], []
        check_9c_lineage_integrity(effects, errors, warnings)
        assert len(errors) == 0

    def test_no_content_hash_field_passes(self):
        """Effects without a content_hash field are considered new -> pass."""
        effects = [{"primitive": "GET"}]
        errors, warnings = [], []
        check_9c_lineage_integrity(effects, errors, warnings)
        assert len(errors) == 0

    def test_none_content_hash_passes(self):
        """content_hash set to None (not empty string) should pass."""
        effects = [{"content_hash": None}]
        errors, warnings = [], []
        check_9c_lineage_integrity(effects, errors, warnings)
        assert len(errors) == 0


# ---------------------------------------------------------------------------
# Check 9d: Federation consent
# ---------------------------------------------------------------------------


class TestCheck9dFederationConsent:
    """Test federation consent check for cross-namespace access."""

    def test_cross_namespace_without_consent_fails(self):
        sct = _make_sct(namespace="my-ns")
        effects = [{"resource": "sync://other-ns/data/table"}]
        errors, warnings = [], []
        check_9d_federation_consent(effects, sct, None, errors, warnings)
        assert len(errors) == 1
        assert errors[0].kind == DenialKind.FEDERATION_CONSENT_DENIED
        assert "other-ns" in errors[0].detail

    def test_cross_namespace_with_consent_passes(self):
        sct = _make_sct(namespace="my-ns")
        edges = [ConsentEdge(from_namespace="other-ns", to_namespace="my-ns", active=True)]
        effects = [{"resource": "sync://other-ns/data/table"}]
        errors, warnings = [], []
        check_9d_federation_consent(effects, sct, edges, errors, warnings)
        assert len(errors) == 0

    def test_same_namespace_passes(self):
        """Access within the same namespace should always pass."""
        sct = _make_sct(namespace="my-ns")
        effects = [{"resource": "sync://my-ns/data/table"}]
        errors, warnings = [], []
        check_9d_federation_consent(effects, sct, None, errors, warnings)
        assert len(errors) == 0

    def test_non_sync_resource_passes(self):
        """Non-sync:// resources are not subject to federation consent."""
        sct = _make_sct(namespace="my-ns")
        effects = [{"resource": "/local/data/table"}]
        errors, warnings = [], []
        check_9d_federation_consent(effects, sct, None, errors, warnings)
        assert len(errors) == 0

    def test_inactive_consent_edge_fails(self):
        sct = _make_sct(namespace="my-ns")
        edges = [ConsentEdge(from_namespace="other-ns", to_namespace="my-ns", active=False)]
        effects = [{"resource": "sync://other-ns/data/table"}]
        errors, warnings = [], []
        check_9d_federation_consent(effects, sct, edges, errors, warnings)
        assert len(errors) == 1

    def test_empty_namespace_skips_check(self):
        """If the SCT has no namespace, federation consent is skipped."""
        sct = _make_sct(namespace="")
        effects = [{"resource": "sync://other-ns/data/table"}]
        errors, warnings = [], []
        check_9d_federation_consent(effects, sct, None, errors, warnings)
        assert len(errors) == 0


# ---------------------------------------------------------------------------
# validate_checks_3_to_9 convenience function
# ---------------------------------------------------------------------------


class TestValidateChecks3To9:
    """Test the aggregate validation convenience function."""

    def test_all_pass(self):
        sct = _make_sct()
        effects = [{"primitive": "GET", "shape": "ONE"}]
        result = validate_checks_3_to_9(effects, sct)
        assert result.valid is True
        assert result.result_type == GovernanceResultType.ALLOWED
        assert len(result.errors) == 0
        assert 3 in result.checks_passed
        assert 4 in result.checks_passed

    def test_failure_returns_denied(self):
        sct = _make_sct(capability=CapabilityEnvelope(primitives={"GET"}))
        effects = [{"primitive": "PUT", "shape": "ONE"}]
        result = validate_checks_3_to_9(effects, sct)
        assert result.valid is False
        assert result.result_type == GovernanceResultType.DENIED
        assert result.denial_kind is not None
        assert 3 in result.checks_failed

    def test_sct_hash_populated(self):
        sct = _make_sct()
        effects = [{"primitive": "GET", "shape": "ONE"}]
        result = validate_checks_3_to_9(effects, sct)
        assert result.sct_hash != ""
        assert len(result.sct_hash) == 64  # SHA-256 hex

    def test_dial_check_integrated(self):
        sct = _make_sct(dial_ceiling=Decimal("0.5"))
        effects = [{"primitive": "GET", "shape": "ONE"}]
        result = validate_checks_3_to_9(
            effects, sct, dial_position=Decimal("0.8"),
        )
        assert result.valid is False
        assert 6 in result.checks_failed

    def test_hash_level_check_integrated(self):
        sct = _make_sct(hash_access={"L0", "L1"})
        effects = [{"primitive": "GET", "shape": "ONE"}]
        result = validate_checks_3_to_9(
            effects, sct, requested_hash_level="L3",
        )
        assert result.valid is False
        assert 7 in result.checks_failed

    def test_max_effects_exceeded(self):
        sct = _make_sct(capability=CapabilityEnvelope(max_effects=2))
        effects = [
            {"primitive": "GET", "shape": "ONE"},
            {"primitive": "GET", "shape": "ONE"},
            {"primitive": "GET", "shape": "ONE"},
        ]
        result = validate_checks_3_to_9(effects, sct)
        assert result.valid is False
        assert 9 in result.checks_failed
