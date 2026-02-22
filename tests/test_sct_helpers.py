"""Tests for SCT helper functions."""

from decimal import Decimal

from syncropel_registry_core.sct.helpers import (
    dial_zone_to_hash_access,
    resolve_namespace_hierarchy,
)


# ---------------------------------------------------------------------------
# resolve_namespace_hierarchy
# ---------------------------------------------------------------------------


class TestResolveNamespaceHierarchy:
    """Test namespace hierarchy resolution."""

    def test_multi_level(self):
        """acme/analytics/prod -> [default, acme, acme/analytics, acme/analytics/prod]."""
        result = resolve_namespace_hierarchy("acme/analytics/prod")
        assert result == [
            "default",
            "acme",
            "acme/analytics",
            "acme/analytics/prod",
        ]

    def test_default_only(self):
        """'default' -> ['default']."""
        result = resolve_namespace_hierarchy("default")
        assert result == ["default"]

    def test_empty_string(self):
        """Empty string -> ['default']."""
        result = resolve_namespace_hierarchy("")
        assert result == ["default"]

    def test_org_level(self):
        """Single segment -> [default, org]."""
        result = resolve_namespace_hierarchy("acme")
        assert result == ["default", "acme"]

    def test_project_level(self):
        """Two segments -> [default, org, project]."""
        result = resolve_namespace_hierarchy("acme/analytics")
        assert result == ["default", "acme", "acme/analytics"]

    def test_job_level(self):
        """Four segments -> [default, org, project, env, job]."""
        result = resolve_namespace_hierarchy("acme/analytics/prod/job-1")
        assert result == [
            "default",
            "acme",
            "acme/analytics",
            "acme/analytics/prod",
            "acme/analytics/prod/job-1",
        ]


# ---------------------------------------------------------------------------
# dial_zone_to_hash_access
# ---------------------------------------------------------------------------


class _FakePolicy:
    """Minimal policy stub with hash_access attribute."""

    def __init__(self, hash_access=None):
        self.hash_access = hash_access


class TestDialZoneToHashAccess:
    """Test dial ceiling -> hash level access mapping."""

    def test_replay_zone(self):
        """Dial < 0.3333 -> L0 only."""
        result = dial_zone_to_hash_access(Decimal("0.2"), [])
        assert result == {"L0"}

    def test_adapt_zone(self):
        """0.3333 <= dial < 0.5 -> L0, L1."""
        result = dial_zone_to_hash_access(Decimal("0.4"), [])
        assert result == {"L0", "L1"}

    def test_explore_zone(self):
        """0.5 <= dial < 0.6667 -> L0, L1, L2."""
        result = dial_zone_to_hash_access(Decimal("0.5"), [])
        assert result == {"L0", "L1", "L2"}

    def test_create_zone(self):
        """dial >= 0.6667 -> L0, L1, L2, L3."""
        result = dial_zone_to_hash_access(Decimal("0.7"), [])
        assert result == {"L0", "L1", "L2", "L3"}

    def test_full_dial(self):
        """dial = 1.0 -> all levels."""
        result = dial_zone_to_hash_access(Decimal("1.0"), [])
        assert result == {"L0", "L1", "L2", "L3"}

    def test_exactly_at_threshold_0_3333(self):
        """Exactly at 0.3333 -> ADAPT zone (L0, L1)."""
        result = dial_zone_to_hash_access(Decimal("0.3333"), [])
        assert result == {"L0", "L1"}

    def test_exactly_at_threshold_0_6667(self):
        """Exactly at 0.6667 -> CREATE zone (all levels)."""
        result = dial_zone_to_hash_access(Decimal("0.6667"), [])
        assert result == {"L0", "L1", "L2", "L3"}

    def test_namespace_policy_intersection(self):
        """Policy restricts hash access — should intersect with dial-based access."""
        policies = [_FakePolicy(hash_access=["L0", "L1"])]
        # dial >= 0.6667 gives all levels, but policy restricts to L0, L1
        result = dial_zone_to_hash_access(Decimal("1.0"), policies)
        assert result == {"L0", "L1"}

    def test_namespace_policy_none_no_restriction(self):
        """Policy with hash_access=None means no restriction."""
        policies = [_FakePolicy(hash_access=None)]
        result = dial_zone_to_hash_access(Decimal("1.0"), policies)
        assert result == {"L0", "L1", "L2", "L3"}

    def test_l0_always_included_in_policy(self):
        """Even if policy specifies only L2, L0 is always added (local-only)."""
        policies = [_FakePolicy(hash_access=["L2"])]
        # dial gives L0, L1, L2, L3; policy gives L0 (forced) + L2
        result = dial_zone_to_hash_access(Decimal("1.0"), policies)
        assert "L0" in result
        assert "L2" in result
