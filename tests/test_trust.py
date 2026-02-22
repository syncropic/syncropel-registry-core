"""Tests for governance trust model: Wilson score with temporal decay."""

from decimal import Decimal

from syncropel_registry_core.trust import (
    PRIOR_TRUST,
    GovernanceTrustScore,
)


# ---------------------------------------------------------------------------
# Wilson lower bound
# ---------------------------------------------------------------------------


class TestWilsonLowerBound:
    """Test Wilson score lower bound computation with cold-start prior."""

    def test_cold_start_zero_observations(self):
        """With 0 actual observations, score is derived from the cold-start
        prior (7/10).  The Wilson lower bound of 7 successes in 10 trials
        at 95% confidence is approximately 0.40."""
        score = GovernanceTrustScore.wilson_lower_bound(0, 0)
        assert isinstance(score, Decimal)
        # Wilson lower bound of 7/10 with z=1.96 is ~0.3968
        assert Decimal("0.35") <= score <= Decimal("0.55")

    def test_many_successes(self):
        """100 successes out of 100 trials should give a high score (~0.92+).

        With cold-start prior (107/110), Wilson lower bound is ~0.9229.
        """
        score = GovernanceTrustScore.wilson_lower_bound(100, 100)
        assert score >= Decimal("0.90")

    def test_mixed_results(self):
        """70 successes out of 100 trials — score should be above prior
        but well below 1."""
        score = GovernanceTrustScore.wilson_lower_bound(70, 100)
        # With cold-start prior (7 extra successes, 10 extra trials) the
        # adjusted ratio is 77/110 ~0.70 — Wilson lower bound should be
        # somewhere around 0.60-0.70.
        assert Decimal("0.55") <= score <= Decimal("0.75")

    def test_all_failures(self):
        """0 successes out of 100 trials — should be very low."""
        score = GovernanceTrustScore.wilson_lower_bound(0, 100)
        assert score < Decimal("0.15")

    def test_score_clamped_zero_to_one(self):
        """Score must always be in [0, 1]."""
        for s, n in [(0, 0), (100, 100), (0, 1000), (1000, 1000)]:
            score = GovernanceTrustScore.wilson_lower_bound(s, n)
            assert Decimal("0") <= score <= Decimal("1")


# ---------------------------------------------------------------------------
# Temporal decay
# ---------------------------------------------------------------------------


class TestApplyDecay:
    """Test exponential decay toward cold-start prior."""

    def test_zero_days_no_decay(self):
        """0 days since last observation -> raw score unchanged."""
        raw = Decimal("0.90")
        result = GovernanceTrustScore.apply_decay(raw, Decimal("0"))
        assert result == raw

    def test_negative_days_no_decay(self):
        """Negative days should also return raw score unchanged."""
        raw = Decimal("0.85")
        result = GovernanceTrustScore.apply_decay(raw, Decimal("-5"))
        assert result == raw

    def test_half_life_decay(self):
        """At exactly 30 days (half-life), score decays halfway toward prior.

        effective = raw * 0.5 + prior * 0.5
        For raw=0.90, prior=0.47: effective ~0.685
        """
        raw = Decimal("0.90")
        result = GovernanceTrustScore.apply_decay(raw, Decimal("30"))
        expected_approx = (float(raw) * 0.5 + float(PRIOR_TRUST) * 0.5)
        assert abs(float(result) - expected_approx) < 0.02

    def test_large_days_approaches_prior(self):
        """After many half-lives, effective score should approach prior."""
        raw = Decimal("0.95")
        result = GovernanceTrustScore.apply_decay(raw, Decimal("300"))
        # 300 days = 10 half-lives, freshness ~= 0.001
        assert abs(float(result) - float(PRIOR_TRUST)) < 0.02

    def test_decay_result_clamped(self):
        """Result must be in [0, 1]."""
        for raw in [Decimal("0"), Decimal("0.5"), Decimal("1")]:
            for days in [Decimal("1"), Decimal("30"), Decimal("365")]:
                result = GovernanceTrustScore.apply_decay(raw, days)
                assert Decimal("0") <= result <= Decimal("1")


# ---------------------------------------------------------------------------
# Trust -> dial ceiling mapping
# ---------------------------------------------------------------------------


class TestTrustToDialCeiling:
    """Test trust score to dial ceiling mapping at each threshold."""

    def test_very_low_trust(self):
        """trust < 0.3 -> 1/3 (REPLAY only)."""
        assert GovernanceTrustScore.trust_to_dial_ceiling(Decimal("0.1")) == Decimal("0.3333")
        assert GovernanceTrustScore.trust_to_dial_ceiling(Decimal("0.29")) == Decimal("0.3333")

    def test_low_trust(self):
        """0.3 <= trust < 0.5 -> 1/2 (up to ADAPT)."""
        assert GovernanceTrustScore.trust_to_dial_ceiling(Decimal("0.3")) == Decimal("0.5")
        assert GovernanceTrustScore.trust_to_dial_ceiling(Decimal("0.49")) == Decimal("0.5")

    def test_medium_trust(self):
        """0.5 <= trust < 0.7 -> 2/3 (up to EXPLORE)."""
        assert GovernanceTrustScore.trust_to_dial_ceiling(Decimal("0.5")) == Decimal("0.6667")
        assert GovernanceTrustScore.trust_to_dial_ceiling(Decimal("0.69")) == Decimal("0.6667")

    def test_high_trust(self):
        """trust >= 0.7 -> 1.0 (full CREATE access)."""
        assert GovernanceTrustScore.trust_to_dial_ceiling(Decimal("0.7")) == Decimal("1.0")
        assert GovernanceTrustScore.trust_to_dial_ceiling(Decimal("0.99")) == Decimal("1.0")
        assert GovernanceTrustScore.trust_to_dial_ceiling(Decimal("1.0")) == Decimal("1.0")

    def test_boundary_at_zero(self):
        """trust = 0 -> REPLAY only."""
        assert GovernanceTrustScore.trust_to_dial_ceiling(Decimal("0")) == Decimal("0.3333")


# ---------------------------------------------------------------------------
# GovernanceTrustScore.compute()
# ---------------------------------------------------------------------------


class TestGovernanceTrustScoreCompute:
    """Test that compute() recomputes all derived fields."""

    def test_compute_fresh(self):
        """compute() with 0 days recomputes raw, freshness=1, effective=raw."""
        ts = GovernanceTrustScore(
            principal_did="did:sync:user:alice",
            domain="analytics",
            successes=50,
            trials=60,
            days_since_last_observation=Decimal("0"),
        )
        ts.compute()

        assert ts.raw_score == GovernanceTrustScore.wilson_lower_bound(50, 60)
        assert ts.freshness_factor == Decimal("1")
        assert ts.effective_score == ts.raw_score
        assert ts.trust_dial_ceiling == GovernanceTrustScore.trust_to_dial_ceiling(
            ts.effective_score
        )

    def test_compute_with_decay(self):
        """compute() with days > 0 applies decay and recalculates ceiling."""
        ts = GovernanceTrustScore(
            successes=100,
            trials=100,
            days_since_last_observation=Decimal("30"),
        )
        ts.compute()

        assert ts.raw_score == GovernanceTrustScore.wilson_lower_bound(100, 100)
        assert ts.freshness_factor < Decimal("1")
        assert ts.effective_score < ts.raw_score
        assert ts.trust_dial_ceiling == GovernanceTrustScore.trust_to_dial_ceiling(
            ts.effective_score
        )

    def test_compute_returns_self(self):
        """compute() returns the instance for fluent chaining."""
        ts = GovernanceTrustScore(successes=10, trials=20)
        result = ts.compute()
        assert result is ts


# ---------------------------------------------------------------------------
# Serialization roundtrip
# ---------------------------------------------------------------------------


class TestSerialization:
    """Test to_dict / from_dict roundtrip."""

    def test_roundtrip(self):
        original = GovernanceTrustScore(
            principal_did="did:sync:user:bob",
            domain="finance",
            successes=42,
            trials=50,
            raw_score=Decimal("0.78"),
            days_since_last_observation=Decimal("7"),
            freshness_factor=Decimal("0.85"),
            effective_score=Decimal("0.73"),
            trust_dial_ceiling=Decimal("0.6667"),
            computed_at="2026-02-21T00:00:00Z",
        )
        d = original.to_dict()
        restored = GovernanceTrustScore.from_dict(d)

        assert restored.principal_did == original.principal_did
        assert restored.domain == original.domain
        assert restored.successes == original.successes
        assert restored.trials == original.trials
        assert restored.raw_score == original.raw_score
        assert restored.days_since_last_observation == original.days_since_last_observation
        assert restored.freshness_factor == original.freshness_factor
        assert restored.effective_score == original.effective_score
        assert restored.trust_dial_ceiling == original.trust_dial_ceiling
        assert restored.computed_at == original.computed_at

    def test_from_dict_empty(self):
        """from_dict with empty/None dict returns defaults."""
        ts = GovernanceTrustScore.from_dict({})
        assert ts.principal_did == ""
        assert ts.successes == 0
        assert ts.raw_score == Decimal("0.47")

    def test_from_dict_none(self):
        ts = GovernanceTrustScore.from_dict(None)
        assert ts.principal_did == ""

    def test_to_dict_types(self):
        """All Decimal fields should serialize as strings."""
        ts = GovernanceTrustScore(raw_score=Decimal("0.85"))
        d = ts.to_dict()
        assert isinstance(d["raw_score"], str)
        assert isinstance(d["effective_score"], str)
        assert isinstance(d["trust_dial_ceiling"], str)
        assert isinstance(d["freshness_factor"], str)
        assert isinstance(d["days_since_last_observation"], str)
