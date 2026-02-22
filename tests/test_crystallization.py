"""Tests for crystallization: Wilson score-based pattern promotion."""

from syncropel_registry_core.crystallization import (
    CRYSTALLIZATION_SCORE,
    CRYSTALLIZATION_THRESHOLD,
    check_crystallization,
)


class TestCheckCrystallization:
    """Test pattern crystallization logic."""

    def test_below_threshold_returns_false(self):
        """Total observations < 50 should never crystallize."""
        assert check_crystallization(49, 0) is False
        assert check_crystallization(25, 24) is False
        assert check_crystallization(0, 0) is False

    def test_at_threshold_with_high_success_rate(self):
        """50 observations with all successes should crystallize."""
        assert check_crystallization(50, 0) is True

    def test_at_threshold_with_low_success_rate(self):
        """50 observations with low success rate should NOT crystallize."""
        # 30 successes / 50 total = 60% success rate — well below the
        # Wilson lower bound threshold of 0.85
        assert check_crystallization(30, 20) is False

    def test_high_count_high_rate_crystallizes(self):
        """1000 successes, 10 failures -> Wilson LB should be well above 0.85."""
        assert check_crystallization(1000, 10) is True

    def test_high_count_low_rate_does_not_crystallize(self):
        """500 successes, 500 failures -> 50% rate, should NOT crystallize."""
        assert check_crystallization(500, 500) is False

    def test_exact_boundary_just_above(self):
        """With exactly 50 total and 49 successes, Wilson LB should be
        high enough to crystallize."""
        assert check_crystallization(49, 1) is True

    def test_exact_boundary_just_below(self):
        """With exactly 50 total and 42 successes (84%), Wilson LB should
        be just below the 0.85 threshold."""
        # 42/50 = 0.84 — Wilson lower bound at 95% confidence will be
        # below 0.84, which is below 0.85
        assert check_crystallization(42, 8) is False

    def test_threshold_constant(self):
        """Verify the crystallization threshold is 50."""
        assert CRYSTALLIZATION_THRESHOLD == 50

    def test_score_constant(self):
        """Verify the crystallization Wilson lower bound threshold is 0.85."""
        assert CRYSTALLIZATION_SCORE == 0.85

    def test_zero_failures_at_threshold(self):
        """Exactly 50 successes and 0 failures -> should crystallize."""
        assert check_crystallization(50, 0) is True

    def test_one_below_threshold(self):
        """49 total observations (all successes) -> should NOT crystallize."""
        assert check_crystallization(49, 0) is False
