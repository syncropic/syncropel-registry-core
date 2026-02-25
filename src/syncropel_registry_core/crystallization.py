"""Crystallization check — Wilson score-based pattern promotion.

A pattern is crystallized (promoted to canonical) when it has enough
observations with a sufficiently high success rate, as measured by
the Wilson score lower bound at 95% confidence.
"""

from __future__ import annotations

# Minimum observations before crystallization is considered
CRYSTALLIZATION_THRESHOLD = 50

# Minimum Wilson lower bound (95% confidence) for crystallization
CRYSTALLIZATION_SCORE = 0.85

# Wilson z-value for 95% confidence
WILSON_Z = 1.96


def check_crystallization(success_count: int, failure_count: int) -> bool:
    """Check if a pattern should be crystallized using Wilson score.

    Args:
        success_count: Number of successful observations.
        failure_count: Number of failed observations.

    Returns:
        True if the pattern meets crystallization criteria.
    """
    total = success_count + failure_count
    if total < CRYSTALLIZATION_THRESHOLD:
        return False
    p = success_count / total
    z2 = WILSON_Z**2
    denom = 1 + z2 / total
    center = (p + z2 / (2 * total)) / denom
    spread = (WILSON_Z / denom) * ((p * (1 - p) / total + z2 / (4 * total**2)) ** 0.5)
    lower_bound = center - spread
    return lower_bound >= CRYSTALLIZATION_SCORE
