"""Governance v3 trust model: Wilson score with temporal decay.

The governance trust score feeds into the SCT's dial_ceiling computation.
Higher trust -> higher dial ceiling -> lighter governance.

This is distinct from the identity-level TrustScore in trust.py — this model
is scoped to (principal_did, domain) pairs for governance purposes.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from decimal import Decimal


# Cold-start prior: 7 successes out of 10 trials
COLD_START_SUCCESSES = 7
COLD_START_TRIALS = 10
# Wilson z-value for 95% confidence
WILSON_Z = 1.96
# Decay half-life in days
DECAY_HALF_LIFE = 30.0
# Prior trust (Wilson lower bound of 7/10)
PRIOR_TRUST = Decimal("0.47")


@dataclass
class GovernanceTrustScore:
    """Evidence-derived trust score for a (principal, domain) pair.

    Uses Wilson score lower bound with cold-start prior and
    exponential decay toward prior on stale observations.
    """
    principal_did: str = ""
    domain: str = ""
    successes: int = 0
    trials: int = 0
    raw_score: Decimal = Decimal("0.47")
    days_since_last_observation: Decimal = Decimal("0")
    freshness_factor: Decimal = Decimal("1")
    effective_score: Decimal = Decimal("0.47")
    trust_dial_ceiling: Decimal = Decimal("0.5")
    computed_at: str = ""

    @staticmethod
    def wilson_lower_bound(successes: int, trials: int) -> Decimal:
        """Compute Wilson score lower bound with cold-start prior.

        Prior: 7 successes / 10 trials added to actual observations.
        Z = 1.96 for 95% confidence.
        """
        z = WILSON_Z
        adj_s = successes + COLD_START_SUCCESSES
        adj_n = trials + COLD_START_TRIALS

        if adj_n == 0:
            return PRIOR_TRUST

        p_hat = adj_s / adj_n
        denominator = 1 + z * z / adj_n
        center = (p_hat + z * z / (2 * adj_n)) / denominator
        margin = z * math.sqrt(
            (p_hat * (1 - p_hat) / adj_n + z * z / (4 * adj_n * adj_n))
        ) / denominator

        result = center - margin
        return Decimal(str(round(max(0.0, min(1.0, result)), 4)))

    @staticmethod
    def apply_decay(raw_score: Decimal, days_since_last: Decimal) -> Decimal:
        """Apply temporal decay toward cold-start prior.

        freshness = exp(-days * ln(2) / half_life)
        effective = raw * freshness + prior * (1 - freshness)
        """
        if days_since_last <= 0:
            return raw_score

        days = float(days_since_last)
        freshness = math.exp(-days * math.log(2) / DECAY_HALF_LIFE)

        raw = float(raw_score)
        prior = float(PRIOR_TRUST)
        effective = raw * freshness + prior * (1 - freshness)
        return Decimal(str(round(max(0.0, min(1.0, effective)), 4)))

    @staticmethod
    def trust_to_dial_ceiling(trust: Decimal) -> Decimal:
        """Map trust score to dial ceiling.

        < 0.3 -> 1/3 (REPLAY only)
        < 0.5 -> 1/2 (up to ADAPT)
        < 0.7 -> 2/3 (up to EXPLORE)
        >= 0.7 -> 1.0 (full CREATE access)
        """
        if trust < Decimal("0.3"):
            return Decimal("0.3333")
        elif trust < Decimal("0.5"):
            return Decimal("0.5")
        elif trust < Decimal("0.7"):
            return Decimal("0.6667")
        else:
            return Decimal("1.0")

    def compute(self) -> GovernanceTrustScore:
        """Recompute derived fields from successes/trials."""
        self.raw_score = self.wilson_lower_bound(self.successes, self.trials)
        days = float(self.days_since_last_observation)
        if days > 0:
            self.freshness_factor = Decimal(str(round(
                math.exp(-days * math.log(2) / DECAY_HALF_LIFE), 4
            )))
        else:
            self.freshness_factor = Decimal("1")
        self.effective_score = self.apply_decay(
            self.raw_score, self.days_since_last_observation
        )
        self.trust_dial_ceiling = self.trust_to_dial_ceiling(self.effective_score)
        return self

    def to_dict(self) -> dict:
        return {
            "principal_did": self.principal_did,
            "domain": self.domain,
            "successes": self.successes,
            "trials": self.trials,
            "raw_score": str(self.raw_score),
            "days_since_last_observation": str(self.days_since_last_observation),
            "freshness_factor": str(self.freshness_factor),
            "effective_score": str(self.effective_score),
            "trust_dial_ceiling": str(self.trust_dial_ceiling),
            "computed_at": self.computed_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> GovernanceTrustScore:
        if not data:
            return cls()
        return cls(
            principal_did=data.get("principal_did", ""),
            domain=data.get("domain", ""),
            successes=data.get("successes", 0),
            trials=data.get("trials", 0),
            raw_score=Decimal(str(data.get("raw_score", "0.47"))),
            days_since_last_observation=Decimal(str(data.get("days_since_last_observation", "0"))),
            freshness_factor=Decimal(str(data.get("freshness_factor", "1"))),
            effective_score=Decimal(str(data.get("effective_score", "0.47"))),
            trust_dial_ceiling=Decimal(str(data.get("trust_dial_ceiling", "0.5"))),
            computed_at=data.get("computed_at", ""),
        )
