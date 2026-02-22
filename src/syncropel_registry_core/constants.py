"""Frozen Foundation constants (F1-F15).

These MUST NEVER change. Any document, implementation, or spec that
contradicts these is wrong.
"""

# F1: Effect Primitives — exactly 4
VALID_PRIMITIVES = {"GET", "PUT", "CALL", "MAP"}

# F2: Data Shapes — exactly 5
VALID_SHAPES = {"VOID", "ONE", "OPTIONAL", "MANY", "KEYED"}

# F3: Dial Range — continuous scalar d in [0, 1]
DIAL_MIN = 0.0
DIAL_MAX = 1.0

# F4: Dial Zone Thresholds
DIAL_T1 = 1 / 3
DIAL_T2 = 1 / 2
DIAL_T3 = 2 / 3

# F5: Dial Zone Names and ranges
DIAL_ZONES = {
    "REPLAY": (0, 1 / 3),
    "ADAPT": (1 / 3, 1 / 2),
    "EXPLORE": (1 / 2, 2 / 3),
    "CREATE": (2 / 3, 1),
}

# F6: Hash Levels — 4 levels
ALL_HASH_LEVELS = ["L0", "L1", "L2", "L3"]

# F10: Hash Algorithm
HASH_ALGORITHM = "sha256"

# F14: Canonical JSON Key Order — alphabetical within each level object
# (enforced by implementation, not a runtime constant)
