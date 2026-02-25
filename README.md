# syncropel-registry-core

Shared governance logic for Syncropel. Pure Python, zero external dependencies.

Used by both [syncropel-registry](https://github.com/syncropic/syncropel-registry) (production) and [syncropel-cli](https://github.com/syncropic/syncropel-cli) (`spl serve`) to ensure identical governance decisions regardless of deployment context.

## What It Provides

| Module | Purpose |
|--------|---------|
| `namespaces` | 5-level namespace resolution (DEFAULT -> ORG -> PROJECT -> ENV -> JOB) |
| `hashing` | 4-level content-addressed hashing (L0-L3), canonical JSON format |
| `trust` | Wilson score lower bound with cold-start prior and temporal decay |
| `crystallization` | Pattern promotion based on observation statistics |
| `validators.governance` | Pure governance checks 3-9 (stateless, no I/O) |
| `sct.helpers` | SCT computation helpers (hierarchy, capability intersection, dial ceiling) |
| `models.sct` | SessionCapabilityToken and envelope dataclasses |
| `models.governance` | Audit, lineage, and observation records |
| `constants` | Frozen Foundation constants (F1-F15) |

## Design Principles

- **Zero dependencies** — stdlib only (`hashlib`, `json`, `math`, `dataclasses`, `decimal`)
- **Pure functions** — no database access, no I/O, no async
- **Callback injection** — `resolve_namespace()` accepts `get_ns`/`get_policy` callbacks for any backing store
- **Spec compliance** — implements Frozen Foundations F1-F15 exactly

## Installation

```bash
# As a dependency (git URL)
pip install "syncropel-registry-core @ git+https://github.com/syncropic/syncropel-registry-core.git"

# For development
git clone https://github.com/syncropic/syncropel-registry-core.git
cd syncropel-registry-core
uv sync --extra dev
```

## Usage

```python
from syncropel_registry_core.hashing import compute_hashes
from syncropel_registry_core.namespaces import resolve_namespace
from syncropel_registry_core.trust import GovernanceTrustScore
from syncropel_registry_core.validators.governance import validate_checks_3_to_9

# Hash effects at all 4 levels
effects = [{"primitive": "GET", "input_shape": "ONE", "output_shape": "ONE", "operation": "db.query"}]
h0, h1, h2, h3 = compute_hashes(effects)

# Compute trust score
trust = GovernanceTrustScore(successes=15, trials=20).compute()

# Validate governance checks 3-9
result = validate_checks_3_to_9(trace_effects, sct, dial_position=Decimal("0.5"))
```

## Testing

```bash
uv run pytest tests/ -v    # 176 tests, ~0.2s
uv run ruff check src/ tests/
uv run ruff format --check src/ tests/
```

## Governance Check Split

| Checks | Location | Requires |
|--------|----------|----------|
| 1 (CRL) | Registry | Store access (CRL lookup) |
| 2 (Policy freshness) | Registry | Store access (version comparison) |
| 3-9 | **This library** | Pure computation only |
| 10 (HITL) | Registry | Store access (approval lookup) |

## License

Apache-2.0
