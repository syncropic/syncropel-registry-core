# syncropel-registry-core

Shared governance logic for [Syncropel](https://docs.syncropel.com) — infrastructure that learns and governs.

Pure Python. Zero external dependencies. Same logic in every deployment.

## Why This Exists

Syncropel has two runtimes that make governance decisions: the [production registry](https://github.com/syncropic/syncropel-registry) and the [local CLI](https://github.com/syncropic/syncropel-cli) (`spl serve`). Both must enforce identical rules. This library is the shared brain — pure functions with no I/O, no database access, no async. You pass callbacks for storage; it handles the math.

## Install

```bash
# Pin to a release tag
pip install "syncropel-registry-core @ git+https://github.com/syncropic/syncropel-registry-core.git@v0.2.0"

# Or latest main
pip install "syncropel-registry-core @ git+https://github.com/syncropic/syncropel-registry-core.git"

# For development
git clone https://github.com/syncropic/syncropel-registry-core.git
cd syncropel-registry-core && uv sync --extra dev
```

Requires Python 3.12+. Zero runtime dependencies.

## Modules

| Module | What It Does |
|--------|-------------|
| `hashing` | Content-addressed hashing across hash levels — L0 exact through L3 intent |
| `namespaces` | Namespace resolution with monotonic narrowing. Children never have more permissions than parents |
| `trust` | Wilson score lower bound with cold-start prior and temporal decay |
| `validators.governance` | Pure governance checks — capability, deny, budget, dial, hash level, output constraints, lineage, federation |
| `models.sct` | SessionCapabilityToken — the primary governance primitive |
| `models.governance` | Audit records, governance decisions, lineage, observations |
| `sct.helpers` | SCT computation helpers (hierarchy walk, capability intersection, dial ceiling) |
| `crystallization` | Pattern promotion based on observation statistics |
| `constants` | Frozen Foundation constants |

## Usage

### Hash effects across all levels

```python
from syncropel_registry_core.hashing import compute_hashes

effects = [
    {
        "primitive": "GET",
        "input_shape": "ONE",
        "output_shape": "MANY",
        "operation": "db.query",
        "parameters": {"table": "users"},
    }
]

hash_l0, hash_l1, hash_l2, hash_l3 = compute_hashes(effects)
# L0 = exact (includes parameters) — never leaves local namespace
# L1 = structural (primitive + shapes + operation)
# L2 = flow (primitive + shapes)
# L3 = intent (shapes only) — safest to federate
```

### Resolve a namespace

```python
from syncropel_registry_core.namespaces import resolve_namespace

# Provide callbacks to your storage layer
def get_ns(ns_id: str) -> dict | None:
    return your_db.get_namespace(ns_id)

def get_policy(ns_id: str) -> dict | None:
    return your_db.get_policy(ns_id)

# Walks the hierarchy, composing governance at each level
# Capability intersects, deny merges, budget takes the tighter constraint
effective = resolve_namespace("acme/analytics/prod", get_ns, get_policy)

print(effective["capability"]["primitives"])  # e.g. ["GET", "CALL"]
print(effective["budget"]["compute_usd"])     # e.g. 10.00
print(effective["dial_ceiling"])              # e.g. 0.5
```

### Compute trust score

```python
from syncropel_registry_core.trust import GovernanceTrustScore

trust = GovernanceTrustScore(
    principal_did="did:sync:user:alice",
    domain="db.query",
    successes=45,
    trials=50,
    days_since_last_observation=5,
).compute()

print(trust.effective_score)      # e.g. 0.8234
print(trust.trust_dial_ceiling)   # e.g. 1.0 (full CREATE access)
```

### Validate governance checks

```python
from decimal import Decimal
from syncropel_registry_core.models.sct import SessionCapabilityToken, CapabilityEnvelope
from syncropel_registry_core.validators.governance import validate_checks_3_to_9

sct = SessionCapabilityToken(
    principal_did="did:sync:user:alice",
    namespace="acme/analytics/prod",
    capability=CapabilityEnvelope(
        primitives={"GET", "CALL"},
        shapes={"ONE", "MANY"},
        operations=["db.*"],
        resources=["/sync/database/*"],
    ),
    dial_ceiling=Decimal("0.6667"),
)

trace_effects = [
    {"primitive": "GET", "shape": "MANY", "operation": "db.query",
     "resource": "/sync/database/users"},
]

result = validate_checks_3_to_9(
    trace_effects, sct,
    dial_position=Decimal("0.5"),
    requested_hash_level="L1",
)

if result.valid:
    print("All checks passed:", result.checks_passed)
else:
    for error in result.errors:
        print(f"Check {error.check_number}: {error.detail}")
```

## Governance Check Split

The full governance pipeline splits between stateful checks (requiring storage) and pure checks (this library):

| Check | Name | Location | Why |
|-------|------|----------|-----|
| 1 | CRL revocation | Registry | Requires database lookup |
| 2 | Policy freshness | Registry | Requires version comparison |
| **3** | **Capability envelope** | **This library** | Pure set/glob matching |
| **4** | **Deny constraints** | **This library** | Pure pattern matching |
| **5** | **Budget (session)** | **This library** | Pure arithmetic |
| **6** | **Dial ceiling** | **This library** | Pure comparison |
| **7** | **Hash level access** | **This library** | Pure set membership |
| **8** | **Budget guard (per-effect)** | **This library** | Pure arithmetic |
| **9** | **Structural constraints** | **This library** | Pure validation |
| 10 | HITL approval | Registry | Requires approval lookup |

## Development

```bash
uv sync --extra dev
uv run pytest tests/ -v
uv run ruff check src/ tests/
uv run ruff format --check src/ tests/
```

## Related

- [Syncropel Studio](https://app.syncropel.com) — operate registries from the browser
- [Documentation](https://docs.syncropel.com) — concepts, guides, reference
- [spl](https://github.com/syncropic/syncropel-cli) — CLI + local registry
- [syncropel-registry](https://github.com/syncropic/syncropel-registry) — production registry
- [syncropel-core](https://github.com/syncropic/syncropel-core) — Rust verification engine

## License

Apache-2.0. See [LICENSE](./LICENSE).
