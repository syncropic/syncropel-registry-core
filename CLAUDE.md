# CLAUDE.md - Agent Configuration for syncropel-registry-core

## What This Is

Pure Python shared governance library. Zero external dependencies (stdlib only).
Used by both `syncropel-registry` (production FastAPI service) and `syncropel-cli`
(`spl serve`) to ensure identical governance decisions regardless of deployment context.

**If you change this library, you change governance for the entire platform.**

## Build & Test

```bash
uv sync --extra dev
uv run pytest tests/ -v          # 218 tests, ~0.3s
uv run ruff check src/ tests/    # must pass clean
uv run ruff format --check src/ tests/
```

## Architecture

```
src/syncropel_registry_core/
├── constants.py           # Frozen Foundations F1-F15, shared helpers
├── namespaces.py          # 5-level namespace resolution (pure functions + callbacks)
├── hashing.py             # 4-level content-addressed hashing (L0-L3)
├── trust.py               # Wilson score + temporal decay trust model
├── crystallization.py     # Pattern promotion based on observation stats
├── models/
│   ├── sct.py             # SessionCapabilityToken, envelopes, grants (536 lines)
│   └── governance.py      # AuditRecord, GovernanceDecision, LineageRecord, ObservationRecord
├── sct/
│   └── helpers.py         # SCT computation helpers (hierarchy, capability intersection)
└── validators/
    └── governance.py      # Pure governance checks 3-9 (stateless, no I/O)
```

## Governance Check Split

| Checks | Location | Why |
|--------|----------|-----|
| 1 (CRL revocation) | Registry | Requires store access |
| 2 (Policy freshness) | Registry | Requires store access |
| **3-9** | **This library** | Pure computation, no I/O |
| 10 (HITL approval) | Registry | Requires store access |

## Key Design Decisions

- **Callback injection**: `resolve_namespace(ns_id, get_ns, get_policy)` accepts store callbacks, works with any backing store (DuckDB, PostgreSQL, in-memory)
- **Pure functions**: No database, no async, no I/O. All functions are synchronous and stateless.
- **Decimal everywhere**: Trust scores, budgets, dial ceilings use `Decimal` for precision
- **StrEnum for all enums**: Python 3.12+ `StrEnum` for JSON serialization compatibility
- **`to_dict()`/`from_dict()`**: All dataclasses have full serialization roundtrips

## Frozen Foundations (MUST NOT change)

Defined in `constants.py`. See parent workspace CLAUDE.md for all 15.

- F1: 4 primitives (GET, PUT, CALL, MAP)
- F2: 5 shapes (VOID, ONE, OPTIONAL, MANY, KEYED)
- F4: Dial thresholds T1=1/3, T2=1/2, T3=2/3
- F5: 4 zones (REPLAY, ADAPT, EXPLORE, CREATE)
- F8: L0 hashes NEVER leave local namespace
- F10: SHA-256, lowercase hex, 64 chars
- F14: Canonical JSON key order — alphabetical

## Consumers

| Consumer | How It Imports | What It Uses |
|----------|---------------|--------------|
| `syncropel-registry` | `git+https://github.com/syncropic/syncropel-registry-core.git` | validators, models, namespaces, hashing, trust |
| `syncropel-cli` | Same git URL + local editable override | Same + sct helpers |

## Code Conventions

- Constants import from `constants.py` (single source of truth)
- Shared helpers (`_any_glob_match`) live in `constants.py`
- Pattern intersection uses subsumption (`pattern_subsumes`), not literal set intersection
- Tests reference spec sections in class/method docstrings
