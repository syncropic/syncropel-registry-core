"""Tests for the pure namespace resolution functions."""

import pytest

from syncropel_registry_core.namespaces import (
    DEFAULT_BINDINGS,
    DEFAULT_BUDGET,
    DEFAULT_CAPABILITY,
    DEFAULT_DEFAULTS,
    DEFAULT_VARIABLES,
    build_ancestor_chain,
    derive_level,
    derive_parent_id,
    intersect_capability,
    merge_variables,
    overlay_bindings,
    override_defaults,
    pattern_subsumes,
    resolve_binding,
    resolve_namespace,
    restrict_budget,
    union_deny,
    validate_namespace_id,
)

# ---------------------------------------------------------------------------
# Path validation — spec §2.3
# ---------------------------------------------------------------------------


class TestValidateNamespaceId:
    def test_valid_org(self):
        validate_namespace_id("acme")

    def test_valid_project(self):
        validate_namespace_id("acme/analytics")

    def test_valid_env(self):
        validate_namespace_id("acme/analytics/prod")

    def test_valid_job(self):
        validate_namespace_id("acme/analytics/prod/job-7f3a")

    def test_valid_default(self):
        validate_namespace_id("default")

    def test_valid_with_underscores(self):
        validate_namespace_id("my_org/my_project")

    def test_valid_with_digits(self):
        validate_namespace_id("org1/proj2/env3")

    def test_invalid_empty(self):
        with pytest.raises(ValueError, match="NAMESPACE_ID_INVALID"):
            validate_namespace_id("")

    def test_invalid_uppercase(self):
        with pytest.raises(ValueError, match="NAMESPACE_ID_INVALID"):
            validate_namespace_id("Acme")

    def test_invalid_starts_with_hyphen(self):
        with pytest.raises(ValueError, match="NAMESPACE_ID_INVALID"):
            validate_namespace_id("-acme")

    def test_invalid_empty_segment(self):
        with pytest.raises(ValueError, match="NAMESPACE_ID_INVALID"):
            validate_namespace_id("acme//analytics")

    def test_invalid_too_deep(self):
        with pytest.raises(ValueError, match="NAMESPACE_ID_TOO_DEEP"):
            validate_namespace_id("a/b/c/d/e")

    def test_invalid_too_long(self):
        with pytest.raises(ValueError, match="NAMESPACE_ID_TOO_LONG"):
            validate_namespace_id("a" * 257)

    def test_invalid_segment_too_long(self):
        with pytest.raises(ValueError, match="NAMESPACE_SEGMENT_TOO_LONG"):
            validate_namespace_id("a" * 64)

    def test_invalid_special_chars(self):
        with pytest.raises(ValueError, match="NAMESPACE_ID_INVALID"):
            validate_namespace_id("acme/analytics.prod")

    def test_invalid_spaces(self):
        with pytest.raises(ValueError, match="NAMESPACE_ID_INVALID"):
            validate_namespace_id("acme/ analytics")


# ---------------------------------------------------------------------------
# Parent derivation — spec §1.2
# ---------------------------------------------------------------------------


class TestDeriveParentId:
    def test_default_has_no_parent(self):
        assert derive_parent_id("default") is None

    def test_org_parent_is_default(self):
        assert derive_parent_id("acme") == "default"

    def test_project_parent(self):
        assert derive_parent_id("acme/analytics") == "acme"

    def test_env_parent(self):
        assert derive_parent_id("acme/analytics/prod") == "acme/analytics"

    def test_job_parent(self):
        assert derive_parent_id("acme/analytics/prod/job-1") == "acme/analytics/prod"


# ---------------------------------------------------------------------------
# Level assignment — spec §1.3
# ---------------------------------------------------------------------------


class TestDeriveLevel:
    def test_default(self):
        assert derive_level("default") == "DEFAULT"

    def test_org(self):
        assert derive_level("acme") == "ORG"

    def test_project(self):
        assert derive_level("acme/analytics") == "PROJECT"

    def test_env(self):
        assert derive_level("acme/analytics/prod") == "ENV"

    def test_job(self):
        assert derive_level("acme/analytics/prod/job-1") == "JOB"


# ---------------------------------------------------------------------------
# Pattern subsumption — spec §5.1
# ---------------------------------------------------------------------------


class TestPatternSubsumes:
    def test_star_matches_all(self):
        assert pattern_subsumes("*", "anything")
        assert pattern_subsumes("*", "db.query")

    def test_slash_star_matches_paths(self):
        assert pattern_subsumes("/*", "/sync/database/foo")
        assert not pattern_subsumes("/*", "db.query")

    def test_prefix_glob(self):
        assert pattern_subsumes("/sync/*", "/sync/database/foo")
        assert not pattern_subsumes("/sync/*", "/exec/llm/gen")

    def test_dot_glob(self):
        assert pattern_subsumes("db.*", "db.query")
        assert pattern_subsumes("db.*", "db.read")
        assert not pattern_subsumes("db.*", "llm.generate")

    def test_exact_match(self):
        assert pattern_subsumes("db.query", "db.query")
        assert not pattern_subsumes("db.query", "db.read")

    def test_nested_path_glob(self):
        assert pattern_subsumes("/sync/database/*", "/sync/database/analytics-db-prod/public")
        assert not pattern_subsumes("/sync/database/*", "/sync/content/wiki")


# ---------------------------------------------------------------------------
# Composition: capability intersection — spec §5.1
# ---------------------------------------------------------------------------


class TestIntersectCapability:
    def test_primitive_intersection(self):
        parent = {
            "primitives": ["GET", "PUT", "CALL", "MAP"],
            "shapes": [],
            "operations": [],
            "resources": [],
            "max_effects": 1000,
            "max_depth": 50,
        }
        child = {
            "primitives": ["GET", "CALL"],
            "shapes": [],
            "operations": [],
            "resources": [],
            "max_effects": 500,
            "max_depth": 25,
        }
        result = intersect_capability(parent, child)
        assert set(result["primitives"]) == {"GET", "CALL"}

    def test_shape_intersection(self):
        parent = {
            "primitives": [],
            "shapes": ["VOID", "ONE", "OPTIONAL", "MANY", "KEYED"],
            "operations": [],
            "resources": [],
            "max_effects": 1000,
            "max_depth": 50,
        }
        child = {
            "primitives": [],
            "shapes": ["ONE", "MANY"],
            "operations": [],
            "resources": [],
            "max_effects": 1000,
            "max_depth": 50,
        }
        result = intersect_capability(parent, child)
        assert set(result["shapes"]) == {"ONE", "MANY"}

    def test_max_effects_min(self):
        parent = {
            "primitives": [],
            "shapes": [],
            "operations": [],
            "resources": [],
            "max_effects": 1000,
            "max_depth": 50,
        }
        child = {
            "primitives": [],
            "shapes": [],
            "operations": [],
            "resources": [],
            "max_effects": 500,
            "max_depth": 15,
        }
        result = intersect_capability(parent, child)
        assert result["max_effects"] == 500
        assert result["max_depth"] == 15

    def test_operation_pattern_intersect(self):
        parent = {
            "primitives": [],
            "shapes": [],
            "operations": ["*"],
            "resources": [],
            "max_effects": 1000,
            "max_depth": 50,
        }
        child = {
            "primitives": [],
            "shapes": [],
            "operations": ["db.query", "llm.generate"],
            "resources": [],
            "max_effects": 1000,
            "max_depth": 50,
        }
        result = intersect_capability(parent, child)
        assert result["operations"] == ["db.query", "llm.generate"]

    def test_resource_pattern_intersect(self):
        parent = {
            "primitives": [],
            "shapes": [],
            "operations": [],
            "resources": ["/sync/*", "/exec/*"],
            "max_effects": 1000,
            "max_depth": 50,
        }
        child = {
            "primitives": [],
            "shapes": [],
            "operations": [],
            "resources": ["/sync/database/*", "/other/*"],
            "max_effects": 1000,
            "max_depth": 50,
        }
        result = intersect_capability(parent, child)
        assert result["resources"] == ["/sync/database/*"]


# ---------------------------------------------------------------------------
# Composition: budget restriction — spec §5.2
# ---------------------------------------------------------------------------


class TestRestrictBudget:
    def test_basic_restriction(self):
        parent = {
            "compute_usd": 0.10,
            "latency_ms": 60000,
            "quality_floor": 0.0,
            "risk_ceiling": 1.0,
        }
        child = {
            "compute_usd": 100.00,
            "latency_ms": 120000,
            "quality_floor": 0.5,
            "risk_ceiling": 0.8,
        }
        result = restrict_budget(parent, child)
        assert result["compute_usd"] == 0.10  # min
        assert result["latency_ms"] == 60000  # min
        assert result["quality_floor"] == 0.5  # max
        assert result["risk_ceiling"] == 0.8  # min

    def test_child_tighter(self):
        parent = {
            "compute_usd": 100.00,
            "latency_ms": 120000,
            "quality_floor": 0.5,
            "risk_ceiling": 0.8,
        }
        child = {
            "compute_usd": 10.00,
            "latency_ms": 30000,
            "quality_floor": 0.8,
            "risk_ceiling": 0.5,
        }
        result = restrict_budget(parent, child)
        assert result["compute_usd"] == 10.00
        assert result["latency_ms"] == 30000
        assert result["quality_floor"] == 0.8
        assert result["risk_ceiling"] == 0.5


# ---------------------------------------------------------------------------
# Composition: deny union — spec §5.4
# ---------------------------------------------------------------------------


class TestUnionDeny:
    def test_empty_parents(self):
        result = union_deny({"rules": []}, {"rules": []})
        assert result["rules"] == []

    def test_accumulates(self):
        parent = {"rules": [{"principal_pattern": "*", "resources": ["/admin"]}]}
        child = {"rules": [{"principal_pattern": "sa:*", "resources": ["/sensitive"]}]}
        result = union_deny(parent, child)
        assert len(result["rules"]) == 2


# ---------------------------------------------------------------------------
# Composition: binding overlay — spec §5.6
# ---------------------------------------------------------------------------


class TestOverlayBindings:
    def test_child_adds(self):
        parent = {"@wikipedia": {"concrete_path": "/document/wikipedia"}}
        child = {"@search": {"concrete_path": "/document/brave"}}
        result = overlay_bindings(parent, child)
        assert "@wikipedia" in result
        assert "@search" in result

    def test_child_overrides(self):
        parent = {"@db": {"concrete_path": "/table/analytics-db/public"}}
        child = {"@db": {"concrete_path": "/table/analytics-db-prod/public"}}
        result = overlay_bindings(parent, child)
        assert result["@db"]["concrete_path"] == "/table/analytics-db-prod/public"

    def test_parent_inherited(self):
        parent = {
            "@wikipedia": {"concrete_path": "/doc"},
            "@weather": {"concrete_path": "/weather"},
        }
        child = {}
        result = overlay_bindings(parent, child)
        assert result == parent


# ---------------------------------------------------------------------------
# Composition: variable merge — spec §5.7
# ---------------------------------------------------------------------------


class TestMergeVariables:
    def test_env_vars(self):
        effective = {"env_vars": {"LOG_LEVEL": "info"}, "secret_vars": {}, "vault_vars": {}}
        child_vars = {"LOG_LEVEL": {"type": "ENV", "value": "warn"}}
        result = merge_variables(effective, child_vars)
        assert result["env_vars"]["LOG_LEVEL"] == "warn"

    def test_secret_vars(self):
        effective = {"env_vars": {}, "secret_vars": {}, "vault_vars": {}}
        child_vars = {"API_KEY": {"type": "SECRET", "value": "enc:v2:..."}}
        result = merge_variables(effective, child_vars)
        assert result["secret_vars"]["API_KEY"] == "enc:v2:..."

    def test_vault_vars(self):
        effective = {"env_vars": {}, "secret_vars": {}, "vault_vars": {}}
        child_vars = {"DB_URL": {"type": "VAULT", "value": "vault://acme/db"}}
        result = merge_variables(effective, child_vars)
        assert result["vault_vars"]["DB_URL"] == "vault://acme/db"

    def test_none_child_vars(self):
        effective = {"env_vars": {"X": "1"}, "secret_vars": {}, "vault_vars": {}}
        result = merge_variables(effective, None)
        assert result["env_vars"]["X"] == "1"


# ---------------------------------------------------------------------------
# Composition: defaults override — spec §5.8
# ---------------------------------------------------------------------------


class TestOverrideDefaults:
    def test_child_overrides(self):
        parent = {"dial": 0.5, "timeout_seconds": 300, "max_cost_usd": 0.10}
        child = {"dial": 0.3, "timeout_seconds": None, "max_cost_usd": 10.00}
        result = override_defaults(parent, child)
        assert result["dial"] == 0.3
        assert result["timeout_seconds"] == 300  # parent preserved
        assert result["max_cost_usd"] == 10.00


# ---------------------------------------------------------------------------
# Binding resolution — spec §7.3
# ---------------------------------------------------------------------------


class TestResolveBinding:
    def test_unscoped(self):
        binding = {"concrete_path": "/document/wikipedia", "scoped": False}
        assert resolve_binding(binding, "acme/analytics/prod") == "/document/wikipedia"

    def test_scoped(self):
        binding = {"concrete_path": "/local/data", "scoped": True}
        assert (
            resolve_binding(binding, "acme/analytics/prod")
            == "/home/acme/analytics/prod/local/data"
        )


# ---------------------------------------------------------------------------
# Ancestor chain construction — spec §4.1
# ---------------------------------------------------------------------------


class TestBuildAncestorChain:
    def _make_store(self, namespaces):
        ns_by_id = {ns["id"]: ns for ns in namespaces}
        return lambda ns_id: ns_by_id.get(ns_id)

    def test_simple_chain(self):
        store = self._make_store(
            [
                {"id": "default", "parent_id": None},
                {"id": "acme", "parent_id": "default"},
                {"id": "acme/analytics", "parent_id": "acme"},
            ]
        )
        chain = build_ancestor_chain("acme/analytics", store)
        assert [ns["id"] for ns in chain] == ["default", "acme", "acme/analytics"]

    def test_default_only(self):
        store = self._make_store([{"id": "default", "parent_id": None}])
        chain = build_ancestor_chain("default", store)
        assert [ns["id"] for ns in chain] == ["default"]

    def test_missing_namespace(self):
        store = self._make_store([{"id": "default", "parent_id": None}])
        with pytest.raises(ValueError, match="NAMESPACE_NOT_FOUND"):
            build_ancestor_chain("nonexistent", store)

    def test_cycle_detection(self):
        store = self._make_store(
            [
                {"id": "default", "parent_id": None},
                {"id": "a", "parent_id": "b"},
                {"id": "b", "parent_id": "a"},
            ]
        )
        with pytest.raises(ValueError, match="NAMESPACE_CYCLE_DETECTED"):
            build_ancestor_chain("a", store)


# ---------------------------------------------------------------------------
# Full resolution — spec §9 walkthrough
# ---------------------------------------------------------------------------


class TestResolveNamespace:
    def _setup_hierarchy(self):
        """Set up the 4-level hierarchy from spec §9.1."""
        namespaces = {
            "default": {
                "id": "default",
                "parent_id": None,
                "level": "DEFAULT",
                "bindings_json": None,
                "bindings": DEFAULT_BINDINGS,
                "variables": DEFAULT_VARIABLES,
                "variables_json": None,
                "config_json": None,
                "defaults": DEFAULT_DEFAULTS,
            },
            "acme": {
                "id": "acme",
                "parent_id": "default",
                "level": "ORG",
                "bindings_json": None,
                "bindings": {
                    "@search": {
                        "concrete_path": "/document/brave",
                        "binding_type": "INVOCABLE",
                        "scoped": False,
                    }
                },
                "variables": {"BRAVE_API_KEY": {"type": "SECRET", "value": "enc:v2:..."}},
                "variables_json": None,
                "config_json": None,
                "defaults": None,
            },
            "acme/analytics": {
                "id": "acme/analytics",
                "parent_id": "acme",
                "level": "PROJECT",
                "bindings_json": None,
                "bindings": {
                    "@db": {
                        "concrete_path": "/table/analytics-db/public",
                        "binding_type": "ANY",
                        "scoped": False,
                    }
                },
                "variables": {"DB_POOL_SIZE": {"type": "ENV", "value": "10"}},
                "variables_json": None,
                "config_json": None,
                "defaults": None,
            },
            "acme/analytics/prod": {
                "id": "acme/analytics/prod",
                "parent_id": "acme/analytics",
                "level": "ENV",
                "bindings_json": None,
                "bindings": {
                    "@db": {
                        "concrete_path": "/table/analytics-db-prod/public",
                        "binding_type": "ANY",
                        "scoped": False,
                    }
                },
                "variables": {
                    "DB_POOL_SIZE": {"type": "ENV", "value": "5"},
                    "DB_URL": {"type": "VAULT", "value": "vault://acme/analytics/prod/db-url"},
                },
                "variables_json": None,
                "config_json": None,
                "defaults": None,
            },
        }

        policies = {
            "default": {
                "capability": DEFAULT_CAPABILITY,
                "deny": {"rules": []},
                "budget": DEFAULT_BUDGET,
                "dial_ceiling": 1.0,
                "hash_access": ["L0", "L1", "L2", "L3"],
            },
            "acme": {
                "capability": {
                    "primitives": ["GET", "PUT", "CALL", "MAP"],
                    "shapes": ["VOID", "ONE", "OPTIONAL", "MANY", "KEYED"],
                    "operations": ["*"],
                    "resources": ["/sync/*", "/exec/*", "/document/*", "/local/*"],
                    "max_effects": 1000,
                    "max_depth": 50,
                },
                "deny": {"rules": []},
                "budget": {
                    "compute_usd": 100.00,
                    "latency_ms": 120000,
                    "quality_floor": 0.5,
                    "risk_ceiling": 0.8,
                },
                "dial_ceiling": 0.8,
                "hash_access": ["L0", "L1", "L2", "L3"],
            },
            "acme/analytics": {
                "capability": {
                    "primitives": ["GET", "CALL", "MAP"],
                    "shapes": ["VOID", "ONE", "OPTIONAL", "MANY", "KEYED"],
                    "operations": ["db.*", "llm.*", "api.read"],
                    "resources": ["/sync/database/*", "/exec/llm/*"],
                    "max_effects": 500,
                    "max_depth": 25,
                },
                "deny": {
                    "rules": [
                        {
                            "principal_pattern": "*",
                            "resources": ["/sync/database/*/system"],
                            "primitives": ["PUT"],
                        }
                    ]
                },
                "budget": {
                    "compute_usd": 50.00,
                    "latency_ms": 90000,
                    "quality_floor": 0.6,
                    "risk_ceiling": 0.7,
                },
                "dial_ceiling": 0.67,
                "hash_access": ["L0", "L1", "L2"],
            },
            "acme/analytics/prod": {
                "capability": {
                    "primitives": ["GET", "CALL"],
                    "shapes": ["VOID", "ONE", "OPTIONAL", "MANY", "KEYED"],
                    "operations": ["db.query", "db.read", "llm.generate"],
                    "resources": ["/sync/database/analytics-db-prod/*"],
                    "max_effects": 200,
                    "max_depth": 15,
                },
                "deny": {
                    "rules": [
                        {
                            "principal_pattern": "did:sync:sa:*",
                            "resources": ["/sync/database/analytics-db-prod/sensitive*"],
                        }
                    ]
                },
                "budget": {
                    "compute_usd": 10.00,
                    "latency_ms": 30000,
                    "quality_floor": 0.8,
                    "risk_ceiling": 0.5,
                },
                "dial_ceiling": 0.5,
                "hash_access": ["L1", "L2"],
            },
        }

        def get_ns(ns_id):
            return namespaces.get(ns_id)

        def get_policy(ns_id):
            return policies.get(ns_id)

        return get_ns, get_policy

    def test_full_resolution(self):
        """Full spec §9 walkthrough — resolve acme/analytics/prod."""
        get_ns, get_policy = self._setup_hierarchy()
        eff = resolve_namespace("acme/analytics/prod", get_ns, get_policy)

        # Chain
        assert eff["chain"] == ["default", "acme", "acme/analytics", "acme/analytics/prod"]

        # Capability
        assert set(eff["capability"]["primitives"]) == {"GET", "CALL"}
        assert set(eff["capability"]["shapes"]) == {"VOID", "ONE", "OPTIONAL", "MANY", "KEYED"}
        assert set(eff["capability"]["operations"]) == {"db.query", "db.read", "llm.generate"}
        assert eff["capability"]["resources"] == ["/sync/database/analytics-db-prod/*"]
        assert eff["capability"]["max_effects"] == 200
        assert eff["capability"]["max_depth"] == 15

        # Budget
        assert eff["budget"]["compute_usd"] == 0.10
        assert eff["budget"]["latency_ms"] == 30000
        assert eff["budget"]["quality_floor"] == 0.8
        assert eff["budget"]["risk_ceiling"] == 0.5

        # Dial
        assert eff["dial_ceiling"] == 0.5

        # Hash access
        assert set(eff["hash_access"]) == {"L1", "L2"}

        # Deny
        assert len(eff["deny"]["rules"]) == 2

        # Variables
        assert eff["env_vars"]["DB_POOL_SIZE"] == "5"
        assert "BRAVE_API_KEY" in eff["secret_vars"]
        assert "DB_URL" in eff["vault_vars"]

    def test_monotonic_narrowing_invariant(self):
        """Verify effective(child) <= effective(parent) at every step."""
        get_ns, get_policy = self._setup_hierarchy()

        chain_ids = ["default", "acme", "acme/analytics", "acme/analytics/prod"]
        prev_eff = None

        for ns_id in chain_ids:
            eff = resolve_namespace(ns_id, get_ns, get_policy)

            if prev_eff is not None:
                # Primitives: child subset of parent
                assert set(eff["capability"]["primitives"]) <= set(
                    prev_eff["capability"]["primitives"]
                )
                # Shapes: child subset of parent
                assert set(eff["capability"]["shapes"]) <= set(prev_eff["capability"]["shapes"])
                # max_effects: child <= parent
                assert eff["capability"]["max_effects"] <= prev_eff["capability"]["max_effects"]
                # max_depth: child <= parent
                assert eff["capability"]["max_depth"] <= prev_eff["capability"]["max_depth"]
                # Budget: tighter
                assert eff["budget"]["compute_usd"] <= prev_eff["budget"]["compute_usd"]
                assert eff["budget"]["latency_ms"] <= prev_eff["budget"]["latency_ms"]
                assert eff["budget"]["quality_floor"] >= prev_eff["budget"]["quality_floor"]
                assert eff["budget"]["risk_ceiling"] <= prev_eff["budget"]["risk_ceiling"]
                # Dial: child <= parent
                assert eff["dial_ceiling"] <= prev_eff["dial_ceiling"]
                # Hash access: child subset of parent
                assert set(eff["hash_access"]) <= set(prev_eff["hash_access"])
                # Deny rules: parent subset of child (accumulation)
                assert len(eff["deny"]["rules"]) >= len(prev_eff["deny"]["rules"])

            prev_eff = eff

    def test_binding_scoped_resolution(self):
        """@files with scoped=True resolves to /home/{ns_id}/local/data."""
        get_ns, get_policy = self._setup_hierarchy()
        eff = resolve_namespace("acme/analytics/prod", get_ns, get_policy)
        assert eff["bindings"]["@files"] == "/home/acme/analytics/prod/local/data"

    def test_binding_override(self):
        """@db overridden at ENV level."""
        get_ns, get_policy = self._setup_hierarchy()
        eff = resolve_namespace("acme/analytics/prod", get_ns, get_policy)
        assert eff["bindings"]["@db"] == "/table/analytics-db-prod/public"

    def test_resolve_default_only(self):
        """Resolving default itself should return full default config."""
        get_ns, get_policy = self._setup_hierarchy()
        eff = resolve_namespace("default", get_ns, get_policy)
        assert eff["chain"] == ["default"]
        assert set(eff["capability"]["primitives"]) == {"GET", "PUT", "CALL", "MAP"}
        assert eff["dial_ceiling"] == 1.0

    def test_resolve_missing_ancestor(self):
        """Missing ancestor should raise NAMESPACE_NOT_FOUND."""
        namespaces = {
            "default": {"id": "default", "parent_id": None},
            # "acme" missing
            "acme/analytics": {"id": "acme/analytics", "parent_id": "acme"},
        }

        def get_ns(ns_id):
            return namespaces.get(ns_id)

        def get_policy(ns_id):
            return None

        with pytest.raises(ValueError, match="NAMESPACE_NOT_FOUND"):
            resolve_namespace("acme/analytics", get_ns, get_policy)
