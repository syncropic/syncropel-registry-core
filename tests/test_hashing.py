"""Tests for 4-level hash computation."""

import hashlib

from syncropel_registry_core.hashing import compute_hashes, hash_effect, hash_effect_sequence


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


class TestHashEffect:
    """Test single-effect hashing at each level."""

    def test_l3_intent(self):
        effect = {"primitive": "GET", "input_shape": "VOID", "output_shape": "MANY"}
        h = hash_effect(effect, level=3)
        expected = _sha256('{"in":"VOID","out":"MANY"}')
        assert h == expected
        assert len(h) == 64

    def test_l2_flow(self):
        effect = {"primitive": "GET", "input_shape": "VOID", "output_shape": "MANY"}
        h = hash_effect(effect, level=2)
        expected = _sha256('{"in":"VOID","out":"MANY","p":"GET"}')
        assert h == expected

    def test_l1_structural_with_operation(self):
        effect = {
            "primitive": "GET",
            "operation": "query",
            "input_shape": "VOID",
            "output_shape": "MANY",
        }
        h = hash_effect(effect, level=1)
        expected = _sha256('{"in":"VOID","op":"query","out":"MANY","p":"GET"}')
        assert h == expected

    def test_l1_fallback_to_lowercase_primitive(self):
        """When no operation, falls back to lowercase primitive."""
        effect = {"primitive": "GET", "input_shape": "VOID", "output_shape": "MANY"}
        h = hash_effect(effect, level=1)
        expected = _sha256('{"in":"VOID","op":"get","out":"MANY","p":"GET"}')
        assert h == expected

    def test_l0_exact_with_params(self):
        effect = {
            "primitive": "GET",
            "operation": "query",
            "input_shape": "VOID",
            "output_shape": "MANY",
            "parameters": {"table": "users", "limit": 10},
        }
        h = hash_effect(effect, level=0)
        # Keys sorted: limit, table
        expected = _sha256(
            '{"in":"VOID","op":"query","out":"MANY","p":"GET","params":{"limit":10,"table":"users"}}'
        )
        assert h == expected

    def test_l0_empty_params(self):
        effect = {
            "primitive": "GET",
            "operation": "get",
            "input_shape": "ONE",
            "output_shape": "ONE",
            "parameters": {},
        }
        h = hash_effect(effect, level=0)
        expected = _sha256('{"in":"ONE","op":"get","out":"ONE","p":"GET","params":{}}')
        assert h == expected

    def test_l0_no_params_key(self):
        effect = {
            "primitive": "GET",
            "operation": "get",
            "input_shape": "ONE",
            "output_shape": "ONE",
        }
        h = hash_effect(effect, level=0)
        expected = _sha256('{"in":"ONE","op":"get","out":"ONE","p":"GET","params":{}}')
        assert h == expected

    def test_hash_is_deterministic(self):
        effect = {"primitive": "MAP", "input_shape": "MANY", "output_shape": "ONE"}
        h1 = hash_effect(effect, level=3)
        h2 = hash_effect(effect, level=3)
        assert h1 == h2

    def test_different_shapes_produce_different_hashes(self):
        e1 = {"primitive": "GET", "input_shape": "VOID", "output_shape": "MANY"}
        e2 = {"primitive": "GET", "input_shape": "ONE", "output_shape": "ONE"}
        assert hash_effect(e1, 3) != hash_effect(e2, 3)


class TestHashEffectSequence:
    """Test sequence hashing."""

    def test_single_effect_sequence(self):
        effects = [{"primitive": "GET", "input_shape": "VOID", "output_shape": "MANY"}]
        h = hash_effect_sequence(effects, level=3)
        single_hash = hash_effect(effects[0], level=3)
        expected = _sha256(single_hash)
        assert h == expected

    def test_multi_effect_sequence(self):
        effects = [
            {"primitive": "GET", "operation": "query", "input_shape": "VOID", "output_shape": "MANY"},
            {"primitive": "MAP", "operation": "filter", "input_shape": "MANY", "output_shape": "MANY"},
            {"primitive": "PUT", "operation": "store", "input_shape": "ONE", "output_shape": "VOID"},
        ]
        h = hash_effect_sequence(effects, level=2)
        h0 = hash_effect(effects[0], 2)
        h1 = hash_effect(effects[1], 2)
        h2 = hash_effect(effects[2], 2)
        expected = _sha256(f"{h0},{h1},{h2}")
        assert h == expected

    def test_order_matters(self):
        e1 = {"primitive": "GET", "input_shape": "VOID", "output_shape": "MANY"}
        e2 = {"primitive": "PUT", "input_shape": "ONE", "output_shape": "VOID"}
        h_forward = hash_effect_sequence([e1, e2], level=3)
        h_reverse = hash_effect_sequence([e2, e1], level=3)
        assert h_forward != h_reverse


class TestComputeHashes:
    """Test the compute_hashes convenience function."""

    def test_returns_four_hashes(self):
        effects = [
            {"primitive": "GET", "operation": "get", "input_shape": "ONE", "output_shape": "ONE"},
            {"primitive": "PUT", "operation": "store", "input_shape": "ONE", "output_shape": "VOID"},
        ]
        l0, l1, l2, l3 = compute_hashes(effects)
        assert len(l0) == 64
        assert len(l1) == 64
        assert len(l2) == 64
        assert len(l3) == 64
        # All different levels should generally produce different hashes
        assert l3 != l2  # L2 includes primitive
        assert l2 != l1  # L1 includes operation

    def test_hash_containment_property(self):
        """L0 match should imply L1, L2, L3 match (same effects)."""
        effects = [
            {"primitive": "GET", "operation": "query", "input_shape": "VOID", "output_shape": "MANY"},
        ]
        l0_a, l1_a, l2_a, l3_a = compute_hashes(effects)
        l0_b, l1_b, l2_b, l3_b = compute_hashes(effects)
        assert l0_a == l0_b
        assert l1_a == l1_b
        assert l2_a == l2_b
        assert l3_a == l3_b


class TestCanonicalKeyOrder:
    """Verify canonical JSON key ordering (alphabetical)."""

    def test_l3_keys_in_out(self):
        """L3: 'in' before 'out' (alphabetical)."""
        effect = {"primitive": "GET", "input_shape": "ONE", "output_shape": "MANY"}
        h = hash_effect(effect, 3)
        expected = _sha256('{"in":"ONE","out":"MANY"}')
        assert h == expected

    def test_l2_keys_in_out_p(self):
        """L2: in, out, p (alphabetical)."""
        effect = {"primitive": "GET", "input_shape": "ONE", "output_shape": "MANY"}
        h = hash_effect(effect, 2)
        expected = _sha256('{"in":"ONE","out":"MANY","p":"GET"}')
        assert h == expected

    def test_l1_keys_in_op_out_p(self):
        """L1: in, op, out, p (alphabetical)."""
        effect = {"primitive": "GET", "operation": "query", "input_shape": "ONE", "output_shape": "MANY"}
        h = hash_effect(effect, 1)
        expected = _sha256('{"in":"ONE","op":"query","out":"MANY","p":"GET"}')
        assert h == expected

    def test_l0_keys_in_op_out_p_params(self):
        """L0: in, op, out, p, params (alphabetical)."""
        effect = {
            "primitive": "GET",
            "operation": "query",
            "input_shape": "ONE",
            "output_shape": "MANY",
            "parameters": {"z": 1, "a": 2},
        }
        h = hash_effect(effect, 0)
        expected = _sha256('{"in":"ONE","op":"query","out":"MANY","p":"GET","params":{"a":2,"z":1}}')
        assert h == expected
