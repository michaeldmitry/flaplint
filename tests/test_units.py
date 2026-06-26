"""Unit tests for the pure AST helpers and the TaintEngine in isolation."""

from __future__ import annotations

import ast

from flaplint import astutils
from flaplint.model import has_local
from flaplint.taint import TaintEngine


def _expr(src: str) -> ast.AST:
    return ast.parse(src, mode="eval").body


def test_final_attr():
    assert astutils.final_attr(_expr("a.b.c")) == "c"
    assert astutils.final_attr(_expr("json.dumps")) == "dumps"
    assert astutils.final_attr(_expr("f")) == "f"


def test_root_name():
    assert astutils.root_name(_expr("d.get('x', {})")) == "d"
    assert astutils.root_name(_expr("d[k][j]")) == "d"
    assert astutils.root_name(_expr("(1, 2)")) is None


def test_annotation_root():
    assert astutils.annotation_root(_expr("Set[str]")) == "Set"
    assert astutils.annotation_root(_expr("typing.List")) == "List"
    assert astutils.annotation_root(_expr("'Dict[str, int]'")) == "Dict"


def test_ctor_class_camelcase_heuristic():
    assert astutils.ctor_class(_expr("Foo()")) == "Foo"
    assert astutils.ctor_class(_expr("lower()")) is None


def test_kw_const_is():
    call = _expr("json.dumps(x, sort_keys=True)")
    assert astutils.kw_const_is(call, "sort_keys", True)
    assert not astutils.kw_const_is(call, "sort_keys", False)


def _engine() -> TaintEngine:
    return TaintEngine(registry={}, class_attr_types={})


def test_engine_set_literal_is_local():
    assert has_local(_engine().eval(_expr("{1, 2, 3}"), {}))


def test_engine_list_literal_is_stable():
    assert _engine().eval(_expr("[1, 2, 3]"), {}) == set()


def test_engine_uuid_is_volatile():
    assert _engine().eval(_expr("uuid.uuid4()"), {}) == {"volatile"}


def test_engine_sorted_sanitizes():
    assert _engine().eval(_expr("sorted({1, 2})"), {}) == set()


def test_engine_dumps_sort_keys_keeps_only_volatile():
    eng = _engine()
    # set inside -> sort_keys removes "local"
    assert eng.eval(_expr("json.dumps({1, 2}, sort_keys=True)"), {}) == set()


def test_engine_relations_opt_in():
    plain = TaintEngine(registry={}, class_attr_types={})
    paranoid = TaintEngine(registry={}, class_attr_types={}, relations_unordered=True)
    node = _expr("self.model.relations['peers']")
    assert plain.eval(node, {}) == set()
    assert has_local(paranoid.eval(node, {}))


def test_engine_propagates_through_dict_and_list_constructors():
    eng = _engine()
    assert has_local(eng.eval(_expr("list({1, 2})"), {}))
    seed = {("local", None, _expr("set()"), None)}
    assert has_local(eng.eval(_expr("dict(some)"), {"some": seed}))
