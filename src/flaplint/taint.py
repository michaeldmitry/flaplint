"""Taint evaluation: deciding whether an expression is order-unstable.

The :class:`TaintEngine` answers one question -- "what makes this AST node an
unstable value?" -- and carries the analysis configuration (the function
registry, per-class member types, and feature toggles) as instance state rather
than module globals. That keeps analyses independent and reentrant: two engines
with different settings never interfere.
"""

from __future__ import annotations

import ast
from typing import Dict, Optional, Set

from . import astutils
from .constants import (
    BUILTIN_COLLECTION_METHODS,
    MODEL_SERIALIZERS,
    NONSORTING_SERIALIZERS,
    PROPAGATE_CALLS,
    FILE_READ_METHODS,
    SANITIZER_CALLS,
    SEQUENCE_MATERIALIZERS,
    STR_SPLIT_METHODS,
    TEMPLATE_RENDER_METHODS,
    UNORDERED_ATTRS,
    UNORDERED_CALLS,
    VOLATILE_CALLS,
)
from .model import FileImports, Origin, Registry, has_element, has_itercaller, has_local, is_element, is_itercaller, is_iterparam, is_local

#: Recursion guard for pathological / deeply nested expressions.
_MAX_DEPTH = 12


def _survives_stringify(origins: Set[Origin]) -> Set[Origin]:
    """Origins that survive a non-sorting serializer (``str``/``repr``/``encode``).

    Stringifying a scalar *parameter* does not make it unstable, but a locally
    unordered, value-position (``element``), sequence-from-parameter
    (``iterparam``/``itercaller``) or nondeterministic value stays unstable.
    """
    return {
        o
        for o in origins
        if is_local(o) or o == "volatile" or is_element(o) or is_iterparam(o) or is_itercaller(o)
    }


def _key_sort_survivors(origins: Set[Origin]) -> Set[Origin]:
    """Origins that survive a *key-sorting* serializer (``yaml.dump`` default,
    ``json.dumps(sort_keys=True)``).

    Sorting mapping keys fixes dict-key-order instability (``"local"``) but not a
    value-position pick (``element``), a sequence-from-parameter (``iterparam`` /
    ``itercaller``, whose *list element* order key-sorting never reaches) or a
    nondeterministic value (``"volatile"``).
    """
    return {
        o for o in origins if o == "volatile" or is_element(o) or is_iterparam(o) or is_itercaller(o)
    }


def _as_value_position(origins: Set[Origin], node: ast.AST) -> Set[Origin]:
    """Promote ``"local"`` -> a value-position pick for an order-dependent index.

    Indexing/slicing an unstable collection (``unordered_list[0]``) selects an
    element whose identity depends on the collection's volatile iteration order.
    That is *value-position* instability: a key-sorting serializer cannot fix a
    list element or scalar, so the result must survive ``yaml.dump`` /
    ``json.dumps(sort_keys=True)``. Volatility and parameter taint pass through.
    The pick ``node`` is carried as provenance (path ``None`` == current file)
    so a downstream finding can point at the subscript, not the serializer.

    A locally-materialized sequence (``itercaller`` -- ``list(some_set)[0]``) is
    likewise demoted to a *pick*: subscripting it selects one position-dependent
    element, which reports as ``unordered-pick`` at the subscript rather than as a
    whole-sequence ``unordered-iteration``.
    """
    return {
        ("element", None, node, None) if (is_local(o) or is_itercaller(o)) else o
        for o in origins
    }


def _as_local_sequence(origins: Set[Origin], node: ast.AST) -> Set[Origin]:
    """Promote ``"local"`` -> an ``itercaller`` for a sequence materialized from it.

    ``list(some_set)`` / ``tuple(relation.units)`` / ``[x for x in some_set]`` fix
    the result's *element order* to the source's hash-seeded iteration order. That
    is value-position instability a key-sorting serializer cannot launder -- so it
    must survive ``yaml.dump`` / ``json.dumps(sort_keys=True)``, reported as
    ``unordered-iteration`` pointing at the materialization ``node`` (where the
    ``sorted()`` fix lands). Everything else passes through unchanged; ``path`` is
    ``None`` (== the current file), resolved by the consumer (mirrors ``element``).
    """
    return {("itercaller", None, node, None) if is_local(o) else o for o in origins}


def _is_str_join(call: ast.Call) -> bool:
    """True for a ``<sep>.join(<iterable>)`` string join (not ``os.path.join``).

    ``str.join`` takes exactly one argument -- the iterable whose element order is
    baked into the result string. ``os.path.join(a, b, ...)`` shares the final
    attribute name but takes several path components, so the single-positional-arg
    shape distinguishes them; the ``os`` module root is excluded as belt-and-braces.
    """
    if not isinstance(call.func, ast.Attribute) or call.keywords:
        return False
    args = [a for a in call.args if not isinstance(a, ast.Starred)]
    if len(args) != 1 or len(call.args) != 1:
        return False
    return astutils.module_root(call.func) != "os"


class TaintEngine:
    """Evaluate the ordering/volatility taint of expressions.

    Parameters
    ----------
    registry:
        Bare-name -> functions table used to resolve user-defined calls.
    class_attr_types:
        ``class name -> {attribute -> constructed class name}`` recorded from
        ``self.<attr> = ClassName(...)`` assignments, so ``self.<member>.<prop>``
        can be resolved to a property summary.
    relations_unordered:
        When True, ``<...>.relations[<name>]`` iteration is treated as an
        unordered source (a paranoid-audit toggle; Juju's relation order is
        usually stable).
    """

    def __init__(
        self,
        registry: Registry,
        class_attr_types: Dict[str, Dict[str, str]],
        *,
        relations_unordered: bool = False,
        file_imports: Optional[Dict[str, "FileImports"]] = None,
    ) -> None:
        self.registry = registry
        self.class_attr_types = class_attr_types
        self.relations_unordered = relations_unordered
        #: path -> that file's import aliases (set per-file via ``enter``).
        self.file_imports = file_imports or {}
        self._aliases = FileImports()
        #: class name -> ``{attr -> origins}``: the taint an instance attribute
        #: carries, unioned over every ``self.<attr> = <expr>`` assignment in any
        #: method of the class. Lets taint survive being parked on ``self`` in one
        #: method (typically ``__init__``) and read back in another -- the
        #: cross-method instance-attribute barrier (the charm idiom: build in
        #: ``__init__``, read in a handler). Born-sites are pre-resolved to the
        #: assigning method's file/name. Grows monotonically (terminates the loop).
        self.instance_attr_taint: Dict[str, Dict[str, Set[Origin]]] = {}
        #: set True whenever :meth:`record_instance_attr` grows the map, so the
        #: summary fixed point keeps iterating until instance-attr taint settles.
        self.instance_attr_changed = False

    def record_instance_attr(
        self, cls_ctx: Optional[str], attr: str, origins: Set[Origin]
    ) -> None:
        """Union ``origins`` into the class-level taint of ``self.<attr>``."""
        if not cls_ctx or not origins:
            return
        bucket = self.instance_attr_taint.setdefault(cls_ctx, {})
        merged = bucket.get(attr, set()) | set(origins)
        if merged != bucket.get(attr, set()):
            bucket[attr] = merged
            self.instance_attr_changed = True

    def _instance_attr_taint(
        self, node: ast.Attribute, cls_ctx: Optional[str]
    ) -> Set[Origin]:
        """Class-level taint of ``self.<attr>`` (cross-method), or empty."""
        if (
            cls_ctx
            and isinstance(node.value, ast.Name)
            and node.value.id in ("self", "cls")
        ):
            return set(self.instance_attr_taint.get(cls_ctx, {}).get(node.attr, ()))
        return set()

    def _instance_attr_subscript_taint(
        self, node: ast.Subscript, cls_ctx: Optional[str]
    ) -> Set[Origin]:
        """Class-level taint of ``self.<attr>['key']`` (cross-method), or empty.

        The dict-by-fixed-key analogue of :meth:`_instance_attr_taint`: a value
        parked under ``self.cfg['jobs']`` in one method and read in another. The
        key is stored class-wide under the compound attr name ``"cfg['jobs']"``.
        """
        base = node.value
        if not (
            cls_ctx
            and isinstance(base, ast.Attribute)
            and isinstance(base.value, ast.Name)
            and base.value.id in ("self", "cls")
        ):
            return set()
        key = node.slice
        if isinstance(key, ast.Index):  # Python 3.8
            key = key.value
        if not (isinstance(key, ast.Constant) and isinstance(key.value, str)):
            return set()
        attr = f"{base.attr}[{key.value!r}]"
        return set(self.instance_attr_taint.get(cls_ctx, {}).get(attr, ()))

    @staticmethod
    def survives_structural_compare(origins: Set[Origin]) -> Set[Origin]:
        """Origins that survive a *structural* (key-order-insensitive) comparison.

        The pebble daemon compares parsed plan structs, not the layer's raw YAML:
        mapping fields (``environment``, ...) are order-insensitive, so dict-key
        disorder (``"local"``) is laundered exactly as a key-sorting serializer
        would. Order-sensitive instability -- a value-position ``element`` pick, a
        sequence built from an unordered source (``itercaller``/``iterparam``), or
        a nondeterministic ``volatile`` -- still flaps the plan and survives. This
        is the same filter a ``yaml.dump`` / ``json.dumps(sort_keys=True)`` applies,
        exposed for the plan sink in :mod:`flaplint.traversal`.
        """
        return _key_sort_survivors(origins)

    def enter(self, path: str) -> None:
        """Select ``path``'s import aliases for the function about to be walked.

        Called once before each function's walk. Name-matching in :meth:`_call`
        then resolves a renamed import (``from uuid import uuid4 as gen``) back to
        its canonical name. Safe because functions are walked one at a time.
        """
        self._aliases = self.file_imports.get(path) or FileImports()

    # -- public -------------------------------------------------------------

    def eval(
        self,
        node: Optional[ast.AST],
        env: Dict[str, Set[Origin]],
        cls_ctx: Optional[str] = None,
        _depth: int = 0,
    ) -> Set[Origin]:
        """Origins that make ``node`` unstable (empty == order-stable)."""
        if node is None or _depth > _MAX_DEPTH:
            return set()

        if isinstance(node, ast.Name):
            return set(env.get(node.id, ()))

        if isinstance(node, (ast.Set, ast.SetComp)):
            return {("local", None, node, None)}

        if isinstance(node, ast.DictComp):
            # A dict comprehension's only ordering instability is *key* order,
            # which a key-sorting serializer launders -- so it inherits the
            # source's taint unchanged (no sequence-element promotion).
            out: Set[Origin] = set()
            for gen in node.generators:
                out |= self.eval(gen.iter, env, cls_ctx, _depth + 1)
            return out

        if isinstance(node, (ast.ListComp, ast.GeneratorExp)):
            # Building a *list* by iterating a source fixes its element order to
            # the source's iteration order. Two cases survive a key-sorting
            # serializer (it is list order, not dict-key order):
            #  * source is a *parameter* -> the order is the caller's to control,
            #    flagged as a contract boundary (``iterparam``) anchored at the
            #    ``for ... in <iter>``;
            #  * source is a locally-born *unordered* collection (``set`` /
            #    ``relation.units``) -> a concrete bug here, promoted ``local`` ->
            #    ``itercaller`` (via :func:`_as_local_sequence`).
            # Other concrete instability (element/volatile/itercaller) propagates
            # unchanged.
            out = set()
            for gen in node.generators:
                inner = self.eval(gen.iter, env, cls_ctx, _depth + 1)
                out |= _as_local_sequence(inner, gen.iter)
                for o in inner:
                    if isinstance(o, tuple) and o[0] == "param":
                        out.add(("iterparam", o[1], None, gen.iter))
            return out

        if isinstance(node, ast.Dict):
            # A serialized literal is as unstable as the most unstable key/value
            # it holds: ``json.dumps({"uuid": str(uuid4())})`` changes every
            # reconcile.
            out = set()
            for key, val in zip(node.keys, node.values):
                if key is not None:
                    out |= self.eval(key, env, cls_ctx, _depth + 1)
                out |= self.eval(val, env, cls_ctx, _depth + 1)
            return out

        if isinstance(node, (ast.List, ast.Tuple)):
            out = set()
            for elt in node.elts:
                out |= self.eval(elt, env, cls_ctx, _depth + 1)
            return out

        if isinstance(node, ast.Subscript):
            # ``<...>.relations[<name>]`` (ops RelationMapping lookup) yields the
            # related Relation objects in Juju ``relation-ids`` order, which is
            # not contractually sorted. Opt-in only.
            if self.relations_unordered and astutils.final_attr(node.value) == "relations":
                return {("local", None, node, None)}
            # Dict-by-fixed-key read-back: ``d['jobs']`` where a per-key taint was
            # recorded at the dict literal (stored under the compound ``env`` key
            # ``"d['jobs']"``, or class-wide for ``self.cfg['jobs']``). A fixed-key
            # lookup is field-sensitive -- it returns *that* key's taint, so the
            # unstable value buried under one key is caught while a clean sibling
            # key stays clean. A fixed-key lookup with no recorded per-key taint is
            # order-independent (clean); only an int index / slice propagates below.
            path = astutils.subscript_path(node)
            if path is not None:
                if path in env:
                    return set(env[path])
                return self._instance_attr_subscript_taint(node, cls_ctx)
            # Sequence indexing/slicing picks an *order-dependent* element of an
            # unstable collection: ``unordered_list[0]`` is a different element
            # across reconciles (the classic "pick the first address" churn bug).
            # A mapping lookup by a fixed key (``d["scheduler"]``) is order-
            # independent, so only an integer index or a slice propagates -- and
            # it does so as value-position (``element``) instability that a
            # key-sorting serializer downstream cannot launder away.
            sl = node.slice
            if isinstance(sl, ast.Slice) or (
                isinstance(sl, ast.Constant) and isinstance(sl.value, int)
            ):
                return _as_value_position(
                    self.eval(node.value, env, cls_ctx, _depth + 1), node
                )
            return set()

        if isinstance(node, ast.Attribute):
            # ``relation.units`` and friends are unordered ops collections.
            if node.attr in UNORDERED_ATTRS:
                return {("local", None, node, None)}
            # Value-object field read-back: ``attrs.sans_dns`` where a per-field
            # taint was recorded at construction / field write (stored under the
            # compound ``env`` key ``"attrs.sans_dns"``). This is what lets an
            # unstable collection survive being stashed in a dataclass/pydantic
            # field and read back out -- the field-insensitivity barrier.
            path = astutils.attr_path(node)
            if path is not None and path in env:
                return set(env[path])
            # ``self.<attr>`` parked in one method and read in another: consult the
            # class-level instance-attribute taint (the cross-method barrier).
            inst = self._instance_attr_taint(node, cls_ctx)
            if inst:
                return inst
            # ``self.<prop>`` / ``self.<member>.<prop>``: consult the summary.
            return self._property_taint(node, cls_ctx)

        if isinstance(node, ast.BinOp) and isinstance(
            node.op, (ast.BitOr, ast.BitAnd, ast.BitXor, ast.Sub, ast.Add)
        ):
            return self.eval(node.left, env, cls_ctx, _depth + 1) | self.eval(
                node.right, env, cls_ctx, _depth + 1
            )

        if isinstance(node, ast.IfExp):
            return self.eval(node.body, env, cls_ctx, _depth + 1) | self.eval(
                node.orelse, env, cls_ctx, _depth + 1
            )

        if isinstance(node, ast.Await):
            return self.eval(node.value, env, cls_ctx, _depth + 1)

        if isinstance(node, ast.Call):
            return self._call(node, env, cls_ctx, _depth)

        return set()

    # -- calls --------------------------------------------------------------

    def _call(
        self,
        call: ast.Call,
        env: Dict[str, Set[Origin]],
        cls_ctx: Optional[str],
        depth: int,
    ) -> Set[Origin]:
        name = astutils.final_attr(call.func)
        # Undo an ``as`` rename so a renamed import matches its canonical name
        # (``from uuid import uuid4 as gen`` -> ``gen()`` resolves to ``uuid4``).
        # A module alias (``import json as j``) leaves the final attribute intact,
        # so only the ``module_root`` checks below need the module map.
        if name in self._aliases.names:
            name = self._aliases.names[name]
        if name in SANITIZER_CALLS:
            return set()
        if name in UNORDERED_CALLS:
            # An *empty* collection constructor (``set()`` / ``frozenset()`` with
            # no arguments) has a single, stable serialization -- it cannot
            # reshuffle. Only a populated collection inherits hash-seed ordering.
            if name in ("set", "frozenset") and not call.args and not call.keywords:
                return set()
            return {("local", None, call, None)}
        if name in VOLATILE_CALLS:
            return {"volatile"}

        # str()/repr() have no key-sorting escape hatch, and ``.encode()`` /
        # ``.decode()`` pass through their receiver. Only a genuinely-unstable
        # value (locally-born unordered, or a nondeterministic ``volatile``)
        # survives these wrappers.
        if name in NONSORTING_SERIALIZERS and call.args:
            return _survives_stringify(self.eval(call.args[0], env, cls_ctx, depth + 1))
        if name in ("encode", "decode") and isinstance(call.func, ast.Attribute):
            return _survives_stringify(
                self.eval(call.func.value, env, cls_ctx, depth + 1)
            )
        if name in STR_SPLIT_METHODS and isinstance(call.func, ast.Attribute):
            # ``s.split(",")`` / ``rsplit`` / ``splitlines`` return a list ordered by
            # the string's content, not by any collection's iteration order -- so the
            # result carries no ordering/parameter instability (you cannot split a
            # set). Only the receiver's *content* volatility passes through.
            return {
                o
                for o in self.eval(call.func.value, env, cls_ctx, depth + 1)
                if o == "volatile"
            }
        if name in FILE_READ_METHODS and isinstance(call.func, ast.Attribute):
            # ``path.read_text()`` / ``read_bytes()`` / ``f.read()`` return the file's
            # content -- determined by the file, not by the receiver -- so they
            # launder ordering taint. A path/handle that arrived as a parameter is a
            # scalar; reading it does not inherit that "might be unordered" worry.
            return set()

        # Serialization: byte-stability of the output follows that of the input.
        if name == "dumps":  # json.dumps(X) / yaml.dump-like .dumps
            inner = self.eval(call.args[0], env, cls_ctx, depth + 1) if call.args else set()
            if astutils.kw_const_is(call, "sort_keys", True):
                # Sorting keys fixes dict-key-order instability but not a
                # value-position pick (``element``) or volatility.
                return _key_sort_survivors(inner)
            return inner
        if name in ("dump", "safe_dump"):
            mod = astutils.module_root(call.func)
            if self._aliases.modules.get(mod, mod) == "json":
                return set()  # json.dump(obj, fp) writes a file, not a databag value
            inner = self.eval(call.args[0], env, cls_ctx, depth + 1) if call.args else set()
            # PyYAML sorts mapping keys by default (sort_keys=True), which fixes
            # dict-key-order instability; only an explicit sort_keys=False keeps
            # it. Either way a value-position (``element``) pick or a volatile
            # value survives -- key-sorting does not reach into list elements.
            if astutils.kw_const_is(call, "sort_keys", False):
                return inner
            return _key_sort_survivors(inner)

        if name in PROPAGATE_CALLS and call.args:
            inner = self.eval(call.args[0], env, cls_ctx, depth + 1)
            if name in SEQUENCE_MATERIALIZERS or _is_str_join(call):
                # ``list(some_set)`` / ``tuple(relation.units)`` fixes the result's
                # element order to the source's iteration order; ``sep.join(some_set)``
                # likewise bakes that order into the result *string*. Both are
                # key-sort-proof (a key-sorting serializer never reaches list-element
                # or in-string order), so promote ``local`` -> ``itercaller`` here.
                # ``join`` is matched only as a single-argument ``<sep>.join(iter)``
                # so it does not collide with ``os.path.join(a, b, ...)`` (which takes
                # several path components and merely propagates their taint).
                return _as_local_sequence(inner, call)
            return inner

        if name in TEMPLATE_RENDER_METHODS and not self.registry.get("render"):
            # ``template.render(x=..., **ctx)`` -- a Jinja2 render. We can't see the
            # template, so the output is treated as text built from the arguments:
            # as unstable as the most-unstable one. An unstable value rendered into
            # the text and then written to a sink (config file / databag) flaps.
            # Parameter taint is kept (not dropped like a scalar ``str()``) so a
            # helper that renders one of its *collection* parameters is caught at
            # the contract boundary -- the report stage grades it by annotation.
            # Gated on there being no user-defined ``render`` so a real method of
            # that name still uses its own summary instead of this heuristic.
            rendered: Set[Origin] = set()
            for arg in call.args:
                rendered |= self.eval(arg, env, cls_ctx, depth + 1)
            for kw in call.keywords:
                rendered |= self.eval(kw.value, env, cls_ctx, depth + 1)
            return rendered

        # User-defined function: consult its return summary.
        out: Set[Origin] = set()
        for fi in self._resolve_summary_candidates(call, name, cls_ctx):
            if fi.returns_element:
                # Carry the callee's pick provenance so the finding points at the
                # subscript inside the helper, not at this call / serializer.
                if fi.element_site is not None:
                    out.add(
                        (
                            "element",
                            fi.element_site[0],
                            fi.element_site[1],
                            fi.element_site[2],
                        )
                    )
                else:
                    out.add(("element", fi.path, call, fi.name))
            if fi.returns_unordered:
                # Carry the callee's born-site so the finding points ``origin=`` at
                # the ``set()`` / ``glob()`` inside the helper, not this call.
                if fi.unordered_site is not None:
                    out.add(
                        (
                            "local",
                            fi.unordered_site[0],
                            fi.unordered_site[1],
                            fi.unordered_site[2],
                        )
                    )
                else:
                    out.add(("local", fi.path, call, fi.name))
            if fi.returns_itercaller:
                # The helper returns a sequence materialized from a locally-born
                # unordered collection (``return list(some_set)``). Carry its
                # materialization site so the finding points at the ``list(...)``
                # inside the helper, and keep it key-sort-resistant.
                if fi.itercaller_site is not None:
                    out.add(
                        (
                            "itercaller",
                            fi.itercaller_site[0],
                            fi.itercaller_site[1],
                            None,
                        )
                    )
                else:
                    out.add(("itercaller", fi.path, call, None))
            if fi.returns_params or fi.iter_params:
                mapping = astutils.map_call_args(call, fi)
                for idx in fi.returns_params:
                    arg = mapping.get(idx)
                    if arg is not None:
                        out |= self.eval(arg, env, cls_ctx, depth + 1)
                # Confirmed iteration instability: when a known-unstable argument
                # flows into a parameter the callee iterates unsorted into a
                # sequence that escapes via return (iter_params[idx] with idx in
                # returns_params), emit an ``itercaller`` origin carrying the
                # callee's iteration site. This replaces the heuristic ``sink``
                # finding (which fires regardless of caller taint) with a
                # confirmed ``caller`` finding that fires only here, only when the
                # actual argument is demonstrably unstable.
                for idx, (ipath, inode) in fi.iter_params.items():
                    if idx not in fi.returns_params:
                        continue  # direct-sink case: handled by report.py
                    arg = mapping.get(idx)
                    if arg is None:
                        continue
                    arg_origins = self.eval(arg, env, cls_ctx, depth + 1)
                    if has_local(arg_origins) or "volatile" in arg_origins or has_element(arg_origins):
                        out.add(("itercaller", ipath, inode, None))

        # Method call on an order-tainted receiver: any view/render of an
        # unordered object (``d.keys()``, ``data[role].add(...)`` then a
        # ``.get()``, a builder's ``.as_dict()`` after an unordered ``.add``)
        # inherits that instability even when the method body is opaque to us.
        # The receiver may itself be an expression -- a chained call
        # (``cluster.gather_addresses_by_role().get(role)``) or a subscript -- so
        # evaluate it rather than only reading a plain name's environment taint.
        if isinstance(call.func, ast.Attribute):
            recv = call.func.value
            if isinstance(recv, ast.Name):
                recv_taint = set(env.get(recv.id, ()))
            else:
                recv_taint = self.eval(recv, env, cls_ctx, depth + 1)
            if name in MODEL_SERIALIZERS:
                # A Pydantic dump emits fields in *definition* order, so it launders
                # the model's own field-NAME order and the contract-boundary
                # uncertainty about an *opaque model param* (the ``param`` /
                # ``iterparam`` flavors) -- ``param.model_dump_json()`` to a databag
                # is not a raw-unordered write. But it does NOT launder a concrete
                # field's *value* order: a list field built from an unordered source
                # is still emitted in element order (the cos_agent ``_dashboards``
                # shape). So keep concrete content taint and drop only the
                # field-name-order / param-boundary flavors.
                recv_taint = {o for o in recv_taint if o[0] not in ("param", "iterparam")}
            out |= recv_taint
        return out

    def _resolve_summary_candidates(self, call, name, cls_ctx):
        """Candidate callees for return-summary lookup.

        ``self.method()`` / ``cls.method()`` resolves to the enclosing class's
        method; without this, same-named methods on *other* classes union their
        summaries in and over-taint the call site (a cross-class collision).
        Builtin mapping views (``x.items()/keys()/values()``) never resolve to a
        user method: on an arbitrary receiver they would collide with an
        unrelated same-named property and import its taint (the receiver-taint
        inheritance rule already carries their real, receiver-following order).
        """
        candidates = self.registry.get(name or "", ())
        if (
            cls_ctx
            and isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id in ("self", "cls")
        ):
            own = [fi for fi in candidates if fi.class_name == cls_ctx]
            if own:
                return own
        if name in BUILTIN_COLLECTION_METHODS and isinstance(call.func, ast.Attribute):
            recv = call.func.value
            is_self = isinstance(recv, ast.Name) and recv.id in ("self", "cls")
            if not is_self:
                return ()
        return candidates

    # -- property / receiver resolution ------------------------------------

    def _receiver_class(self, recv: ast.AST, cls_ctx: Optional[str]) -> Optional[str]:
        """Infer the class behind a (property) attribute-access receiver.

        Handles ``self``/``cls`` (the enclosing class) and ``self.<member>``
        typed via a recorded ``self.<member> = ClassName(...)`` assignment.
        """
        if isinstance(recv, ast.Name) and recv.id in ("self", "cls"):
            return cls_ctx
        if (
            isinstance(recv, ast.Attribute)
            and isinstance(recv.value, ast.Name)
            and recv.value.id in ("self", "cls")
            and cls_ctx is not None
        ):
            return self.class_attr_types.get(cls_ctx, {}).get(recv.attr)
        return None

    def _property_taint(
        self, node: ast.Attribute, cls_ctx: Optional[str]
    ) -> Set[Origin]:
        """Taint of ``self.<prop>`` / ``self.<member>.<prop>`` via summaries."""
        recv_cls = self._receiver_class(node.value, cls_ctx)
        if recv_cls is None:
            return set()
        for fi in self.registry.get(node.attr, ()):
            if fi.is_property and fi.class_name == recv_cls and fi.returns_unordered:
                if fi.unordered_site is not None:
                    return {
                        (
                            "local",
                            fi.unordered_site[0],
                            fi.unordered_site[1],
                            fi.unordered_site[2],
                        )
                    }
                return {("local", fi.path, node, fi.name)}
        return set()
