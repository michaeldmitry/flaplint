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
    BUILDER_ARG_PROPAGATORS,
    BUILTIN_COLLECTION_METHODS,
    BYTES_SERIALIZER_METHODS,
    MODEL_SERIALIZERS,
    NONSORTING_SERIALIZERS,
    ORDER_INDEPENDENT_CALLS,
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

    The promoted origin's 4th slot carries the *born-site* of the underlying
    ``local`` value -- ``(born_path, born_node, born_func)`` -- so a finding can
    still point ``origin=`` at the ``set()`` / ``glob()`` that created the churn,
    even though the finding itself anchors at the materialization. (Before the
    ``local`` -> ``itercaller`` split this trail came for free, because such a value
    was reported as ``unordered-collection`` at the write with a born-site origin.)
    """
    out: Set[Origin] = set()
    for o in origins:
        if is_local(o):
            out.add(("itercaller", None, node, (o[1], o[2], o[3])))
        else:
            out.add(o)
    return out


def _promote_to_sequence(origins: Set[Origin], node: ast.AST) -> Set[Origin]:
    """Taint of a *sequence materialized by iterating* ``node``.

    Shared by a list comprehension (``[x for x in src]``) and a loop ``.append``
    accumulator (``for x in src: acc.append(x)``) -- both bake the source's
    iteration order into element order. Promotes ``local`` -> ``itercaller``
    (survives a key-sorting serializer) and a parameter -> ``iterparam`` (the
    contract-boundary iteration), both anchored at ``node`` where the ``sorted()``
    fix lands. Every other flavor passes through unchanged.
    """
    out = _as_local_sequence(origins, node)
    for o in origins:
        if isinstance(o, tuple) and o[0] == "param":
            out.add(("iterparam", o[1], None, node))
    return out


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
        model_seq_fields: Optional[Dict[str, Set[str]]] = None,
        class_set_fields: Optional[Dict[str, Set[str]]] = None,
    ) -> None:
        self.registry = registry
        #: class names flaplint has *method summaries* for -- i.e. user-defined
        #: collaborators (a ``Patroni`` / ``ConfigBuilder``), as opposed to opaque
        #: library wrappers (``ops.pebble.Layer``) or pure dataclasses. A constructor
        #: of one of these is a *stateful collaborator* whose methods are traced, so
        #: the generic constructor-propagation (Phase 1 in :meth:`_call`) must skip it
        #: -- otherwise storing it as ``self._patroni = Patroni(peer_ips, ...)`` would
        #: taint the object and, via the receiver-inheritance rule, poison every
        #: unrelated ``self._patroni.method()`` call. Opaque wrappers keep no state we
        #: trace, so propagating their argument (``Layer(plan_dict)``) is correct.
        self._method_classes: Set[str] = {
            fi.class_name for fns in registry.values() for fi in fns if fi.class_name
        }
        self.class_attr_types = class_attr_types
        #: pydantic-model class name -> sequence-typed field names (``list``/
        #: ``tuple``/``Sequence``). A ``set`` coerced into one of these fields has
        #: its ``local`` taint promoted to ``itercaller`` at construction, because
        #: the model's ``__init__`` bakes the set into element order.
        self.model_seq_fields = model_seq_fields or {}
        #: class name -> ``Set``/``frozenset``-typed attribute names. A read of
        #: ``x.attr`` where ``x``'s type resolves to such a class reads as unordered
        #: (``event.certificates`` on a ``CertificatesAvailableEvent``).
        self.class_set_fields = class_set_fields or {}
        #: variable name -> class name for the function currently being analysed
        #: (params by annotation, locals by constructor). Set per ``eval`` entry by
        #: the traversal so an attribute read can resolve its receiver's class.
        self._var_types: Dict[str, str] = {}
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

    def set_var_types(self, var_types: Dict[str, Optional[str]]) -> None:
        """Set the current function's variable -> class-name map (see ``_var_types``).

        Filtered to real class names so a lookup is a cheap ``dict.get``. Called by
        the traversal before each ``eval`` with the live context (params + locals).
        """
        self._var_types = {k: v for k, v in var_types.items() if v}

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
        """Class-level taint of ``self.<attr>`` / ``self._stored.<attr>`` (cross-method)."""
        if not cls_ctx:
            return set()
        key = astutils.self_attr_key(node)
        if key is None:
            return set()
        return set(self.instance_attr_taint.get(cls_ctx, {}).get(key, ()))

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
    def coerce_to_sequence_field(origins: Set[Origin], node: ast.AST) -> Set[Origin]:
        """Promote ``local`` -> ``itercaller`` for a value coerced into a sequence field.

        When a bare ``set`` is passed to a pydantic ``list``/``tuple``/``Sequence``
        field, the model's ``__init__`` materialises it into element order -- the
        same promotion :func:`_as_local_sequence` applies to ``list(some_set)``. The
        argument ``node`` anchors the finding at the construction site where the
        ``sorted()`` fix belongs. Every other flavor passes through unchanged.
        """
        return _as_local_sequence(origins, node)

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
                out |= _promote_to_sequence(inner, gen.iter)
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
                inst = self._instance_attr_subscript_taint(node, cls_ctx)
                if inst:
                    return inst
                # per-key provenance absent: fall through to the element rule below.
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
            # A key read *off a value-position pick* inherits the pick: if the whole
            # object was selected by position from an unstable collection
            # (``list(peers)[0]``), then every field of it (``[0]["ip"]``, and any
            # depth of chaining) is equally position-dependent. Only ``element``
            # propagates -- a plain param/local dict stays field-sensitive (its
            # individual keys are order-stable), so the guard that keeps
            # ``config["endpoint"]`` clean is untouched. Mirrors ``x.get("ip")``,
            # which already inherits the receiver's taint via the method-call path:
            # the subscript spelling must not decide whether the flap is seen.
            return {
                o
                for o in self.eval(node.value, env, cls_ctx, _depth + 1)
                if is_element(o)
            }

        if isinstance(node, ast.Attribute):
            # ``relation.units`` and friends are unordered ops collections.
            if node.attr in UNORDERED_ATTRS:
                return {("local", None, node, None)}
            # A ``Set``/``frozenset``-typed attribute on a known class -- e.g.
            # ``event.certificates`` where ``event: CertificatesAvailableEvent`` --
            # is unordered, so joining/serialising it without ``sorted()`` flaps.
            if isinstance(node.value, ast.Name):
                cls = self._var_types.get(node.value.id)
                if cls and node.attr in self.class_set_fields.get(cls, ()):
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
        if name in BYTES_SERIALIZER_METHODS and isinstance(call.func, ast.Attribute):
            # ``csr.public_bytes(encoding)`` renders the object to DER/PEM whose
            # byte-stability follows the object's own -- a SAN built from a set makes
            # the bytes reshuffle. Like ``.encode()``, only genuine instability
            # survives (the ``encoding`` argument is a clean enum, ignored).
            return _survives_stringify(
                self.eval(call.func.value, env, cls_ctx, depth + 1)
            )
        if name in BUILDER_ARG_PROPAGATORS and isinstance(call.func, ast.Attribute):
            # Fluent builder: ``builder = builder.add_extension(ext, critical=...)``
            # returns a new builder carrying the receiver's taint plus the added
            # extension's, so a set-built SAN flows on to ``.sign().public_bytes()``.
            out = self.eval(call.func.value, env, cls_ctx, depth + 1)
            for a in call.args:
                if not isinstance(a, ast.Starred):
                    out |= self.eval(a, env, cls_ctx, depth + 1)
            return out
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
        resolved = False
        for fi in self._resolve_summary_candidates(call, name, cls_ctx):
            resolved = True
            out |= self._summary_return_origins(fi, call)
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
                # field-name-order / param-boundary flavors. Return here: the dump's
                # output is the receiver's field taint, and its keyword args
                # (``exclude``/``include``/``mode`` -- often *sets* of field names) are
                # control parameters that do NOT flow into the output, so they must not
                # be arg-propagated by the default rule below.
                return out | {o for o in recv_taint if o[0] not in ("param", "iterparam")}
            out |= recv_taint

        # Default-propagate (the inverted taint model): an unknown call carries its
        # arguments' instability forward rather than dropping it -- a wrapper, a
        # constructor, a formatter, a codec all *hold* or *reformat* their input, so
        # order instability survives. This replaces the open-ended allowlist of
        # transparent propagators (``Layer``, ``public_bytes``, the next lib wrapper)
        # with a *bounded denylist*: only genuine launderers stop it, and those are
        # matched earlier (``sorted``/``split``/``read``/key-sorting dumps) or listed
        # in :data:`ORDER_INDEPENDENT_CALLS` (``len``/``min``/``max``/... that reduce a
        # collection to an order-independent scalar). Two exclusions:
        #
        # * a *user collaborator* (a class we have method summaries for -- a
        #   ``Patroni`` / ``ConfigBuilder``) is stateful; tainting its constructor
        #   would, via the receiver-inheritance rule, poison every ``self._x.method()``
        #   call on it, so its methods' own summaries are trusted instead;
        # * a call that *resolved* to a user method is trusted to its own summary --
        #   which already models its arg-flow (``returns_params``) and any laundering
        #   (a ``render`` that ``sorted()``s internally) -- so its raw args are not
        #   re-propagated on top.
        if (
            name
            and not resolved
            and name not in ORDER_INDEPENDENT_CALLS
            and name not in self._method_classes
        ):
            for a in call.args:
                if not isinstance(a, ast.Starred):
                    out |= self.eval(a, env, cls_ctx, depth + 1)
            for kw in call.keywords:
                if kw.value is not None:
                    out |= self.eval(kw.value, env, cls_ctx, depth + 1)
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

        Walks a member chain of *any depth*, resolving one hop at a time against the
        recorded ``self.<member>`` types (``class_attr_types``):

        * ``self`` / ``cls`` -> the enclosing class ``cls_ctx``;
        * a typed local/parameter ``x`` -> its class from ``_var_types``;
        * ``<base>.<attr>`` -> the class recorded for ``<attr>`` on ``<base>``'s class.

        So ``self.charm`` (1 hop), ``self.charm.async_replication`` (2 hops), and
        deeper chains all resolve, as long as every intermediate attribute's class is
        known (a constructor assignment or a class-annotated back-reference). A hop
        whose class is unknown stops the walk (returns ``None``).
        """
        if isinstance(recv, ast.Name):
            if recv.id in ("self", "cls"):
                return cls_ctx
            return self._var_types.get(recv.id)
        if isinstance(recv, ast.Attribute):
            base_cls = self._receiver_class(recv.value, cls_ctx)
            if base_cls is not None:
                return self.class_attr_types.get(base_cls, {}).get(recv.attr)
        return None

    def _summary_return_origins(self, fi: "FuncInfo", node: ast.AST) -> Set[Origin]:
        """Origins a callee/property contributes from its element/unordered/itercaller
        return summary, each carrying the callee's born-site (so a finding points into
        the helper, not at this call). Shared by call resolution and property reads --
        a property is a zero-argument call, so both must surface *every* ordering
        flavor, not just ``returns_unordered``.
        """
        out: Set[Origin] = set()
        if fi.returns_element:
            if fi.element_site is not None:
                out.add(
                    ("element", fi.element_site[0], fi.element_site[1], fi.element_site[2])
                )
            else:
                out.add(("element", fi.path, node, fi.name))
        if fi.returns_unordered:
            if fi.unordered_site is not None:
                out.add(
                    ("local", fi.unordered_site[0], fi.unordered_site[1], fi.unordered_site[2])
                )
            else:
                out.add(("local", fi.path, node, fi.name))
        if fi.returns_itercaller:
            if fi.itercaller_site is not None:
                out.add(
                    ("itercaller", fi.itercaller_site[0], fi.itercaller_site[1], None)
                )
            else:
                out.add(("itercaller", fi.path, node, None))
        return out

    def _property_taint(
        self, node: ast.Attribute, cls_ctx: Optional[str]
    ) -> Set[Origin]:
        """Taint of ``self.<prop>`` / ``self.<member>.<prop>`` via summaries.

        Surfaces every ordering flavor the property returns -- ``unordered`` (a set),
        ``element`` (a positional pick), *and* ``itercaller`` (a sequence materialized
        from an unordered source, the ``[dict(t) for t in {…}]`` dedup idiom) -- not
        just the ``local`` set case. A ``remote_write.endpoints`` property that returns
        an itercaller list is then correctly unstable at its reader.
        """
        recv_cls = self._receiver_class(node.value, cls_ctx)
        if recv_cls is None:
            return set()
        out: Set[Origin] = set()
        for fi in self.registry.get(node.attr, ()):
            if fi.is_property and fi.class_name == recv_cls:
                out |= self._summary_return_origins(fi, node)
        return out
