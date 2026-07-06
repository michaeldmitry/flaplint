"""Taint evaluation: deciding whether an expression is order-unstable.

The :class:`TaintEngine` answers one question -- "what makes this AST node an
unstable value?" -- and carries the analysis configuration (the function
registry, per-class member types, and feature toggles) as instance state rather
than module globals. That keeps analyses independent and reentrant: two engines
with different settings never interfere.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Optional, Set

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

    The born-site of the underlying unordered value is carried in the 4th slot --
    ``(born_path, born_node, born_func)`` for a ``local``, or the trail already on an
    ``itercaller`` -- so a pick finding can still point ``origin=`` at the ``set()`` /
    helper that created the churn (mirrors :func:`_as_local_sequence`).
    """
    out: Set[Origin] = set()
    for o in origins:
        if is_local(o):
            out.add(("element", None, node, (o[1], o[2], o[3])))
        elif is_itercaller(o):
            out.add(("element", None, node, o[3]))
        else:
            out.add(o)
    return out


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


def _sole_set_element(elts: "list[ast.expr]") -> Optional[ast.expr]:
    """The single element of a *provably one-element* set, else ``None``.

    A one-element set has no iteration-order ambiguity -- ``{x}`` / ``set([x])`` /
    ``frozenset((x,))`` serialize deterministically -- so it is not an unordered
    collection. Given a collection's element list, this returns the sole element
    when there is exactly one and it is not a ``*starred`` unpack (which may expand
    to several). The caller then evaluates *that element's* own taint, so a
    ``{str(uuid4())}`` still surfaces its volatile content while the empty
    set-order ``local`` flavor is dropped.
    """
    if len(elts) == 1 and not isinstance(elts[0], ast.Starred):
        return elts[0]
    return None


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
        class_bases: Optional[Dict[str, "List[str]"]] = None,
        value_object_fields: Optional[Dict[str, "List[str]"]] = None,
        render_sites: Optional[Dict[str, "tuple[str, str, int, int]"]] = None,
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
        #: class name -> base class names, so a method/property inherited from a base
        #: resolves on a subclass receiver (``LokiPushApiConsumer(ConsumerBase)``).
        self.class_bases = class_bases or {}
        #: every class flaplint actually has a *definition* for -- one with a collected
        #: method (``_method_classes``) or a recorded base. A receiver precisely typed
        #: to a class *absent* here is an external library type (``lightkube``'s
        #: ``KubernetesResourceManager``); a same-name method call on it must not fall
        #: back to the union of unrelated user methods (see ``_resolve_methods``).
        self._analyzed_classes = self._method_classes | set(self.class_bases)
        #: value-object class name -> its fields in constructor (declaration) order,
        #: so ``_ctor_field_taint`` can map a *positional* construction argument to
        #: the field it fills -- exactly as a keyword one -- but only for a class
        #: known to be a value bag (dataclass / pydantic / NamedTuple), never a
        #: stateful collaborator built positionally.
        self.value_object_fields = value_object_fields or {}
        #: builder class -> ``(sink_type, path, line, col)`` of the byte-sink write that
        #: renders its state. Gives a builder-absorb finding its real sink *type* (file /
        #: databag / secret -- not an assumed ``file``) and *location* (the
        #: ``push(config.build())`` write, not the ``add_component`` commit). A builder
        #: absent here is never rendered to a byte-sink, so its setter is not a contract
        #: sink at all -- both the type gate and the location come from this map.
        self.render_sites = render_sites or {}
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

        if isinstance(node, ast.Set):
            # A set *literal* with a single element has no ordering ambiguity: ``{x}``
            # iterates deterministically, so it is not an unordered collection (the
            # ``{auth_url}`` / ``{backend_url}`` idiom). It still carries its element's
            # own taint -- ``{str(uuid4())}`` stays volatile -- but not set-order
            # ``local``. A multi-element literal is genuinely hash-unstable.
            sole = _sole_set_element(node.elts)
            if sole is not None:
                return self.eval(sole, env, cls_ctx, _depth + 1)
            return {("local", None, node, None)}

        if isinstance(node, ast.SetComp):
            # A set comprehension that provably yields a single element -- one
            # generator, no ``if`` filter, iterating a one-element collection literal
            # (``{f(x) for x in [v]}``) -- is order-stable like a ``{x}`` literal. Drop
            # the set-order ``local`` but keep the residual taint of the source element
            # and of the body expression (``{str(uuid4()) for _ in [1]}`` stays
            # volatile). Anything else stays a genuine unordered collection.
            gens = node.generators
            if (
                len(gens) == 1
                and not gens[0].ifs
                and not gens[0].is_async
                and isinstance(gens[0].iter, (ast.List, ast.Tuple, ast.Set))
                and _sole_set_element(gens[0].iter.elts) is not None
            ):
                sole = _sole_set_element(gens[0].iter.elts)
                return self.eval(node.elt, env, cls_ctx, _depth + 1) | self.eval(
                    sole, env, cls_ctx, _depth + 1
                )
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
            # A key read *off a positionally-derived element* inherits the pick: if
            # the whole object was selected by position from an unstable collection
            # (``list(peers)[0]``) or bound by ``enumerate`` (``for i, e in
            # enumerate(seq): e["url"]``), then every field of it (``["ip"]``, and any
            # depth of chaining) is equally position-dependent. ``element`` (a concrete
            # pick) and ``iterparam`` (the same off a *parameter* the caller controls)
            # propagate. ``itercaller`` deliberately does NOT: it is also what a *dict
            # literal* carries when one of its values is a materialized sequence
            # (``{"jobs": list(set(x)), "name": "fixed"}``), and a sibling-key read off
            # such a container (``cfg["name"]``) must stay field-sensitive. The
            # enumerate/pick element cases are seeded as ``element``, so they ride the
            # unambiguous flavor; a plain ``param``/local dict stays clean.
            return {
                o
                for o in self.eval(node.value, env, cls_ctx, _depth + 1)
                if is_element(o) or is_iterparam(o)
            }

        if isinstance(node, ast.Attribute):
            # ``relation.units`` and friends are unordered ops collections. This is
            # a *bare-name* recognizer: ops framework types (``Relation``) are never
            # collected (flaplint is stdlib-only), so an untyped ``relation``
            # receiver can only be matched by attribute name. But when the receiver
            # is ``self``/``cls`` -- resolvable to a *known user class* -- the
            # framework guess is wrong: fire only if that class actually declares
            # the field as a set (via ``class_set_fields``), so a charm's own
            # ``self.units`` (a unit count, a property) is not mistaken for the ops
            # ``Relation.units``. Any other receiver keeps the untyped fallback.
            if node.attr in UNORDERED_ATTRS:
                recv = node.value
                is_self = isinstance(recv, ast.Name) and recv.id in ("self", "cls")
                if not (is_self and cls_ctx):
                    return {("local", None, node, None)}
                if node.attr in self.class_set_fields.get(cls_ctx, ()):
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

        if isinstance(node, ast.NamedExpr):
            # A walrus ``(name := expr)`` evaluates to ``expr``'s value, so its taint
            # is exactly ``expr``'s. The *binding* of ``name`` into the environment is
            # done by the traversal (see ``_bind_walruses``) so it survives into the
            # guarded block; here we only need the value flavor so ``x = (y := f())``
            # tracks too.
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
            if name in ("set", "frozenset"):
                # An *empty* constructor (``set()`` / ``frozenset()``) has a single,
                # stable serialization -- it cannot reshuffle. And a single-element
                # collection literal argument (``set([x])`` / ``frozenset((x,))``) is
                # a one-element set: no ordering ambiguity, so carry the element's own
                # taint rather than set-order ``local`` (mirrors the ``{x}`` literal).
                if not call.args and not call.keywords:
                    return set()
                if (
                    len(call.args) == 1
                    and not call.keywords
                    and isinstance(call.args[0], (ast.List, ast.Tuple, ast.Set))
                ):
                    sole = _sole_set_element(call.args[0].elts)
                    if sole is not None:
                        return self.eval(sole, env, cls_ctx, depth + 1)
            # A populated collection inherits hash-seed ordering.
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
            if name == "get" and not resolved:
                # ``d.get(key[, default])`` is a single keyed extraction -- the method
                # analogue of the ``d[key]`` subscript -- so it launders the *mapping's
                # own order* while PRESERVING *value* taint. Precisely: a value fetched
                # by key does not depend on the mapping's iteration order, so the
                # collection-order flavors (``itercaller``/``local``) that describe the
                # container's disorder are dropped; a value-position pick
                # (``element``/``iterparam``) survives, and -- via the constant-key path
                # below -- so does taint recorded *on the retrieved value itself*. This
                # is NOT "we proved the receiver is a dict": like the sibling
                # views/mutators (``.items()``/``.update()``/...), it is a name-based
                # rule keyed on ``get`` being a builtin-collection method on a *non-self*
                # receiver (so it never unions a same-named user method -- a cross-class
                # collision). The accepted trade-off is a user class that reimplements
                # ``get`` to return a whole collection would be mis-laundered; in
                # exchange, an *untyped* receiver (the real case: the data_platform_libs
                # ``fetch_my_relation_field`` -> ``.get(rid, {}).get(field)`` chain, whose
                # receiver has no inferred class) is still correctly laundered instead of
                # inheriting the ``result`` dict's whole ``secret_fields`` iteration
                # taint -- the false positive on the extracted scalar (a TLS key/cert
                # string that cannot flap). Mirrors the subscript's fixed-key path: a
                # constant string key with recorded per-key taint returns *that* key's
                # taint (a value buried under one key stays caught); everything else
                # launders. The default argument can itself become the result, so its
                # taint flows; the key argument does not.
                if call.args and isinstance(call.args[0], ast.Constant) and isinstance(
                    call.args[0].value, str
                ):
                    base = call.func.value
                    base_path = None
                    if isinstance(base, ast.Name):
                        base_path = base.id
                    elif isinstance(base, ast.Attribute) and isinstance(
                        base.value, ast.Name
                    ):
                        base_path = f"{base.value.id}.{base.attr}"
                    if base_path is not None:
                        keyed = f"{base_path}[{call.args[0].value!r}]"
                        if keyed in env:
                            return out | set(env[keyed])
                out |= {o for o in recv_taint if is_element(o) or is_iterparam(o)}
                for a in call.args[1:]:
                    if not isinstance(a, ast.Starred):
                        out |= self.eval(a, env, cls_ctx, depth + 1)
                return out
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
                return self._attr_type_in_chain(base_cls, recv.attr)
        return None

    def _attr_type_in_chain(self, cls: str, attr: str) -> Optional[str]:
        """Type recorded for ``self.<attr>`` on ``cls`` or its nearest base.

        ``self.attr`` is often stored in a *base* ``__init__`` (``EventHandlers`` sets
        ``self.relation_data``) while the access lives in a subclass method, so the
        lookup must walk the inheritance chain rather than only the exact class.
        Breadth-first from ``cls`` outward, so a *more-derived* class's recorded type
        (a self-pass refinement, ``class_attr_types[DataPeer]["relation_data"]``) wins
        over an inherited one -- the hook the context-sensitive pass relies on.
        """
        seen: Set[str] = set()
        queue = [cls]
        while queue:
            c = queue.pop(0)
            if c in seen:
                continue
            seen.add(c)
            t = self.class_attr_types.get(c, {}).get(attr)
            if t is not None:
                return t
            queue.extend(self.class_bases.get(c, ()))
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
        chain = self._class_chain(recv_cls)
        out: Set[Origin] = set()
        for fi in self.registry.get(node.attr, ()):
            if fi.is_property and fi.class_name in chain:
                out |= self._summary_return_origins(fi, node)
        return out

    def _class_chain(self, cls: Optional[str]) -> Set[str]:
        """``cls`` plus its transitive base classes (for inherited method/property
        resolution). Bounded by a ``seen`` set against cyclic/self-referential bases.
        """
        if not cls:
            return set()
        seen: Set[str] = set()
        stack = [cls]
        while stack:
            c = stack.pop()
            if c in seen:
                continue
            seen.add(c)
            stack.extend(self.class_bases.get(c, ()))
        return seen
