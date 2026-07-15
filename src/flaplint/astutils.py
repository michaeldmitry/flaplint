"""Pure AST helpers shared across the analyzer.

None of these inspect global state; given the same node they always return the
same result, which makes them trivial to unit-test in isolation.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Optional, Set, Tuple

from .constants import (
    ACCUMULATOR_METHODS,
    FILE_WRITE_METHODS,
    LIST_ACCUMULATOR_METHODS,
    MAPPING_WRITE_METHODS,
    PLAN_WRITE_METHODS,
    PROPAGATE_CALLS,
    SECRET_WRITE_METHODS,
    UNORDERED_CALLS,
)
from .model import FuncInfo


def final_attr(func: ast.AST) -> Optional[str]:
    """Return the final callable name: ``a.b.c`` -> ``c``, ``f`` -> ``f``."""
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def _attr_chain(node: ast.AST) -> Optional[list]:
    """Dotted parts of a pure ``Name.a.b.c`` attribute chain, root first, else ``None``.

    ``attrs.sans_dns`` -> ``["attrs", "sans_dns"]``; ``self.ctx.config.targets`` ->
    ``["self", "ctx", "config", "targets"]``. Any non-``Attribute`` / non-``Name``
    link -- a call (``a.b().c``) or a subscript (``a[0].b``) -- returns ``None``,
    because a value reached through one isn't a stable field slot.
    """
    parts = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if not isinstance(cur, ast.Name):
        return None
    parts.append(cur.id)
    parts.reverse()
    return parts


def attr_path(node: ast.AST) -> Optional[str]:
    """Access-path key for a field read/write on a ``Name``-rooted chain, else ``None``.

    ``attrs.sans_dns`` -> ``"attrs.sans_dns"``; ``self.ctx.config.targets`` ->
    ``"self.ctx.config.targets"``. Used as a compound ``env`` key so a value object's
    *per-field* taint can be stored and read back without modelling the heap (see the
    value-object field provenance in :mod:`flaplint.traversal`). The chain must be
    pure attribute access rooted at a plain ``Name`` -- a call or subscript link
    returns ``None`` (not a stable field slot). Reads and writes go through the same
    helper, so the key is symmetric to any depth.
    """
    if not isinstance(node, ast.Attribute):
        return None
    parts = _attr_chain(node)
    return ".".join(parts) if parts is not None else None


def self_attr_key(node: ast.AST) -> Optional[str]:
    """Class-level key for a ``self``/``cls``-rooted attribute, to any depth.

    ``self.jobs`` -> ``"jobs"``; ``self._stored.jobs`` -> ``"_stored.jobs"`` (the ops
    **StoredState** idiom); ``self.ctx.config.targets`` -> ``"ctx.config.targets"``.
    Returning the whole sub-chain lets an unstable value parked on a nested ``self``
    field in one method (typically ``__init__``) and read in another stay tracked,
    field-sensitively. Returns ``None`` for a non-``self``/``cls`` root or any chain
    passing through a call/subscript.
    """
    if not isinstance(node, ast.Attribute):
        return None
    parts = _attr_chain(node)
    if parts is None or parts[0] not in ("self", "cls"):
        return None
    return ".".join(parts[1:])


def subscript_path(node: ast.AST) -> Optional[str]:
    """Access-path key for a fixed-string subscript: ``d['k']`` / ``self.cfg['k']``.

    The dict-by-fixed-key analogue of :func:`attr_path`: it lets a dict literal's
    *per-key* value taint be stored under a compound ``env`` key
    (``"d['k']"``) and read back on the same ``base['k']`` access, so a value
    buried under one key is field-sensitive (a clean sibling key stays clean).
    Returns ``None`` for a non-constant or non-string key -- an integer index is
    order-*dependent* and handled separately -- and for a base deeper than one
    attribute level. The base may be a plain ``Name`` (``d``) or a one-level
    ``self``/``cls`` attribute (``self.cfg``).
    """
    if not isinstance(node, ast.Subscript):
        return None
    key = node.slice
    if isinstance(key, ast.Index):  # Python 3.8 wraps the constant in an Index
        key = getattr(key, "value")  # deprecated stub: ``.value`` is untyped
    if not (isinstance(key, ast.Constant) and isinstance(key.value, str)):
        return None
    base = node.value
    if isinstance(base, ast.Name):
        base_path: Optional[str] = base.id
    elif isinstance(base, ast.Attribute) and isinstance(base.value, ast.Name):
        base_path = f"{base.value.id}.{base.attr}"
    else:
        return None
    return f"{base_path}[{key.value!r}]"


def root_name(node: ast.AST) -> Optional[str]:
    """Root variable of an access chain: ``d.get('g', {})`` / ``d[k]`` -> ``d``."""
    cur = node
    while True:
        if isinstance(cur, ast.Attribute):
            cur = cur.value
        elif isinstance(cur, ast.Subscript):
            cur = cur.value
        elif isinstance(cur, ast.Call):
            cur = cur.func
        else:
            break
    return cur.id if isinstance(cur, ast.Name) else None


def module_root(func: ast.AST) -> Optional[str]:
    """Module name of an ``a.b`` call target: ``json.dumps`` -> ``json``."""
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.value.id
    return None


def is_databag_target(target: ast.AST, databags: Optional[Set[str]] = None) -> bool:
    """An item-assignment whose target is a relation databag: ``bag[key] = ...``.

    ``bag`` is the databag *mapping* -- either written literally as
    ``<expr>.data[<entity>]`` (the stable ``ops`` ``Relation.data`` API) or a
    local variable previously aliased to one (tracked in ``databags``). Anchoring
    on this structural shape -- a write into the ``.data[entity]`` mapping --
    rather than on a method name keeps sink detection robust.
    """
    if not isinstance(target, ast.Subscript):
        return False
    bag = target.value
    if databag_expr(bag):
        return True
    return databags is not None and isinstance(bag, ast.Name) and bag.id in databags


def databag_expr(node: ast.AST) -> bool:
    """``<expr>.data[<entity>]`` -- a Juju relation databag mapping object.

    This is the canonical "databag" recogniser. ``Relation.data`` is the stable,
    documented ``ops`` API for relation data, so a subscript of any ``.data``
    attribute is the mapping a charm writes into. Recognising the *object*
    (rather than a particular write syntax or helper name) lets every kind of
    mutation -- ``bag[k] = v``, ``bag.update(...)``, an aliased local -- be
    treated uniformly as a relation-data sink.
    """
    return (
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == "data"
    )


def databag_get_call(node: ast.AST) -> bool:
    """``<expr>.data.get(<entity>)`` -- a databag accessed via ``.get`` not ``[]``.

    The ``.get(app | unit)`` form is equivalent to ``.data[entity]`` for reading a
    relation databag. Requiring the argument to be an ``app``/``unit`` entity keeps
    this from matching an unrelated ``.data.get("key")`` on some other mapping.
    """
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and isinstance(node.func.value, ast.Attribute)
        and node.func.value.attr == "data"
        and len(node.args) >= 1
        and is_entity(node.args[0])
    )


def is_entity(node: ast.AST) -> bool:
    """``<expr>.app`` / ``<expr>.unit`` -- a Juju ``Application``/``Unit`` entity.

    Relation data is keyed by one of these two entities (``relation.data[app]``,
    ``relation.save(obj, self.unit)``). Anchoring on the ``.app``/``.unit``
    attribute is the same structural signal the ``.data[entity]`` subscript
    already relies on, and is what distinguishes an ``ops`` ``Relation.save``
    call from an unrelated ``.save`` method.
    """
    return isinstance(node, ast.Attribute) and node.attr in ("app", "unit")


def databag_save_content(call: ast.Call) -> Optional[ast.expr]:
    """Content object written to a relation databag by ``Relation.save``.

    Recognises ``<relation>.save(<obj>, <entity>)`` -- the documented ``ops``
    ``Relation.save(obj, dst: Unit | Application)`` API, which serialises
    ``obj``'s fields into ``relation.data[dst]``. Returns ``<obj>`` (the first
    argument, whose taint becomes the databag's) when ``call`` matches that
    signature, else ``None``. Anchored on the two-argument shape plus an entity
    second argument so it is not confused with an unrelated ``.save`` method.
    """
    if not isinstance(call.func, ast.Attribute):
        return None
    if call.func.attr != "save":
        return None
    if len(call.args) != 2:
        return None
    if not is_entity(call.args[1]):
        return None
    return call.args[0]


def is_databag_value(node: ast.AST, databags: Optional[Set[str]] = None) -> bool:
    """True if ``node`` *is* a databag mapping (not a write into one).

    Either a literal ``<expr>.data[<entity>]`` or a local aliased to one. Used to
    spot a databag handed to a writer as an argument (``model.dump(bag)``), the
    escape-analysis analogue of the subscript-assignment sink.
    """
    if databag_expr(node):
        return True
    return databags is not None and isinstance(node, ast.Name) and node.id in databags


def databag_mutation_args(
    call: ast.Call, databags: Optional[Set[str]] = None
) -> Optional[List[ast.expr]]:
    """Arguments written into a databag by ``bag.update(...)`` / ``setdefault``.

    Returns the argument expressions (whose taint becomes the databag's) when
    ``call`` is a mapping-write method invoked on a databag receiver -- a literal
    ``<expr>.data[<entity>]`` or a databag-aliased local -- else ``None``. This is
    the method-call analogue of ``is_databag_target`` and shares the same
    structural databag anchor instead of matching a fixed helper name.
    """
    if not isinstance(call.func, ast.Attribute):
        return None
    if call.func.attr not in MAPPING_WRITE_METHODS:
        return None
    recv = call.func.value
    if databag_expr(recv) or (
        databags is not None and isinstance(recv, ast.Name) and recv.id in databags
    ):
        return list(call.args)
    return None


def annotation_root(node: Optional[ast.AST]) -> Optional[str]:
    """Outermost name of an annotation: ``Iterable[X]`` -> ``Iterable``.

    ``Optional[X]`` and ``Union[X, None]`` are transparent wrappers: the
    interesting type is the payload, not the wrapper. ``Optional[str]`` is a
    scalar string, not an unordered collection, so it must resolve to ``str``
    (the wrapper itself carries no ordering semantics). The first
    non-``None``/``NoneType`` argument of the wrapper is used.
    """
    if node is None:
        return None
    if isinstance(node, ast.Subscript):
        head = annotation_root(node.value)
        if head in ("Optional", "Union"):
            return _unwrap_optional(node.slice) or head
        return head
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        # PEP 604 union: ``str | None`` is the same as ``Optional[str]`` -- the
        # payload type is what matters (``str | None`` is a scalar string, not a
        # collection). Resolve to the first non-``None`` operand.
        for side in (node.left, node.right):
            root = annotation_root(side)
            if root not in (None, "None", "NoneType"):
                return root
        return None
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.split("[", 1)[0].strip()
    return None


#: Annotation roots that denote a mapping whose *values* are a distinct type from its
#: keys -- so ``Dict[K, V]``'s value type is the second subscript argument.
_MAPPING_ANNOTATION_ROOTS = {
    "dict",
    "Dict",
    "Mapping",
    "MutableMapping",
    "OrderedDict",
    "defaultdict",
    "DefaultDict",
}


def mapping_value_root(node: Optional[ast.AST]) -> Optional[str]:
    """Value-type root of a ``Dict[K, V]`` / ``Mapping[K, V]`` annotation, else ``None``.

    ``Dict[str, Set[str]]`` -> ``"Set"``; ``dict[str, list[int]]`` -> ``"list"``. Used
    to see that indexing / ``.get()`` / ``.values()`` of a mapping parameter yields a
    value of type ``V`` -- so a ``Dict[str, Set[str]]`` hands back an *unordered* set
    even though the mapping itself is key-ordered. Only a two-argument mapping subscript
    qualifies; anything else returns ``None``.
    """
    if isinstance(node, ast.Subscript) and annotation_root(node.value) in _MAPPING_ANNOTATION_ROOTS:
        sl = node.slice
        if isinstance(sl, ast.Index):  # py3.8 wraps the slice
            sl = getattr(sl, "value")  # deprecated stub: ``.value`` is untyped
        if isinstance(sl, ast.Tuple) and len(sl.elts) == 2:
            return annotation_root(sl.elts[1])
    return None


def _unwrap_optional(sl: ast.AST) -> Optional[str]:
    """Resolve the payload type of an ``Optional``/``Union`` subscript slice.

    ``Optional[str]`` -> ``str``; ``Union[Set[str], None]`` -> ``Set``. A bare
    ``Optional[X]`` has a single-element slice; ``Union[A, B]`` is an
    ``ast.Tuple``. ``None`` / ``NoneType`` members are ignored.
    """
    elts = sl.elts if isinstance(sl, ast.Tuple) else [sl]
    for elt in elts:
        root = annotation_root(elt)
        if root not in (None, "None", "NoneType"):
            return root
    return None


def kw_const_is(call: ast.Call, name: str, value: bool) -> bool:
    """True if ``call`` passes keyword ``name`` as the constant ``value``."""
    for kw in call.keywords:
        if (
            kw.arg == name
            and isinstance(kw.value, ast.Constant)
            and kw.value.value is value
        ):
            return True
    return False


def is_set_construction(node: ast.AST) -> bool:
    """True if ``node`` builds a ``set``/``frozenset`` value.

    A set literal (``{a, b}``), a set comprehension (``{x for x in ...}``), or a
    ``set(...)`` / ``frozenset(...)`` call. Used to tag a variable as set-valued so
    a later ``.add()`` / ``.update()`` is known to keep it an (unordered) set --
    even when it started from an empty ``set()`` that is otherwise stable. A bare
    ``{}`` is a *dict* literal (``ast.Dict``), not a set, so it is excluded.
    """
    if isinstance(node, (ast.Set, ast.SetComp)):
        return True
    if isinstance(node, ast.Call):
        return final_attr(node.func) in ("set", "frozenset")
    return False


def is_dict_construction(node: ast.AST) -> bool:
    """True if ``node`` builds a ``dict`` value.

    A dict literal (``{}`` / ``{"k": v}``), a dict comprehension, or a ``dict(...)``
    call. Used to tag a variable as dict-valued so a later ``.update()`` /
    ``.setdefault()`` on it is known to merge another mapping's *key-insertion
    order* into it -- even when it started from an empty ``{}`` that is otherwise
    stable (mirrors :func:`is_set_construction`).
    """
    if isinstance(node, (ast.Dict, ast.DictComp)):
        return True
    if isinstance(node, ast.Call):
        return final_attr(node.func) == "dict"
    return False


#: Calls whose result is a ``str``/``bytes`` -- used by :func:`contains_provable_string`
#: to decide whether a builtin ``hash()`` is hashing string content (and so is
#: PYTHONHASHSEED-salted). ``dumps``/``dump``/``safe_dump`` (json/yaml → text),
#: ``str``/``repr``/``format``/``join`` (→ str), ``hexdigest`` (hashlib digest → str),
#: ``encode``/``decode`` (str↔bytes -- both salted).
_STRING_PRODUCING_CALLS = frozenset(
    {"dumps", "dump", "safe_dump", "str", "repr", "format", "join",
     "hexdigest", "encode", "decode"}
)


def is_string_valued(node: ast.AST) -> bool:
    """True if ``node`` is *provably* a ``str``/``bytes`` value.

    Conservative: an f-string, a str/bytes literal, a string-concatenation, or a
    call to a known text-producer (``json.dumps(...)``, ``str(...)``,
    ``",".join(...)``, ``x.format(...)``, ...). A bare name/attribute is *not*
    provable (its type is unknown), so it returns ``False``.
    """
    if isinstance(node, ast.JoinedStr):  # f-string
        return True
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
        return True
    if isinstance(node, ast.Call):
        return final_attr(node.func) in _STRING_PRODUCING_CALLS
    if isinstance(node, ast.BinOp):  # ``"prefix" + x`` / ``a + b`` string concat
        return is_string_valued(node.left) or is_string_valued(node.right)
    return False


def contains_provable_string(node: ast.AST) -> bool:
    """True if ``node``, or an element of a tuple/list/set it builds, is a string.

    ``hash(json.dumps(x))`` and ``hash((addr, routing, json.dumps(x)))`` both hash
    string content; the tuple case is why this recurses into literal collections.
    """
    if is_string_valued(node):
        return True
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return any(contains_provable_string(e) for e in node.elts)
    return False


def ctor_class(node: ast.AST) -> Optional[str]:
    """If ``node`` looks like ``ClassName(...)``, return the class name."""
    if isinstance(node, ast.Call):
        name = final_attr(node.func)
        if name and name[:1].isupper():  # CamelCase heuristic for a constructor
            return name
    return None


def infer_class(recv: ast.AST, types: Dict[str, str]) -> Optional[str]:
    """Best-effort class of a method-call receiver from local construction info."""
    cls = ctor_class(recv)
    if cls:
        return cls
    if isinstance(recv, ast.Name):
        return types.get(recv.id)
    return None


def source_desc(node: ast.AST) -> str:
    """Short human description of why a value is considered unordered."""
    if isinstance(node, ast.Call):
        name = final_attr(node.func)
        if name in UNORDERED_CALLS:
            return f"{name}(...)"
        if name in PROPAGATE_CALLS and node.args:
            return f"{name}(...) of {source_desc(node.args[0])}"
    if isinstance(node, ast.Name):
        return f"'{node.id}'"
    if isinstance(node, (ast.Set, ast.SetComp)):
        return "a set"
    if isinstance(node, ast.BinOp):
        return "set algebra"
    return "an unordered value"


def guards(stmt: ast.stmt) -> List[ast.expr]:
    """Sub-expressions that gate a compound statement (``if``/``while``/``with``)."""
    result: List[ast.expr] = []
    for attr in ("test", "iter"):
        val = getattr(stmt, attr, None)
        if isinstance(val, ast.expr):
            result.append(val)
    if isinstance(stmt, ast.With):
        result.extend(item.context_expr for item in stmt.items)
    return result


def isinstance_ordered_name(test: ast.expr, ordered_types: Set[str]) -> Optional[str]:
    """Name narrowed to an ordered type by ``isinstance(<Name>, <ordered>)``, else None.

    Recognises ``isinstance(raw, list)`` and ``isinstance(raw, (list, tuple))`` and
    returns ``"raw"`` -- but only when *every* checked type is in ``ordered_types``,
    so a ``set``/``frozenset`` (or unknown) branch never narrows. Used to suppress
    the contract-boundary "a caller might pass an unordered collection" finding
    inside a block where the parameter is provably ordered.
    """
    if not (
        isinstance(test, ast.Call)
        and isinstance(test.func, ast.Name)
        and test.func.id == "isinstance"
        and len(test.args) == 2
    ):
        return None
    target, types = test.args
    if not isinstance(target, ast.Name):
        return None
    type_nodes = types.elts if isinstance(types, ast.Tuple) else [types]
    names = [final_attr(t) for t in type_nodes]
    if names and all(n in ordered_types for n in names):
        return target.id
    return None


def child_bodies(stmt: ast.stmt) -> List[List[ast.stmt]]:
    """Every nested statement list of a compound statement."""
    bodies: List[List[ast.stmt]] = []
    for attr in ("body", "orelse", "finalbody"):
        val = getattr(stmt, attr, None)
        if isinstance(val, list):
            bodies.append(val)
    for handler in getattr(stmt, "handlers", []):
        bodies.append(handler.body)
    return bodies


def enumerate_arg(node: ast.AST) -> Optional[ast.AST]:
    """The iterable inside an ``enumerate(<iterable>[, start])`` call, else ``None``.

    ``enumerate(some_set)`` pairs each element with a *positional* index, so when the
    source is unordered the (index -> element) binding flaps run-to-run even though
    the indices ``0, 1, 2`` are stable. Returned so the ``for i, x in enumerate(...)``
    walk can mark the value target ``x`` a value-position pick (the ``{i}.crt`` /
    ``.../{idx}`` naming pattern). Only a bare ``enumerate`` name matches.
    """
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "enumerate"
        and node.args
    ):
        return node.args[0]
    return None


def loop_accumulators(node: ast.For) -> set:
    """Local names mutated as accumulators anywhere within a loop body.

    ``list.append``/``extend``/``insert``, ``set.add``/``update``,
    ``dict.setdefault``/``update``, ``d[k] = v`` and ``+=`` all collect values
    in iteration order, so when the loop iterates an unordered source the
    accumulated value inherits that ordering instability. A dict filled this way
    is order-sensitive once serialized unsorted (``str(d)`` / ``json.dumps(d)``
    without ``sort_keys=True``), which is exactly the alerts-hash pattern.
    """
    names: set = set()
    for sub in ast.walk(node):
        if (
            isinstance(sub, ast.Call)
            and isinstance(sub.func, ast.Attribute)
            and sub.func.attr in ACCUMULATOR_METHODS
        ):
            recv = sub.func.value
            # ``x.append(v)`` taints ``x``; ``data[role].add(v)`` taints the
            # root mapping ``data`` (a dict-of-sets / dict-of-lists filled by
            # iterating an unordered source -- the gather-addresses-by-role
            # pattern). A plain attribute receiver (``self.foo.append``) is left
            # alone: that is not a local accumulator.
            if isinstance(recv, ast.Name):
                names.add(recv.id)
            elif isinstance(recv, ast.Subscript):
                rn = root_name(recv)
                if rn is not None:
                    names.add(rn)
        elif isinstance(sub, ast.AugAssign):
            if isinstance(sub.target, ast.Name):
                names.add(sub.target.id)
            elif isinstance(sub.target, ast.Subscript) and isinstance(
                sub.target.value, ast.Name
            ):
                names.add(sub.target.value.id)  # d[k] += v
        elif isinstance(sub, ast.Assign):
            for tgt in sub.targets:
                if isinstance(tgt, ast.Subscript) and isinstance(tgt.value, ast.Name):
                    names.add(tgt.value.id)  # d[k] = v dict-construction
    return names


def list_loop_accumulators(node: ast.For) -> set:
    """Local names filled as *list* accumulators in a loop body.

    The list-building subset of :func:`loop_accumulators`: a name mutated by
    ``.append``/``.extend``/``.insert`` (or ``+= [..]`` with a list literal). Such a
    list bakes the loop's iteration order into its *element* order, so when the loop
    iterates an unordered source it inherits *sequence* (``itercaller``) instability
    that survives a key-sorting serializer -- unlike a ``set``/``dict`` accumulator
    (``.add``/``.update``/``d[k]=v``), whose disorder is key-order and stays
    ``local``. Receivers mirror :func:`loop_accumulators` (a ``Name``, or the root of
    a ``Subscript`` like ``buckets[k].append(v)`` -- a dict whose list values flap).
    """
    names: set = set()
    for sub in ast.walk(node):
        if (
            isinstance(sub, ast.Call)
            and isinstance(sub.func, ast.Attribute)
            and sub.func.attr in LIST_ACCUMULATOR_METHODS
        ):
            recv = sub.func.value
            if isinstance(recv, ast.Name):
                names.add(recv.id)
            elif isinstance(recv, ast.Subscript):
                rn = root_name(recv)
                if rn is not None:
                    names.add(rn)
        elif (
            isinstance(sub, ast.AugAssign)
            and isinstance(sub.op, ast.Add)
            and isinstance(sub.value, ast.List)
        ):
            if isinstance(sub.target, ast.Name):
                names.add(sub.target.id)  # acc += [v]
            elif isinstance(sub.target, ast.Subscript) and isinstance(
                sub.target.value, ast.Name
            ):
                names.add(sub.target.value.id)  # acc[k] += [v]
    return names


def identity_passthrough_accumulators(node: ast.For) -> set:
    """List accumulators filled *only* by appending a loop target *unchanged*.

    ``for x in src: out.append(x)`` (and ``.extend``/``.insert`` of a bare loop
    target) is an order-preserving *copy/filter* of ``src`` -- the ``_dedupe_list``
    shape -- not a fresh materialization: it creates no new element order, it
    inherits ``src``'s. So a caller's flap must not be re-anchored *here* (this
    passthrough is transparent); its born-site belongs upstream. Excludes any
    accumulator that also receives a *transformed* element (``out.append(f(x))`` /
    ``out.append({...})``) or is otherwise mutated -- those genuinely build a new
    structure and stay materializers.
    """
    targets = {t.id for t in ast.walk(node.target) if isinstance(t, ast.Name)}
    all_identity: dict = {}
    for sub in ast.walk(node):
        if not (
            isinstance(sub, ast.Call)
            and isinstance(sub.func, ast.Attribute)
            and isinstance(sub.func.value, ast.Name)
            and sub.func.attr in LIST_ACCUMULATOR_METHODS
        ):
            continue
        acc = sub.func.value.id
        # appended value: ``insert(i, v)`` -> args[1]; ``append``/``extend`` -> args[0]
        val = (
            sub.args[1]
            if sub.func.attr == "insert" and len(sub.args) >= 2
            else (sub.args[0] if sub.args else None)
        )
        is_identity = isinstance(val, ast.Name) and val.id in targets
        all_identity[acc] = all_identity.get(acc, True) and is_identity
    return {acc for acc, ident in all_identity.items() if ident}


def file_write_args(call: ast.Call) -> Optional[Tuple[str, List[ast.expr]]]:
    """``(method, content exprs)`` written by a known on-disk file call.

    Recognises the workload/charm file writers in :data:`FILE_WRITE_METHODS` --
    ``container.push(path, source)``,
    ``Path.write_text``/``write_bytes`` (also ``charmlibs.pathops``), open-handle
    ``f.write(data)`` / ``f.writelines(lines)``, and ``os.write(fd, data)`` --
    and returns the method key plus the argument(s) carrying the *content* (so an
    order-unstable payload there is a file flap). Returns ``None`` when ``call``
    is not such a write, and ``(method, [])`` when the method matches but the
    content argument is absent.

    ``os.write`` and a path/handle's ``.write`` share the final attribute name
    but differ in content position (``os.write(fd, data)`` vs ``f.write(data)``),
    so ``os.write`` is disambiguated by its ``os`` module root and looked up
    under the synthetic ``os_write`` key. Like the other sinks this anchors on a
    stable framework/stdlib method name; the *content position* is structural.
    """
    if not isinstance(call.func, ast.Attribute):
        return None
    attr = call.func.attr
    key = attr
    if attr == "write" and module_root(call.func) == "os":
        key = "os_write"  # os.write(fd, data) -- content is the 2nd positional
    return _content_args(call, FILE_WRITE_METHODS, key)


def secret_write_args(call: ast.Call) -> Optional[Tuple[str, List[ast.expr]]]:
    """``(method, content exprs)`` written by a Juju secret call (the ``secret`` sink).

    Recognises ``Secret.set_content(content)`` and
    ``Application/Unit.add_secret(content, ...)`` from :data:`SECRET_WRITE_METHODS`
    and returns the method key plus the *content* argument -- an order-unstable value
    there churns secret revisions. Returns ``None`` when ``call`` is not such a write.
    """
    if not isinstance(call.func, ast.Attribute):
        return None
    return _content_args(call, SECRET_WRITE_METHODS, call.func.attr)


def plan_write_args(call: ast.Call) -> Optional[Tuple[str, List[ast.expr]]]:
    """``(method, content exprs)`` written by a pebble-plan call (the ``plan`` sink).

    Recognises ``container.add_layer(label, layer)`` (and the lower-level
    ``pebble.Client.add_layer``) from :data:`PLAN_WRITE_METHODS` and returns the
    method key plus the *layer* argument(s). Separate from :func:`file_write_args`
    because a pebble layer is compared *structurally* by the daemon, not byte-
    diffed, so the caller applies key-sort (not raw-byte) survival to the content.
    Returns ``None`` when ``call`` is not a plan write.
    """
    if not isinstance(call.func, ast.Attribute):
        return None
    return _content_args(call, PLAN_WRITE_METHODS, call.func.attr)


def _content_args(
    call: ast.Call,
    table: "Dict[str, Tuple[int, Tuple[str, ...]]]",
    key: str,
) -> Optional[Tuple[str, List[ast.expr]]]:
    """Shared extraction: the content expr(s) for ``key`` in a sink ``table``.

    Returns ``(key, content exprs)`` -- the positional at the table's index plus
    any keyword-aliased content -- or ``None`` if ``key`` is not in the table.
    """
    spec = table.get(key)
    if spec is None:
        return None
    idx, kw_aliases = spec
    out: List[ast.expr] = []
    positional = [a for a in call.args if not isinstance(a, ast.Starred)]
    if idx < len(positional):
        out.append(positional[idx])
    for kw in call.keywords:
        if kw.arg in kw_aliases and kw.value is not None:
            out.append(kw.value)
    return key, out


def map_call_args(call: ast.Call, fi: FuncInfo) -> Dict[int, ast.expr]:
    """Map a call's arguments onto ``fi``'s parameter indices.

    Accounts for the implicit ``self``/``cls`` of a bound method call so that
    ``obj.method(a, b)`` maps ``a``/``b`` onto the method's first two *explicit*
    parameters.
    """
    mapping: Dict[int, ast.expr] = {}
    is_attr_call = isinstance(call.func, ast.Attribute)
    offset = 1 if (fi.is_method and is_attr_call) else 0
    for i, arg in enumerate(call.args):
        if isinstance(arg, ast.Starred):
            continue
        didx = i + offset
        if didx < fi.n_positional and didx < len(fi.params):
            mapping[didx] = arg
    for kw in call.keywords:
        if kw.arg and kw.arg in fi.param_index:
            mapping[fi.param_index[kw.arg]] = kw.value
    return mapping
