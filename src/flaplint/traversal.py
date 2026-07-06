"""Statement-level traversal: flow taint through a function body to sinks.

:class:`FunctionAnalyzer` walks a single function's statements, maintaining an
environment of ``name -> taint`` and a best-effort ``name -> class`` map, and
notifies a :class:`~flaplint.handlers.Handler` whenever taint reaches a
databag/hash sink or a ``return``. The same walk powers both the summary and the
report passes; only the handler differs.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from . import astutils
from .constants import (
    ACCUMULATOR_METHODS,
    BUILDER_ARG_PROPAGATORS,
    BUILTIN_COLLECTION_METHODS,
    BYTES_SERIALIZER_METHODS,
    FILE_WRITE_DESCS,
    HASH_CALLS,
    ISINSTANCE_ORDERED_TYPES,
    MAPPING_MERGE_METHODS,
    MAPPING_WRITE_METHODS,
    MODEL_SERIALIZERS,
    NONSORTING_SERIALIZERS,
    ORDERED_ANNOTATIONS,
    PLAN_WRITE_DESC,
    PROPAGATE_CALLS,
    RENDER_SERIALIZERS,
    SANITIZER_CALLS,
    SECRET_WRITE_DESC,
    SET_MUTATION_METHODS,
    STR_SPLIT_METHODS,
    TEMPLATE_RENDER_METHODS,
    UNORDERED_ATTRS,
    UNORDERED_CALLS,
    VOLATILE_CALLS,
)
from . import databag
from .handlers import Handler, _RemoteSite
from .model import FuncInfo, Origin, Registry
from .taint import (
    TaintEngine,
    _as_value_position,
    _promote_to_sequence,
)


#: Call names that don't introduce ordering/volatility instability, so a call to one
#: in a write's content is *not* a blind spot. Deterministic string/scalar transforms
#: and order-independent builtins (``min``/``max``/``sum`` of a set give the same
#: result whatever the order). Used only by the ``--explain-gaps`` blind-spot scan;
#: tune freely -- a name missing here only costs a (benign) gap entry, never a finding.
_BENIGN_CALLS = frozenset(
    {
        # string / bytes / scalar transforms
        "get", "format", "format_map", "strip", "lstrip", "rstrip", "replace",
        "lower", "upper", "title", "capitalize", "casefold", "swapcase",
        "removeprefix", "removesuffix", "zfill", "ljust", "rjust", "center",
        "encode", "decode", "hex", "digest", "hexdigest",
        "b64encode", "b64decode", "b16encode", "b16decode", "b32encode", "b32decode",
        "loads", "load", "isoformat", "startswith", "endswith",
        # reading a file returns its (deterministic) content -- for a hash/file write
        # that *is* the intended change-detector input, not an ordering source
        "read", "read_text", "read_bytes", "readline", "readlines",
        # order-independent builtins
        "str", "repr", "int", "float", "bool", "bytes", "len", "abs", "round",
        "min", "max", "sum", "any", "all", "ord", "chr", "getattr", "cast",
        # path helpers
        "basename", "dirname", "splitext", "abspath", "expanduser", "as_posix",
    }
)

#: Call names the taint engine already understands (sources, sinks-as-content,
#: sanitisers, serialisers, propagators, …). A call to one of these is fully
#: accounted for -- never a blind spot.
_ENGINE_KNOWN_CALLS = (
    SANITIZER_CALLS
    | UNORDERED_CALLS
    | VOLATILE_CALLS
    | PROPAGATE_CALLS
    | STR_SPLIT_METHODS
    | TEMPLATE_RENDER_METHODS
    | NONSORTING_SERIALIZERS
    | MODEL_SERIALIZERS
    | BUILTIN_COLLECTION_METHODS
    | HASH_CALLS
    | BUILDER_ARG_PROPAGATORS
    | BYTES_SERIALIZER_METHODS
    | {"dumps", "dump", "safe_dump"}
)


@dataclass
class Context:
    """Mutable per-function analysis state threaded through the walk."""

    env: Dict[str, Set[Origin]]
    types: Dict[str, str] = field(default_factory=dict)  # variable -> class name
    #: variables currently holding a ``set``/``frozenset`` value, so a later
    #: ``.add()`` / ``.update()`` on one is known to keep it an unordered set even
    #: when it started from an otherwise-stable empty ``set()``.
    set_vars: Set[str] = field(default_factory=set)
    #: variables currently holding a ``dict`` value, so a later ``.update()`` /
    #: ``.setdefault()`` on one is known to merge another mapping's key-insertion
    #: order into it -- even when it started from an otherwise-stable empty ``{}``.
    dict_vars: Set[str] = field(default_factory=set)
    cls: Optional[str] = None  # enclosing class of the analyzed function
    #: local variable -> its databag-provenance kind (relation/relation_data/databag)
    databag_kinds: Dict[str, str] = field(default_factory=dict)
    #: local variable -> the ``self.<attr>`` path it aliases, when it was bound from a
    #: getter that returns exactly ``self.<attr>`` (``ctx = self._get_ctx()`` where
    #: ``_get_ctx`` does ``return self._ctx`` -> ``{"ctx": "_ctx"}``). Lets a mutation
    #: of a field on the alias (``ctx.targets = set(x)``) be recorded against the real
    #: instance attribute, so a read of ``self._ctx.targets`` elsewhere still sees it.
    self_aliases: Dict[str, str] = field(default_factory=dict)
    #: this function's parameter names (by index) and their annotations -- used by
    #: the ``--explain-gaps`` scan to grade an untraced-parameter blind spot.
    params: List[str] = field(default_factory=list)
    param_annotations: Dict[str, Optional[str]] = field(default_factory=dict)
    #: file/name of the function being walked -- used to resolve the born-site of a
    #: ``self.<attr> = <expr>`` instance-attribute taint to the assigning method.
    func_path: Optional[str] = None
    func_name: Optional[str] = None


class FunctionAnalyzer:
    """Flow-sensitive intraprocedural walk over one function at a time."""

    def __init__(self, engine: TaintEngine) -> None:
        self.engine = engine

    @property
    def registry(self) -> Registry:
        return self.engine.registry

    # -- entry point --------------------------------------------------------

    def analyze(self, fi: FuncInfo, handler: Handler) -> None:
        """Walk ``fi`` seeding each parameter with its own ``("param", idx)``."""
        # Select this function's file's import aliases so name-matching in the
        # engine resolves any renamed imports. One function is walked at a time.
        self.engine.enter(fi.path)
        env: Dict[str, Set[Origin]] = {
            pname: {("param", idx)} for idx, pname in enumerate(fi.params)
        }
        ctx = Context(
            env=env,
            types={},
            cls=fi.class_name,
            params=list(fi.params),
            param_annotations=dict(fi.param_annotations),
            func_path=fi.path,
            func_name=fi.name,
        )
        self._visit_body(getattr(fi.node, "body", []), ctx, handler)

    # -- helpers ------------------------------------------------------------

    def _eval(self, node, ctx: Context) -> Set[Origin]:
        # Give the engine this function's live variable -> class map (params by
        # annotation, locals by constructor) so an attribute read can resolve its
        # receiver's class -- ``event.certificates`` -> ``CertificatesAvailableEvent``.
        self.engine.set_var_types({**ctx.param_annotations, **ctx.types})
        return self.engine.eval(node, ctx.env, ctx.cls)

    def _resolve_methods(self, call: ast.Call, ctx: Context) -> List[FuncInfo]:
        """Candidate definitions for a call, narrowed by receiver class if known."""
        name = astutils.final_attr(call.func)
        candidates = self.registry.get(name or "", [])
        if isinstance(call.func, ast.Attribute):
            cls = astutils.infer_class(call.func.value, ctx.types)
            if cls:
                # Include inherited definitions: a method resolved on a subclass
                # receiver may be defined on a base (``LokiPushApiConsumer`` ->
                # ``ConsumerBase.loki_endpoints``).
                chain = self.engine._class_chain(cls)
                matched = [fi for fi in candidates if fi.class_name in chain]
                if matched:
                    return matched
            # Receiver precisely typed to a class we have *no definition* for -- an
            # external library type (``self._krm = KubernetesResourceManager(...)`` from
            # lightkube). Do NOT fall back to the same-name union of *unrelated* user
            # methods: that imports a wrong summary (``Nginx.reconcile`` pushes a TLS
            # key to a file, colliding with an external ``krm.reconcile`` that only
            # applies k8s objects). Only for *external* classes -- an *untyped* receiver
            # (no ``cls``) keeps the union (the load-bearing case that resolves real
            # findings through imperfect typing), and one of *our* classes with an
            # imperfect method match also keeps it.
            recv_cls = cls or self.engine._receiver_class(call.func.value, ctx.cls)
            if recv_cls and recv_cls not in self.engine._analyzed_classes:
                return []
            # A builtin collection method (``subnets.update(...)``) on a receiver of
            # unknown class must NOT fall back to a same-named user method -- that is
            # a cross-class collision (e.g. the charm's own ``update``). Without a
            # known class, treat it as the builtin and resolve to nothing.
            if name in BUILTIN_COLLECTION_METHODS:
                recv = call.func.value
                if not (isinstance(recv, ast.Name) and recv.id in ("self", "cls")):
                    return []
        return candidates

    def _record_type(self, target: ast.AST, value: ast.AST, ctx: Context) -> None:
        if not isinstance(target, ast.Name):
            return
        cls = astutils.ctor_class(value)
        if cls is None and isinstance(value, ast.Call):
            # ``x = helper()`` where ``helper``'s ``-> Ret`` annotation names a class we
            # analysed: type ``x`` as ``Ret`` so a later ``x.method()`` resolves on that
            # class instead of the same-name union (which collides across classes). Only
            # an analysed class is trusted -- an external/typing return annotation
            # (``-> List`` / ``-> KubernetesResourceManager``) leaves ``x`` untyped, as
            # before.
            for fi in self._resolve_methods(value, ctx):
                rc = fi.returns_class
                if rc and rc in self.engine._analyzed_classes:
                    cls = rc
                    break
        if cls:
            ctx.types[target.id] = cls
        elif target.id in ctx.types:
            del ctx.types[target.id]
        # Track set-valued bindings so a later ``.add()`` / ``.update()`` on this
        # name is known to keep it an unordered set (see ``_visit_expr_stmt``).
        if astutils.is_set_construction(value):
            ctx.set_vars.add(target.id)
        else:
            ctx.set_vars.discard(target.id)
        # Track dict-valued bindings so a later ``.update()`` / ``.setdefault()``
        # on this name is known to merge another mapping's key-order into it.
        if astutils.is_dict_construction(value):
            ctx.dict_vars.add(target.id)
        else:
            ctx.dict_vars.discard(target.id)
        # ``ctx = self._get_ctx()`` where ``_get_ctx`` is a pure getter (``return
        # self._ctx``): record ``ctx`` as an alias of ``self._ctx``, so a later field
        # mutation on it (``ctx.targets = set(x)``) is charged to the real attribute.
        alias = self._self_getter_target(value, ctx)
        if alias is not None:
            ctx.self_aliases[target.id] = alias
        else:
            ctx.self_aliases.pop(target.id, None)

    def _self_getter_target(self, value: ast.AST, ctx: Context) -> Optional[str]:
        """``self.<attr>`` path a ``self.<getter>()`` call returns as an alias, else None.

        ``self._get_ctx()`` -> ``"_ctx"`` when ``_get_ctx`` is a pure getter. Resolved on
        the enclosing class so a same-named getter on an unrelated class can't hijack it.
        """
        if not (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and isinstance(value.func.value, ast.Name)
            and value.func.value.id in ("self", "cls")
        ):
            return None
        for fi in self._resolve_methods(value, ctx):
            if ctx.cls and fi.class_name and fi.class_name != ctx.cls:
                chain = self.engine._class_chain(ctx.cls)
                if not (chain and fi.class_name in chain):
                    continue
            if fi.returns_self_attr:
                return fi.returns_self_attr
        return None

    def _record_databag_alias(
        self, target: ast.AST, value: ast.AST, ctx: Context
    ) -> None:
        """Track ``b = relation.data[app]`` (or ``r = get_relation(...)``) so a later
        write through ``b`` -- or ``b.data[app].update(...)`` -- is still a sink."""
        if not isinstance(target, ast.Name):
            return
        kind = self._databag_kind_of(value, ctx)
        if kind is not None:
            ctx.databag_kinds[target.id] = kind
        else:
            ctx.databag_kinds.pop(target.id, None)

    def _clear_field_taint(self, name: str, ctx: Context) -> None:
        """Drop every ``name.<field>`` compound key (on reassignment of ``name``)."""
        prefix = name + "."
        for key in [k for k in ctx.env if k.startswith(prefix)]:
            del ctx.env[key]

    def _record_field_taint(self, name: str, value: ast.AST, ctx: Context) -> None:
        """Record the per-field taint of a value object bound to ``name``.

        Value-object field provenance: an unstable collection stashed in a
        dataclass / pydantic / NamedTuple field survives being read back off the
        object. The field taint is stored under compound ``env`` keys
        (``"name.field"``), which the engine reads on ``name.field`` access. Three
        binding shapes populate it:

        * ``name = Ctor(field=expr, ...)`` -- per-keyword field taint;
        * ``name = other`` -- alias copy of ``other``'s field keys;
        * ``name = helper(...)`` -- read the callee's ``returns_field_origins``
          summary (the cross-function half).
        """
        self._clear_field_taint(name, ctx)
        ctor = astutils.ctor_class(value)
        if isinstance(value, ast.Call) and ctor is not None:
            seq_fields = self.engine.model_seq_fields.get(ctor, ())
            for kw in value.keywords:
                if kw.arg is None or kw.value is None:
                    continue
                t = self._eval(kw.value, ctx)
                if t and kw.arg in seq_fields:
                    # A set coerced into a ``list``/``tuple`` pydantic field bakes
                    # element order (``local`` -> ``itercaller``), so it survives a
                    # key-sorting ``model_dump_json`` / ``json.dumps(sort_keys=True)``.
                    t = self.engine.coerce_to_sequence_field(t, kw.value)
                if t:
                    ctx.env[f"{name}.{kw.arg}"] = t
            return
        if isinstance(value, ast.Name):
            prefix = value.id + "."
            for key, origins in list(ctx.env.items()):
                if key.startswith(prefix) and origins:
                    ctx.env[f"{name}.{key[len(prefix):]}"] = set(origins)
            return
        if isinstance(value, ast.Call):
            for fi in self._resolve_methods(value, ctx):
                for fld, origins in fi.returns_field_origins.items():
                    if origins:
                        ctx.env[f"{name}.{fld}"] = set(
                            ctx.env.get(f"{name}.{fld}", ())
                        ) | set(origins)

    def _record_dict_key_taint(
        self, base_path: str, value: ast.AST, ctx: Context
    ) -> None:
        """Record the per-key taint of a dict literal bound to ``base_path``.

        Dict-by-fixed-key provenance: a value buried under a constant
        string key survives being read back on ``base_path['key']``, *field-
        sensitively* -- a clean sibling key is not tainted. Stored under compound
        ``env`` keys (``"base['key']"``), which the engine reads on a fixed-key
        subscript. Only a direct ``base_path = {...}`` dict literal populates it
        (the common shape); every ``base_path[...]`` key is cleared first so a
        stale entry can't linger across a rebinding.
        """
        prefix = base_path + "["
        for key in [k for k in ctx.env if k.startswith(prefix)]:
            del ctx.env[key]
        if not isinstance(value, ast.Dict):
            return
        for key, val in zip(value.keys, value.values):
            if isinstance(key, ast.Constant) and isinstance(key.value, str) and val:
                t = self._eval(val, ctx)
                if t:
                    ctx.env[f"{base_path}[{key.value!r}]"] = t

    def _record_instance_attr_dict_keys(
        self, tgt: ast.AST, value: ast.AST, ctx: Context
    ) -> None:
        """For ``self.<attr> = {<const-key>: <expr>}``, carry each key's taint into
        the class map under the compound attr ``"<attr>['key']"`` -- the cross-
        method half of dict-by-fixed-key provenance (build in ``__init__``, read on
        ``self.<attr>['key']`` in a handler)."""
        if not (
            isinstance(tgt, ast.Attribute)
            and isinstance(tgt.value, ast.Name)
            and tgt.value.id in ("self", "cls")
            and ctx.cls
            and isinstance(value, ast.Dict)
        ):
            return
        for key, val in zip(value.keys, value.values):
            if not (isinstance(key, ast.Constant) and isinstance(key.value, str) and val):
                continue
            resolved = {self._resolve_attr_origin(o, ctx) for o in self._eval(val, ctx)}
            origins = {o for o in resolved if o}
            if origins:
                self.engine.record_instance_attr(
                    ctx.cls, f"{tgt.attr}[{key.value!r}]", origins
                )

    @staticmethod
    def _resolve_attr_origin(o: Origin, ctx: Context):
        """Resolve a ``self.<attr>`` taint origin's born-site to the assigning method.

        Mirrors :func:`handlers._resolve_field_origin`: a locally-born origin carries
        ``None`` placeholders (== "this file / this function"). The attribute may be
        read back in *another* method/file, so the placeholders are pinned to the
        assigning method here, letting a finding blame the ``set()`` in ``__init__``
        rather than the reader's serializer. Param-flavored origins are dropped (not
        remappable without the call's arg mapping).
        """
        if o == "volatile":
            return o
        if not isinstance(o, tuple):
            return None
        tag = o[0]
        if tag in ("local", "element"):
            return (tag, o[1] or ctx.func_path, o[2], o[3] or ctx.func_name)
        if tag == "itercaller":
            born = o[3]
            if born is not None:
                born = (born[0] or ctx.func_path, born[1], born[2] or ctx.func_name)
            return (tag, o[1] or ctx.func_path, o[2], born)
        return None  # param / iterparam: not cross-method-resolvable here

    def _record_instance_attr(
        self, tgt: ast.AST, taint: Set[Origin], ctx: Context
    ) -> None:
        """For ``self.<attr> = <expr>``, union the field's taint into the class map.

        The cross-method half of instance-attribute provenance: the within-method
        read-back is already handled by the ``"self.<attr>"`` env key; this carries
        the same taint to a read in a *different* method of the class.
        """
        key = astutils.self_attr_key(tgt) if ctx.cls else None
        if key is None and ctx.cls:
            # The target's base isn't a plain ``self.<attr>`` chain but reaches a real
            # instance attribute through a *pure getter* -- either inline
            # (``self._get_ctx().targets = …``) or via a local aliased to one
            # (``ctx = self._get_ctx(); ctx.targets = …``). Charge the write to the
            # attribute the getter returns, so a read of ``self._ctx.targets`` elsewhere
            # sees it. Bridges the "value reached through a call" tracking gap.
            key = self._aliased_self_attr_key(tgt, ctx)
        if key is None:
            return
        resolved = {self._resolve_attr_origin(o, ctx) for o in taint}
        self.engine.record_instance_attr(
            ctx.cls, key, {o for o in resolved if o}
        )

    def _aliased_self_attr_key(self, tgt: ast.AST, ctx: Context) -> Optional[str]:
        """``self``-relative attr path for a write target whose base is a getter/alias.

        Walks the trailing ``.attr`` chain of ``tgt`` down to its base; resolves the
        base to a ``self.<attr>`` path when it is a pure ``self.<getter>()`` call
        (case A) or a local aliased to one (case C, via ``ctx.self_aliases``). Returns
        the combined ``"<attr>.<trailing…>"`` key, or ``None`` if the base doesn't
        resolve. Only fires for the getter/alias shapes -- a plain ``self`` chain is
        handled by :func:`astutils.self_attr_key` before this is consulted.
        """
        trailing: List[str] = []
        cur = tgt
        while isinstance(cur, ast.Attribute):
            trailing.append(cur.attr)
            cur = cur.value
        trailing.reverse()
        if not trailing:
            return None
        base: Optional[str] = None
        if isinstance(cur, ast.Name) and cur.id in ctx.self_aliases:
            base = ctx.self_aliases[cur.id]
        else:
            base = self._self_getter_target(cur, ctx)
        if base is None:
            return None
        return ".".join([base] + trailing)

    def _returned_field_map(self, value: ast.AST, ctx: Context):
        """Per-field taint of a returned value object: ``{field -> origins}``.

        Mirrors :meth:`_record_field_taint` for the two return shapes that escape a
        function -- ``return obj`` (collect its field keys) and the inline
        ``return Ctor(field=expr)`` -- so a callee's value-object fields become its
        ``returns_field_origins`` summary.
        """
        out = {}
        if isinstance(value, ast.Name):
            prefix = value.id + "."
            for key, origins in ctx.env.items():
                if key.startswith(prefix) and origins:
                    out[key[len(prefix):]] = set(origins)
        elif isinstance(value, ast.Call) and astutils.ctor_class(value) is not None:
            for kw in value.keywords:
                if kw.arg is None or kw.value is None:
                    continue
                t = self._eval(kw.value, ctx)
                if t:
                    out[kw.arg] = t
        return out

    # -- blind-spot (gap) detection (--explain-gaps) ------------------------

    def _gap_check(
        self, content: ast.AST, sink: str, ctx: Context, handler: Handler
    ) -> None:
        """Report parts of a write's ``content`` that flaplint couldn't trace.

        A *gap* is where the analysis gives up -- an unresolved call, a value-object
        field it doesn't model, an untraced parameter -- so it's where a missed flap
        could hide. No-ops unless the handler is collecting gaps. See :class:`Gap`.
        """
        if not handler.wants_gaps:
            return
        seen = set()
        for node, reason in self._content_gaps(content, sink, ctx):
            key = (getattr(node, "lineno", 0), getattr(node, "col_offset", 0), reason)
            if key not in seen:
                seen.add(key)
                handler.gap(node, sink, reason)

    def _content_gaps(self, content: ast.AST, sink: str, ctx: Context):
        """Yield ``(node, reason)`` for each untraceable part of ``content``."""
        # Attributes that are the target of a call (``obj.method(...)``) are method
        # calls, not field reads -- handled by the call check, never a field gap.
        called = {
            c.func
            for c in ast.walk(content)
            if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)
        }
        # Leaf scan: an unresolved call or a field off a value object we don't model.
        for sub in ast.walk(content):
            if isinstance(sub, ast.Call):
                if not self._call_accounted(sub, ctx):
                    name = astutils.final_attr(sub.func) or "?"
                    yield sub, (
                        f"calls `{name}(...)`, which flaplint can't see into "
                        "(an external library?) — if it can return unordered data, "
                        "an unstable value here would be missed"
                    )
            elif isinstance(sub, ast.Attribute) and sub not in called:
                recv = sub.value
                if (
                    isinstance(recv, ast.Name)
                    and recv.id in ctx.types
                    and not self._attr_accounted(sub, ctx)
                ):
                    yield sub, (
                        f"reads `.{sub.attr}` off `{recv.id}`, a value object whose "
                        "fields flaplint doesn't fully track (e.g. one buried in a "
                        "dict, or rebuilt by a method)"
                    )
        # Content scan: does the *whole* value depend on an untraced parameter? Plan/
        # hash writes get no caller-contract check, so an unordered caller would
        # slip through. (Databag, secret and *file* writes do fold into parameter
        # summaries -- see ``SummaryHandler.sink`` -- so they are a real finding, not
        # a blind spot, and are excluded here.) Computed from the content's taint
        # (not a textual name match),
        # so a parameter that's already neutralised on the way in -- ``template.format(
        # **ctx)`` (template-ordered) -- is *not* a gap. A parameter the caller already
        # promises to keep ordered (``data: list``/``str``) is the caller's job, not a
        # blind spot, so an ordered annotation is skipped.
        if sink in ("plan", "hash", "render"):
            origins = self._eval(content, ctx)
            seen_params = set()
            for o in origins:
                if not (isinstance(o, tuple) and o[0] == "param"):
                    continue
                idx = o[1]
                if idx in seen_params or idx >= len(ctx.params):
                    continue
                seen_params.add(idx)
                pname = ctx.params[idx]
                if pname in ("self", "cls"):
                    continue
                if ctx.param_annotations.get(pname) in ORDERED_ANNOTATIONS:
                    continue
                hint = (
                    "" if ctx.param_annotations.get(pname) else
                    " — add a type hint (e.g. `: list`/`: str` if ordered, `: Set` if not)"
                )
                site = "render" if sink == "render" else f"{sink} write"
                yield content, (
                    f"depends on parameter `{pname}`, not traced to its callers "
                    f"(a {site} gets no caller-contract check, so an unordered "
                    f"caller would be missed){hint}"
                )

    def _call_accounted(self, call: ast.Call, ctx: Context) -> bool:
        """True if the engine understands this call (so it's not a blind spot)."""
        name = astutils.final_attr(call.func) or ""
        name = self.engine._aliases.names.get(name, name)
        if name in _ENGINE_KNOWN_CALLS or name in _BENIGN_CALLS:
            return True
        return bool(self._resolve_methods(call, ctx))

    def _attr_accounted(self, node: ast.Attribute, ctx: Context) -> bool:
        """True if a field read resolves to tracked taint or a known property."""
        if node.attr in UNORDERED_ATTRS:
            return True
        path = astutils.attr_path(node)
        if path is not None and path in ctx.env:
            return True
        recv_cls = self.engine._receiver_class(node.value, ctx.cls)
        if recv_cls is not None:
            for fi in self.registry.get(node.attr, []):
                if fi.is_property and fi.class_name == recv_cls:
                    return True
        return False

    def _accessor_kind(self, attr: str, ctx: Context):
        """Return kind of ``self.<attr>`` resolved against this class's accessors."""
        if not ctx.cls:
            return None
        for fi in self.registry.get(attr, []):
            if fi.class_name == ctx.cls and fi.returns_databag_kind:
                return fi.returns_databag_kind
        return None

    def _databag_kind_of(self, node: ast.AST, ctx: Context):
        """The databag-provenance kind of ``node`` in this context (or ``None``)."""
        return databag.databag_kind(
            node, ctx.databag_kinds, lambda attr: self._accessor_kind(attr, ctx)
        )

    def _is_databag_object(self, node: ast.AST, ctx: Context) -> bool:
        """True if ``node`` *is* a single relation databag (the thing writes land on)."""
        return self._databag_kind_of(node, ctx) == databag.DATABAG

    def _is_databag_target(self, tgt: ast.AST, ctx: Context) -> bool:
        """True if ``tgt`` is an item-assignment into a databag: ``<databag>[k] = …``."""
        return isinstance(tgt, ast.Subscript) and self._is_databag_object(
            tgt.value, ctx
        )

    def _ctor_field_taint(self, value: ast.AST, ctx: Context) -> Set[Origin]:
        """Taint a value object inherits from its constructor fields.

        ``Model(field=<unordered>)`` builds an object that carries the field's
        instability: a later ``model.dump(relation.data[app])`` serializes those
        fields into the databag. This mirrors the builder rule (``obj.add(x)``
        taints ``obj``) for the pydantic-model construction idiom, and stays
        local to the analysed function (it never alters global expression taint).
        """
        ctor = astutils.ctor_class(value)
        if ctor is None or not isinstance(value, ast.Call):
            return set()
        seq_fields = self.engine.model_seq_fields.get(ctor, ())
        out: Set[Origin] = set()
        # *Positional* args carry field taint only when the class is a *known value
        # object* (dataclass / pydantic / NamedTuple): its declared fields, in order,
        # are its constructor's positional parameters, so ``ScrapeJobContext(job)``
        # fills ``updated_job`` exactly as ``ScrapeJobContext(updated_job=job)`` does.
        # A plain class (a stateful collaborator) is absent from ``value_object_fields``,
        # so its positional args (config -- ``ClusterProvider(frozenset(roles), ...)``)
        # are NOT absorbed: tainting the object from them would, via the receiver-
        # inheritance rule, mis-flag every unrelated ``self._cluster.method()`` call
        # (``.grant_privkey()`` -> a false ``unordered-collection``).
        vo_fields = self.engine.value_object_fields.get(ctor)
        if vo_fields is not None:
            for i, arg in enumerate(value.args):
                if isinstance(arg, ast.Starred) or i >= len(vo_fields):
                    continue
                t = self._eval(arg, ctx)
                if vo_fields[i] in seq_fields:
                    t = self.engine.coerce_to_sequence_field(t, arg)
                out |= t
        # *Keyword* args carry field taint for any constructor -- the ``Model(field=
        # <unordered>)`` value-object idiom works even for an external model class we
        # never see defined (so cannot list in ``value_object_fields``). A keyword arg
        # names a field explicitly, so it is unambiguous where a bare positional is not.
        for kw in value.keywords:
            if kw.value is None:
                continue
            t = self._eval(kw.value, ctx)
            if kw.arg in seq_fields:
                # Match the field-level promotion so a whole-object model dump
                # (``Model(hosts=set(...)).model_dump_json()``) is key-sort-proof too.
                t = self.engine.coerce_to_sequence_field(t, kw.value)
            out |= t
        return out

    def _absorb_into_constructor(self, value: ast.AST, ctx: Context) -> None:
        """Constructor analogue of :meth:`_absorb_into_callee`.

        A *stateful class* whose ``__init__`` stores a constructor argument into
        ``self.<attr>`` (``def __init__(self, roles): self._roles = roles``) makes
        that attribute carry the argument's instability -- so a *later* method that
        dumps it (``def publish(self): write(json.dumps(list(self._roles)))``) or
        returns it (``def get_roles(self): return list(self._roles)``) flaps. The
        surfacing half already works for setter-absorbed attributes; this wires the
        *construction site* into the same path, which method calls (``builder.add(x)``)
        already use but constructors (``Prov(frozenset(roles))``) did not.

        ``__init__.absorbs`` (computed for every function) gives ``{param_idx -> attr}``.
        We map each absorbed parameter to its construction argument (positional by
        offset -- the constructor supplies ``self`` implicitly, so arg *N* is param
        *N+1* -- or by keyword) and record the argument's *concrete* taint onto the
        class's ``instance_attr_taint``. Bare ``param``/``iterparam`` origins are
        dropped (a keyed lookup that merely touches a parameter is order-stable),
        mirroring the setter barrier -- so this is field-precise: a method that does
        not read the attribute (``grant_privkey`` on a ``ClusterProvider`` built with
        an unordered arg) never inherits it.
        """
        if not isinstance(value, ast.Call):
            return
        cls = astutils.ctor_class(value)
        if cls is None:
            return
        chain = self.engine._class_chain(cls)
        for init in self.registry.get("__init__", []):
            if not (init.class_name and init.absorbs):
                continue
            if init.class_name != cls and not (chain and init.class_name in chain):
                continue
            for pidx, attr in init.absorbs.items():
                arg = self._constructor_arg(value, init, pidx)
                if arg is None or isinstance(arg, ast.Starred):
                    continue
                argtaint = self._eval(arg, ctx)
                if not argtaint:
                    continue
                resolved = {
                    self._resolve_attr_origin(o, ctx)
                    for o in argtaint
                    if not (isinstance(o, tuple) and o[0] in ("param", "iterparam"))
                }
                self.engine.record_instance_attr(
                    init.class_name, attr, {o for o in resolved if o}
                )

    @staticmethod
    def _constructor_arg(
        call: ast.Call, init: FuncInfo, pidx: int
    ) -> "Optional[ast.expr]":
        """The construction argument filling ``__init__`` parameter ``pidx``.

        A constructor call binds ``self`` implicitly, so positional arg *N* fills
        parameter *N+1*; a keyword arg is matched by the parameter's name.
        """
        argpos = pidx - 1
        if 0 <= argpos < len(call.args):
            return call.args[argpos]
        pname = init.params[pidx] if pidx < len(init.params) else None
        for kw in call.keywords:
            if kw.arg is not None and kw.arg == pname:
                return kw.value
        return None

    def _escape_content_taint(self, call: ast.Call, ctx: Context) -> Set[Origin]:
        """Taint written into a databag handed to a writer call.

        For ``writer(<databag>, payload)`` / ``model.dump(<databag>)`` the content
        that lands in the bag comes from the *non-databag* arguments and, when the
        receiver is a tracked value object (a constructed model), from the
        receiver's own taint. The databag argument itself is the destination, not
        content, so it is excluded.
        """
        out: Set[Origin] = set()
        for arg in call.args:
            if isinstance(arg, ast.Starred) or self._is_databag_object(arg, ctx):
                continue
            out |= self._eval(arg, ctx)
        for kw in call.keywords:
            if kw.value is None or self._is_databag_object(kw.value, ctx):
                continue
            out |= self._eval(kw.value, ctx)
        if isinstance(call.func, ast.Attribute):
            recv = call.func.value
            if isinstance(recv, ast.Name) and recv.id in ctx.types:
                # A tracked value object (a constructed model) writes its own
                # state into the bag. A plain list/dict receiver would be
                # *reading* the bag (``acc.extend(bag)``), so it is excluded.
                out |= set(ctx.env.get(recv.id, ()))
            else:
                # Inline ``Model(field=<unordered>).dump(bag)``: attribute the
                # constructed object's field taint directly.
                out |= self._ctor_field_taint(recv, ctx)
                # A model built in a *different* method/function than the dump
                # still carries its fields' instability to the bag.
                out |= self._cross_boundary_receiver_taint(recv, ctx)
        return out

    def _cross_boundary_receiver_taint(
        self, recv: ast.AST, ctx: Context
    ) -> Set[Origin]:
        """Taint of a ``<recv>.dump(bag)`` receiver built in another method/function.

        Bridges the construct-here / dump-there separation for the ``DatabagModel``
        idiom, gated to *known value objects* so a plain list/dict receiver that
        merely reads the bag is never tainted:

        * ``self.<attr>.dump(bag)`` where ``self.<attr> = Model(...)`` was recorded
          elsewhere -- consult instance-attribute provenance (the attr is known to
          hold a constructed model via ``class_attr_types``);
        * ``self._build().dump(bag)`` where the builder returns a value object --
          union its ``returns_field_origins`` summary.
        """
        if (
            isinstance(recv, ast.Attribute)
            and isinstance(recv.value, ast.Name)
            and recv.value.id in ("self", "cls")
            and ctx.cls
            and recv.attr in self.engine.class_attr_types.get(ctx.cls, {})
        ):
            return self._eval(recv, ctx)
        if isinstance(recv, ast.Call):
            out: Set[Origin] = set()
            for fi in self._resolve_methods(recv, ctx):
                for origins in fi.returns_field_origins.values():
                    out |= set(origins)
            return out
        return set()

    def _writer_content_node(self, call: ast.Call, ctx: Context) -> ast.AST:
        """The node that *names* the content a writer puts into a databag.

        For ``writer(<databag>, payload)`` / ``model.dump(<databag>)`` the
        offending value is a non-databag argument (the payload) or, for the
        ``model.dump(bag)`` idiom, the receiver model -- never the databag
        argument. Naming the databag (e.g. ``relation`` in
        ``model.dump(relation.data[app])``) would point at the *destination*, not
        the unstable value, so it is deliberately excluded here.
        """
        for arg in call.args:
            if isinstance(arg, ast.Starred) or self._is_databag_object(arg, ctx):
                continue
            return arg
        for kw in call.keywords:
            if kw.value is None or self._is_databag_object(kw.value, ctx):
                continue
            return kw.value
        if isinstance(call.func, ast.Attribute):
            return call.func.value
        return call

    # -- expression scan (forwarding + hash sinks) -------------------------

    def _scan_expr(self, node: ast.expr, ctx: Context, handler: Handler) -> None:
        """Report forwarding sinks (calls into dangerous params) inside an expr."""
        for sub in ast.walk(node):
            if not isinstance(sub, ast.Call):
                continue
            name = astutils.final_attr(sub.func)
            if name in HASH_CALLS and sub.args:
                origins = self._eval(sub.args[0], ctx)
                # The *builtin* ``hash()`` is PYTHONHASHSEED-salted for str/bytes
                # content, so it returns a different int every process -- every Juju
                # hook is a fresh interpreter -- even when the content is identical.
                # A hash that is persisted and compared across reconciles then trips
                # every time (``hash(json.dumps(x))`` is the classic "I sorted it so
                # it's stable" trap). hashlib (sha256/md5/...) is stable, so this
                # applies only to ``hash`` and only when a string is provably hashed.
                # A ``saltedhash`` origin is its own nondeterministic flavor: the
                # instability is the *hash call itself*, not any single value inside
                # it, so the finding is reported against the hash, not a content var.
                if name == "hash" and astutils.contains_provable_string(sub.args[0]):
                    origins = origins | {"saltedhash"}
                if origins:
                    handler.sink(
                        sub,
                        origins,
                        "direct",
                        "content hash (change-detection gate)",
                        sub.args[0],
                        "hash",
                    )
                self._gap_check(sub.args[0], "hash", ctx, handler)
            fwrite = astutils.file_write_args(sub)
            if fwrite is not None:
                fmethod, fwargs = fwrite
                origins = set()
                for content in fwargs:
                    origins |= self._eval(content, ctx)
                if origins:
                    handler.sink(
                        sub,
                        origins,
                        "direct",
                        FILE_WRITE_DESCS.get(fmethod, "on-disk file write"),
                        fwargs[0],
                        "file",
                    )
                if fwargs:
                    self._gap_check(fwargs[0], "file", ctx, handler)
            pwrite = astutils.plan_write_args(sub)
            if pwrite is not None:
                _, pwargs = pwrite
                origins = set()
                for content in pwargs:
                    origins |= self._eval(content, ctx)
                # A pebble layer is compared structurally by the daemon, not byte-
                # diffed: mapping-key disorder is laundered (like a key-sorting
                # serializer), so only order-sensitive / volatile instability flaps
                # the plan. Filter the content taint accordingly before reporting.
                origins = self.engine.survives_structural_compare(origins)
                if origins:
                    handler.sink(
                        sub,
                        origins,
                        "direct",
                        PLAN_WRITE_DESC,
                        pwargs[0],
                        "plan",
                    )
                if pwargs:
                    self._gap_check(pwargs[0], "plan", ctx, handler)
            swrite = astutils.secret_write_args(sub)
            if swrite is not None:
                _, swargs = swrite
                origins = set()
                for content in swargs:
                    origins |= self._eval(content, ctx)
                # A Juju secret value is byte-compared like a databag value: an
                # unstable ``json.dumps(<unordered>)`` string churns revisions. Use
                # raw (not structural) survival, matching the databag write.
                if origins:
                    handler.sink(
                        sub,
                        origins,
                        "direct",
                        SECRET_WRITE_DESC,
                        swargs[0],
                        "secret",
                    )
                if swargs:
                    self._gap_check(swargs[0], "secret", ctx, handler)
            margs = None
            if (
                isinstance(sub.func, ast.Attribute)
                and sub.func.attr in MAPPING_WRITE_METHODS
                and self._is_databag_object(sub.func.value, ctx)
            ):
                # ``<databag>.update(...)`` / ``.setdefault(...)`` -- the databag may
                # be the literal ``relation.data[entity]``, a tracked local, or a
                # property/accessor that resolves to one (see flaplint.databag).
                margs = list(sub.args)
            if margs is not None:
                origins = set()
                for arg in margs:
                    origins |= self._eval(arg, ctx)
                if origins:
                    handler.sink(
                        sub,
                        origins,
                        "direct",
                        "relation databag",
                        margs[0],
                        "databag",
                    )
                if margs:
                    self._gap_check(margs[0], "databag", ctx, handler)
            elif any(
                self._is_databag_object(a, ctx)
                for a in (*sub.args, *(kw.value for kw in sub.keywords))
            ):
                # A databag handed to a writer call (``model.dump(bag)``): the bag
                # is the destination, so attribute the churn to the content the
                # writer puts into it (sibling args / a value-object receiver).
                origins = self._escape_content_taint(sub, ctx)
                if origins:
                    # The bag argument pins the *write* line -- for a multi-line
                    # ``Model(\n...\n).dump(bag)`` that is the ``.dump(bag)`` line,
                    # not the outer call's start line -- so the downstream sink
                    # pointer lands on the actual write.
                    bag_node = next(
                        (
                            a
                            for a in (*sub.args, *(kw.value for kw in sub.keywords))
                            if self._is_databag_object(a, ctx)
                        ),
                        sub,
                    )
                    handler.sink(
                        sub,
                        origins,
                        "direct",
                        "relation databag (written by callee)",
                        self._writer_content_node(sub, ctx),
                        "databag",
                        write_node=bag_node,
                    )
            save_content = astutils.databag_save_content(sub)
            if save_content is not None:
                # ``relation.save(obj, entity)`` serialises ``obj``'s fields into
                # ``relation.data[entity]``: the churn comes from ``obj`` (and,
                # for the inline ``relation.save(Model(field=<unordered>), app)``
                # idiom, from its constructor fields).
                origins = self._eval(save_content, ctx) | self._ctor_field_taint(
                    save_content, ctx
                )
                if origins:
                    handler.sink(
                        sub,
                        origins,
                        "direct",
                        "relation databag (ops save)",
                        save_content,
                        "databag",
                    )
            for fi in self._resolve_methods(sub, ctx):
                if not fi.dangerous:
                    continue
                for didx, arg in astutils.map_call_args(sub, fi).items():
                    if didx in fi.dangerous:
                        origins = self._eval(arg, ctx)
                        if origins:
                            # The param may reach several Juju stores (a databag
                            # *and* a secret); emit one finding per store so each
                            # churn source is surfaced, each pointing at that store's
                            # actual write inside the callee (not the call site).
                            for st in sorted(
                                fi.dangerous_sinks.get(didx) or {"databag"}
                            ):
                                site = fi.dangerous_sites.get(didx, {}).get(st)
                                wn = (
                                    _RemoteSite(site[0], site[1], site[2])
                                    if site else None
                                )
                                handler.sink(
                                    sub,
                                    origins,
                                    "via",
                                    f"{fi.name}() parameter '{fi.params[didx]}'",
                                    arg,
                                    st,
                                    write_node=wn,
                                )

    # -- statement walk -----------------------------------------------------

    def _visit_body(self, body: List[ast.stmt], ctx: Context, handler: Handler) -> None:
        for stmt in body:
            self._visit_stmt(stmt, ctx, handler)

    def _visit_stmt(self, stmt: ast.stmt, ctx: Context, handler: Handler) -> None:
        # Nested functions / classes are analyzed as their own FuncInfo.
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return

        if isinstance(stmt, ast.Assign):
            self._visit_assign(stmt, ctx, handler)
            return

        if isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            self._visit_ann_assign(stmt, ctx, handler)
            return

        if isinstance(stmt, ast.AugAssign):
            self._scan_expr(stmt.value, ctx, handler)
            if isinstance(stmt.target, ast.Name):
                ctx.env[stmt.target.id] = set(
                    ctx.env.get(stmt.target.id, ())
                ) | self._eval(stmt.value, ctx)
            return

        if isinstance(stmt, ast.Expr):
            self._visit_expr_stmt(stmt, ctx, handler)
            return

        if isinstance(stmt, ast.Return) and stmt.value is not None:
            self._scan_expr(stmt.value, ctx, handler)
            # ``return yaml.dump(x)`` / ``return json.dumps(x)`` is a config-render
            # boundary: the rendered blob escapes to a consumer that diffs it, so
            # instability surviving the serializer's own key-sorting (an
            # ``element`` pick or a ``volatile`` value) flaps the output. The
            # taint engine launders benign key-order-only (``local``) instability
            # to an empty set here, so this never fires on it.
            v = stmt.value
            if (
                isinstance(v, ast.Call)
                and astutils.final_attr(v.func) in RENDER_SERIALIZERS
            ):
                origins = self._eval(v, ctx)
                if origins:
                    handler.sink(
                        v,
                        origins,
                        "direct",
                        "config rendered for the workload",
                        v.args[0] if v.args else v,
                        # A ``return yaml.dump(x)`` renders a config blob that
                        # escapes to *some* consumer (a workload push, a file, a
                        # databag) which diffs it -- flaplint can't prove which,
                        # so it's a "render" boundary, not a claimed on-disk file.
                        "render",
                    )
                if v.args:
                    self._gap_check(v.args[0], "render", ctx, handler)
            handler.ret(self._eval(stmt.value, ctx))
            handler.ret_fields(self._returned_field_map(stmt.value, ctx))
            if isinstance(stmt.value, (ast.Tuple, ast.List)):
                # ``return ",".join(rw), ",".join(ro), ...`` -- record each position's
                # taint so a caller unpacking the result binds it element-wise.
                handler.ret_tuple(
                    [self._eval(e, ctx) for e in stmt.value.elts]
                )
            return

        if isinstance(stmt, ast.For):
            self._visit_for(stmt, ctx, handler)
            return

        if isinstance(stmt, ast.If):
            self._visit_if(stmt, ctx, handler)
            return

        for guard in astutils.guards(stmt):
            self._scan_expr(guard, ctx, handler)
        for inner in astutils.child_bodies(stmt):
            self._visit_body(inner, ctx, handler)

    # -- statement kinds ----------------------------------------------------

    def _visit_assign(self, stmt: ast.Assign, ctx: Context, handler: Handler) -> None:
        self._scan_expr(stmt.value, ctx, handler)
        self._absorb_into_constructor(stmt.value, ctx)
        taint = self._eval(stmt.value, ctx) | self._ctor_field_taint(stmt.value, ctx)
        for tgt in stmt.targets:
            if self._is_databag_target(tgt, ctx):
                if taint:
                    handler.sink(stmt, taint, "direct", "relation databag", stmt.value)
                self._gap_check(stmt.value, "databag", ctx, handler)
        for tgt in stmt.targets:
            if isinstance(tgt, ast.Name):
                ctx.env[tgt.id] = set(taint)
                self._record_type(tgt, stmt.value, ctx)
                self._record_databag_alias(tgt, stmt.value, ctx)
                self._record_field_taint(tgt.id, stmt.value, ctx)
                self._record_dict_key_taint(tgt.id, stmt.value, ctx)
            elif isinstance(tgt, (ast.Tuple, ast.List)):
                self._unpack_assign(tgt, stmt.value, ctx)
            elif self._is_databag_target(tgt, ctx):
                continue  # the databag write is reported as a sink above
            else:
                # ``obj.attr = expr`` records the field's taint under the compound
                # ``obj.attr`` key (set even when clean, to clear a stale value), so
                # a later read-back of that field is field-sensitive.
                path = astutils.attr_path(tgt)
                if path is not None:
                    ctx.env[path] = set(taint)
                    # ``obj.attr = {const-key: expr}`` -- per-key provenance, so a
                    # later ``obj.attr['key']`` read is field-sensitive.
                    self._record_dict_key_taint(path, stmt.value, ctx)
                # ``self.<attr> = expr``: also carry the taint class-wide, so a read
                # in another method (the build-in-__init__, read-in-handler idiom)
                # stays field-sensitive across the method boundary.
                self._record_instance_attr(tgt, taint, ctx)
                self._record_instance_attr_dict_keys(tgt, stmt.value, ctx)
                # ``container[k] = <unordered>`` / ``obj.attr = <unordered>``: the
                # element write also taints the enclosing container, so a later
                # serialization of the *whole* container is order-unstable.
                if taint:
                    base = astutils.root_name(tgt)
                    if base is not None and base not in ("self", "cls"):
                        ctx.env[base] = set(ctx.env.get(base, ())) | set(taint)

    def _unpack_assign(
        self, target: ast.AST, value: ast.AST, ctx: Context
    ) -> None:
        """Bind a tuple/list unpacking target ``a, b, _ = <value>`` *per position*.

        Without this the instability of a returned tuple (``get_cluster_endpoints``
        returning three ``",".join(set)`` strings) never reaches ``rw`` / ``ro``, so
        the later ``set_endpoints(rw)`` databag write reads clean. Precision is by
        position so a stable element unpacked next to an unstable one stays clean
        (``cert, key = get_assigned_certificate()`` -- the ``key`` must not inherit the
        certificate's SAN instability). Positions come from a matching-arity literal
        RHS, or a resolved call's ``returns_tuple_origins`` summary; anything else
        leaves the targets clean rather than smearing the whole taint across them.
        """
        elts = target.elts
        if any(isinstance(e, ast.Starred) for e in elts):
            positions: "Optional[List[Set[Origin]]]" = None
        elif isinstance(value, (ast.Tuple, ast.List)) and len(value.elts) == len(elts):
            positions = [
                self._eval(v, ctx) | self._ctor_field_taint(v, ctx) for v in value.elts
            ]
        elif isinstance(value, ast.Call):
            positions = next(
                (
                    [set(s) for s in fi.returns_tuple_origins]
                    for fi in self._resolve_methods(value, ctx)
                    if fi.returns_tuple_origins is not None
                    and len(fi.returns_tuple_origins) == len(elts)
                ),
                None,
            )
        else:
            positions = None
        for i, te in enumerate(elts):
            origins = positions[i] if positions is not None else set()
            if isinstance(te, ast.Name):
                ctx.env[te.id] = set(origins)
            elif isinstance(te, (ast.Tuple, ast.List)):
                sub = (
                    value.elts[i]
                    if isinstance(value, (ast.Tuple, ast.List)) and i < len(value.elts)
                    else value
                )
                self._unpack_assign(te, sub, ctx)

    def _visit_ann_assign(
        self, stmt: ast.AnnAssign, ctx: Context, handler: Handler
    ) -> None:
        self._scan_expr(stmt.value, ctx, handler)
        if stmt.value is not None:
            self._absorb_into_constructor(stmt.value, ctx)
        if self._is_databag_target(stmt.target, ctx):
            origins = self._eval(stmt.value, ctx)
            if origins:
                handler.sink(stmt, origins, "direct", "relation databag", stmt.value)
        if isinstance(stmt.target, ast.Name):
            ctx.env[stmt.target.id] = self._eval(stmt.value, ctx) | self._ctor_field_taint(
                stmt.value, ctx
            )
            self._record_type(stmt.target, stmt.value, ctx)
            self._record_databag_alias(stmt.target, stmt.value, ctx)
            self._record_field_taint(stmt.target.id, stmt.value, ctx)
            self._record_dict_key_taint(stmt.target.id, stmt.value, ctx)
        elif stmt.value is not None:
            path = astutils.attr_path(stmt.target)
            if path is not None:
                ctx.env[path] = self._eval(stmt.value, ctx)
                self._record_dict_key_taint(path, stmt.value, ctx)
            self._record_instance_attr(
                stmt.target, self._eval(stmt.value, ctx), ctx
            )
            self._record_instance_attr_dict_keys(stmt.target, stmt.value, ctx)

    def _visit_expr_stmt(self, stmt: ast.Expr, ctx: Context, handler: Handler) -> None:
        call = stmt.value
        if (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and call.func.attr == "sort"
            and isinstance(call.func.value, ast.Name)
        ):
            ctx.env[call.func.value.id] = set()  # x.sort() sanitizes in place
            return
        # Populating a known ``set`` variable (``s.add(x)`` / ``s.update(x)``) makes
        # it a (possibly non-empty) set, whose iteration order is hash-seeded and so
        # unstable -- independent of what was inserted. Mark it ``local`` here so a
        # ``s = set(); for ...: s.update(...); return s`` (or a later serialization)
        # is caught even when the empty ``set()`` was stable and the loop source was
        # ordered. The mutation call anchors the born-site.
        if (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and call.func.attr in SET_MUTATION_METHODS
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id in ctx.set_vars
        ):
            name = call.func.value.id
            ctx.env[name] = set(ctx.env.get(name, ())) | {("local", None, call, None)}
        # Mapping-merge mutation on a plain dict variable: ``certs.update(other)``
        # / ``certs.setdefault(k, v)`` merges another mapping's items -- and its
        # key-insertion order -- into ``certs``, so ``certs`` inherits the
        # argument's instability (a later ``json.dumps(certs)`` without
        # ``sort_keys`` then flaps). Gated to a *known dict* (``dict_vars``) so it
        # never absorbs onto an arbitrary ``.update()`` receiver; the loop form is
        # already covered by ``loop_accumulators``, this is the same idiom outside a
        # loop (the ``certs.update(self._get_certs_from_relation())`` shape).
        if (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and call.func.attr in MAPPING_MERGE_METHODS
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id in ctx.dict_vars
        ):
            name = call.func.value.id
            argtaint: Set[Origin] = set()
            for arg in call.args:
                argtaint |= self._eval(arg, ctx)
            if argtaint:
                ctx.env[name] = set(ctx.env.get(name, ())) | argtaint
        # Builder mutation: ``obj.add(<unordered>)`` on a locally-constructed
        # object absorbs the argument's instability into the object's state, so a
        # later ``obj.as_dict()`` / ``obj.render()`` is order-unstable. Gated to a
        # *constructed* object (``ctx.types``): broadening to any ``list.append``
        # pushes a *nested* field's instability up onto the container, which then
        # mis-fires when that container is iterated through an order-preserving
        # pass-through (``_dedupe_list``) -- flaplint can't tell element-order
        # instability from nested-content instability, so both read as itercaller.
        if (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id in ctx.types
        ):
            recv = call.func.value.id
            # When the receiver's *concrete* class is known and its setter is in the
            # registry, trust the per-parameter absorb summary instead of blanket-
            # tainting from every argument. A setter that *launders* its argument
            # (``def add(self, k, v): self._c[k] = sorted(v)``) leaves that param out
            # of ``absorbs``, so a local ``b.add(some_set)`` into a sorting builder no
            # longer taints ``b`` -- the local analogue of the ``_absorb_into_callee``
            # gate. Only the args the summary marks absorbed contribute. The receiver
            # is a locally-constructed object, so ``infer_class`` is exact (not the
            # imperfect ``self.<member>`` typing that made a broad union worth keeping);
            # if the class is known but its setter isn't registered (defined elsewhere /
            # unanalyzed), fall back to the broad match for recall.
            recv_cls = astutils.infer_class(call.func.value, ctx.types)
            chain = self.engine._class_chain(recv_cls) if recv_cls else None
            own_methods = (
                [fi for fi in self.registry.get(call.func.attr, [])
                 if fi.class_name in chain]
                if chain is not None else []
            )
            argtaint: Set[Origin] = set()
            if own_methods:
                absorbed = {pidx for fi in own_methods for pidx in fi.absorbs}
                for i, arg in enumerate(call.args):
                    # bound call arg ``i`` maps to param ``i + 1`` (param 0 is ``self``).
                    if (i + 1) in absorbed:
                        argtaint |= self._eval(arg, ctx)
            else:
                for arg in call.args:
                    argtaint |= self._eval(arg, ctx)
            if argtaint:
                ctx.env[recv] = set(ctx.env.get(recv, ())) | argtaint
        # Nested container-element mutation: ``template["sinks"].update(x)`` /
        # ``buckets[k].append(x)`` writes ``x`` into an element of the root
        # container, so the root inherits ``x``'s taint -- a later
        # ``yaml.dump(template)`` is then order-unstable. The subscript receiver is
        # what marks this as a container (you can't subscript-then-mutate a scalar),
        # so no ``ctx.types`` gate is needed; the loop form is already covered by
        # ``loop_accumulators``, this is the same idiom outside a loop.
        elif (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and call.func.attr in ACCUMULATOR_METHODS
            and isinstance(call.func.value, ast.Subscript)
        ):
            root = astutils.root_name(call.func.value)
            if root is not None and root not in ("self", "cls"):
                argtaint = set()
                for arg in call.args:
                    argtaint |= self._eval(arg, ctx)
                if argtaint:
                    ctx.env[root] = set(ctx.env.get(root, ())) | argtaint
        self._absorb_into_callee(call, ctx, handler)
        self._scan_expr(stmt.value, ctx, handler)

    def _absorb_into_callee(self, call: ast.AST, ctx: Context, handler: Handler) -> None:
        """Cross-object config-builder chain: a setter call that stores an unstable
        argument into the *callee's* own state taints that callee class's attribute.

        ``self.config.add_component(..., {"endpoint": <unstable>})`` resolves to
        ``ConfigBuilder.add_component``, whose summary says it absorbs param 3 into
        ``self._config`` (:attr:`FuncInfo.absorbs`). We record the argument's taint on
        ``instance_attr_taint[ConfigBuilder]["_config"]`` -- the same class-level map
        the within-class barrier uses -- so ``ConfigBuilder.build()`` (which returns
        ``yaml.safe_dump(self._config)``) surfaces it, and a caller writing
        ``config_manager.config.build()`` to a file is flagged. The fixed point re-runs
        on the resulting ``instance_attr_changed``.
        """
        if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)):
            return
        # When the receiver's class is known (a ``self.<member>`` builder), only that
        # class's setter absorbs -- so two builders that both define ``add_component``
        # don't cross-contaminate. Unknown receiver keeps the broad match (an absorb is
        # a no-op unless the arg is actually unstable, so over-matching is harmless).
        recv_cls = astutils.infer_class(
            call.func.value, ctx.types
        ) or self.engine._receiver_class(call.func.value, ctx.cls)
        chain = self.engine._class_chain(recv_cls) if recv_cls else None
        for fi in self._resolve_methods(call, ctx):
            if not fi.absorbs or not fi.class_name:
                continue
            if chain is not None and fi.class_name not in chain:
                continue
            # The builder's real render-write (byte-sink type + location), or ``None``
            # if its state is never rendered to a byte-sink (then the setter is not a
            # contract sink -- Path B stays silent).
            render = self.engine.render_sites.get(fi.class_name)
            for pidx, attr in fi.absorbs.items():
                # param 0 is ``self``; a bound-call arg N maps to param N+1.
                argpos = pidx - 1
                if argpos < 0 or argpos >= len(call.args):
                    continue
                if isinstance(call.args[argpos], ast.Starred):
                    continue
                argtaint = self._eval(call.args[argpos], ctx)
                if not argtaint:
                    continue
                # (A) Concrete surfacing: record the argument's *concrete* instability
                # on the callee class's attribute so its state-returning method
                # (``build()``) surfaces it -- catching an unstable value born in the
                # same object as the absorb. A bare ``param`` origin is dropped: a keyed
                # lookup that merely touches a param set (``secrets.get(id).get(k)``) is
                # order-stable, so forwarding the param would over-taint the absorb.
                resolved = {
                    self._resolve_attr_origin(o, ctx)
                    for o in argtaint
                    if not (isinstance(o, tuple) and o[0] in ("param", "iterparam"))
                }
                self.engine.record_instance_attr(
                    fi.class_name, attr, {o for o in resolved if o}
                )
                # (B) Param boundary: an ``iterparam`` argument is *positionally
                # derived from this helper's parameter* (``enumerate(endpoints)`` ->
                # ``endpoint["url"]``) -- order-dependent, unlike a field-sensitive
                # ``param``. Absorbed into a builder that renders to a byte-sink, the
                # parameter reaches that sink: mark it ``dangerous`` with the *real*
                # sink type + location so a caller passing a concrete-unstable value
                # (``add_log_forwarding(loki_endpoints)``) is flagged -- the caller-side
                # signal, which unlike the helper-side ``iter_params`` contract is not
                # silenced by an ``endpoints: List[dict]`` annotation (a list the caller
                # nonetheless built from unordered data). The ``render`` gate keeps a
                # private, never-rendered cache from becoming a sink; the ``iterparam``
                # gate keeps a keyed ``param`` lookup (``secrets.get(id).get(k)``) out.
                if render is not None:
                    param_origins = {
                        ("param", o[1], None, None)
                        for o in argtaint
                        if isinstance(o, tuple) and o[0] == "iterparam"
                    }
                    if param_origins:
                        sink_type, site = render[0], render[1:]
                        handler.sink(
                            call, param_origins, "via", "config builder",
                            None, sink_type=sink_type, write_node=call,
                            sink_site=site,
                        )


    def _visit_if(self, stmt: ast.If, ctx: Context, handler: Handler) -> None:
        """Walk an ``if``, applying ``isinstance``-to-ordered narrowing to the body.

        ``if isinstance(raw, list): return [x for x in raw]`` only iterates ``raw``
        when it is provably a list, so a caller passing a set never reaches it -- the
        contract-boundary "might be unordered" worry is resolved. Inside the guarded
        body we therefore drop ``raw``'s *parameter* taint (the caller-uncertainty),
        but keep any concrete instability: ``isinstance(x, list)`` proves the *type*,
        not the order, so a genuinely unstable ``list(some_set)`` must still flag.
        """
        self._scan_expr(stmt.test, ctx, handler)
        narrowed = astutils.isinstance_ordered_name(stmt.test, ISINSTANCE_ORDERED_TYPES)
        if narrowed is not None and narrowed in ctx.env:
            saved = ctx.env[narrowed]
            kept = {o for o in saved if not (isinstance(o, tuple) and o[0] == "param")}
            ctx.env[narrowed] = kept
            self._visit_body(stmt.body, ctx, handler)
            ctx.env[narrowed] = saved
        else:
            self._visit_body(stmt.body, ctx, handler)
        self._visit_body(stmt.orelse, ctx, handler)

    def _visit_for(self, stmt: ast.For, ctx: Context, handler: Handler) -> None:
        iter_taint = self._eval(stmt.iter, ctx)
        self._scan_expr(stmt.iter, ctx, handler)
        targets = [t.id for t in ast.walk(stmt.target) if isinstance(t, ast.Name)]
        container = astutils.root_name(stmt.iter)
        # ``for i, x in enumerate(<unordered>)``: enumerate materialises the source
        # into a *positional* sequence, so each ``x`` is the element at position ``i``.
        # When ``i`` forms a stable key (a ``{i}.crt`` filename, a ``.../{idx}``
        # component name) and ``x`` is written under it, the value-under-each-position
        # flaps run-to-run -- order a key-sorting serializer can't launder. Seed the
        # value target(s) as the key-sort-resistant iteration flavor (``local`` ->
        # ``itercaller``, born at the enumerate where ``sorted()`` belongs) so a sink on
        # ``x`` *inside* the loop is caught -- the direct-write case the accumulator
        # rule below doesn't cover -- and consistently with how an accumulator built
        # from the same loop is already reported. The index target (the first) stays
        # clean: ``0, 1, 2`` don't move.
        enum_arg = astutils.enumerate_arg(stmt.iter)
        if (
            enum_arg is not None
            and isinstance(stmt.target, ast.Tuple)
            and len(stmt.target.elts) >= 2
        ):
            # ``e`` is the *element at position idx*. A concrete unordered source ->
            # ``element`` (the unambiguous value-position pick, so a field read
            # ``e["url"]`` inherits it via the subscript rule). A *parameter* source ->
            # ``iterparam``: enumerating a param materialises it into positional
            # bindings, so the value under each index is a contract-boundary pick the
            # caller controls -- not dropped (that was a false negative), but a medium
            # contract finding, not a concrete flap at the helper. The raw ``param``
            # origin is filtered so a plain ``param`` still means "a value the caller
            # passes", distinct from "positionally derived from the param".
            raw = self._eval(enum_arg, ctx)
            pick = _as_value_position(raw, stmt.iter)
            for o in raw:
                if isinstance(o, tuple) and o[0] == "param":
                    pick.add(("iterparam", o[1], None, stmt.iter))
            pick = {o for o in pick if not (isinstance(o, tuple) and o[0] == "param")}
            if pick:
                for value_elt in stmt.target.elts[1:]:
                    for nm in (
                        t.id for t in ast.walk(value_elt) if isinstance(t, ast.Name)
                    ):
                        ctx.env[nm] = set(ctx.env.get(nm, ())) | set(pick)
        for inner in astutils.child_bodies(stmt):
            self._visit_body(inner, ctx, handler)
        # If the loop iterates an unordered source, every accumulator it fills
        # inherits that instability for the rest of the function. A *list*
        # accumulator (``acc.append(x)``) bakes the iteration order into element
        # order, so it is promoted ``local`` -> ``itercaller`` exactly like the
        # equivalent comprehension -- otherwise a key-sorting serializer
        # (``yaml.dump``) would launder the raw ``local`` and miss the flap. A
        # ``set``/``dict`` accumulator keeps the raw taint (its disorder is
        # key-order, which key-sorting legitimately launders).
        if iter_taint:
            seq_taint = _promote_to_sequence(iter_taint, stmt.iter)
            list_accs = astutils.list_loop_accumulators(stmt)
            for acc in astutils.loop_accumulators(stmt):
                add = seq_taint if acc in list_accs else iter_taint
                ctx.env[acc] = set(ctx.env.get(acc, ())) | set(add)
        # Loop-variable aliasing: ``for x in c: x[k] = <unordered>`` mutates an
        # element of ``c`` in place, so ``c`` itself becomes order-unstable.
        if container is not None and container not in ("self", "cls"):
            for tname in targets:
                tt = ctx.env.get(tname)
                if tt:
                    ctx.env[container] = set(ctx.env.get(container, ())) | set(tt)
