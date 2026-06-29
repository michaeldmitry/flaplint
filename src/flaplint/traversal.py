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
    BUILTIN_COLLECTION_METHODS,
    FILE_WRITE_DESCS,
    HASH_CALLS,
    ISINSTANCE_ORDERED_TYPES,
    MAPPING_WRITE_METHODS,
    MODEL_SERIALIZERS,
    NONSORTING_SERIALIZERS,
    ORDERED_ANNOTATIONS,
    PLAN_WRITE_DESC,
    PROPAGATE_CALLS,
    RENDER_SERIALIZERS,
    SANITIZER_CALLS,
    STR_SPLIT_METHODS,
    TEMPLATE_RENDER_METHODS,
    UNORDERED_ATTRS,
    UNORDERED_CALLS,
    VOLATILE_CALLS,
)
from . import databag
from .handlers import Handler
from .model import FuncInfo, Origin, Registry
from .taint import TaintEngine


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
    | {"dumps", "dump", "safe_dump"}
)


@dataclass
class Context:
    """Mutable per-function analysis state threaded through the walk."""

    env: Dict[str, Set[Origin]]
    types: Dict[str, str] = field(default_factory=dict)  # variable -> class name
    cls: Optional[str] = None  # enclosing class of the analyzed function
    #: local variable -> its databag-provenance kind (relation/relation_data/databag)
    databag_kinds: Dict[str, str] = field(default_factory=dict)
    #: this function's parameter names (by index) and their annotations -- used by
    #: the ``--explain-gaps`` scan to grade an untraced-parameter blind spot.
    params: List[str] = field(default_factory=list)
    param_annotations: Dict[str, Optional[str]] = field(default_factory=dict)


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
        )
        self._visit_body(getattr(fi.node, "body", []), ctx, handler)

    # -- helpers ------------------------------------------------------------

    def _eval(self, node, ctx: Context) -> Set[Origin]:
        return self.engine.eval(node, ctx.env, ctx.cls)

    def _resolve_methods(self, call: ast.Call, ctx: Context) -> List[FuncInfo]:
        """Candidate definitions for a call, narrowed by receiver class if known."""
        name = astutils.final_attr(call.func)
        candidates = self.registry.get(name or "", [])
        if isinstance(call.func, ast.Attribute):
            cls = astutils.infer_class(call.func.value, ctx.types)
            if cls:
                matched = [fi for fi in candidates if fi.class_name == cls]
                if matched:
                    return matched
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
        if cls:
            ctx.types[target.id] = cls
        elif target.id in ctx.types:
            del ctx.types[target.id]

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
        if isinstance(value, ast.Call) and astutils.ctor_class(value) is not None:
            for kw in value.keywords:
                if kw.arg is None or kw.value is None:
                    continue
                t = self._eval(kw.value, ctx)
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
        # Content scan: does the *whole* value depend on an untraced parameter? File/
        # plan/hash writes get no caller-contract check, so an unordered caller would
        # slip through. Computed from the content's taint (not a textual name match),
        # so a parameter that's already neutralised on the way in -- ``template.format(
        # **ctx)`` (template-ordered) -- is *not* a gap. A parameter the caller already
        # promises to keep ordered (``data: list``/``str``) is the caller's job, not a
        # blind spot, so an ordered annotation is skipped.
        if sink in ("file", "plan", "hash"):
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
                yield content, (
                    f"depends on parameter `{pname}`, not traced to its callers "
                    f"(a {sink} write gets no caller-contract check, so an unordered "
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
        if astutils.ctor_class(value) is None or not isinstance(value, ast.Call):
            return set()
        out: Set[Origin] = set()
        for arg in value.args:
            if isinstance(arg, ast.Starred):
                continue
            out |= self._eval(arg, ctx)
        for kw in value.keywords:
            if kw.value is not None:
                out |= self._eval(kw.value, ctx)
        return out

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
        return out

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
                    handler.sink(
                        sub,
                        origins,
                        "direct",
                        "relation databag (written by callee)",
                        self._writer_content_node(sub, ctx),
                        "databag",
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
                            handler.sink(
                                sub,
                                origins,
                                "via",
                                f"{fi.name}() parameter '{fi.params[didx]}'",
                                arg,
                                "databag",
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
                        "file",
                    )
                if v.args:
                    self._gap_check(v.args[0], "file", ctx, handler)
            handler.ret(self._eval(stmt.value, ctx))
            handler.ret_fields(self._returned_field_map(stmt.value, ctx))
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
            elif self._is_databag_target(tgt, ctx):
                continue  # the databag write is reported as a sink above
            else:
                # ``obj.attr = expr`` records the field's taint under the compound
                # ``obj.attr`` key (set even when clean, to clear a stale value), so
                # a later read-back of that field is field-sensitive.
                path = astutils.attr_path(tgt)
                if path is not None:
                    ctx.env[path] = set(taint)
                # ``container[k] = <unordered>`` / ``obj.attr = <unordered>``: the
                # element write also taints the enclosing container, so a later
                # serialization of the *whole* container is order-unstable.
                if taint:
                    base = astutils.root_name(tgt)
                    if base is not None and base not in ("self", "cls"):
                        ctx.env[base] = set(ctx.env.get(base, ())) | set(taint)

    def _visit_ann_assign(
        self, stmt: ast.AnnAssign, ctx: Context, handler: Handler
    ) -> None:
        self._scan_expr(stmt.value, ctx, handler)
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
        # Builder mutation: ``obj.add(<unordered>)`` on a locally-constructed
        # object absorbs the argument's instability into the object's state, so a
        # later ``obj.as_dict()`` / ``obj.render()`` is order-unstable.
        if (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id in ctx.types
        ):
            recv = call.func.value.id
            argtaint: Set[Origin] = set()
            for arg in call.args:
                argtaint |= self._eval(arg, ctx)
            if argtaint:
                ctx.env[recv] = set(ctx.env.get(recv, ())) | argtaint
        self._scan_expr(stmt.value, ctx, handler)

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
        for inner in astutils.child_bodies(stmt):
            self._visit_body(inner, ctx, handler)
        # If the loop iterates an unordered source, every accumulator it fills
        # inherits that instability for the rest of the function.
        if iter_taint:
            for acc in astutils.loop_accumulators(stmt):
                ctx.env[acc] = set(ctx.env.get(acc, ())) | set(iter_taint)
        # Loop-variable aliasing: ``for x in c: x[k] = <unordered>`` mutates an
        # element of ``c`` in place, so ``c`` itself becomes order-unstable.
        if container is not None and container not in ("self", "cls"):
            for tname in targets:
                tt = ctx.env.get(tname)
                if tt:
                    ctx.env[container] = set(ctx.env.get(container, ())) | set(tt)
