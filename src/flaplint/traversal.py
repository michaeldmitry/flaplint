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
from .constants import FILE_WRITE_DESCS, HASH_CALLS, RENDER_SERIALIZERS
from .handlers import Handler
from .model import FuncInfo, Origin, Registry
from .taint import TaintEngine


@dataclass
class Context:
    """Mutable per-function analysis state threaded through the walk."""

    env: Dict[str, Set[Origin]]
    types: Dict[str, str] = field(default_factory=dict)  # variable -> class name
    cls: Optional[str] = None  # enclosing class of the analyzed function
    databags: Set[str] = field(default_factory=set)  # locals aliased to a databag


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
        env: Dict[str, Set[Origin]] = {
            pname: {("param", idx)} for idx, pname in enumerate(fi.params)
        }
        ctx = Context(env=env, types={}, cls=fi.class_name)
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
        """Track ``b = relation.data[app]`` so later ``b.update(...)`` is a sink."""
        if not isinstance(target, ast.Name):
            return
        if astutils.databag_expr(value):
            ctx.databags.add(target.id)
        else:
            ctx.databags.discard(target.id)

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
            if isinstance(arg, ast.Starred) or astutils.is_databag_value(
                arg, ctx.databags
            ):
                continue
            out |= self._eval(arg, ctx)
        for kw in call.keywords:
            if kw.value is None or astutils.is_databag_value(kw.value, ctx.databags):
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
            if isinstance(arg, ast.Starred) or astutils.is_databag_value(
                arg, ctx.databags
            ):
                continue
            return arg
        for kw in call.keywords:
            if kw.value is None or astutils.is_databag_value(kw.value, ctx.databags):
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
            margs = astutils.databag_mutation_args(sub, ctx.databags)
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
            elif any(
                astutils.is_databag_value(a, ctx.databags)
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
            handler.ret(self._eval(stmt.value, ctx))
            return

        if isinstance(stmt, ast.For):
            self._visit_for(stmt, ctx, handler)
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
            if astutils.is_databag_target(tgt, ctx.databags) and taint:
                handler.sink(stmt, taint, "direct", "relation databag", stmt.value)
        for tgt in stmt.targets:
            if isinstance(tgt, ast.Name):
                ctx.env[tgt.id] = set(taint)
                self._record_type(tgt, stmt.value, ctx)
                self._record_databag_alias(tgt, stmt.value, ctx)
            elif taint and not astutils.is_databag_target(tgt, ctx.databags):
                # ``container[k] = <unordered>`` / ``obj.attr = <unordered>``: the
                # element write taints the enclosing container, so a later
                # serialization of the whole container is order-unstable.
                base = astutils.root_name(tgt)
                if base is not None and base not in ("self", "cls"):
                    ctx.env[base] = set(ctx.env.get(base, ())) | set(taint)

    def _visit_ann_assign(
        self, stmt: ast.AnnAssign, ctx: Context, handler: Handler
    ) -> None:
        self._scan_expr(stmt.value, ctx, handler)
        if astutils.is_databag_target(stmt.target, ctx.databags):
            origins = self._eval(stmt.value, ctx)
            if origins:
                handler.sink(stmt, origins, "direct", "relation databag", stmt.value)
        if isinstance(stmt.target, ast.Name):
            ctx.env[stmt.target.id] = self._eval(stmt.value, ctx) | self._ctor_field_taint(
                stmt.value, ctx
            )
            self._record_type(stmt.target, stmt.value, ctx)
            self._record_databag_alias(stmt.target, stmt.value, ctx)

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
