"""Collection pass: build the function registry from a parsed module.

:class:`Collector` is an :class:`ast.NodeVisitor` that records every function and
method as a :class:`~flaplint.model.FuncInfo`, plus the
``self.<attr> = ClassName(...)`` member types used later to resolve property
accesses on stored collaborators.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Optional, Set

from . import astutils
from .constants import (
    ACCUMULATOR_METHODS,
    SEQUENCE_FIELD_ANNOTATIONS,
    UNORDERED_ANNOTATIONS,
    UNORDERED_RETURN_ANNOTATIONS,
)
from .model import FileImports, FuncInfo, Registry


class Collector(ast.NodeVisitor):
    """Populate ``registry`` (and ``attr_types``) from one module AST."""

    def __init__(
        self,
        path: str,
        primary: bool,
        registry: Registry,
        attr_types: Dict[str, Dict[str, str]],
        file_imports: Optional[Dict[str, FileImports]] = None,
        model_seq_fields: Optional[Dict[str, Set[str]]] = None,
        class_set_fields: Optional[Dict[str, Set[str]]] = None,
        class_bases: Optional[Dict[str, List[str]]] = None,
        value_object_fields: Optional[Dict[str, List[str]]] = None,
        ctor_arg_types: Optional[Dict[str, Dict[object, Set[str]]]] = None,
        attr_backrefs: Optional[Dict[str, List[tuple]]] = None,
    ) -> None:
        self.path = path
        self.primary = primary
        self.registry = registry
        self.attr_types = attr_types
        #: callee class name -> {construction-arg key -> set of inferred type names}.
        #: The key is an int (0-based positional index into the *call*'s args) or a
        #: str (keyword name). Filled from every ``ClassName(self, ...)`` /
        #: ``ClassName(ctor_result, ...)`` site so an *unannotated* ``__init__``
        #: parameter can be typed from what it is actually constructed with (the
        #: sub-component-gets-the-charm idiom). Reconciled after all files are read.
        self.ctor_arg_types = ctor_arg_types if ctor_arg_types is not None else {}
        #: class name -> [(attr, param_name)] for ``self.<attr> = <param>`` back-refs
        #: whose param has no (class) annotation, so the type must come from the
        #: construction site above rather than the annotation.
        self.attr_backrefs = attr_backrefs if attr_backrefs is not None else {}
        #: class name -> its base class names (``LokiPushApiConsumer`` ->
        #: ``["ConsumerBase"]``), so a method/property inherited from a base resolves
        #: on a subclass receiver -- the ``loki_consumer.loki_endpoints`` idiom where
        #: the property lives on ``ConsumerBase``.
        self.class_bases = class_bases if class_bases is not None else {}
        #: pydantic-model class name -> sequence-typed field names, so a set
        #: coerced into such a field is promoted ``local`` -> ``itercaller``.
        self.model_seq_fields = model_seq_fields if model_seq_fields is not None else {}
        #: class name -> ``Set``/``frozenset``-typed attribute names, so a read of
        #: ``x.attr`` (where ``x``'s type is known) is treated as unordered -- e.g.
        #: ``event.certificates`` on a ``CertificatesAvailableEvent``.
        self.class_set_fields = class_set_fields if class_set_fields is not None else {}
        #: *value-object* class name -> its declared fields in constructor order
        #: (dataclass / pydantic / NamedTuple). Lets a *positional* construction
        #: (``ScrapeJobContext(job)``) map its args to fields the same way a keyword
        #: one (``ScrapeJobContext(updated_job=job)``) does -- but only for a class
        #: known to be a value bag, so a stateful collaborator built positionally
        #: (``ClusterProvider(frozenset(roles), ...)``) is *not* absorbed.
        self.value_object_fields = (
            value_object_fields if value_object_fields is not None else {}
        )
        self.functions: List[FuncInfo] = []
        self.class_stack: List[str] = []
        #: this file's import aliases, filled as ``import``/``from`` are visited.
        self.imports = FileImports()
        if file_imports is not None:
            file_imports[path] = self.imports

    def visit_Import(self, node: ast.Import) -> None:
        # ``import json as j`` -> modules["j"] = "json"; ``import json`` is identity.
        for alias in node.names:
            self.imports.modules[alias.asname or alias.name] = alias.name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        # ``from uuid import uuid4 as gen`` -> names["gen"] = "uuid4". A bare
        # ``from json import dumps`` records an (harmless) identity mapping.
        for alias in node.names:
            if alias.name != "*":
                self.imports.names[alias.asname or alias.name] = alias.name

    def _add_function(self, node: ast.AST) -> None:
        args = node.args  # type: ignore[attr-defined]
        positional = list(getattr(args, "posonlyargs", [])) + list(args.args)
        ordered = positional + list(args.kwonlyargs)
        params = [a.arg for a in ordered]
        annotations = {
            a.arg: astutils.annotation_root(a.annotation)
            for a in ordered
            if a.annotation
        }
        is_method = bool(params) and params[0] in ("self", "cls")
        decorators = getattr(node, "decorator_list", [])
        is_property = any(
            astutils.final_attr(d) in ("property", "cached_property")
            for d in decorators
        )
        cls_name = self.class_stack[-1] if self.class_stack else None
        fi = FuncInfo(
            name=node.name,  # type: ignore[attr-defined]
            path=self.path,
            node=node,
            params=params,
            param_index={p: i for i, p in enumerate(params)},
            param_annotations=annotations,
            n_positional=len(positional),
            is_method=is_method,
            is_property=is_property,
            class_name=cls_name,
            primary=self.primary,
        )
        # Return-type inference: a ``-> set[str]`` (or frozenset / AbstractSet ...)
        # promises an unordered collection. Trust the annotation the same way a
        # ``: Set`` *parameter* is trusted, so a caller that materialises or
        # serialises the result without ``sorted()`` is caught even when the body is
        # opaque (a cross-object call, an unresolved helper). Seeded once here and
        # only ever *grown* by the summary fixed point (booleans flip once), so it
        # coexists with any body-derived taint. The born-site points at the ``def``
        # so a finding blames the annotated accessor, not the caller's serializer.
        if astutils.annotation_root(
            getattr(node, "returns", None)
        ) in UNORDERED_RETURN_ANNOTATIONS:
            fi.returns_unordered = True
            fi.unordered_site = (self.path, node, fi.name)
        fi.returns_class = astutils.annotation_root(getattr(node, "returns", None))
        if is_method:
            fi.absorbs = self._compute_absorbs(node, fi.param_index)
            fi.returns_self_attrs = self._compute_returns_self_attrs(node)
            fi.returns_self_attr = self._compute_returns_self_attr(node)
        self.registry.setdefault(fi.name, []).append(fi)
        self.functions.append(fi)
        if cls_name:
            # A property that returns a class (``@property def _patroni(self) ->
            # Patroni``) reads like a typed attribute at the use site
            # (``self.charm._patroni.render_file(...)``), so type it as one -- a member
            # chain can then resolve through it. Only when the attribute isn't already
            # typed by an assignment, and only for a capitalised (class) return.
            if (
                is_property
                and fi.returns_class
                and fi.returns_class[:1].isupper()
                and node.name not in self.attr_types.get(cls_name, {})
            ):
                self.attr_types.setdefault(cls_name, {})[node.name] = fi.returns_class
            self._record_member_types(node, cls_name, annotations, params)
        self._record_call_arg_types(node, cls_name or "", annotations)

    @staticmethod
    def _compute_absorbs(node: ast.AST, param_index: Dict[str, int]) -> Dict[int, str]:
        """Parameters this method stores into ``self.<attr>`` state (as a taint container).

        Detects the setter/accumulator shape that makes a class a taint *container*:

        * ``self.<attr> = <v>`` / ``self.<attr>[...] = <v>``  -- attr/subscript-assign;
        * ``self.<attr>.append/extend/update/add/setdefault(<param>)`` -- accumulator.

        The stored value ``<v>`` counts a parameter as absorbed when it *carries* the
        param's content taint without laundering it: the bare param (``= config``), the
        param as an element of a container literal (``= {"cfg": config}``), or wrapped
        in an order-preserving constructor (``= dict(config)``). A launderer
        (``= sorted(config)``) carries nothing. Returns ``{param_index -> attr}``.
        """
        #: order-preserving pass-through constructors -- a param wrapped in one still
        #: flows its (dis)order in; ``sorted`` is deliberately absent.
        wrappers = {"dict", "list", "tuple", "set", "frozenset", "copy", "deepcopy", "reversed"}

        def self_attr_root(tgt: ast.AST) -> Optional[str]:
            cur = tgt
            while isinstance(cur, ast.Subscript):
                cur = cur.value
            if (
                isinstance(cur, ast.Attribute)
                and isinstance(cur.value, ast.Name)
                and cur.value.id in ("self", "cls")
            ):
                return cur.attr
            return None

        def carried(value: ast.AST) -> "set[int]":
            got: "set[int]" = set()
            if isinstance(value, ast.Name) and value.id in param_index:
                got.add(param_index[value.id])
            elif isinstance(value, (ast.List, ast.Tuple, ast.Set)):
                for e in value.elts:
                    if isinstance(e, ast.Name) and e.id in param_index:
                        got.add(param_index[e.id])
            elif isinstance(value, ast.Dict):
                for v in value.values:
                    if isinstance(v, ast.Name) and v.id in param_index:
                        got.add(param_index[v.id])
            elif (
                isinstance(value, ast.Call)
                and astutils.final_attr(value.func) in wrappers
            ):
                for a in value.args:
                    if isinstance(a, ast.Name) and a.id in param_index:
                        got.add(param_index[a.id])
            return got

        out: Dict[int, str] = {}
        for stmt in ast.walk(node):
            # ``self.<attr> = <v>`` / ``self.<attr>[...] = <v>``
            if (
                isinstance(stmt, ast.Assign)
                and len(stmt.targets) == 1
                and isinstance(stmt.targets[0], (ast.Subscript, ast.Attribute))
            ):
                attr = self_attr_root(stmt.targets[0])
                if attr is not None:
                    for pi in carried(stmt.value):
                        out[pi] = attr
            # ``self.<attr>.append(<param>)`` / ``.update(<param>)`` / ...
            elif (
                isinstance(stmt, ast.Expr)
                and isinstance(stmt.value, ast.Call)
                and isinstance(stmt.value.func, ast.Attribute)
                and stmt.value.func.attr in ACCUMULATOR_METHODS
            ):
                attr = self_attr_root(stmt.value.func.value)
                if attr is not None:
                    for a in stmt.value.args:
                        if isinstance(a, ast.Name) and a.id in param_index:
                            out[param_index[a.id]] = attr
        return out

    @staticmethod
    def _compute_returns_self_attrs(node: ast.AST) -> Set[str]:
        """``self.<attr>`` names any ``return`` in this method exposes.

        A method whose return value reads ``self.<attr>`` (raw, or wrapped in a
        serializer -- ``return yaml.safe_dump(self._config)``) exposes that attribute
        to callers, marking the class a *renderable builder*. Gates the cross-object
        absorb's contract-boundary sink: only a param absorbed into an attr that is
        actually returned/rendered somewhere makes the enclosing helper a file sink.
        """
        out: Set[str] = set()
        for stmt in ast.walk(node):
            if not (isinstance(stmt, ast.Return) and stmt.value is not None):
                continue
            for sub in ast.walk(stmt.value):
                if (
                    isinstance(sub, ast.Attribute)
                    and isinstance(sub.value, ast.Name)
                    and sub.value.id in ("self", "cls")
                ):
                    out.add(sub.attr)
        return out

    @staticmethod
    def _compute_returns_self_attr(node: ast.AST) -> Optional[str]:
        """The ``self.<attr>`` sub-path this method returns *as an alias*, or ``None``.

        Strict form of :meth:`_compute_returns_self_attrs`: set only when the method is
        a *pure getter* -- every ``return`` in it is exactly ``return self.<attr>[.<a>…]``
        naming the same attribute path, with no wrapping call/serializer. The returned
        object then *is* that attribute, so a caller (``ctx = self._get_ctx()``) can
        treat the local as an alias and record a field mutation on it against the real
        instance attribute. A wrapped return (``return list(self._x)``) or two returns
        naming different attributes leave it ``None`` -- those are values, not aliases.
        """
        seen: Optional[str] = None
        found = False
        for stmt in ast.walk(node):
            if not (isinstance(stmt, ast.Return) and stmt.value is not None):
                continue
            key = astutils.self_attr_key(stmt.value)
            if key is None or key == "":
                return None  # a return that isn't a bare self-attr chain -> not a getter
            if found and key != seen:
                return None  # returns disagree on which attribute
            seen, found = key, True
        return seen if found else None

    @staticmethod
    def _ctor_arg_type(
        arg: ast.AST, cls_name: str, param_annotations: Dict[str, Optional[str]]
    ) -> Optional[str]:
        """High-confidence class of a construction argument, or ``None``.

        Only trusts unambiguous signals so an inferred type never mis-resolves a
        method: ``self``/``cls`` -> the enclosing class; a nested constructor
        (``Patroni(...)``) -> its class; a class-annotated parameter -> its
        annotation. Anything else (a literal, an unannotated local, a bare attribute)
        stays ``None`` rather than guessing.
        """
        if isinstance(arg, ast.Name):
            if arg.id in ("self", "cls"):
                return cls_name
            ann = param_annotations.get(arg.id)
            return ann if ann and ann[:1].isupper() else None
        cls = astutils.ctor_class(arg)
        return cls if cls and cls[:1].isupper() else None

    def _record_call_arg_types(
        self, node: ast.AST, cls_name: str, param_annotations: Dict[str, Optional[str]]
    ) -> None:
        """Record the argument types of every call in this method, keyed by callee name.

        Feeds :attr:`ctor_arg_types` so a later pass can type an *unannotated* callee
        parameter from what is actually passed at the call site -- not just
        constructors (``Backups(self, "s3")`` types ``Backups.charm``) but any
        uniquely-named function/method (``_render(self)`` types ``_render``'s param).
        The callee is keyed by its final name (``ClassName`` / ``method`` / ``func``);
        positional args by their 0-based index into the *call*, keyword args by name.
        Names are recorded raw and reconciled against real classes/functions later --
        a name that resolves ambiguously (a method defined on several classes) is
        dropped there, so this only records; it never resolves.
        """
        for sub in ast.walk(node):
            if not isinstance(sub, ast.Call):
                continue
            name = astutils.final_attr(sub.func)
            if not name:
                continue
            # Key by ``Class#method`` when the receiver's class is known (``self``, a
            # fresh ``ClassName()``, a class-annotated value) -- then a *shared* method
            # name resolves precisely, no global-uniqueness needed. Otherwise key by the
            # bare name (a constructor / free function, or an unknown-receiver method
            # that the post-pass only trusts if globally unique).
            key: str = name
            if isinstance(sub.func, ast.Attribute):
                recv_cls = self._ctor_arg_type(sub.func.value, cls_name, param_annotations)
                if recv_cls:
                    key = f"{recv_cls}#{name}"
            bucket = self.ctor_arg_types.setdefault(key, {})
            for i, arg in enumerate(sub.args):
                if isinstance(arg, ast.Starred):
                    break  # positions past a splat are unknown
                t = self._ctor_arg_type(arg, cls_name, param_annotations)
                if t:
                    bucket.setdefault(i, set()).add(t)
            for kw in sub.keywords:
                if kw.arg is None:
                    continue
                t = self._ctor_arg_type(kw.value, cls_name, param_annotations)
                if t:
                    bucket.setdefault(kw.arg, set()).add(t)

    def _record_member_types(
        self,
        node: ast.AST,
        cls_name: str,
        param_annotations: Dict[str, Optional[str]],
        params: List[str],
    ) -> None:
        """Record ``self.<attr>``'s class so member accesses resolve to it.

        Two shapes are recorded, both keyed by the attribute name on ``cls_name``:

        * ``self.<attr> = ClassName(...)`` -- a constructor assignment (the
          collaborator idiom, ``self.async_replication = PostgreSQLAsyncReplication(...)``);
        * ``self.<attr> = <param>`` where ``<param>`` is a *class-annotated* parameter
          of the enclosing method (``def __init__(self, charm: TheCharm): self.charm =
          charm``). This is the near-universal *back-reference* every charm library
          holds, and without it a cross-object call ``self.charm.<manager>.<method>()``
          can't resolve its receiver. Trusting the annotation mirrors how a ``: Set``
          parameter is trusted elsewhere.

        Recording a spurious type is harmless: it is only ever consulted to look up a
        method/property *by class name*, so a non-class annotation resolves to nothing.
        """
        for sub in ast.walk(node):
            if not isinstance(sub, ast.Assign):
                continue
            cls = astutils.ctor_class(sub.value)
            if cls is None and isinstance(sub.value, ast.Name):
                # ``self.charm = charm`` -- type the attribute from the parameter's
                # class annotation (a capitalised root is a class, not a scalar/builtin).
                ann = param_annotations.get(sub.value.id)
                if ann and ann[:1].isupper():
                    cls = ann
                elif sub.value.id in params:
                    # ``self.charm = charm`` where ``charm`` has no class annotation:
                    # record the back-ref so the construction-site pass can type it from
                    # what this class is built with. Only for a genuine self-attr target.
                    for tgt in sub.targets:
                        if (
                            isinstance(tgt, ast.Attribute)
                            and isinstance(tgt.value, ast.Name)
                            and tgt.value.id in ("self", "cls")
                        ):
                            self.attr_backrefs.setdefault(cls_name, []).append(
                                (tgt.attr, sub.value.id)
                            )
            if cls is None:
                continue
            for tgt in sub.targets:
                if (
                    isinstance(tgt, ast.Attribute)
                    and isinstance(tgt.value, ast.Name)
                    and tgt.value.id in ("self", "cls")
                ):
                    self.attr_types.setdefault(cls_name, {})[tgt.attr] = cls

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._record_model_seq_fields(node)
        self._record_class_set_fields(node)
        self._record_value_object_fields(node)
        bases = [b for b in (astutils.final_attr(x) for x in node.bases) if b]
        if bases:
            self.class_bases.setdefault(node.name, [])
            for b in bases:
                if b not in self.class_bases[node.name]:
                    self.class_bases[node.name].append(b)
        self.class_stack.append(node.name)
        self.generic_visit(node)
        self.class_stack.pop()

    def _record_class_set_fields(self, node: ast.ClassDef) -> None:
        """Record a class's ``Set``/``frozenset``-typed attributes.

        Two shapes are recognised, covering dataclasses/pydantic models and the ops
        event idiom (``CertificatesAvailableEvent.certificates: Set[str]``):

        * a class-body annotation -- ``certificates: Set[str]``;
        * an ``__init__`` that stores a ``Set``-annotated parameter on ``self`` --
          ``def __init__(self, certificates: Set[str], ...): self.certificates =
          certificates``.

        A read of such an attribute (``event.certificates``) then reads as unordered,
        so joining/serialising it without ``sorted()`` is caught even though the
        attribute's element type lives on another class.
        """
        fields = {
            stmt.target.id
            for stmt in node.body
            if isinstance(stmt, ast.AnnAssign)
            and isinstance(stmt.target, ast.Name)
            and astutils.annotation_root(stmt.annotation) in UNORDERED_ANNOTATIONS
        }
        for stmt in node.body:
            if not (
                isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
                and stmt.name == "__init__"
            ):
                continue
            args = stmt.args
            set_params = {
                a.arg
                for a in list(args.args) + list(args.kwonlyargs)
                if a.annotation is not None
                and astutils.annotation_root(a.annotation) in UNORDERED_ANNOTATIONS
            }
            for s in ast.walk(stmt):
                if (
                    isinstance(s, ast.Assign)
                    and len(s.targets) == 1
                    and isinstance(s.targets[0], ast.Attribute)
                    and isinstance(s.targets[0].value, ast.Name)
                    and s.targets[0].value.id in ("self", "cls")
                    and isinstance(s.value, ast.Name)
                    and s.value.id in set_params
                ):
                    fields.add(s.targets[0].attr)
        if fields:
            self.class_set_fields.setdefault(node.name, set()).update(fields)

    def _record_model_seq_fields(self, node: ast.ClassDef) -> None:
        """Record a pydantic model's sequence-typed fields (``hosts: list[str]``).

        A pydantic ``__init__`` coerces an incoming value into the field's declared
        type, so a ``set`` passed to a ``list``/``tuple``/``Sequence`` field is
        turned into a positionally-ordered sequence internally -- baking element
        order a key-sorting serializer can't reach. Recording these fields lets the
        constructor site promote such an argument ``local`` -> ``itercaller``.

        Gated on a direct ``BaseModel`` base: a plain dataclass does *not* coerce
        (it stores the ``set`` as-is, whose disorder stays key-order/``local``), so
        promoting there would be a false positive.
        """
        if not any(astutils.final_attr(b) == "BaseModel" for b in node.bases):
            return
        fields = {
            stmt.target.id
            for stmt in node.body
            if isinstance(stmt, ast.AnnAssign)
            and isinstance(stmt.target, ast.Name)
            and astutils.annotation_root(stmt.annotation) in SEQUENCE_FIELD_ANNOTATIONS
        }
        if fields:
            self.model_seq_fields.setdefault(node.name, set()).update(fields)

    #: Decorators / bases that mark a class as a *value object* -- a bag of fields
    #: whose constructor stores them positionally (in declaration order) as its
    #: state. ``dataclass``/``attr.s``/``attrs``/``define``/``frozen`` decorators; a
    #: ``BaseModel`` / ``NamedTuple`` base. A plain class (a stateful collaborator)
    #: is deliberately absent: its positional ctor args are config, not fields.
    _VALUE_OBJECT_DECORATORS = {"dataclass", "define", "frozen", "s", "attrs", "attrib"}
    _VALUE_OBJECT_BASES = {"BaseModel", "NamedTuple"}

    def _record_value_object_fields(self, node: ast.ClassDef) -> None:
        """Record a value object's fields in declaration (= constructor) order.

        A ``@dataclass`` / pydantic / ``NamedTuple`` synthesises an ``__init__``
        whose positional parameters are the class-level annotated fields, in order.
        Capturing that order lets ``_ctor_field_taint`` map a *positional* argument
        to the field it fills -- so ``ScrapeJobContext(job)`` is absorbed exactly
        like ``ScrapeJobContext(updated_job=job)``. Gated to value objects so a
        stateful collaborator (a plain class) is never absorbed from its positional
        (config) arguments -- that would re-taint the object and, via the receiver-
        inheritance rule, mis-flag every unrelated method call on it.
        """
        decorated = any(
            astutils.final_attr(d) in self._VALUE_OBJECT_DECORATORS
            for d in getattr(node, "decorator_list", [])
        )
        based = any(
            astutils.final_attr(b) in self._VALUE_OBJECT_BASES for b in node.bases
        )
        if not (decorated or based):
            return
        fields = [
            stmt.target.id
            for stmt in node.body
            if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name)
        ]
        if fields:
            self.value_object_fields.setdefault(node.name, fields)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._add_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._add_function(node)
        self.generic_visit(node)
