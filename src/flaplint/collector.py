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
from .constants import SEQUENCE_FIELD_ANNOTATIONS
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
    ) -> None:
        self.path = path
        self.primary = primary
        self.registry = registry
        self.attr_types = attr_types
        #: pydantic-model class name -> sequence-typed field names, so a set
        #: coerced into such a field is promoted ``local`` -> ``itercaller``.
        self.model_seq_fields = model_seq_fields if model_seq_fields is not None else {}
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
        self.registry.setdefault(fi.name, []).append(fi)
        self.functions.append(fi)
        if cls_name:
            self._record_member_types(node, cls_name)

    def _record_member_types(self, node: ast.AST, cls_name: str) -> None:
        """Record ``self.<attr> = ClassName(...)`` so members resolve to a class."""
        for sub in ast.walk(node):
            if not isinstance(sub, ast.Assign):
                continue
            ctor = astutils.ctor_class(sub.value)
            if not ctor:
                continue
            for tgt in sub.targets:
                if (
                    isinstance(tgt, ast.Attribute)
                    and isinstance(tgt.value, ast.Name)
                    and tgt.value.id in ("self", "cls")
                ):
                    self.attr_types.setdefault(cls_name, {})[tgt.attr] = ctor

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._record_model_seq_fields(node)
        self.class_stack.append(node.name)
        self.generic_visit(node)
        self.class_stack.pop()

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

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._add_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._add_function(node)
        self.generic_visit(node)
