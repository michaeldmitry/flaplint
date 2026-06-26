"""Collection pass: build the function registry from a parsed module.

:class:`Collector` is an :class:`ast.NodeVisitor` that records every function and
method as a :class:`~flaplint.model.FuncInfo`, plus the
``self.<attr> = ClassName(...)`` member types used later to resolve property
accesses on stored collaborators.
"""

from __future__ import annotations

import ast
from typing import Dict, List

from . import astutils
from .model import FuncInfo, Registry


class Collector(ast.NodeVisitor):
    """Populate ``registry`` (and ``attr_types``) from one module AST."""

    def __init__(
        self,
        path: str,
        primary: bool,
        registry: Registry,
        attr_types: Dict[str, Dict[str, str]],
    ) -> None:
        self.path = path
        self.primary = primary
        self.registry = registry
        self.attr_types = attr_types
        self.functions: List[FuncInfo] = []
        self.class_stack: List[str] = []

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
        self.class_stack.append(node.name)
        self.generic_visit(node)
        self.class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._add_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._add_function(node)
        self.generic_visit(node)
