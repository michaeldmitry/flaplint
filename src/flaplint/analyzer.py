"""High-level orchestration: paths in, findings out.

:class:`Analyzer` ties the passes together -- discovery, collection, summary
fixed point, reporting, confidence filtering -- behind a small, importable API.
A fresh :class:`~flaplint.taint.TaintEngine` is built per run, so two
analyses with different options never share state.
"""

from __future__ import annotations

import ast
import os
import sys
from typing import Dict, List, Sequence, Set, Tuple

from . import astutils
from .collector import Collector
from .constants import CONFIDENCE_RANK, KIND_RANK, SUPPRESS_COMMENT
from .discovery import (
    auto_interpreter,
    candidate_venvs,
    discover_site_packages,
    filter_sink_roots,
    gather_py_files,
    imported_top_levels,
    interpreter_module_paths,
    owned_lib_dirs,
    read_source,
    sibling_libs,
    sink_dep_roots,
)
from .model import FileImports, Finding, FuncInfo, Registry
from .report import collapse_pipelines, report
from .summary import compute_summaries, mark_databag_accessors
from .taint import TaintEngine
from .traversal import FunctionAnalyzer


class Analyzer:
    """Configurable, reusable charm relation-databag ordering analyzer.

    Parameters mirror the command-line flags. After :meth:`run`, the
    ``primary_files`` and ``secondary_files`` attributes report what was scanned
    (useful for a summary line).
    """

    def __init__(
        self,
        paths: Sequence[str],
        *,
        deps: Sequence[str] = (),
        venvs: Sequence[str] = (),
        resolve_deps: bool = True,
        python: str = "",
        report_deps: bool = True,
        relations_unordered: bool = False,
        min_confidence: str = "medium",
        sort: str = "criticality",
        explain_gaps: bool = False,
    ) -> None:
        self.paths = list(paths)
        self.deps = list(deps)
        self.venvs = list(venvs)
        #: automatically discover the charm's dependency environment (a sibling
        #: ``.venv`` interpreter, else its site-packages) and trace the deps that
        #: write relation data. On by default; disabled with ``--no-deps``.
        self.resolve_deps = resolve_deps
        self.python = python
        self.report_deps = report_deps
        self.relations_unordered = relations_unordered
        self.min_confidence = min_confidence
        self.sort = sort
        self.explain_gaps = explain_gaps
        self.primary_files: List[str] = []
        self.secondary_files: List[str] = []
        self.gaps: List = []

    def run(self) -> List[Finding]:
        """Execute every pass and return the filtered, sorted findings."""
        primary_roots = list(self.paths) + list(self.deps)
        primary_roots += sibling_libs(self.paths)  # always include sibling lib/
        primary_files = set(gather_py_files(primary_roots, include_tests=False))
        self.primary_files = sorted(primary_files)

        secondary_roots = discover_site_packages(self.venvs)  # explicit --venv
        if self.resolve_deps:
            imported = imported_top_levels(self.primary_files)
            # Prefer an interpreter (explicit --python, else an auto-picked sibling
            # .venv's bin/python): it follows PEP 420 namespace packages that a bare
            # folder scan misses. Fall back to folder-scanning the sibling venv's
            # site-packages when no interpreter is available (e.g. an unpacked .charm).
            python = self.python or auto_interpreter(self.paths)
            if python:
                resolved = interpreter_module_paths(python, imported)
                secondary_roots = sorted(
                    set(secondary_roots) | set(filter_sink_roots(resolved))
                )
            else:
                site_packages = secondary_roots or discover_site_packages(
                    candidate_venvs(self.paths)
                )
                secondary_roots = sink_dep_roots(site_packages, imported)

        secondary_files = set(gather_py_files(secondary_roots, include_tests=False))
        # Drop any secondary file that is really a primary file reached under a
        # different path spelling -- an *editable* install (``pip install -e``)
        # resolves a package back to the charm's own ``src``, so the interpreter
        # returns absolute paths that string-differ from the relative primary
        # paths. Compare by ``realpath`` so those are not analysed (and reported)
        # twice.
        primary_real = {os.path.realpath(p) for p in primary_files}
        secondary_files = {
            f for f in secondary_files if os.path.realpath(f) not in primary_real
        }
        self.secondary_files = sorted(secondary_files)

        registry: Registry = {}
        class_attr_types: Dict[str, Dict[str, str]] = {}
        model_seq_fields: Dict[str, Set[str]] = {}
        class_set_fields: Dict[str, Set[str]] = {}
        class_bases: Dict[str, List[str]] = {}
        value_object_fields: Dict[str, List[str]] = {}
        file_imports: Dict[str, FileImports] = {}
        functions: List[FuncInfo] = []
        suppressed: Dict[str, Set[int]] = {}
        ctor_arg_types: Dict[str, Dict[object, Set[str]]] = {}
        attr_backrefs: Dict[str, List[tuple]] = {}

        for path in self.primary_files:
            self._ingest(
                path, True, registry, class_attr_types, model_seq_fields,
                class_set_fields, class_bases, value_object_fields, file_imports,
                functions, suppressed, ctor_arg_types, attr_backrefs,
            )
        for path in self.secondary_files:
            self._ingest(
                path, False, registry, class_attr_types, model_seq_fields,
                class_set_fields, class_bases, value_object_fields, file_imports,
                functions, suppressed, ctor_arg_types, attr_backrefs,
            )
        _infer_ctor_param_types(
            registry, class_attr_types, ctor_arg_types, attr_backrefs
        )
        selfpass_refinements = _infer_selfpass_refinements(
            registry, class_attr_types, class_bases
        )

        engine = TaintEngine(
            registry,
            class_attr_types,
            relations_unordered=self.relations_unordered,
            file_imports=file_imports,
            model_seq_fields=model_seq_fields,
            class_set_fields=class_set_fields,
            class_bases=class_bases,
            value_object_fields=value_object_fields,
            render_sites=_render_sites(functions, registry),
        )
        analyzer = FunctionAnalyzer(engine)
        mark_databag_accessors(functions, registry)
        compute_summaries(functions, analyzer)
        findings, gaps = report(
            functions, analyzer, suppressed, self.explain_gaps,
            selfpass_refinements=selfpass_refinements,
        )

        threshold = CONFIDENCE_RANK[self.min_confidence]
        findings = [f for f in findings if CONFIDENCE_RANK[f.confidence] >= threshold]
        if self.sort == "location":
            findings.sort(key=lambda f: (f.path, f.line, f.col))
        else:  # "criticality": most severe first, location as a stable tie-break.
            findings.sort(
                key=lambda f: (
                    f.level != "error",  # actionable (charm-owned) errors first
                    -CONFIDENCE_RANK[f.confidence],
                    KIND_RANK.get(f.kind, 99),
                    f.path,
                    f.line,
                    f.col,
                )
            )
        self._classify_levels(findings)
        # Pipeline collapse runs here -- after ownership is known -- so the survivor
        # of a source+carriers group is chosen by error-over-warning, not by an
        # accidental absolute-path ordering that favours the vendored copy.
        findings = collapse_pipelines(findings)
        self._relativize(findings)
        cwd = os.getcwd()
        for g in gaps:
            g.path = os.path.relpath(os.path.abspath(g.path), cwd)
        self.gaps = gaps
        return findings

    def _classify_levels(self, findings: List[Finding]) -> None:
        """Tag each finding ``error`` (charm-owned fix) or ``warning`` (dependency).

        A finding is an **error** when its fix lives in code the charm owns -- a
        file/directory the user explicitly pointed at (a positional ``paths``
        argument) or the charm's own ``lib/charms/<name>/`` namespace. Everything
        else -- a *vendored* copy of another charm's library (whether reached via
        the auto-included sibling ``lib/`` or an explicit ``--dep``), or an
        installed dependency reported by default (unless ``--no-report-deps``) -- is
        a **warning**: real, but not the charm's to fix, so it must not fail CI.

        ``--dep`` only adds a root to *analyze and report*; it never changes a
        finding's level. Ownership is decided purely by location (own ``src`` or
        own charm-lib namespace), so a vendored lib reported via ``--dep`` stays a
        warning, while the charm's own lib stays an error.

        Runs before :meth:`_relativize`, while ``f.path`` is still absolute.
        """
        owned_roots: Set[str] = set()
        for p in list(self.paths):
            ap = os.path.abspath(p)
            if os.path.isfile(ap):
                owned_roots.add(os.path.dirname(ap))
            elif os.path.basename(ap) != "src" and os.path.isdir(
                os.path.join(ap, "src")
            ):
                # A charm root was pointed at: only its own src/ is owned, not the
                # vendored lib/ that sits beside it.
                owned_roots.add(os.path.join(ap, "src"))
            else:
                owned_roots.add(ap)
        owned_libs = [os.path.abspath(d) for d in owned_lib_dirs(self.paths)]

        def _under(ap: str, root: str) -> bool:
            return ap == root or ap.startswith(root + os.sep)

        for f in findings:
            ap = os.path.abspath(f.path)
            owned = any(_under(ap, r) for r in owned_roots) or any(
                _under(ap, d) for d in owned_libs
            )
            f.level = "error" if owned else "warning"

    def _relativize(self, findings: List[Finding]) -> None:
        """Rewrite every finding's path relative to the current directory.

        One consistent, click-to-navigate style for *all* findings -- a charm's
        own ``src/coordinator/src/mimir_config.py`` reads the same way as a
        vendored ``.../lib/charms/foo/v0/foo.py`` -- so the path always points
        somewhere you can open from where you ran the linter.
        """
        cwd = os.getcwd()
        for f in findings:
            f.path = os.path.relpath(os.path.abspath(f.path), cwd)
            if f.origin_path:
                f.origin_path = os.path.relpath(os.path.abspath(f.origin_path), cwd)
            if f.sink_path:
                f.sink_path = os.path.relpath(os.path.abspath(f.sink_path), cwd)

    def _ingest(
        self,
        path: str,
        primary: bool,
        registry: Registry,
        class_attr_types: Dict[str, Dict[str, str]],
        model_seq_fields: Dict[str, Set[str]],
        class_set_fields: Dict[str, Set[str]],
        class_bases: Dict[str, List[str]],
        value_object_fields: Dict[str, List[str]],
        file_imports: Dict[str, FileImports],
        functions: List[FuncInfo],
        suppressed: Dict[str, Set[int]],
        ctor_arg_types: Dict[str, Dict[object, Set[str]]],
        attr_backrefs: Dict[str, List[tuple]],
    ) -> None:
        source = read_source(path)
        if source is None:
            return
        try:
            tree = ast.parse(source, filename=path)
        except SyntaxError as exc:
            print(f"warning: skipping {path}: {exc}", file=sys.stderr)
            return
        suppressed[path] = {
            i + 1
            for i, line in enumerate(source.splitlines())
            if SUPPRESS_COMMENT in line
        }
        report_here = primary or self.report_deps
        collector = Collector(
            path, report_here, registry, class_attr_types, file_imports,
            model_seq_fields=model_seq_fields,
            class_set_fields=class_set_fields,
            class_bases=class_bases,
            value_object_fields=value_object_fields,
            ctor_arg_types=ctor_arg_types,
            attr_backrefs=attr_backrefs,
        )
        collector.visit(tree)
        functions.extend(collector.functions)
        # Module-level code is its own (parameterless) scope.
        functions.append(
            FuncInfo(name="<module>", path=path, node=tree, primary=report_here)
        )


def _infer_ctor_param_types(
    registry: Registry,
    class_attr_types: Dict[str, Dict[str, str]],
    ctor_arg_types: Dict[str, Dict[object, Set[str]]],
    attr_backrefs: Dict[str, List[tuple]],
) -> None:
    """Type an *unannotated* callee parameter from what is passed at its call sites.

    The general form of interprocedural type inference: a parameter with no class
    annotation is typed from the argument the call site actually supplies
    (:meth:`Collector._ctor_arg_type` trusts only ``self``/``cls``, a nested
    constructor, or a class-annotated arg). Two consumers of that type:

    * **constructors** -- ``self.backup = PostgreSQLBackups(self, ...)`` types
      ``Backups``'s ``charm`` param, and because it is stored (``self.charm = charm``)
      the type is lifted onto ``class_attr_types`` so *every* method resolves
      ``self.charm.<...>`` (the cross-method, high-leverage case);
    * **any other function/method** -- the inferred type is written onto the callee's
      own ``param_annotations``, so a receiver use *inside that function's body*
      (``def _render(charm): charm._patroni.render_file(...)``) resolves.

    Conservative by construction: a name that resolves to more than one function (a
    method defined on several classes) is skipped -- only a unique callee is trusted,
    which sidesteps the cross-class collision that name-based resolution otherwise
    risks; a parameter passed conflicting types across sites is dropped; and an
    existing annotation / constructor-assignment type is never overwritten. So it only
    *adds* resolution power, never redirects it.
    """
    init_by_class: Dict[str, FuncInfo] = {
        fi.class_name: fi for fi in registry.get("__init__", []) if fi.class_name
    }

    def resolve(args: Dict[object, Set[str]], params: List[str], offset: int) -> Dict[str, str]:
        """{param_name -> single unambiguous type} for one callee's call sites."""
        out: Dict[str, str] = {}
        for key, types in args.items():
            if len(types) != 1:
                continue  # conflicting types across call sites -> ambiguous
            (t,) = tuple(types)
            if isinstance(key, int):
                pidx = key + offset  # positional call arg i fills param i(+1 for self)
                pname = params[pidx] if 0 <= pidx < len(params) else None
            else:
                pname = key if key in params else None
            if pname is not None:
                out[pname] = t
        return out

    def apply(fi: FuncInfo, param_type: Dict[str, str]) -> None:
        for pname, t in param_type.items():
            fi.param_annotations.setdefault(pname, t)  # never overwrite an annotation

    def _method_offset(fi: FuncInfo) -> int:
        return 1 if fi.params and fi.params[0] in ("self", "cls") else 0

    for name, args in ctor_arg_types.items():
        if "#" in name:
            # ``Class#method`` -- a method call with a *known* receiver class, so it
            # resolves precisely even if the method name is shared across classes.
            clsname, method = name.split("#", 1)
            cands = [fi for fi in registry.get(method, []) if fi.class_name == clsname]
            if len(cands) == 1:
                apply(cands[0], resolve(args, cands[0].params, _method_offset(cands[0])))
            continue
        init = init_by_class.get(name)
        if init is not None:
            # Constructor: positional arg i fills param i+1 (self is implicit).
            param_type = resolve(args, init.params, offset=1)
            apply(init, param_type)
            bucket = class_attr_types.setdefault(name, {})
            for attr, pname in attr_backrefs.get(name, []):
                if pname in param_type and attr not in bucket:
                    bucket[attr] = param_type[pname]
            continue
        # Bare-name method on an *unknown* receiver: only a globally unique callee is
        # safe to type (no receiver class to disambiguate a shared method name).
        candidates = registry.get(name, [])
        if len(candidates) == 1:
            apply(candidates[0], resolve(args, candidates[0].params, _method_offset(candidates[0])))


_SELF_ARG = object()  # sentinel: a construction argument that is the ``self`` object


def _init_arg_source(arg: ast.AST, own_params: Set[str]) -> object:
    """Classify a ``__init__``-call argument: ``self`` (sentinel), a param name, or None."""
    if isinstance(arg, ast.Name):
        if arg.id in ("self", "cls"):
            return _SELF_ARG
        if arg.id in own_params:
            return arg.id
    return None


def _init_callee(recv: ast.AST, cls: str, class_bases: Dict[str, List[str]]) -> "Tuple[Optional[str], bool]":
    """Resolve the callee of a ``<recv>.__init__(...)`` call and whether ``self`` is explicit.

    ``super().__init__(...)`` -> the first base of ``cls`` (self is implicit, so its
    positional args start at param 1); ``Base.__init__(self, ...)`` -> ``Base`` (self is
    passed explicitly as arg 0).
    """
    if (
        isinstance(recv, ast.Call)
        and isinstance(recv.func, ast.Name)
        and recv.func.id == "super"
    ):
        bases = class_bases.get(cls, [])
        return (bases[0] if bases else None, False)
    if isinstance(recv, ast.Name):
        return (recv.id, True)
    return (None, True)


def _infer_selfpass_refinements(
    registry: Registry,
    class_attr_types: Dict[str, Dict[str, str]],
    class_bases: Dict[str, List[str]],
) -> Dict[str, Set[str]]:
    """Refine an attribute's type to the concrete subclass that self-passes it.

    A mixin like ``class DataPeer(DataPeerData, DataPeerEventHandlers)`` wires the
    inherited handler to itself -- ``DataPeerEventHandlers.__init__(self, charm, self,
    ...)`` -- so for ``DataPeer`` instances ``self.relation_data`` is exactly a
    ``DataPeer`` (which overrides ``local_secret_fields`` to be unordered). The base
    ``__init__`` stores that parameter under an annotation of the *base* type, masking
    it. This follows the ``self`` argument through the ``__init__`` delegation chain to
    the attribute it is ultimately stored on and records ``class_attr_types[C][attr] =
    C`` -- a *fact* from the construction, not a guess. Returns ``{C: {attrs}}`` for the
    context-sensitive re-analysis worklist (see :func:`report`).
    """
    inits: Dict[str, FuncInfo] = {
        fi.class_name: fi for fi in registry.get("__init__", []) if fi.class_name
    }

    def resolve_init(cls: Optional[str]) -> Optional[str]:
        """Nearest class in ``cls``'s chain that *defines* ``__init__`` (own or inherited)."""
        seen: Set[str] = set()
        queue = [cls] if cls else []
        while queue:
            c = queue.pop(0)
            if c is None or c in seen:
                continue
            seen.add(c)
            if c in inits:
                return c
            queue.extend(class_bases.get(c, ()))
        return None
    # Per class: params stored directly as ``self.<attr>``, and delegations to a base
    # ``__init__`` (callee -> {callee param name -> source: self-sentinel / param / None}).
    stored_as: Dict[str, Dict[str, str]] = {}
    forwards: Dict[str, List["Tuple[str, Dict[str, object]]"]] = {}
    for cls, fi in inits.items():
        own = set(fi.params)
        st: Dict[str, str] = {}
        fw: List["Tuple[str, Dict[str, object]]"] = []
        for node in ast.walk(fi.node):
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Attribute)
                and isinstance(node.targets[0].value, ast.Name)
                and node.targets[0].value.id in ("self", "cls")
                and isinstance(node.value, ast.Name)
                and node.value.id in own
            ):
                st[node.value.id] = node.targets[0].attr
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "__init__"
            ):
                callee, explicit = _init_callee(node.func.value, cls, class_bases)
                callee = resolve_init(callee)  # an inherited __init__ resolves to its definer
                if callee is None:
                    continue
                cparams = inits[callee].params
                offset = 0 if explicit else 1  # explicit self is arg 0; super() implicit
                srcmap: Dict[str, object] = {}
                for i, a in enumerate(node.args):
                    if isinstance(a, ast.Starred):
                        break
                    pidx = i + offset
                    if 0 <= pidx < len(cparams):
                        srcmap[cparams[pidx]] = _init_arg_source(a, own)
                for kw in node.keywords:
                    if kw.arg:
                        srcmap[kw.arg] = _init_arg_source(kw.value, own)
                fw.append((callee, srcmap))
        stored_as[cls] = st
        forwards[cls] = fw

    # Fixpoint: propagate "this param ends up stored as self.<attr>" up the delegation
    # chain, so a param forwarded through several ``super().__init__`` hops is resolved.
    changed = True
    while changed:
        changed = False
        for cls, fws in forwards.items():
            for callee, srcmap in fws:
                callee_map = stored_as.get(callee, {})
                for cparam, src in srcmap.items():
                    if isinstance(src, str) and cparam in callee_map:
                        attr = callee_map[cparam]
                        if stored_as.setdefault(cls, {}).get(src) != attr:
                            stored_as[cls][src] = attr
                            changed = True

    # A ``self`` argument that reaches a stored parameter refines that attribute to the
    # self-passing class.
    refinements: Dict[str, Set[str]] = {}
    for cls, fws in forwards.items():
        for callee, srcmap in fws:
            callee_map = stored_as.get(callee, {})
            for cparam, src in srcmap.items():
                if src is _SELF_ARG and cparam in callee_map:
                    attr = callee_map[cparam]
                    class_attr_types.setdefault(cls, {})[attr] = cls
                    refinements.setdefault(cls, set()).add(attr)
    return refinements


def _render_sites(
    functions: List[FuncInfo], registry: Registry
) -> Dict[str, Tuple[str, str, int, int]]:
    """Builder class -> ``(sink_type, path, line, col)`` where its output is written.

    A builder (``ConfigBuilder``) commits values via a setter (``add_component``) and
    is later serialized by a *render* method (``build()``, which returns ``self._config``
    -- see :attr:`FuncInfo.returns_self_attrs`) whose result is written to a byte-sink:
    ``container.push(CONFIG_PATH, config_manager.config.build())`` (file),
    ``relation.data[app][k] = pb.build()`` (databag), ``secret.set_content(b.build())``
    (secret). The setter call is where a value *enters* the config, not where bytes are
    committed -- so a builder-absorb finding must take its **sink type and location**
    from this real render-write (not assume ``file``), found by matching a byte-sink
    whose written content is a render-method call. A builder never rendered to any
    byte-sink yields no entry, so its setter is not treated as a contract sink at all.
    """
    render_methods: Dict[str, Set[str]] = {}
    for fns in registry.values():
        for fi in fns:
            if fi.returns_self_attrs and fi.class_name:
                render_methods.setdefault(fi.name, set()).add(fi.class_name)
    if not render_methods:
        return {}

    sites: Dict[str, Tuple[str, str, int, int]] = {}
    for fi in functions:
        # Local variables that hold a render call's result, so a *deferred* write
        # (``config = builder.build(); container.push(path, config)``) is recognised
        # as a render-write -- not only the inline ``push(path, builder.build())``.
        render_vars: Dict[str, Set[str]] = {}
        for node in ast.walk(fi.node):
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Attribute)
                and node.value.func.attr in render_methods
            ):
                render_vars[node.targets[0].id] = render_methods[node.value.func.attr]

        def content_classes(node) -> Set[str]:
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                return render_methods.get(node.func.attr, set())
            if isinstance(node, ast.Name):
                return render_vars.get(node.id, set())
            return set()

        for node in ast.walk(fi.node):
            hits: "List[Tuple[str, Set[str], ast.AST]]" = []
            if isinstance(node, ast.Call):
                fw = astutils.file_write_args(node)
                if fw is not None:
                    for c in fw[1]:
                        hits.append(("file", content_classes(c), node))
                sw = astutils.secret_write_args(node)
                if sw is not None:
                    for c in sw[1]:
                        hits.append(("secret", content_classes(c), node))
            elif isinstance(node, ast.Assign) and any(
                astutils.is_databag_target(t) for t in node.targets
            ):
                hits.append(("databag", content_classes(node.value), node))
            for sink_type, classes, at_node in hits:
                for cls in classes:
                    sites.setdefault(
                        cls,
                        (sink_type, fi.path, at_node.lineno,
                         getattr(at_node, "col_offset", 0)),
                    )
    return sites


def analyze_paths(
    paths: Sequence[str],
    *,
    deps: Sequence[str] = (),
    venvs: Sequence[str] = (),
    resolve_deps: bool = True,
    python: str = "",
    report_deps: bool = True,
    relations_unordered: bool = False,
    min_confidence: str = "medium",
    sort: str = "criticality",
) -> List[Finding]:
    """Convenience wrapper: build an :class:`Analyzer`, run it, return findings."""
    return Analyzer(
        paths,
        deps=deps,
        venvs=venvs,
        resolve_deps=resolve_deps,
        python=python,
        report_deps=report_deps,
        relations_unordered=relations_unordered,
        min_confidence=min_confidence,
        sort=sort,
    ).run()
