# Resolving Charm Dependencies

Charms don't usually write their own databags — they forward values into a *library* that does. These libraries reach a running charm by two distinct routes, and `flaplint` treats them differently:

## Vendored Libraries

A charm-lib copied into the charm's tree, located in `lib/charms/<x>/vN/<x>.py`. Examples: `grafana-k8s`'s dashboards library or another charm's provider library.

- **Stored:** on disk, beside your source code
- **Discovered:** automatically (no flag needed) — `flaplint` looks for and includes the sibling `lib/` directory by default
- **Reported:** findings inside vendored code are reported with the charm's ownership model (see [Errors vs. warnings](../README.md#errors-vs-warnings--who-can-fix-it))

Vendored code is your responsibility to maintain, so findings in it are surfaced alongside your own.

## Installed Python Libraries

Real PyPI or `charmlibs` dependencies: `cosl`, `ops`, `charmlibs.interfaces.otlp`, coordinated-workers, etc.

- **Stored:** in a venv / `site-packages` directory — and at charm pack time, inside the `.charm` zip's `venv/` directory
- **Not beside your source** during development (hence invisible to a simple filesystem scan)
- **Discovered:** only if you point `flaplint` at the environment using one of three resolution flags

### Resolution Flags

All three flags add **trace-only** roots — their functions inform the call-graph so calls into installed libraries resolve correctly, but findings are still reported against *your* code (unless you pass `--report-deps`).

#### `--venv PATH`
Scan a `site-packages` directory you name. Use when you have a bare site-packages dir (or, later, an unpacked `.charm`) and no interpreter to ask.

#### `--auto-deps`
Locate a **sibling** `.venv`/`venv` automatically and scan it, narrowing to only the packages that write to relation data. Zero-config — use this when a dev venv sits next to the charm. Examples:
```bash
flaplint src --auto-deps
```

For coordinated-workers charms this picks up `coordinated_workers/coordinator.py`, which writes the worker/coordinator relation data.

#### `--python PATH` ⭐ Most Robust
Ask an **interpreter's import system** (`importlib.util.find_spec`) where each imported dependency lives. Use when you have a *working* env (a `uv sync` `.venv`, a tox env, `$VIRTUAL_ENV`).

Example:
```bash
flaplint src --python my-charm/.venv/bin/python
```

**Why it's most robust:**
- A directory scan lists folders, but `charmlibs.interfaces.*` ships as a **PEP 420 namespace package** (no `__init__.py` at the namespace level) that `find_spec` follows correctly and folder-listing misses
- Resolves namespace packages, version-exact locations, and single-module deps
- **Installs nothing** — only reads what is already present in that environment

## Narrow Scanning: Why the Tool Doesn't Just Read `site-packages`

Scanning the whole `site-packages` is slow and produces noise. So `--auto-deps` and `--python` narrow it down with two cheap signals:

1. **Imports:** Only the top-level modules your charm actually `import`s are considered. A package you never touch is never traced (stdlib modules are skipped outright).

2. **Databag-sink pre-scan:** For each imported package, a fast AST pass keeps it **only if its code really writes a relation databag**. The linter recognizes three sink shapes:
   - `relation.data[entity][key] = …` (subscript assign)
   - `relation.save(obj, entity)` (ops typed-databag API)
   - `relation.data[entity].update(…)` / `.setdefault(…)` (mapping writes)

This is why the new `charmlibs.interfaces.otlp` requirer, which publishes via `relation.save(databag, self._charm.app)`, is correctly selected as a dependency worth tracing.

## When Findings Come from Dependencies: Error vs. Warning

See [Errors vs. warnings](../README.md#errors-vs-warnings--who-can-fix-it) for how the tool distinguishes between code you own (error level) and libraries you consume (warning level).
