# Finding a charm's dependencies

Charms don't usually write their own databags — they hand values to a *library* that
does. Those libraries reach a running charm by two different routes, and `flaplint`
treats them differently.

## It's automatic by default

You usually need **no flags**. `flaplint src` auto-discovers the charm's own
environment and traces the dependencies that write relation data:

1. a sibling `.venv`/`venv`'s `bin/python` is auto-picked and used to resolve
   imports through its import system (namespace-package-aware — the most reliable
   path); failing that,
2. the sibling `.venv`/`venv`'s `site-packages` is folder-scanned.

Findings *inside* traced dependencies are shown by default (as non-blocking
warnings).

## When to reach for a flag

| my situation | flag |
|---|---|
| The right environment isn't a sibling `.venv` (e.g. a `uv`/`tox`/system env elsewhere) | `--python path/to/that/.venv/bin/python` |
| I only have a bare `site-packages` directory (an unpacked `.charm`, no interpreter) | `--venv path/to/site-packages` |
| I want a fast, own-code-only run (CI gate, or no venv present) | `--no-deps` |
| I want to trace deps but *not* see findings inside them | `--no-report-deps` |

`--no-deps` reads only the charm's own `src/` and sibling `lib/` — it won't trace
calls into installed packages.

## Vendored libraries

A charm-lib copied into the charm's tree, at `lib/charms/<x>/vN/<x>.py`. Examples:
`grafana-k8s`'s dashboards library, or another charm's provider library.

- **Where it lives:** on disk, beside your source code.
- **How it's found:** automatically — no flag needed. `flaplint` includes the sibling
  `lib/` directory by default.
- **How it's reported:** findings follow the charm's ownership rule (code in
  `lib/charms/<charm-name>/` is yours; code in `lib/charms/<other>/` is a warning).

Vendored code is yours to maintain, so findings in it are shown alongside your own.

## Installed Python libraries

Real PyPI or `charmlibs` dependencies: `cosl`, `ops`, `charmlibs.interfaces.otlp`,
`coordinated-workers`, and so on.

- **Where it lives:** in a venv / `site-packages` — not beside your source.
- **How it's found:** automatically (a sibling `.venv`), or by pointing `flaplint`
  at the environment with a flag.

These roots are **read-only**: the library code is read so calls into it can be
followed. Findings inside them are shown by default (as warnings) unless you pass
`--no-report-deps`.

### Automatic (the default)

`flaplint src` picks up a sibling `.venv`/`venv` on its own: it prefers the venv's
`bin/python` (see below), falling back to folder-scanning its `site-packages`, and
keeps only the packages that actually write to relation data. For coordinated-workers
charms this picks up `coordinated_workers/coordinator.py`, which writes the
worker/coordinator relation data. Use `--no-deps` to skip this entirely.

### `--python PATH` — point at a specific interpreter

By default a sibling `.venv`'s `bin/python` is auto-picked; pass `--python` to use a
different environment (`uv sync`, tox, `$VIRTUAL_ENV`, a CI cache):

```bash
flaplint src --python /path/to/other/.venv/bin/python
```

Resolving through an interpreter is the most reliable mechanism because:
- It handles namespace packages (`charmlibs.interfaces.*` ships as a namespace package
  with no `__init__.py` at the top level — folder scanning misses it; the interpreter
  finds it correctly).
- It handles exact install locations and single-file dependencies.
- It **installs nothing** — it only reads what's already there.

An **editable install** (`pip install -e`) resolves a package back to the charm's own
`src`; flaplint compares real paths so that code is analysed once, not reported twice.

### `--venv PATH` — a bare site-packages

Point at a `site-packages` directory you name. Use when you have a bare
`site-packages` dir (or an unpacked `.charm`) and no interpreter to ask:

```bash
flaplint src --venv .venv/lib/python3.12/site-packages
```

## Why the tool doesn't scan all of `site-packages`

Scanning the whole `site-packages` tree is slow and noisy. Automatic resolution and
`--python` narrow it down with two cheap checks:

1. **Imports:** only the top-level modules your charm actually `import`s are
   considered. A package you never touch is never read (stdlib modules are skipped
   outright).

2. **A quick databag-write check:** for each imported package, a fast read of its
   code keeps it only if it looks like it writes to a relation databag — one of:
   - `relation.data[entity][key] = …` (assignment)
   - `relation.save(obj, entity)` (the ops typed-databag call)
   - `relation.data[entity].update(…)` / `.setdefault(…)` (mapping writes)

   This check is deliberately loose (no Relation-provenance tracing) to avoid
   missing a dependency. A false match only costs reading one extra file, which is
   then analysed precisely and can't produce a false finding. Missing a
   databag-writing dep *would* cause a false negative — so erring toward inclusion is
   the right bias.

That's why `charmlibs.interfaces.otlp`, which publishes via
`relation.save(databag, self._charm.app)`, is correctly included.

## When a finding comes from a dependency: yours or not?

See [Ownership — whose job is the fix?](../README.md#ownership--whose-job-is-the-fix) for
how the tool tells apart code you own (`✖` yours, fails the run) from libraries you only
use (`▲` in a dependency, non-blocking) — a separate axis from `confidence`.
