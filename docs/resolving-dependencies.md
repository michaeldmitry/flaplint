# Finding a charm's dependencies

Charms don't usually write their own databags — they hand values to a *library* that
does. Those libraries reach a running charm by two different routes, and `flaplint`
treats them differently.

## Quick guide: which flag to use

| my situation | flag |
|---|---|
| A venv already exists for this charm | `--python .venv/bin/python` ⭐ most reliable |
| No venv, but there's a `.venv`/`venv` folder next to the charm | `--auto-deps` |
| I have a bare `site-packages` directory | `--venv path/to/site-packages` |
| I want to see findings *inside* the dependency (not just trace through it) | add `--report-deps` to any of the above |

If you skip all three flags, `flaplint` only reads the charm's own `src/` and the
sibling `lib/` directory — it won't trace calls into installed packages.

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
- **How it's found:** only if you point `flaplint` at the environment with a flag.

All three flags add **read-only** roots: the library code is read so calls into it can
be followed, but findings are reported against *your* code unless you pass `--report-deps`.

### `--python PATH` ⭐ most reliable

Ask a working interpreter where each imported dependency lives. Use when you have an
active venv (`uv sync`, tox, `$VIRTUAL_ENV`):

```bash
flaplint src --python my-charm/.venv/bin/python
```

This is the most reliable option because:
- It handles namespace packages (`charmlibs.interfaces.*` ships as a namespace package
  with no `__init__.py` at the top level — folder scanning misses it; the interpreter
  finds it correctly).
- It handles exact install locations and single-file dependencies.
- It **installs nothing** — it only reads what's already there.

### `--auto-deps`

Find a sibling `.venv`/`venv` automatically and scan it, keeping only the packages
that actually write to relation data. No config required:

```bash
flaplint src --auto-deps
```

For coordinated-workers charms this picks up `coordinated_workers/coordinator.py`,
which writes the worker/coordinator relation data.

### `--venv PATH`

Point at a `site-packages` directory you name. Use when you have a bare
`site-packages` dir (or an unpacked `.charm`) and no interpreter to ask:

```bash
flaplint src --venv .venv/lib/python3.12/site-packages
```

## Why the tool doesn't scan all of `site-packages`

Scanning the whole `site-packages` tree is slow and noisy. `--auto-deps` and
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

## When a finding comes from a dependency: error or warning?

See [Errors vs. warnings](../README.md#errors-vs-warnings--who-can-fix-it) for how the
tool tells apart code you own (error) from libraries you only use (warning).
