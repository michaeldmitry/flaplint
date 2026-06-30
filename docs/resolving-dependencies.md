# Finding a charm's dependencies

Charms don't usually write their own databags — they hand values to a *library* that
does. Those libraries reach a running charm by two different routes, and `flaplint`
treats them differently.

## Vendored libraries

A charm-lib copied into the charm's tree, at `lib/charms/<x>/vN/<x>.py`. Examples:
`grafana-k8s`'s dashboards library, or another charm's provider library.

- **Where it lives:** on disk, beside your source code.
- **How it's found:** automatically (no flag needed) — `flaplint` looks for and
  includes the sibling `lib/` directory by default.
- **How it's reported:** findings in vendored code follow the charm's ownership rule
  (see [Errors vs. warnings](../README.md#errors-vs-warnings--who-can-fix-it)).

Vendored code is yours to maintain, so findings in it are shown alongside your own.

## Installed Python libraries

Real PyPI or `charmlibs` dependencies: `cosl`, `ops`, `charmlibs.interfaces.otlp`,
coordinated-workers, and so on.

- **Where it lives:** in a venv / `site-packages` directory — and, when the charm is
  packed, inside the `.charm` zip's `venv/` directory.
- **Not beside your source** during development, so a plain look at the files won't see
  it.
- **How it's found:** only if you point `flaplint` at the environment with one of three
  flags.

### The three flags

All three add **read-only** roots — their functions are read so calls into installed
libraries can be followed, but findings are still reported against *your* code (unless
you pass `--report-deps`).

#### `--venv PATH`
Scan a `site-packages` directory you name. Use when you have a bare site-packages dir
(or, later, an unpacked `.charm`) and no interpreter to ask.

#### `--auto-deps`
Find a **sibling** `.venv`/`venv` automatically and scan it, narrowing to only the
packages that write to relation data. No config — use this when a dev venv sits next to
the charm:
```bash
flaplint src --auto-deps
```

For coordinated-workers charms this picks up `coordinated_workers/coordinator.py`, which
writes the worker/coordinator relation data.

#### `--python PATH` ⭐ most reliable
Ask a **working interpreter** where each imported dependency lives (it uses Python's own
`importlib.util.find_spec`). Use when you have a working env (a `uv sync` `.venv`, a tox
env, `$VIRTUAL_ENV`):
```bash
flaplint src --python my-charm/.venv/bin/python
```

Why it's the most reliable:
- Listing folders misses `charmlibs.interfaces.*`, which ships as a *namespace package*
  — a folder with no `__init__.py` at the top level. The interpreter follows it
  correctly; a plain folder listing doesn't.
- It handles namespace packages, exact install locations, and single-file dependencies.
- It **installs nothing** — it only reads what's already there.

## Why the tool doesn't just read all of `site-packages`

Scanning the whole `site-packages` is slow and noisy. So `--auto-deps` and `--python`
narrow it down with two cheap checks:

1. **Imports:** only the top-level modules your charm actually `import`s are considered.
   A package you never touch is never read (standard-library modules are skipped
   outright).

2. **A quick databag-write check:** for each imported package, a fast read of its code
   keeps it **only if it looks like it writes to a relation databag**. The three shapes
   that count:
   - `relation.data[entity][key] = …` (assignment)
   - `relation.save(obj, entity)` (the ops typed-databag call)
   - `relation.data[entity].update(…)` / `.setdefault(…)` (mapping writes)

   These are the same write shapes the engine recognises, but matched here by
   **structure alone** — without the Relation-provenance tracing the engine applies when
   it actually reports (it does not check that the receiver traces back to a
   `get_relation(...)`). That makes this a fast, deliberately **loose**
   over-approximation: a false match only costs reading one extra file (which is then
   analysed precisely, so it can't produce a false finding), whereas missing a
   databag-writing dep *would* cause a false negative — so erring toward inclusion is the
   right bias.

That's why the `charmlibs.interfaces.otlp` requirer, which publishes via
`relation.save(databag, self._charm.app)`, is correctly picked as a dependency worth
reading.

## When a finding comes from a dependency: error or warning?

See [Errors vs. warnings](../README.md#errors-vs-warnings--who-can-fix-it) for how the
tool tells apart code you own (error) from libraries you only use (warning).
