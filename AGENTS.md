# AGENTS.md

Operational guide for AI coding agents working in this repository. Humans should
start with [README.md](README.md); the deep docs are in [docs/](docs/README.md).

## What this is

`flaplint` is a static analyser for Juju charms. It reads charm source with Python's
`ast` and flags values with no stable byte-order (a `set`, a `glob`, a `uuid4()`, a
`list(set)`, …) that reach a churn-sensitive sink — a relation **databag**, an
on-disk **file**, or a content-**hash** change-detector. Unstable bytes make Juju
fire spurious `relation-changed` events (or trip a restart/replan gate), so the tool
exists to catch the missing `sorted()`.

It is a **taint analysis with inter-procedural function summaries**. The whole
package lives in `src/flaplint/`.

## Setup & commands

- **Stdlib-only.** No runtime dependencies (`pyproject.toml` `dependencies = []`).
  Do **not** add third-party runtime deps — the analyser must run anywhere with a
  bare interpreter. `pytest` is the only dev dependency.
- **Run the test suite** (fast — ~0.5s) from the project root
- **Run the linter** via the `flaplint` console script or the module — both work.

## Architecture (orientation)

Four stages, one module each, wired by `analyzer.py`:

`discovery.py` (find files) → `collector.py` (register every function into a
registry of `FuncInfo`) → `summary.py` (fixed-point taint summaries) →
`report.py` (emit findings).

The central seam:
- **`taint.py` — `TaintEngine.eval(node, env)`** answers "is this *expression*
  unstable, and why?", returning a set of **origins** (empty = stable).
- **`traversal.py` — `FunctionAnalyzer`** flows that taint through a function's
  *statements* to sinks/returns.
- **`handlers.py`** — `SummaryHandler` (build summaries) and `ReportHandler` (emit
  findings) let the same walk drive both passes.
- **`constants.py`** — pure, richly-commented name-sets (sources, serializers, sink
  shapes). Most "teach it a new name" changes are one line here.
- **`model.py`** — `Origin`, `FuncInfo`, `Finding` + origin predicates.

Full detail: [docs/architecture.md](docs/architecture.md).

## The core mental model (read this before changing analysis logic)

Every unstable value carries an **origin**. The six flavors and — critically —
**whether a key-sorting serializer (`yaml.dump`, `json.dumps(sort_keys=True)`)
launders them** is the crux of the whole tool:

| origin | born from | survives key-sorting? |
|---|---|---|
| `local` | a bare `set`/`glob`/`relation.units` | **no** — it's mapping-key order, key-sorting fixes it |
| `element` | a positional pick (`addrs[0]`) | yes |
| `itercaller` | a sequence materialized from an unordered source (`list(some_set)`) | yes |
| `iterparam` | iterating a *parameter* into a sequence (contract boundary) | yes |
| `volatile` | `uuid4()`/`time()`/`random()` | yes (sorting can't help at all) |
| `param` | a parameter reference (placeholder, resolved at the call site) | n/a |

The subtlety that trips up naive linters and was the subject of recent work:
**`set` is laundered by key-sorting, but `list(set)` is not** — materializing a set
into a sequence converts mapping-key disorder into list-element disorder, which
key-sorting never touches. That is why `list(set)` is *promoted* `local → itercaller`.
The same promotion applies to `" ".join(some_set)`: joining bakes the element order
into the result *string*, which key-sorting can't reach either.

Full reference (with the survival matrix and propagation rules):
[docs/taint-model.md](docs/taint-model.md). Sinks and how origins become findings:
[docs/sinks-and-findings.md](docs/sinks-and-findings.md).

## Conventions

- **Match the comment density.** This codebase explains *why*, not *what*, in
  generous docstrings and inline comments — especially around taint flavors and the
  key-sort distinction. New code should read the same way.
- **Tests are end-to-end behaviour specs.** The `lint_source` fixture
  (`tests/conftest.py`) lints an inline charm snippet through the whole pipeline and
  returns `Finding`s. Prefer adding a snippet test that asserts on
  `f.rule` / `f.kind` / `f.confidence` / `f.variable` over white-box assertions.
  Engine-level unit tests (origins from a bare expression) live in
  `tests/test_units.py`. Files are grouped by concern (`test_iteration.py`,
  `test_sink.py`, `test_volatile.py`, `test_ownership.py`, …).
- A finding has a **`rule`** (failure mode — *how to fix*: `unordered-collection`,
  `unordered-pick`, `unordered-iteration`, `nondeterministic`) and a **`kind`**
  (vantage — *whose code*: `caller` = concrete bug here; `sink` = a helper that
  writes a *parameter* unsorted). These are orthogonal.
- Suppression comment is `# databag-order: ignore` (`SUPPRESS_COMMENT`).
- **No module globals for analysis state** — the registry, per-class member types,
  and toggles live on the `TaintEngine` instance so analyses don't leak into each
  other. Keep it that way.

## Recipes (where to make common changes)

- **New unordered source** (a new set-like call / attribute): add to
  `UNORDERED_CALLS` / `UNORDERED_ATTRS` in `constants.py`.
- **New serializer** the engine should understand: extend the relevant set in
  `constants.py` and, if it has new survival semantics, the `_call` handling in
  `taint.py`.
- **New sink** (a databag/file/hash/plan API): `FILE_WRITE_METHODS` / `HASH_CALLS`
  / `PLAN_WRITE_METHODS` in `constants.py`; databag recognition is **object
  provenance** in `databag.py` (Relation→RelationData→databag, seeded by
  `get_relation`), used by `traversal.py`. A `file` sink is byte-diffed (flags any
  origin); a `plan`/`hash`/`databag` sink is compared structurally / key-sorted, so
  it uses **key-sort survival** (`TaintEngine.survives_structural_compare`) — a bare
  `set` is laundered there, a `list(set)`/`join(set)`/volatile is not.
- **A new origin flavor or a flavor change**: this touches several files in lockstep
  — the predicate in `model.py`, both survival filters in `taint.py`
  (`_survives_stringify` **and** `_key_sort_survivors`), the `SummaryHandler.ret`
  propagation and `ReportHandler.sink` emission in `handlers.py`, and the
  rule/message in `report.py` / `render.py`. Grep for an existing flavor (e.g.
  `itercaller`) and mirror every site.

## Gotchas & known limitations

- **The dataclass-field-taint barrier.** Taint does *not* flow through an unstable
  collection that is buried in a dict, stored in a dataclass field, and rebuilt by a
  method downstream (the cos-proxy `ScrapeJobContext` shape). A plain string-valued
  dataclass field *does* propagate (the alertmanager `ConfigSuite` shape). If a
  cross-function trace "should" connect but doesn't, suspect this.
- **Confirmed vs. precautionary `unordered-iteration`.** A traced unstable caller
  yields `kind=caller` (high); an untraced helper that iterates a param yields a
  precautionary `kind=sink` (medium). The caller finding *supersedes* the
  precautionary one at the same site — don't "fix" the dedup that does this.
- **Editing docs?** Cross-links use GitHub heading slugs; ` — ` (spaced em-dash)
  produces a `--` (double hyphen) in the anchor. Validate links after edits.
- Always re-run the full suite after touching `taint.py` / `handlers.py` /
  `report.py` — flavor changes have non-obvious ripple effects across passes.
