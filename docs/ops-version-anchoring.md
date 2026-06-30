# Which ops version flaplint anchors on (and how drift is caught)

flaplint recognises relation databags, pebble plans, and a few unordered sources by
matching **ops/pebble API names and shapes** (`relation.units`, `.data[entity]`,
`relation.save`, `container.push`, `add_layer`, …). ops is the one part of the
ecosystem that genuinely evolves, so this is the surface that can drift. This note
records the decision: *which* ops version those anchors are valid for, why, and the
machinery that turns a future ops change into a loud failure instead of silent rot.

## The fact that shapes everything: flaplint's verdict is ops-version-invariant

flaplint reads charm source **as text** and never imports or runs ops. So its verdict on
a snippet is identical no matter which ops version is installed — it can't change when
ops changes. That has one good consequence and one awkward one:

- **Good:** a charm written for ops 2.x and one for ops 3.x are analysed the same; there
  is no per-charm "which ops" branching to get wrong.
- **Awkward:** the anchored *assumptions* (e.g. "`relation.units` is unordered") are
  baked in once, globally. They are only correct if they hold for **every ops version a
  charm might actually run on**. And because flaplint never sees ops, it cannot notice
  on its own when one stops holding — coverage would just rot silently.

So the question isn't "which single ops version do we target" — it's "across which
*range* of ops versions are our assumptions true," plus "how do we get told when that
stops being the case."

## The range we anchor on

We anchor on the semantics that are **invariant across the whole window of ops versions
a *supported Juju LTS* can run** — not a single pinned version.

- **Floor — ops 2.x** (constant `OPS_FLOOR = "2.23"` in [`tests/drift/corpus.py`](../tests/drift/corpus.py)).
  The oldest ops a supported Juju LTS can run is via **Juju 2.9 LTS → Ubuntu Focal 20.04
  → Python 3.8 → ops 2.x**; ops 2.23 is the supported 2.x LTS line. ops 1.5 is
  end-of-life (2024-04), so 2.x is the real floor.
- **Ceiling — latest ops 3.x** (3.8 at time of writing; whatever CI installs).
- ops officially supports Juju **2.9 (LTS)**, **3.6 (LTS)**, and **4.0**, which all fall
  inside this window.

The semantics flaplint actually depends on — `units` is an unordered `set`, `.data` is
the databag mapping, `.save` serialises fields, `get_relation` yields a Relation,
`container.push`/`add_layer`/`list_files` exist and mean what we assume — are **stable
across that entire 2.x–3.x window**. So flaplint's single, version-free assumption is
correct for *any* charm a person could deploy on a supported Juju. That is exactly the
property the machinery below exists to keep verifying.

Sources: [ops tool-versions / support policy](https://canonical.com/juju/docs/ops/latest/explanation/versions/),
[Juju roadmap & releases](https://documentation.ubuntu.com/juju/3.6/reference/juju/juju-roadmap-and-releases/).

## The three ways ops can drift, and what catches each

| ops change | flaplint's failure | direction | caught by |
|---|---|---|---|
| **renames/removes** an anchor (`relation.data` → `.databag`) | stops recognising the sink/source | silent **false negative** | [`test_api_anchors.py`](../tests/drift/test_api_anchors.py) — `import ops; hasattr(...)` fails loudly on the next bump |
| **changes semantics** of an anchor (`units` becomes sorted) | keeps flagging a now-stable value | **false positive** | the **oracle** below — the anchor's semantic check flips and names the affected cases |
| **adds a shape** we never knew (`relation.publish(...)`) | never looks for it | silent **false negative** | nothing automatic (the unknown-unknown); coverage only ratchets up as we add cases for new shapes |

## The machinery

Three files, layered. Each is a named, standard kind of test — worth recognising so the
intent is clear:

| file | standard technique | what it pins |
|---|---|---|
| `test_api_anchors.py` | **API contract test** (against the third-party ops surface) | the ops symbols flaplint matches on still *exist* |
| `corpus.py` + `test_corpus_verdicts` | **ground-truth labelled corpus**, run as a **regression/characterization test** | flaplint's *verdict* on each case still matches its known label |
| `test_corpus_anchor_oracle` | a **test oracle** | the ops *semantics* each label assumes still hold |

The labelled-corpus method is exactly how static analysers are evaluated and regression-
tested in the wild — a curated set of flaw/clean cases with **ground-truth labels** (the
NSA [Juliet test suite](https://samate.nist.gov/SARD/test-suites/112), the
[OWASP Benchmark](https://owasp.org/www-project-benchmark/)), where the tool's measured
verdict is checked against the label. The **oracle** layer is a separate idea: the labels
are valid *only under stated assumptions* (`units` is unordered, …), so the oracle
independently verifies those assumptions against the live dependency rather than trusting
them forever.

Now the three files in detail:

1. **[`tests/drift/test_api_anchors.py`](../tests/drift/test_api_anchors.py) — existence (contract).** Asserts
   each anchored ops member still exists. Catches **renames/removals** the moment the dev
   `ops` is bumped. (Asserts existence only, which is why the next layer is needed.)

2. **[`tests/drift/corpus.py`](../tests/drift/corpus.py) — a labelled flap/clean corpus.** ~23
   snippets, each with a known verdict *and* the ops/stdlib assumptions its verdict rests
   on (`anchors`). It serves two tests:

   - **regression net** (`test_corpus_verdicts`): flaplint's verdict on each snippet must
     match its label. Catches *flaplint's own* regressions (an engine edit that breaks
     `relation.units` detection fails here). Runs without ops.
   - **ops-drift oracle** (`test_corpus_anchor_oracle`): for each ops-typed anchor, assert
     its semantic still holds against the **installed** ops; on failure, list every case
     the change would mislabel. This is the **only** test that can see a *semantic* drift,
     precisely because flaplint's own verdict never moves with the ops version. The
     anchor is the seam: the corpus says "this verdict assumes `units` is unordered," the
     oracle says "is `units` still unordered on this ops?"

   Each assumption is registered as an `Anchor` with a `check(ops) -> bool` (or `None` for
   frozen stdlib/language facts like "`set` is unordered"). An unregistered or unused
   anchor is itself a test failure, so the corpus stays honest.

### Running it as a matrix

Locally the oracle validates against whatever ops is installed. The **decision** is that
CI runs it against an **ops version matrix — `{OPS_FLOOR, latest-3.x}`** (and ideally a
couple in between). The meaning:

- a semantic that passes across the whole matrix → safe for every charm in the supported
  window, no version-awareness needed (today's situation);
- a semantic that passes on one end and fails on the other → it has **diverged** at some
  ops version, and a single global assumption is no longer correct.

The committed `uv.lock` pins `ops` for *reproducible* local/dev runs (whatever the lock
resolved — `ops==3.8` for Python ≥3.10, `ops==2.23` below it), so a plain `uv sync` is
deterministic. That determinism is the opposite of what the drift matrix wants, so the
matrix job must *override* the lock: install each end explicitly — e.g.
`uv pip install 'ops==2.23.*'` and `uv pip install 'ops'` (latest) — or
`uv lock --upgrade-package ops` before running the oracle, so a newly released ops
*surfaces* instead of being frozen behind the lock. The lock keeps day-to-day runs
stable; the matrix is what deliberately steps outside it to hunt drift.

## The escape hatch, if a semantic ever genuinely diverges

We do **not** build this now (nothing diverges across 2.x–3.x — YAGNI). But if a future
ops makes, say, `relation.units` sorted while charms still run on older ops, the matrix
oracle fires, and the response is to make *that one anchor* **version-aware**: read the
charm's declared ops dependency (`uv.lock` / `requirements.txt`) and branch the
rule by version (`units` unordered for `ops<N`, ordered for `ops>=N`), with the corpus
case carrying a per-range label. The `Anchor.holds_for` field is the slot for that, so
it stays a localised change rather than a redesign.

## Maintenance

- **Bump `OPS_FLOOR`** only when a Juju LTS leaves support and takes an ops 2.x floor
  with it.
- **Add a corpus case** whenever you teach the engine a new ops shape — coverage of the
  known surface only ratchets up.
- On an **ops major bump**, run the matrix and skim the ops release notes for
  relation/databag/pebble changes; pair with `--explain-gaps` over the charm corpus to
  surface any recognised-but-untraceable new writes.
