# ops version anchoring and drift detection

## The short answer

flaplint works with **any charm targeting a supported Juju LTS** — no version
configuration required. It reads charm source as text and never imports or runs ops,
so its verdict on a snippet is identical no matter which ops version is installed.

The ops API shapes it anchors on (`relation.units`, `relation.data[entity]`,
`relation.save`, `container.push`, `add_layer`) are **stable across the entire
ops 2.x–3.x range** — which covers every charm a person could deploy on a supported
Juju today.

## What "anchoring on a range" means

flaplint's assumptions ("`relation.units` is unordered", "`.data` is the databag
mapping") are baked in globally — it can't branch per charm. For that to be safe, the
assumptions must hold for *every* ops version a charm might run on.

**Floor — ops 2.x** (`OPS_FLOOR = "2.23"` in
[`tests/drift/corpus.py`](../tests/drift/corpus.py)): the oldest ops a supported Juju
LTS can run (Juju 2.9 LTS → Ubuntu Focal → Python 3.8 → ops 2.x). ops 1.5 is
end-of-life (2024-04), so 2.x is the real floor.

**Ceiling — latest ops 3.x** (whatever CI installs; 3.8 at time of writing). ops
officially supports Juju 2.9 (LTS), 3.6 (LTS), and 4.0, all of which fall inside this window.

## How drift is caught

Since flaplint never imports ops, it can't notice on its own when an assumption stops
holding — coverage would silently rot. Three test layers catch this instead:

| ops change | failure mode | caught by |
|---|---|---|
| **renames/removes** an anchor (`relation.data` → `.databag`) | stops recognising the sink/source — silent false negative | [`test_api_anchors.py`](../tests/drift/test_api_anchors.py) — `hasattr(ops, ...)` fails on the next bump |
| **changes semantics** of an anchor (`units` becomes sorted) | keeps flagging a now-stable value — false positive | the corpus oracle below |
| **adds a new shape** we never knew (`relation.publish(...)`) | never looks for it — silent false negative | nothing automatic; coverage ratchets up as new shapes are added |

### The three test files

| file | technique | what it verifies |
|---|---|---|
| `test_api_anchors.py` | API contract test | the ops symbols flaplint matches on still *exist* |
| `corpus.py` + `test_corpus_verdicts` | labelled corpus / regression test | flaplint's verdict on each case still matches its known label |
| `test_corpus_anchor_oracle` | test oracle | the ops *semantics* each label assumes still hold against the installed ops |

**`test_api_anchors.py`** asserts each anchored ops member still exists. Catches
renames and removals the moment the dev `ops` is bumped.

**`corpus.py`** is ~23 labelled snippets — each with a known verdict (`flap` /
`clean`) and the ops/stdlib assumptions its verdict rests on (`anchors`). It feeds
two tests:
- **`test_corpus_verdicts`** — regression net: flaplint's verdict on each snippet must
  match its label. Catches engine regressions (an edit that breaks `relation.units`
  detection fails here). Runs without ops.
- **`test_corpus_anchor_oracle`** — for each anchor, asserts its semantic still holds
  against the *installed* ops; on failure, lists every corpus case the drift would
  mislabel. This is the only test that can detect a *semantic* drift, because
  flaplint's own verdict never moves with the ops version. An unregistered or unused
  anchor is itself a test failure, keeping the corpus honest.

### Running the oracle as a matrix

Locally the oracle validates against whatever ops is installed. In CI the intent is
to run it against **`{OPS_FLOOR, latest-3.x}`** (and ideally versions in between):

- a semantic that passes across the whole matrix → safe for every charm in the window;
- a semantic that passes on one end but fails on the other → it has diverged, and the
  single global assumption is no longer correct.

The committed `uv.lock` pins ops for reproducible local runs (`ops==3.8` for
Python ≥3.10, `ops==2.23` below). For the drift matrix, override the lock:
`uv pip install 'ops==2.23.*'` and `uv pip install 'ops'` (latest), or
`uv lock --upgrade-package ops` to surface a newly released ops. The lock keeps
day-to-day runs stable; the matrix deliberately steps outside it.

## Design decision: escape hatch if semantics ever diverge

We do **not** build this now (nothing diverges across 2.x–3.x — YAGNI). But if a
future ops makes `relation.units` sorted while charms still run on older ops, the
matrix oracle fires. The response: make *that one anchor* version-aware — read the
charm's declared ops dependency (`uv.lock` / `requirements.txt`) and branch the rule
by version, with the corpus case carrying a per-range label. `Anchor.holds_for` is
the slot for that, so it stays a localised change rather than a redesign.

## Maintenance

- **Bump `OPS_FLOOR`** only when a Juju LTS leaves support and takes the ops 2.x
  floor with it.
- **Add a corpus case** whenever you teach the engine a new ops shape — coverage of
  the known surface only ratchets up.
- **On an ops major bump**, run the matrix and skim the ops release notes for
  relation/databag/pebble changes; pair with `--explain-gaps` over the charm corpus to
  surface any recognised-but-untraceable new writes.
