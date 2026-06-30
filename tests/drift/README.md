# tests/drift — ecosystem-drift guards

A special kind of test: these don't check flaplint's own logic (that's `tests/unit/`).
They guard against **drift in the ops/pebble API surface** flaplint anchors on — the one
external thing that can quietly invalidate the analyzer's assumptions.

Each file is a named, standard kind of test (so the intent reads clearly):

- **`test_api_anchors.py`** — an **API contract test** against the third-party ops
  surface: asserts each anchored ops member still *exists* (catches a rename/removal on an
  ops bump).
- **`corpus.py`** — a **ground-truth labelled corpus** (the way SAST tools are evaluated —
  cf. the NSA Juliet suite, the OWASP Benchmark): a flap/clean corpus, each case tagged
  with the ops/stdlib assumptions its verdict rests on.
- **`test_corpus.py`** — runs the corpus two ways: a **regression/characterization test**
  (`test_corpus_verdicts` — flaplint's verdict must match each ground-truth label) and a
  **test oracle** (`test_corpus_anchor_oracle` — each label's ops assumption must still
  hold against the installed ops, naming the cases any drift would invalidate).

The `test_api_anchors` and oracle tests require `ops` installed (`uv sync` installs the
dev group: pytest + ops) and skip otherwise; the corpus regression net runs without it.

Run against an **ops version matrix** (`{OPS_FLOOR, latest-3.x}`) in CI. Full rationale —
which ops versions we anchor on, why, and the technique table for these three files — is
in [`docs/ops-version-anchoring.md`](../../docs/ops-version-anchoring.md#the-machinery).
