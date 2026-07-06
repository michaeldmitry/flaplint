# How flaplint works

A high-level walkthrough of what happens during a run and how the analysis is structured. For what flaplint *detects*, see [taint-model.md](taint-model.md). For the four write targets and how findings are graded, see [sinks-and-findings.md](sinks-and-findings.md).

## The idea

flaplint follows values from where they're **created** to where they're **written**, and flags the ones that are still unstable when they get there. Three moving parts:

- **Sources** — where instability enters: `set(...)`, `glob(...)`, `uuid4()`, `relation.units`, ...
- **Propagation** — how it moves: through assignments, function calls, return values, and object fields.
- **Sinks** — where it causes harm: one of four write targets.

```mermaid
flowchart LR
    S["born unstable<br/>(set · glob · uuid4 · …)"] --> P["followed through<br/>assignments · calls · returns"]
    P --> K{still unstable<br/>when written?}
    K -- yes --> F["finding"]
    K -- "no (sorted / laundered)" --> OK["stable ✓"]
```

## Background: this is taint analysis

flaplint's core analysis is a standard static-analysis technique called **taint analysis**: mark data from an untrusted **source**, follow it as it flows through the program, and raise an alarm if it reaches a dangerous **sink** without passing through a **sanitiser**. Classic taint analysis comes from security (source = user input; sink = SQL query; sanitiser = escaper). flaplint keeps that machinery and changes only what "tainted" *means*: here a value is tainted when it's **derived from an unordered or volatile source**. A `set` is a source, a databag is a sink, and `sorted()` is a sanitiser.

What's specific to flaplint is that "tainted" isn't one bit — it tracks *why* a value is unstable, because the right fix differs case by case. In particular, whether letting a serializer sort the keys is enough to save you, or whether the disorder has already been baked into a list and can only be fixed by sorting before the list is built. See [Patterns flaplint catches](taint-model.md#patterns-flaplint-catches) for the concrete cases.


## The four sinks

When an unstable value reaches any of these, it's a finding:

```mermaid
flowchart LR
    V["unstable value"] --> DB["databag\nrelation.data[app][key] = …"]
    V --> FILE["file\ncontainer.push(path, …)"]
    V --> PLAN["pebble plan\ncontainer.add_layer(…)"]
    V --> HASH["content hash\nsha256(content)"]
    DB --> WHY1["⚠ byte changes → spurious relation-changed\n→ reconcile ping-pong"]
    FILE --> WHY2["⚠ reshuffled text → unnecessary\nrerender / restart"]
    PLAN --> WHY3["⚠ changed plan → replan()\nrestarts the workload"]
    HASH --> WHY4["⚠ different hash → change-gate\nfires every reconcile"]
```

Note: `file` writes are compared character-for-character (any instability matters), while `databag`, `plan`, and `hash` are compared structurally or key-first — so a bare `set` written to a plan may be harmless if pebble sorts it, but a `list(set)` is not. See [sinks-and-findings.md](sinks-and-findings.md#the-four-write-targets) for how each sink interprets what it receives.

## The pipeline

A run is four stages, driven in order by `analyzer.py`:

```mermaid
flowchart LR
    IN[source files] --> D["1 · discover\nfind every .py file"]
    D --> C["2 · collect\nlist every function"]
    C --> S["3 · summarise\nwhat does each function do?"]
    S --> R["4 · report\nemit findings"]
    R --> OUT[findings]
```

1. **Discover** — turn the inputs into a list of Python files. Your charm's `src/` and its sibling `lib/` are scanned and reported on. Dependencies (installed packages, vendored libraries) are read to understand calls but findings inside them are only shown if you ask. See [resolving-dependencies.md](resolving-dependencies.md).
2. **Collect** — read each file once and record every function and method with its parameters and type hints.
3. **Summarise** — work out, for each function, what it does to unstable values. This stage repeats in a loop until the answers stop changing — see [The summary loop](#the-summary-loop) below.
4. **Report** — walk each primary function with the finished summaries and emit a finding wherever an unstable value reaches a sink.

## The summary loop

Stage 3 is the interesting part. The problem: to decide whether `helper(x)` in function `A` is safe, you need `helper`'s summary — but `helper` may call `A`, forming a cycle. There's no ordering that finishes every callee before its caller.

So flaplint repeats. It walks every function, fills in whatever answers it can from what's known so far, and goes around again. Each pass can only *add* facts, never remove them, so the answers keep growing until a full pass changes nothing — a **fixed point**. Order of visiting doesn't affect the final result, only how many passes it takes (usually two or three).

```mermaid
flowchart TD
    L["list every function"] --> B["walk every function\nfill in summary answers from what's known"]
    B --> B2{did any answer change?}
    B2 -- yes --> B
    B2 -- no --> R["answers are complete"]
    R --> C["report: walk primary functions\nand emit findings"]
```

What the summary records for each function:

| question | what it enables |
|---|---|
| Does this function write any of its parameters without sorting? | A caller passing an unstable value into that parameter gets a `caller` finding at the call site |
| Does it return an unstable value, and which kind? | A caller that writes the return value is flagged |
| Does it pass any of its inputs straight back through the return? | The instability flavor travels with the return |
| Does it loop any of its parameters into a list? | A `sink` finding at the loop (helper trusts caller to pass ordered data) |

This is what makes cross-function tracing work: your charm builds a `set`, passes it to a library helper that writes it to a databag two calls away, and flaplint connects the two — one function at a time, by looking up summaries instead of re-analysing callees.

## A worked example

```python
# lib/charms/foo/v0/foo.py
class Provider:
    def publish(self, relation, items):                        # 'items' has no type hint
        relation.data[self.app]["peers"] = json.dumps(items)  # ← write

# src/charm.py
def _on_changed(self, event):
    peers = {u.name for u in self.model.relations["foo"]}      # a set → unstable
    Provider().publish(event.relation, peers)                  # passes the set in
```

- **Collect** lists `Provider.publish` and `_on_changed`.
- **Summarise** walks `publish`: `items` is written straight into a databag without sorting → records `items` as a dangerous parameter.
- **Report** walks `_on_changed`: `peers` is a set (unstable). The call to `publish` passes it into the dangerous parameter → emits a finding at the call line (`kind=caller`, high confidence) and a lower-confidence finding inside `foo.py` (`kind=sink` — the helper trusts its caller).
- The fix is one word: `sorted(peers)` at the call, or sort inside `publish`.


## What the analysis anchors on

It's worth being clear about what flaplint depends on, because that tells you where it's solid and where it can drift.

**The core knows nothing about charms.** The engine — the instability labels, the forward walk, the summaries, the reasoning about what sorting fixes — is built on the Python language. It would run on any Python codebase and never changes when the charm ecosystem changes.

**Starting points and serializers are standard library.** Sets, set math, and comprehensions are the language itself. `glob`, `listdir`, `uuid4`, `time`, `sorted`, `list`, `json.dumps`, and `sort_keys=True` are standard-library names that have been stable for years.

These are matched as **names in the source text**, so flaplint isn't bound to any Python version — a charm written for 3.8 or 3.12 is read the same. One *semantic* shift that matters — dicts becoming insertion-ordered in 3.7 — is already baked in, and every charm runs 3.8+. The residual risks are: a brand-new source or serializer would be missed (a false negative), and a charm method that happens to share a name with a stdlib function (`now`, `sample`, `choice`) could be mistaken for it (a rare false positive; renamed *imports* are resolved, but same-named methods can't be distinguished).

**Only a small edge is tied to the charm world:**

| anchor | what flaplint uses it for |
|---|---|
| `model.get_relation(...)` | produces a Relation (the only way "this is a databag" starts) |
| `<relation>.data[app\|unit]` | the databag itself |
| `.update()` / `.setdefault()` / `[k]=`, `relation.save(...)` | databag writes |
| `relation.units` | an unordered source |
| `container.push` | file write |
| `container.add_layer` | pebble plan write |
| `.render(...)` | a Jinja template render (best guess) |

flaplint recognises a databag by **tracing where it came from**, not by one fixed shape: a Relation comes from `get_relation(...)`; `.data` on something *already known to be a Relation* is its mapping; indexing that by an `app`/`unit` is a databag. So a write is caught even when it's wrapped several property hops deep — and `.data` on anything else is never mistaken for a databag.

**Renamed imports are handled.** Matching is on the *name a call actually uses*, so `from uuid import uuid4 as gen` would hide `gen()`. To prevent that, the collector records each file's import aliases and the engine resolves the real name before matching — so `gen()` is treated as `uuid4`, and `import json as j` → `j.dumps` as `dumps`.

**There is no version lockstep with ops.** flaplint never imports ops — it reads source as text. It matches the API *surface* (`relation.data[...]`, `relation.units`, `container.push`), which ops has kept stable across releases. See [ops-version-anchoring.md](ops-version-anchoring.md) for how drift is caught.

## Design decisions

### Why the analysis runs forward, not backward

A backward search would start at each sink and walk toward the sources that feed it, potentially skipping functions that don't reach any sink. There are four reasons forward was chosen instead:

- **The codebase is small.** A charm scans in well under a second. The code a backward pass would skip is not worth a more complex design.
- **Forward already avoids re-work.** Each function's summary records "if you pass me an unstable argument, does it reach a sink?" — computed once and looked up at every call, never recomputed. That's the same savings a backward search buys.
- **Forward fits the actual question.** The job isn't just "does a source reach a sink" — it's *what kind* of instability and whether a serializer along the way fixes it. Those facts start at the source and change step by step as the value moves forward. Going backward, you'd reach the serializer first and have to undo its effects in reverse, which the analysis can't cleanly do.
- **Direction doesn't remove the loop.** Because calls can form cycles, you'd still need the same repeat-until-settled loop either way. The complexity saving doesn't materialise.

### Processing order doesn't change the result

The order functions are summarised (which follows the order files are read) does **not** change the final output. The fixed-point loop guarantees it, because each pass only ever *adds* facts — never removes one. Repeating that kind of update until nothing changes always lands on the same answer regardless of order.

Order only changes **how many passes** it takes. If `A` calls `B` and `A` is walked first, `A`'s summary is incomplete that pass and gets completed the next pass, once `B` is known. The analyzer doesn't try to find a good visiting order (impossible when calls form a cycle, `A`→`B`→`C`→`A`) — it just repeats until a pass changes nothing.

### Contract-boundary findings land on the direct writer, not on forwarders

A `kind=sink` finding — "this function writes one of its parameters unsorted" — only fires on the function that does the write **directly**. A function that just passes the parameter along to another writer doesn't get its own finding, even if its own parameter had a more useful type hint. Flagging every forwarder along the way would multiply one bug into many findings, so the tool deliberately reports it once, at the actual write. See [what this looks like in practice](#a-forwarded-parameters-finding-lands-on-the-writer-not-the-forwarder) in the limitations below.

## What flaplint misses

flaplint follows a value as far as its code makes that possible — through local variables, function calls, return values, object fields (to any depth of plain attribute access, and across methods of the same object). Past that, tracking loses the thread and the value looks stable even though it isn't. That's a **false negative**: no crash, no wrong finding, just silence where there should have been one. Nothing below produces an incorrect finding — they're all things that stay quiet when they shouldn't.

The common thread: **a value that takes an unusual detour on its way to a write** — through an index or a variable dict key — can lose flaplint partway through. A value that goes straight from where it's built to where it's written is always caught; it's the indirection in between that matters.

### A value reached through an index

```python
self.ctx.config.targets = set(x)   # caught — a plain chain of attributes, any depth
ctx = self.get_ctx()               # caught — a getter that returns self.<attr> is
ctx.targets = set(x)               #          followed as an alias of that attribute
self.items[0].targets = set(x)     # missed — an index into a list breaks the chain
```

flaplint follows a chain of plain attribute access (`self.ctx.config.targets`) to any depth, in one method or across several — including a value stored on `self` in one method and read back in another, through a builder object assembled by a separate `build()`, or through a *getter* that returns one of its own attributes (`return self._ctx`), whose result is treated as an alias of that attribute. What it still can't follow is a **subscript** in the middle of the chain: `self.items[0].targets` reaches a field on a *list element*, and which element `[0]` is isn't a stable slot flaplint can name — so a value stored there, and read back there, looks stable.

### A cross-object call through an unannotated attribute

```python
class Manager:
    def __init__(self, charm: "MyCharm"):   # type hint present: resolves
        self.charm = charm
    def go(self): push(",".join(self.charm.peer_ips))   # caught

class Cluster:
    def __init__(self, charm):              # no type hint: opaque
        self.charm = charm
    def go(self): push(",".join(self.charm.peer_ips))   # missed
```

Reaching into another object's data (`self.charm.peer_ips`) only works when flaplint knows what class `self.charm` actually is. That's usually obvious (`self.x = SomeClass(...)`), but for the common "hold a reference back to the charm" pattern, it depends on a type hint on the parameter that gets assigned to `self.charm`. Add the hint and the call resolves; leave it off and the call looks opaque.

### A value looked up by a variable dict key

```python
cfg["peers"] = set(x)         # caught — the constant key "peers" is tracked
cfg[key] = set(x)             # missed — a variable key: which slot even is this?
```

flaplint tracks which dict *key* holds an unstable value, so a sibling key stays clean even when this one isn't. That only works for a literal string key — once the key itself is a variable, there's no fixed slot to remember.

### A Pydantic model two or more subclasses away from `BaseModel`

```python
class _Base(BaseModel): ...
class Cfg(_Base):           # one step removed from BaseModel — not recognised
    hosts: list[str]
cfg = Cfg(hosts=some_set)   # the set → list coercion is missed here
```

Pydantic silently turns a `set` handed to a `list`-typed field into an ordered list — which flaplint treats as its own small flap. It recognises that coercion for a model that subclasses `BaseModel` directly. An intermediate base class in between isn't followed, so this specific promotion is missed (everything else about the model is still tracked normally).

### A forwarded parameter's finding lands on the writer, not the forwarder

```python
def set_endpoints(self, endpoints: Iterable[str]):
    self._write_databag("endpoints", endpoints)   # just forwards — no finding here

def _write_databag(self, key, value):             # the finding lands here instead
    self.relation.data[self.app][key] = json.dumps(value)   # value has no type hint
```

By design, not an accident: only the function doing the **actual write** gets a "this parameter is written unsorted" finding, even when an earlier, better-annotated function in the chain would have made a clearer one. Flagging every forwarder along the way would turn one bug into a pile of findings, so the tool reports it once, where the write happens — see [why](architecture.md#contract-boundary-findings-land-on-the-direct-writer-not-on-forwarders).

### Anything defined in a dependency you didn't include in the scan

If a library function returns something unstable and that library wasn't part of the scan, the return value looks stable — flaplint has nothing to read. Point `--venv` or `--python` at your dependencies (usually auto-detected already) so their code is included.

---

Run with `--explain-gaps` to get a worklist of writes flaplint could see but couldn't fully trace — a starting point for manually checking the spots above.

---


