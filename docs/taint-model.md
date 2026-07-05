# What flaplint detects

This page explains *what makes a value unstable* in flaplint's eyes and *how it changes* as the value moves through your code. [sinks-and-findings.md](sinks-and-findings.md) builds on the vocabulary introduced here.

## The question flaplint asks

For any value reaching a sink, flaplint asks:

> If this value is written to a databag (or a file, or a hash) on two otherwise-identical reconciles, will the text be the same both times?

If yes → stable, no finding. If no → unstable, and *why* it's unstable determines both the fix and whether a given serializer can save you.

## Patterns flaplint catches

Here are the concrete patterns, grouped by what makes them flap and what fixes them. Each one names the `type=` value you'll see in a finding (`--format concise` / `--json`), so you can match what you're reading here to what the tool actually printed.

### Pattern 1: Unordered dict keys written directly

```python
config = {u.name: u.app.name for u in relation.units}   # dict — key order not fixed
databag["config"] = json.dumps(config)                    # key order varies each reconcile
```

**What's wrong:** the dict is built by iterating over `relation.units`, which is an unordered set. The key order follows whatever order the set happens to produce — different each reconcile.

**Fix:** `json.dumps(config, sort_keys=True)` — or `yaml.dump(config)` (sorts keys by default).

**Why key-sorting is enough here:** the *entire* disorder is in the dict's key order. `sort_keys=True` locks key order alphabetically regardless of how the dict was built, so the output is identical every reconcile.

Reported as `type=unordered-collection`.

### Pattern 2: List built from an unordered source

The critical difference from Pattern 1: **once you convert a set to a list, the disorder moves from key order into element positions** — and key-sorting is blind to element positions.

```python
addrs = list(self.endpoints)               # set → list: element order is now baked in
databag["addrs"] = json.dumps(addrs)       # flaps even with sort_keys=True
```

**What's wrong:** `json.dumps(addrs, sort_keys=True)` sorts dict *keys* inside the JSON but leaves the list elements in whatever order they came out of the set. `[c, a, b]` stays `[c, a, b]` — the serializer never touches it.

**Fix:** `list(sorted(self.endpoints))` — sort *before* materialising the list.

The same problem appears in comprehensions and loops:

```python
addrs = [ep.address for ep in self.endpoints]   # endpoints is a set — same flap
addrs = []
for ep in self.endpoints:                        # loop materialises the same disorder
    addrs.append(ep.address)
```

And in joins — joining bakes the set's order into the resulting string, which nothing can reorder:

```python
joined = ",".join(self.endpoints)   # same as list(set): string bakes in the order
```

Reported as `type=unordered-iteration` — the instability survives any key-sorting serializer. It's the most easily missed case by hand, and the central distinction flaplint exists to catch.

### Pattern 3: Positional pick from an unordered source

```python
first_addr = list(self.endpoints)[0]   # which item is "first" depends on the run
databag["primary"] = first_addr
```

**What's wrong:** picking by position from an unordered collection gives a different item each time.

**Fix:** `sorted(self.endpoints)[0]` — sort before picking so "first" is deterministic.

Reported as `type=unordered-pick`.

### Pattern 4: A different-every-run value

```python
databag["nonce"] = str(uuid4())    # different every reconcile, no matter what
```

**What's wrong:** `uuid4()`, `time()`, `random()`, and similar calls produce a new value every time the code runs. No sorting can help — the value itself changes, not just its order.

**Fix:** derive the value deterministically (e.g. from something stable, like an app name), or persist it once and reuse it.

Reported as `type=nondeterministic`.

### Pattern 5: A helper that trusts its caller

```python
def publish(self, relation, items):               # no type hint on items
    relation.data[self.app]["peers"] = json.dumps(items)   # writes items unsorted
```

flaplint can't see what `items` will actually hold, but it can see that if any caller passes an unordered value, it'll be written to the databag without sorting. This is flagged as a `kind=sink` finding (medium confidence) — a helper that trusts its caller to pass ordered data.

If a caller is traced passing an unstable `items`, a higher-confidence `kind=caller` finding is emitted at the call site instead.

**The mirror image — a helper that promises a set.** An accessor annotated to *return* a set is trusted the same way a `: Set` parameter is:

```python
@property
def peer_addresses(self) -> set[str]:      # promises an unordered collection
    return self._compute()                 # …even though the body is opaque

databag["peers"] = ",".join(self.peer_addresses)   # caught: joins a set unsorted
```

flaplint can't trace `_compute()`, but the `-> set[str]` annotation asserts the result is unordered — so a caller that materialises or serialises it without `sorted()` is flagged, pointing back at the annotated `def`. Only the **set family** (`set`, `frozenset`, `Set`, `FrozenSet`, `AbstractSet`, `MutableSet`) counts here: a `-> Iterable`/`-> Collection` return is usually an ordered generator, so — unlike for a *parameter* — it is deliberately not treated as unordered (return-type inference asserts the value *is* unordered and drives concrete findings, so it stays tight).

When a property's body *is* traceable, whatever instability it returns reaches its readers — not just a plain set. A property that turns a set into a list internally (`return [dict(t) for t in {tuple(d.items()) for d in raw}]`, a common dedup idiom) still flags a reader that serialises `consumer.endpoints`, exactly as if the reader had built that list itself (Pattern 2).

### Pattern 6: Unstable value stored in a field or on `self`

**What's wrong:** storing an unstable value in a dataclass field, a Pydantic model field, on `self`, or under a constant dict key doesn't make it stable — the instability is in the value itself, not in the variable name it's read back through.

**Fix:** sort when the value is first created (`self._endpoints = sorted(...)`), or at the point of use (`sorted(self._endpoints)`).

```python
# Dataclass / value object
@dataclass
class Cfg:
    endpoints: set[str]
    name: str

cfg = Cfg(endpoints=set(hosts), name="primary")
databag["hosts"] = json.dumps(list(cfg.endpoints))   # caught: cfg.endpoints is still a set
```

```python
# Instance attribute, across methods
class Provider:
    def __init__(self):
        self._endpoints = {u.name for u in self.relation.units}   # stored on self

    def publish(self, databag):
        databag["hosts"] = json.dumps(list(self._endpoints))      # caught: self._endpoints is unstable
```

```python
# Dict by constant key — each key tracked independently
self.cfg["jobs"] = set(hosts)
databag["jobs"] = json.dumps(list(self.cfg["jobs"]))   # caught: this key is unstable
databag["name"] = json.dumps(self.cfg["name"])          # clean: a sibling key is unaffected
```

This is field-by-field, not all-or-nothing: `cfg.name` stays clean even though `cfg.endpoints` is unstable. It also carries across a function return (`cfg = self._build_cfg(); cfg.endpoints` is caught if `_build_cfg` returns an object with an unstable field) and follows a chain of attributes to any depth (`self.ctx.config.targets` works the same as `self.targets` — though a call or an index partway through the chain breaks it; see [What flaplint misses](architecture.md#what-flaplint-misses)).

### Pattern 7: Filesystem listing

`glob`, `listdir`, `scandir`, and `iterdir` return files in **filesystem order**, which is not guaranteed to be consistent across runs — it follows inode order, not alphabetical.

```python
alert_files = glob.glob("/etc/rules/*.yaml")      # order is not predictable
databag["alerts"] = json.dumps(alert_files)        # caught: list order flaps
```

**What's wrong:** the filesystem can return the same set of files in a different order between container restarts or after any file sync. Each reconcile the databag sees a different list.

**Fix:** `sorted(glob.glob("/etc/rules/*.yaml"))` — sort immediately after the listing.

This applies to any directory-listing call: `os.listdir`, `Path.iterdir`, `os.walk`.

### Pattern 8: Jinja template render with unstable values

flaplint treats `.render(...)` as opaque — it can't see inside the template — so it assumes the **rendered output is as unstable as the values passed in**.

```python
config = template.render(
    peers=list(self.endpoints),    # set → list → itercaller
    name=self.app.name,            # stable
)
container.push("/etc/app/config.yaml", config)    # caught: output inherits itercaller
```

**What's wrong:** even though the template itself is a fixed text file, its output depends on the order the inputs appear. An unstable list passed in produces unstable rendered text — the config will reshuffle every reconcile.

**Fix:** sort the unstable inputs before passing them: `sorted(self.endpoints)`.

The rendered text inherits the instability kind of its inputs — if `itercaller` goes in, `itercaller` comes out. If all inputs are stable, the render is stable.

### Pattern 9: Pydantic model with an unstable list field

`model_dump_json()` writes field names in fixed order — it acts like a key-sorting serializer. But like any key-sorting serializer, it only fixes key (field-name) order. A field whose value is itself a list built from an unordered source still flaps.

```python
class UnitData(BaseModel):
    dashboards: list[str]

data = UnitData(dashboards=list(glob.glob("*.json")))   # list from glob → itercaller
relation.data[app]["d"] = data.model_dump_json()         # caught: field names are fixed;
                                                          # list elements are not
```

**What's wrong:** `model_dump_json` writes the list in element order — the same way `json.dumps` would. The field name "dashboards" is always in the same place, but the elements inside `[...]` reshuffle every reconcile.

**Fix:** `sorted(glob.glob("*.json"))` — sort before constructing the model.

**A bare `set` handed to a list field is caught too.** Pydantic's `__init__` coerces the value into the field's declared type, so a `set` passed to a `list`/`tuple`/`Sequence` field is turned into a positionally-ordered sequence *inside the model* — its disorder moves from key order (which key-sorting fixes) into element order (which it can't):

```python
class Cfg(BaseModel):
    hosts: list[str]                       # __init__ runs list(hosts) internally

cfg = Cfg(hosts=set(peers))                # set → list field: promoted to itercaller
relation.data[app]["h"] = cfg.model_dump_json()          # caught (not laundered)
relation.data[app]["h"] = json.dumps(cfg.hosts, sort_keys=True)  # caught on read-back too
```

flaplint reads the model's field annotation to recognise this. It applies to a **set** handed to a **list/tuple-typed** field on a model that subclasses `BaseModel` **directly**: a `Set[str]`-typed field keeps set semantics (still just key order, still fixed by sorting), and a plain `@dataclass` doesn't coerce at all, so this specific promotion doesn't apply there (see [What flaplint misses](architecture.md#what-flaplint-misses)).

**Pydantic v1 note:** the v1 spellings `.json()` / `.dict()` take the conservative path — they inherit *all* receiver taint, so they also catch the field-value flaps above (and are the reason the pre-annotation-aware analysis still caught the `list(...)` case).

---

## What each serializer does

You don't need to memorise this to use flaplint — it explains *why* the fixes above work, for anyone who wants the reasoning rather than just the rule.

Serializers come in two kinds:
- **plain** — `str`, `repr`, `.encode()`, `json.dumps(x)` without `sort_keys`. Output follows input order exactly.
- **key-sorting** — `yaml.dump` / `yaml.safe_dump`, `json.dumps(sort_keys=True)`, a Pydantic dump. These put *mapping keys* in alphabetical order, and nothing else.

That "and nothing else" is the crux of the whole tool: key-sorting fixes Pattern 1 (dict key order) but does **nothing** for Patterns 2–4 (a list's element order, a positional pick, a fresh-every-run value) — those need to be fixed at the source, not at the write.

| pattern | survives `str()` / `repr()` | survives a key-sorting serializer |
|---|:---:|:---:|
| 1 — dict keys (`type=unordered-collection`) | yes | **no** — key-sorting fixes it |
| 2 — list from a set (`type=unordered-iteration`) | yes | yes — needs `sorted()` before the list is built |
| 3 — positional pick (`type=unordered-pick`) | yes | yes — needs `sorted()` before picking |
| 4 — fresh value (`type=nondeterministic`) | yes | yes — no serializer can fix it |

The single most common bug this tool exists to catch — and the one simpler checkers miss — is **a list-from-a-set surviving a key-sorting serializer** (Pattern 2): it looks like "just another collection" but key-sorting can't touch element order.

<details>
<summary>Internal vocabulary (for reading flaplint's own source or code comments)</summary>

Internally, the engine tracks *why* a value is unstable with one of six short labels, used throughout the codebase and its comments. They don't appear in any finding — a finding's `type=`/`kind=` fields (above) are what you'll actually see — but this table is here as a Rosetta stone if you're reading the source.

| internal label | what it means | roughly maps to |
|---|---|---|
| `local` | a bare set/dict/glob — disorder is at the key-order level | Pattern 1 |
| `itercaller` | a list/string/tuple materialised from an unordered source | Pattern 2 |
| `element` | one item picked by position out of something unordered | Pattern 3 |
| `volatile` | a value that's different every run | Pattern 4 |
| `iterparam` | a list built by looping over a *parameter* — caller decides the order | `type=unordered-iteration`, `kind=sink` |
| `param` | a stand-in for "as unstable as parameter N", resolved at each call site | how a `kind=sink` finding is computed |

</details>

## Where unstable values come from (sources)

### Things with no fixed order

- **Sets**: `set(...)`, `frozenset(...)`, set literals `{a, b}`, set comprehensions `{x for x in …}`
- **Set math**: `a | b`, `a & b`, `a - b`, and so on
- **Directory listings**: `glob`, `listdir`, `scandir`, `walk`, `iterdir`, … — filesystem order is not guaranteed
- **`relation.units`** — the set of units in a relation; order varies run-to-run
- **A `Set`-typed attribute on a known class** — reading `x.attr` where `x`'s declared type is a class with `attr` annotated `Set`/`frozenset` (`event.certificates` on an event whose `__init__` takes `certificates: Set[str]`, or a class-body `hosts: Set[str]`). The class is resolved from the variable's own type (a parameter annotation or a constructor call) — no class or attribute name is special-cased. An untyped receiver, or a `list`-typed attribute, stays conservative (no finding).

### Values that differ every run

`uuid4()` and its siblings, `time()`, `random()` and related functions, `token_hex()`, and so on.

### Parameters — "as unstable as whatever the caller passes"

A reference to a function's own parameter is recorded as "as unstable as parameter N" — a placeholder resolved at each call site. This is how "does this function write an unstable argument?" is answered without re-analysing the callee every time it's called.

## How a value changes as it moves (propagation)

### Instability propagates by default

flaplint follows the standard taint model: **an unknown call carries its arguments' instability forward unless something explicitly launders it.** A wrapper, constructor, formatter, or codec all *hold* or *reformat* their input, so order instability survives — `ops.pebble.Layer(plan_dict)`, `SomeConfig(hosts=set)`, `codec.encode(x)` are all as unstable as what went in. This is a *denylist*, not an allowlist: rather than enumerating every transparent wrapper (which is open-ended — every new library adds one), only the bounded set of **launderers** stops propagation:

- explicit sorts (`sorted`, `.sort()`) and key-sorting serializers (`yaml.dump`, `json.dumps(sort_keys=True)`) — remove order instability;
- **order-independent reducers** (`len`, `min`, `max`, `sum`, `any`, `all`, `count`, `bool`, …) — collapse a collection to a scalar the order can't affect;
- content re-determined from elsewhere (`.split()`, `.read()`).

So `ops.pebble.Layer({… "HOSTS": ",".join(set) …})` carries that instability across a property return to the `add_layer(…)` plan sink with no special-casing, while `len(set)` or `sorted(x)` launder cleanly. Two things are *not* propagated this way: a call to a method flaplint has analysed trusts that method's own summary instead (a `render()` that sorts internally is correctly seen as clean), and constructing a stateful helper object (`Patroni(peer_ips, …)`) does not taint the object itself — only the specific state it's later told to store (see [Pattern 6](#pattern-6-unstable-value-stored-in-a-field-or-on-self)).

A template render (`template.render(x=…)`) is treated the same way — flaplint can't see inside the template, so it assumes the rendered text is as unstable as the values handed in. This catches the common pattern of rendering a config from Jinja and writing it to a file.

**Tuple unpacking is tracked per position.** `rw, ro, _ = self.get_cluster_endpoints(...)` binds each name its *own* slot's taint: if the helper returns `",".join(rw_set), ",".join(ro_set), …` (three joins of sets), both `rw` and `ro` flap into the databag while the discarded `_` is ignored — the mysql "self-defeating endpoint guard" flap. Position taint comes from a matching-arity literal (`a, b = x, sorted(y)`) or a resolved callee's per-position return summary; a *stable* slot unpacked alongside an unstable one stays clean (`cert, key = get_assigned_certificate()` — the `key` doesn't inherit the certificate's SAN instability). When neither is available (a starred target, an opaque callee), the targets are left clean rather than smeared.

### Things that make a value stable again

- `sorted(...)` and `.sort()` make a value stable.
- A key-sorting serializer fixes Pattern 1 (dict key order) but leaves Patterns 2–4 intact.
- **`str.split` / `rsplit` / `splitlines`**: splitting a string gives back a list in left-to-right order, never in a collection's order — so the loop is predictable. (A fresh-every-run string's *content* still carries through, though.)
- **`isinstance(x, <ordered type>)` check**: inside `if isinstance(raw, list):`, the "caller might pass something unordered" worry is cleared, because the caller can't pass a bare set through that branch. (It only clears that contract-boundary worry, not a concrete flap — a real `list(some_set)` built *inside* the check still flags.)

### Things that make instability worse

Three shapes turn a milder flap into a more stubborn one:

1. **Picking by position** (Pattern 3): `unordered[0]` grabs one item whose identity depends on run-to-run ordering, and no serializer can fix that. Reading a field off that pick stays unstable too — `list(peers)[0]["ip"]` (at any depth of chaining) flaps just as `list(peers)[0]` does, because the whole picked object flaps. That only applies to a genuine positional pick, though: a fixed-key read off a plain parameter or a locally-built dict (`config["endpoint"]`) stays clean on its own, since a mapping's individual keys are order-stable regardless of how the mapping was built.

2. **Building a list from a set** (Pattern 2): `list(some_set)`, `tuple(relation.units)`, `[x for x in some_set]`, a loop accumulator (`for u in relation.units: eps.append(…)`). The list's item order now carries the disorder for good. A `set` or `dict` accumulator doesn't have this problem — its disorder stays at the key-order level, which a key-sorting serializer still fixes.

   A few idioms worth knowing by name, because they're easy to miss by eye:
   - **`enumerate` on an already-flapping list** carries the flap through, so an index-keyed dict (`{f"k-{i}": e for i, e in enumerate(eps)}`) still flaps even though its keys sort.
   - **`enumerate` over an unordered source** pins a positional index to each value, so the loop *value* itself becomes as stubborn as the picks above: `for i, cert in enumerate(some_set): write(f"{i}.crt", cert)` writes each `cert` under a stable index `i` whose *content* still flaps run-to-run. The fix is `sorted()` before `enumerate`.
   - **Mutating a nested element** (`template["sinks"].update(eps)`) makes the whole `template` unstable, so a later `yaml.dump(template)` is caught.
   - **Merging one mapping into another** (`certs.update(other)` on a plain `dict`) folds `other`'s key-insertion order into `certs`, so `certs` inherits its instability the same way a loop doing the same thing would.
   - **Building an x509 SAN from a set** (`x509.SubjectAlternativeName(set(sans))`) bakes the set's order into an order-significant certificate field, so the certificate's bytes reshuffle every time it's (re)issued — even if the charm itself passed in a sorted list. This is the classic TLS flap where the *library* re-shuffles a value the charm already sorted, so it usually shows up as a dependency finding rather than one in the charm's own code.

3. **Looping a parameter (not a concrete value) into a list**: the caller decides the order here, not this function, so it's flagged as the "helper trusts its caller" case (Pattern 5) rather than a confirmed bug.


## A worked example

```python
group_by = set(route.get("group_by", []))               # Pattern 1: a bare set
group_by = list(group_by.union(["juju_model"]))         # Pattern 2: list built from a set
config["route"]["group_by"] = group_by
return yaml.safe_dump(config)                           # sorts keys — but not list items
```

`yaml.safe_dump` sorts `config`'s keys but can't reorder the `group_by` list's elements. Because the disorder already moved into the list (Pattern 2) by the time it reaches `yaml.safe_dump`, it survives the key-sorting and gets reported — pointing at the `list(...)` line where `sorted(...)` belongs, not at the `yaml.safe_dump` call. Had `group_by` stayed a plain set all the way to the write, the key-sorting would have been enough and flaplint would correctly say nothing.
