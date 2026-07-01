# What flaplint detects

This page explains *what makes a value unstable* in flaplint's eyes and *how it changes* as the value moves through your code. [sinks-and-findings.md](sinks-and-findings.md) builds on the vocabulary introduced here.

## The question flaplint asks

For any value reaching a sink, flaplint asks:

> If this value is written to a databag (or a file, or a hash) on two otherwise-identical reconciles, will the text be the same both times?

If yes → stable, no finding. If no → unstable, and *why* it's unstable determines both the fix and whether a given serializer can save you.

## Patterns flaplint catches

Here are the concrete patterns, grouped by what makes them flap and what fixes them.

### Pattern 1: Unordered dict keys written directly

```python
config = {u.name: u.app.name for u in relation.units}   # dict — key order not fixed
databag["config"] = json.dumps(config)                    # key order varies each reconcile
```

**What's wrong:** the dict is built by iterating over `relation.units`, which is an unordered set. The key order follows whatever order the set happens to produce — different each reconcile.

**Fix:** `json.dumps(config, sort_keys=True)` — or `yaml.dump(config)` (sorts keys by default).

**Why key-sorting is enough here:** the *entire* disorder is in the dict's key order. `sort_keys=True` locks key order alphabetically regardless of how the dict was built, so the output is identical every reconcile.

This is labelled **`local`** — the instability is at the "key order" level, which a key-sorting serializer genuinely fixes.

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

This is labelled **`itercaller`** — the instability is in the iterated sequence's element order, which survives any key-sorting serializer. It's the most easily missed case and the central distinction flaplint exists to catch.

### Pattern 3: Positional pick from an unordered source

```python
first_addr = list(self.endpoints)[0]   # which item is "first" depends on the run
databag["primary"] = first_addr
```

**What's wrong:** picking by position from an unordered collection gives a different item each time. This is labelled **`element`**.

**Fix:** `sorted(self.endpoints)[0]` — sort before picking so "first" is deterministic.

### Pattern 4: A different-every-run value

```python
databag["nonce"] = str(uuid4())    # different every reconcile, no matter what
```

**What's wrong:** `uuid4()`, `time()`, `random()`, and similar calls produce a new value every time the code runs. No sorting can help — the value itself changes, not just its order. This is labelled **`volatile`**.

**Fix:** derive the value deterministically (e.g. from something stable, like an app name), or persist it once and reuse it.

### Pattern 5: A helper that trusts its caller

```python
def publish(self, relation, items):               # no type hint on items
    relation.data[self.app]["peers"] = json.dumps(items)   # writes items unsorted
```

flaplint can't see what `items` will actually hold, but it can see that if any caller passes an unordered value, it'll be written to the databag without sorting. This is flagged as a **`sink`** finding (medium confidence) — a helper that trusts its caller to pass ordered data.

If a caller is traced passing an unstable `items`, a higher-confidence **`caller`** finding is emitted at the call site.

### Pattern 6: Unstable value stored in a field or on `self`

Storing an unstable value in a dataclass field, a Pydantic model field, or on `self` doesn't make it stable. Flaplint tracks the taint through field reads and across method boundaries.

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

**What's wrong:** the instability is in the value itself, not in the variable name. Reading it back from a field or from `self` doesn't change that.

**Fix:** sort when the value is first created (`self._endpoints = sorted(...)`) or at the point of use (`sorted(self._endpoints)`).

```python
# Dict by constant key — tracked field-sensitively
self.cfg["jobs"] = set(hosts)
databag["jobs"] = json.dumps(list(self.cfg["jobs"]))   # caught: cfg["jobs"] is unstable
databag["name"] = json.dumps(self.cfg["name"])          # clean: sibling key is not tainted
```

**What's wrong:** the instability is in the value itself, not in the variable name. Reading it back from a field, from `self`, or by a constant dict key doesn't change that.

**Fix:** sort when the value is first created (`self._endpoints = sorted(...)`) or at the point of use (`sorted(self._endpoints)`).

Flaplint tracks each field independently — `cfg.name` stays clean even if `cfg.endpoints` is unstable. The tracking also carries across a function return: `cfg = self._build_cfg(); cfg.endpoints` is caught if `_build_cfg` returns an object with an unstable field. It also follows a nested field chain to any depth — `self.ctx.config.targets` is tracked the same as `self.targets`, so long as the chain is pure attribute access (a `.get_ctx().targets` call or `self.items[0].targets` index in the middle stops it; see [Known gaps](architecture.md#known-gaps)).

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

flaplint reads the model's field annotation to recognise this. It's gated on a **set** into a **sequence-typed** field of a **directly-`BaseModel`-based** model: a `Set[str]` field keeps set semantics (still key-order, still laundered), and a plain `@dataclass` doesn't coerce at all (see [Known gaps](architecture.md#known-gaps)).

**Pydantic v1 note:** the v1 spellings `.json()` / `.dict()` take the conservative path — they inherit *all* receiver taint, so they also catch the field-value flaps above (and are the reason the pre-annotation-aware analysis still caught the `list(...)` case).

---

## The six kinds of instability (reference)

Internally, flaplint tracks *why* a value is unstable with one of six labels:

| label | what it means | the fix |
|---|---|---|
| `local` | a bare set/dict/glob — disorder is at the key-order level | key-sorting serializer, or `sorted()` |
| `element` | one item picked by position out of something unordered | `sorted(x)[i]` before picking |
| `itercaller` | a list/string/tuple materialised from an unordered source | `sorted(...)` before materialising |
| `iterparam` | a list built by looping over a *parameter* — caller decides the order | sort at the call site, or sort inside the loop |
| `volatile` | a value that's different every run — `uuid4()`, `time()`, `random()` | make it stable / persistent |
| `param` | a stand-in for "as unstable as parameter N" — resolved at each call site | depends on what the caller passes |

The label matters because it determines **which fix works** and whether a given serializer can help.

## What each serializer does

Serializers come in two kinds:
- **plain** — `str`, `repr`, `.encode()`, `json.dumps(x)` without `sort_keys`. Output follows input order exactly.
- **key-sorting** — `yaml.dump` / `yaml.safe_dump`, `json.dumps(sort_keys=True)`, a Pydantic dump. These put *mapping keys* in alphabetical order, and nothing else.

Which labels survive each:

| label | survives `str()` / `repr()` | survives a key-sorting serializer |
|---|:---:|:---:|
| `local` | yes | **no** — key-sorting fixes it |
| `element` | yes | yes |
| `itercaller` | yes | yes |
| `iterparam` | yes | yes |
| `volatile` | yes | yes |
| `param` | — | — *(resolved at the call)* |

The single most common bug this tool exists to catch — and the one simpler checkers miss — is **`itercaller` surviving a key-sorting serializer**: a list built from a set looks like "just another collection" but key-sorting can't reorder its elements.

## Where unstable values come from (sources)

### Things with no fixed order → `local`

- **Sets**: `set(...)`, `frozenset(...)`, set literals `{a, b}`, set comprehensions `{x for x in …}`
- **Set math**: `a | b`, `a & b`, `a - b`, and so on
- **Directory listings**: `glob`, `listdir`, `scandir`, `walk`, `iterdir`, … — filesystem order is not guaranteed
- **`relation.units`** — the set of units in a relation; order varies run-to-run

### Values that differ every run → `volatile`

`uuid4()` and its siblings, `time()`, `random()` and related functions, `token_hex()`, and so on.

### Parameters → `param`

A reference to a parameter is recorded as "as unstable as parameter N" — a placeholder resolved at each call site. This is how "does this function write an unstable argument?" is answered without re-analysing the callee every time.

## How a value changes as it moves (propagation)

### Things that pass instability through unchanged

`list`, `tuple`, `reversed`, `dict`, `copy`, `deepcopy` carry the input's instability forward. A plain (non-key-sorting) serializer passes it through too: `json.dumps(x)` is only as stable as `x`.

A template render (`template.render(x=…)`) is treated the same way — flaplint can't see inside the template, so it assumes the rendered text is as unstable as the values handed in. This catches the common pattern of rendering a config from Jinja and writing it to a file.

### Things that make a value stable (sanitisers)

- `sorted(...)` and `.sort()` make a value stable.
- A key-sorting serializer makes the `local` kind safe but leaves `itercaller` / `element` / `volatile` intact.
- **`str.split` / `rsplit` / `splitlines`**: splitting a string gives back a list in left-to-right order, never in a collection's order — so the loop is predictable. (Only a `volatile` string's *content* carries through.)
- **`isinstance(x, <ordered type>)` check**: inside `if isinstance(raw, list):`, the `param` worry is cleared because the caller can't pass a bare set through that branch. (It only clears the type concern, not concrete instability — a real `list(some_set)` inside the check still flaps.)

### Things that change which kind it is

Three operations promote a value to a more severe label:

1. **Picking by position → `element`**: `unordered[0]` grabs one item whose identity depends on the run-to-run ordering. Can't be fixed by sorting keys.

2. **Building a list from a set → `itercaller`**: `list(some_set)`, `tuple(relation.units)`, `[x for x in some_set]`, a loop accumulator (`for u in relation.units: eps.append(…)`). The list's item order now carries the disorder. A `set` or `dict` accumulator stays `local` — its disorder is key-order, which a key-sorting serializer does fix.

   Two subtle cases:
   - **`enumerate` on a flapping list** carries the taint through, so an index-keyed dict (`{f"k-{i}": e for i, e in enumerate(eps)}`) still flaps even though the keys sort.
   - **Mutating a nested element** (`template["sinks"].update(eps)`) makes the root `template` unstable, so a later `yaml.dump(template)` is caught.

3. **Looping a parameter into a list → `iterparam`**: the caller decides the order, so this is flagged as a `sink` finding at the loop.


## A worked example

```python
group_by = set(route.get("group_by", []))               # local: a set
group_by = list(group_by.union(["juju_model"]))         # itercaller: list from a set
config["route"]["group_by"] = group_by
return yaml.safe_dump(config)                           # sorts keys — but not list items
```

`yaml.safe_dump` sorts `config`'s keys but can't reorder the `group_by` list's elements. Because `group_by` is `itercaller`, it survives the key-sorting and is reported — pointing at the `list(...)` where `sorted(...)` belongs. Had it stayed a plain set, the key-sorting would have been enough and flaplint would correctly say nothing.
