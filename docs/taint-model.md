# How flaplint spots an unstable value

This is the heart of `flaplint`: what makes a value's text come out differently from
one run to the next, how that gets labelled, and how the label changes as the value
is copied, transformed, and passed around. [sinks-and-findings.md](sinks-and-findings.md)
builds on the words introduced here.

For any expression, flaplint asks one question:

> If this value reaches a databag (or a file, or a hash), will its text be the same
> on two otherwise-identical reconciles — and if not, why not?

A stable value has no answer to "why not". An unstable one carries a short label that
says *why* it's unstable. That label is what the rest of this page is about.

## The six kinds of instability

There are six labels. What separates them is **which fix actually works** — and in
particular, whether it's enough to let a serializer sort the keys for you. (A
key-sorting serializer is one that puts mapping keys in order as it writes them:
`yaml.dump`, `json.dumps(sort_keys=True)`, a Pydantic dump.)

| what it is (plain English) | name in the code | the fix |
|---|---|---|
| a whole thing with no fixed order — a `set`, a `glob()` result, `relation.units` | `local` | let a key-sorting serializer handle it, or `sorted()` |
| one item picked by **position** out of something unordered — `addrs[0]` | `element` | `sorted(addrs)[0]` — sort *before* picking |
| a **list made from** something unordered — `list(some_set)`, `[x for x in some_set]` | `itercaller` | `sorted(...)` where the list is built |
| a list made by looping over a **parameter** — the *caller* decides the order, not this function | `iterparam` | sort where it's looped over, or have the caller pass sorted data |
| a value that's **different every run** — `uuid4()`, `time()`, `random()` | `volatile` | nothing; sorting can't help — don't write it to the bag |
| "as unstable as parameter N" — a stand-in, filled in at each call | `param` | depends on what the caller passes |

Every unstable value also remembers **where it was created**, so a finding can point
at the `set()` or `list(...)` that started the trouble instead of the place it was
finally written.

### Why a plain set and a list-made-from-a-set are different

This is the most easily-missed point in the whole tool, so here it is plainly:

- A **`set`** written through a key-sorting serializer is **fine**. The serializer
  puts the items in order for you (`yaml.safe_dump` writes a set as a sorted mapping;
  `json.dumps(sort_keys=True)` sorts the keys). → labelled `local`.
- A **`list(set)`** written through the **same** serializer is **not** fine. Sorting
  keys does nothing to the order of a list's items: `[c, a, b]` stays `[c, a, b]`.
  Turning a set into a list moves the disorder somewhere sorting-the-keys never
  reaches. → labelled `itercaller`.

So `list(some_set)` is treated differently from a bare `set` for one reason: it
changes whether letting the serializer sort the keys is enough to save you.

`" ".join(some_set)` is the same story in disguise. Joining bakes the set's order
into the resulting **string**, and a key-sorting serializer can't reach inside a
string any more than it can reorder a list. So joining an unordered collection is
also `itercaller`, not `local` — sort *before* the join.

## What each serializer fixes

Serializers come in two kinds:

- **plain** — `str`, `repr`, `.encode()`, `json.dumps(x)` with no `sort_keys`. The
  text comes out in exactly the order it went in.
- **key-sorting** — `yaml.dump`/`safe_dump`, `json.dumps(sort_keys=True)`, a Pydantic
  dump. These put *mapping keys* in order, and nothing else.

Which kinds of instability each one leaves behind:

| kind | survives `str()` / `repr()` | survives a key-sorting serializer |
|---|:---:|:---:|
| `local` | yes | **no** — sorting the keys fixes it |
| `element` | yes | yes |
| `itercaller` | yes | yes |
| `iterparam` | yes | yes |
| `volatile` | yes | yes |
| `param` | — | — *(a stand-in, filled in at the call)* |

The single most common bug this tool exists to catch — and the one simpler checkers
miss — is the bottom of this table: a value whose **list order** is unstable, written
through a serializer that only sorts **keys**.

## Where unstable values come from

### Things with no fixed order (`local`)

- **Sets**: `set(...)`, `frozenset(...)` with contents (an empty `set()` is fine),
  set literals `{a, b}`, and set comprehensions `{x for x in …}`.
- **Set math**: `a | b`, `a & b`, `a - b`, and so on.
- **Listing a directory**: `glob`, `listdir`, `scandir`, `walk`, `iterdir`, … —
  the order files come back in isn't guaranteed.
- **`relation.units`** — a set of units whose order changes from one run to the next.

### Different-every-run values (`volatile`)

`uuid4()` and its siblings, `time()`, `random()` and the other random functions,
`token_hex()`, and so on.

### Parameters (`param`)

A reference to a parameter is recorded as "as unstable as parameter N" rather than a
real instability. It's a promise to check the actual argument at each call — the idea
behind [following values across function calls](architecture.md#following-values-across-function-calls).

### Type hints (a hint at the write, not a source)

A parameter's type hint never makes a value unstable by itself. It only adjusts the
confidence of a [helper-trusts-its-caller finding](sinks-and-findings.md#when-a-helper-trusts-its-caller):
a hint like `Set` or `Iterable` raises confidence; `List`, `Dict`, or `str` skips the
finding (the caller owns the order); a named object type like a dataclass also skips
it (you can't `sorted()` a dataclass).

## How a value changes as it moves

### Things that pass it through unchanged

`list`, `tuple`, `reversed`, `dict`, `copy`, `deepcopy` carry their input's
instability along — `copy.deepcopy(dict(x))` is exactly as unstable as `x`. A
serializer that doesn't sort keys passes it through too: `json.dumps(x)` is only as
stable as `x`.

A template render (`template.render(x=…)`) is treated the same way. flaplint can't
see inside the template, so it assumes the rendered text is as unstable as the values
handed in — which catches the common pattern of rendering a config from a Jinja
template and writing it to a file. (The looping that actually reorders the text lives
in the template, so a plain read of the Python would miss it.)

### Things that make it safe

`sorted(...)` (and `.sort()`) make a value stable. A key-sorting serializer makes the
`local` kind safe (it sorts the keys), but — as the table shows — not the others.

Two more things clear the "this parameter *might* be an unordered collection" worry of
a `param`:

- **`str.split` / `rsplit` / `splitlines`.** Splitting a string gives back a list in
  the order the string reads, left to right — never a collection's order (you can't
  `.split()` a set). So looping over `s.split(",")` is predictable; only the string's
  own *different-every-run* content (a `uuid4()` inside it) carries through.
- **An `isinstance(x, <ordered type>)` check.** Inside `if isinstance(raw, list):`,
  `raw` is definitely a list — a caller passing a set can't reach that branch — so the
  caller-might-pass-a-set worry is dropped there. It's the runtime twin of hinting the
  parameter as `list`. Only the `param` worry is cleared: `isinstance` proves the
  *type*, not the *order*, so a genuinely unstable `list(some_set)` inside the check
  still gets flagged.

### Things that change which kind it is

Three operations move a value from one kind to another, because they change which fix
works:

1. **Picking by position out of something unordered → `element`.** `unordered[0]`
   grabs one item whose identity depends on the unstable order — the classic
   "grab the first address" bug. Sorting the keys can't fix a single picked value.

2. **Building a list from a set → `itercaller`.** `list(some_set)`,
   `tuple(relation.units)`, `[x for x in some_set]`. The list's item order now carries
   the disorder, where sorting the keys won't reach. (`dict`/`copy` are *not* in this
   group — they keep a mapping, whose key order a serializer does fix.)

3. **Looping a parameter into a list → `iterparam`.** The order belongs to the
   caller, so this is flagged as a place that trusts its caller, pointing at the loop
   where a `sorted()` would go.

### What each serializer does

| call | what happens |
|---|---|
| `str(x)`, `repr(x)`, `x.encode()` | text comes out in input order — every kind of instability survives except a bare parameter |
| `json.dumps(x)` | passes everything through |
| `json.dumps(x, sort_keys=True)` | makes the `local` kind safe; the rest survive |
| `yaml.dump`/`safe_dump(x)` | sorts keys by default (makes `local` safe); `sort_keys=False` passes everything through |
| `json.dump(obj, fp)` | writes a *file*, not a value — handled as a [file write](sinks-and-findings.md) instead |
| a Pydantic dump | writes fields in a fixed order, so it makes ordering instability safe |

### A method call keeps the receiver's instability

Calling a method on an unstable value generally keeps it unstable, even when we can't
see inside the method — `d.keys()`, or a builder's `.as_dict()` after an unordered
`.add()`. The one exception is a Pydantic dump, which writes a fixed field order and
so makes it safe.

### Through a value object's field

An unstable value stored in a **value object's field** (a dataclass, a pydantic
model, a NamedTuple) is read back out with its instability intact:

```python
ctx = Ctx(targets=set(hosts), name="x")     # the targets field → local
push(",".join(ctx.targets))                  # read back → itercaller (a joined set)
```

This tracks **each field separately** — reading a clean field (`ctx.name`) stays
clean — and it carries across a function return (`ctx = self._build(); ctx.targets`).
It does **not** reach through a value buried inside a dict, a field rebuilt by a
method, or a deeper `a.b.c` path. See
[the architecture note](architecture.md#following-values-through-object-fields-and-where-it-stops).

## A worked example

```python
group_by = set(route.get("group_by", []))                 # a set → local
group_by = list(group_by.union(["juju_model"]))           # now a list → itercaller
config["route"]["group_by"] = group_by
return yaml.safe_dump(config)                              # sorts keys — but the list survives
```

`yaml.safe_dump` sorts the config's keys but can't reorder the `group_by` list, so the
text changes every reconcile. Because the value is the list kind (`itercaller`), it
survives the key-sorting serializer and is reported, pointing at the `list(...)` where
`sorted(...)` belongs. Had it stayed a plain set, flaplint would have correctly
assumed `yaml.safe_dump` sorted it and said nothing.
