# The taint model

This is the core idea of `flaplint`: what makes a value's bytes unstable, how that
instability is labelled, and how it changes as the value flows through calls and
serializers. Everything in [sinks-and-findings.md](sinks-and-findings.md) builds on
the vocabulary here.

For any expression, the analyzer answers one question:

> If this value reaches a databag (or a file, or a hash), will its bytes be the same
> on two otherwise-identical reconciles — and if not, why not?

The "why not" is called an **origin**. A stable value has no origin; an unstable one
has one or more.

## The origin taxonomy

There are six kinds of origin. What separates them is **what fixes the
instability** — and especially whether a *key-sorting* serializer is enough. (A
key-sorting serializer is one that sorts mapping keys for you: `yaml.dump`,
`json.dumps(sort_keys=True)`, a Pydantic dump.)

| origin | what it means | the fix |
|---|---|---|
| `local` | a value that is unordered as a whole — a `set`, a `glob()` result, `relation.units`. Its disorder is in the *keys* of a mapping. | a key-sorting serializer already fixes it, or `sorted()` |
| `element` | a single element chosen by **position** from something unordered — `addrs[0]`. | `sorted(addrs)[0]` — sort *before* indexing |
| `itercaller` | a **list built from an unordered source** — `list(some_set)`, `[x for x in some_set]`. Its disorder is in the *order of the list's elements*. | `sorted(...)` where the list is built |
| `iterparam` | a list built by iterating a **parameter** — the caller, not this function, controls the order. | sort where it's iterated, or have the caller pass ordered data |
| `volatile` | a value that is **different every run** — `uuid4()`, `time()`, `random()`. | nothing; sorting can't help — don't write it to the bag |
| `param` | "this value is as unstable as parameter N" — a placeholder, filled in at each call site. | depends on what the caller passes |

Each unstable value also remembers *where it was created*, so a finding can point at
the `set()` or `list(...)` that started the problem rather than the place it was
finally written.

### Why `local` and `itercaller` are different

This is the subtlest distinction in the model, and the one most worth stating
plainly:

- A **`set`** written through a key-sorting serializer is **safe**. The serializer
  sorts the elements for you (`yaml.safe_dump` writes a set as a sorted mapping;
  `json.dumps(sort_keys=True)` sorts keys). → `local`.
- A **`list(set)`** written through the *same* serializer is **not** safe. Sorting
  keys does nothing to the order of a list's elements: `[c, a, b]` stays `[c, a, b]`.
  Turning a set into a list moves the disorder somewhere the serializer won't touch.
  → `itercaller`.

So `list(some_set)` is treated differently from a bare `set` precisely because it
changes whether a key-sorting serializer can save you.

`" ".join(some_set)` is the same story in disguise: joining bakes the set's
iteration order into the result *string*, and a key-sorting serializer can't reach
inside a string any more than it can reorder a list's elements. So a join of an
unordered collection is also `itercaller`, not `local` — sort *before* the join.

## The key-sort survival matrix

Serializers come in two kinds:

- **non-sorting** — `str`, `repr`, `.encode()`, `json.dumps(x)` with no `sort_keys`.
  The output order matches the input order exactly.
- **key-sorting** — `yaml.dump`/`safe_dump`, `json.dumps(sort_keys=True)`, a Pydantic
  dump. These sort *mapping keys*, and nothing else.

Which kinds of instability survive each:

| origin | survives `str()` / `repr()` | survives a key-sorting serializer |
|---|:---:|:---:|
| `local` | yes | **no** — the serializer sorts it away |
| `element` | yes | yes |
| `itercaller` | yes | yes |
| `iterparam` | yes | yes |
| `volatile` | yes | yes |
| `param` | — | — *(placeholder, filled in at the call site)* |

The single most common bug this tool exists to catch — and the one naive checkers
miss — is the bottom of this table: a value whose *list-element* order is unstable,
written through a serializer that only sorts *keys*.

## Source discovery: what creates an origin

### Unordered values (`local`)

- **Sets**: `set(...)`, `frozenset(...)` (with contents — an empty `set()` is
  stable), set literals `{a, b}`, and set comprehensions `{x for x in …}`.
- **Set algebra**: `a | b`, `a & b`, `a - b`, and so on.
- **Filesystem listing**: `glob`, `listdir`, `scandir`, `walk`, `iterdir`, … —
  directory order isn't guaranteed.
- **`relation.units`** — a set of units whose order changes between processes.

### Different-every-run values (`volatile`)

`uuid4()` and friends, `time()`, `random()` and the other random functions,
`token_hex()`, and so on.

### Parameters (`param`)

A reference to a parameter is recorded as "as unstable as parameter N" rather than a
real instability. It's a promise to check the actual argument at each call site —
the mechanism behind [inter-procedural summaries](architecture.md#inter-procedural-summaries).

### Type annotations (a hint at the sink, not a source)

A parameter's annotation never makes a value unstable on its own. It only adjusts the
confidence of a [contract-boundary finding](sinks-and-findings.md#contract-boundary-sink-findings):
an annotation like `Set` or `Iterable` raises confidence; `List`, `Dict`, or `str`
skips the finding (the caller owns the order); a named object type like a dataclass
also skips it (you can't `sorted()` a dataclass).

## Propagation: how taint changes

### Things that pass instability through unchanged

`list`, `tuple`, `reversed`, `dict`, `copy`, `deepcopy` carry their argument's
instability along — `copy.deepcopy(dict(x))` is exactly as unstable as `x`.
Serializing without key-sorting passes it through too: `json.dumps(x)` is only as
stable as `x`.

A template render (`template.render(x=…)`) is treated the same way. The analyzer
can't see inside the template, so it assumes the rendered text is as unstable as the
values passed into it — which catches the common pattern of rendering a config from
a Jinja template and writing it to a file. (The iteration that actually reorders the
text lives in the template, so a plain dataflow check would go blind here.)

### Things that clear it

`sorted(...)` (and `.sort()`) make a value stable. A key-sorting serializer clears
the `local` kind of instability (it sorts the keys), but — as the matrix shows — not
the others.

### Things that change which kind it is

Three operations move a value from one kind of instability to another, because they
change which serializer can fix it:

1. **Indexing an unordered thing → `element`.** `unordered[0]` picks one
   position-dependent element — the classic "grab the first address" churn. A
   key-sorting serializer can't fix a single picked value.

2. **Building a list from an unordered set → `itercaller`.** `list(some_set)`,
   `tuple(relation.units)`, `[x for x in some_set]`. The list's element order now
   carries the disorder, where key-sorting won't reach. (`dict`/`copy` are *not* in
   this group — they keep a mapping, whose key disorder a serializer does fix.)

3. **Iterating a parameter into a list → `iterparam`.** The order belongs to the
   caller, so this is flagged as a contract boundary, pointing at the loop where a
   `sorted()` would go.

### Serializer semantics in detail

| call | what happens |
|---|---|
| `str(x)`, `repr(x)`, `x.encode()` | output order matches input — every kind of instability survives except a bare parameter |
| `json.dumps(x)` | passes everything through |
| `json.dumps(x, sort_keys=True)` | clears the `local` kind; the rest survive |
| `yaml.dump`/`safe_dump(x)` | sorts keys by default (clears `local`); `sort_keys=False` passes everything through |
| `json.dump(obj, fp)` | writes a *file*, not a value — handled as a [file sink](sinks-and-findings.md) instead |
| a Pydantic dump | writes fields in a fixed order, so it clears ordering instability |

### Inheriting instability from the receiver

Calling a method on an unstable value generally keeps the instability, even when we
can't see inside the method — `d.keys()`, or a builder's `.as_dict()` after an
unordered `.add()`. The exception is a Pydantic dump, which writes a fixed field
order and so clears it.

## Worked transformation

```python
group_by = set(route.get("group_by", []))                 # a set → local
group_by = list(group_by.union(["juju_model"]))           # now a list → itercaller
config["route"]["group_by"] = group_by
return yaml.safe_dump(config)                              # key-sorting — but the list survives
```

`yaml.safe_dump` sorts the config's keys but can't reorder the `group_by` list, so
the rendered text changes every reconcile. Because the value is the list kind
(`itercaller`), it survives the key-sorting serializer and is reported, pointing at
the `list(...)` where `sorted(...)` belongs. Had it stayed a plain set, the analyzer
would have correctly assumed `yaml.safe_dump` sorted it and said nothing.
