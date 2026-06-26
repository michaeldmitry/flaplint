"""The analyzer's vocabulary: the call/attribute/annotation name sets it matches.

Everything here is pure data with no behaviour. Each set is matched on a *name*
(usually the final attribute of a call target, e.g. ``glob.glob`` -> ``glob``),
which keeps matching robust to how a symbol was imported.

Extending the linter to a new source/sink almost always means adding a name to
one of these sets rather than touching the engine.
"""

from __future__ import annotations

from typing import Dict, Set

#: Callables whose result has incidental (hash-seed or filesystem dependent)
#: ordering. Matched on the *final* attribute name, so both ``glob.glob`` and
#: ``some_path.glob`` are covered.
UNORDERED_CALLS: Set[str] = {
    "set",
    "frozenset",
    "listdir",
    "scandir",
    "walk",
    "glob",
    "iglob",
    "iterdir",
    "rglob",
}

#: Callables that pass through the taint of their first argument. ``dict``/
#: ``copy``/``deepcopy`` preserve their input's iteration order, so an unordered
#: value survives them unchanged (``copy.deepcopy(dict(x))`` is exactly as
#: unordered as ``x``); they must propagate taint rather than launder it.
PROPAGATE_CALLS: Set[str] = {
    "list",
    "tuple",
    "reversed",
    "join",
    "dict",
    "copy",
    "deepcopy",
}

#: Callables that neutralize ordering taint.
SANITIZER_CALLS: Set[str] = {"sorted"}

#: Attribute accesses whose value is an unordered ops collection.
#: ``relation.units`` is a ``Set[Unit]`` whose iteration order is not stable
#: across reconciles, so a value built by iterating it inherits that instability.
UNORDERED_ATTRS: Set[str] = {"units"}

#: Callables returning a fresh, nondeterministic value on every invocation.
#: Writing one (directly, or nested inside a serialized structure) to a databag
#: makes the *textual* value differ on every reconcile -> unconditional
#: relation-changed churn. Unlike order instability, ``sorted()`` does not help:
#: such a value simply must not be placed in the bag. Matched on the final
#: attribute name (``uuid.uuid4`` -> ``uuid4``, ``time.time`` -> ``time``).
VOLATILE_CALLS: Set[str] = {
    "uuid1",
    "uuid3",
    "uuid4",
    "uuid5",
    "time",
    "time_ns",
    "monotonic",
    "monotonic_ns",
    "perf_counter",
    "perf_counter_ns",
    "process_time",
    "now",
    "utcnow",
    "random",
    "randint",
    "randrange",
    "uniform",
    "getrandbits",
    "choice",
    "choices",
    "sample",
    "urandom",
    "token_hex",
    "token_bytes",
    "token_urlsafe",
}

#: Serializers with no key-sorting escape hatch (unlike
#: ``json.dumps(sort_keys=True)``): their byte output is exactly as ordered as
#: their input.
NONSORTING_SERIALIZERS: Set[str] = {"str", "repr"}

#: Digest/hash calls used as change-detectors. Hashing an unordered value yields
#: a different digest for the same logical content, which spuriously trips
#: config-hash-gated workload restarts / pebble replans.
HASH_CALLS: Set[str] = {
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha3_224",
    "sha3_256",
    "sha3_384",
    "sha3_512",
    "blake2b",
    "blake2s",
    "hash",
}

#: Parameter annotations that strongly suggest the value may be unordered.
UNORDERED_ANNOTATIONS: Set[str] = {
    "set",
    "Set",
    "frozenset",
    "FrozenSet",
    "AbstractSet",
    "MutableSet",
    "Iterable",
    "Collection",
    "KeysView",
    "ValuesView",
    "ItemsView",
}

#: Parameter annotations that are ordered/irrelevant: dumping them is the
#: caller's responsibility, so the helper itself is not at fault.
ORDERED_ANNOTATIONS: Set[str] = {
    "list",
    "List",
    "tuple",
    "Tuple",
    "Sequence",
    "str",
    "bytes",
    "int",
    "float",
    "bool",
}

#: Names of the attribute-mutation methods that accumulate values in iteration
#: order inside a loop body (so an unordered loop taints the accumulator).
ACCUMULATOR_METHODS: Set[str] = {
    "append",
    "extend",
    "insert",
    "add",
    "update",
    "setdefault",
}

#: Mutating ``MutableMapping`` methods that write *content* into a databag. A
#: call ``bag.update(x)`` / ``bag.setdefault(k, x)`` on a relation databag is a
#: relation-data write just like ``bag[k] = x`` -- the value ``x`` is what lands
#: in the databag. We anchor on the *receiver being a databag* (see
#: ``astutils.databag_expr``), not on the method name in isolation, so this is a
#: structural sink, not a fragile name match.
MAPPING_WRITE_METHODS: Set[str] = {"update", "setdefault"}

#: Builtin mapping *view* methods (``dict.items()/keys()/values()``). They
#: iterate a mapping in its own insertion order, so their ordering follows the
#: receiver's -- which the receiver-taint inheritance rule already captures.
#: Crucially they are *not* user-defined calls: when the receiver's class is
#: unknown, resolving ``x.items()`` by bare name would union in an unrelated
#: same-named user method (e.g. a charm library's ``items`` property that walks
#: ``model.relations[...]``) and import its taint -- a cross-class collision.
#: These names must therefore bypass user-summary resolution.
BUILTIN_VIEW_METHODS: Set[str] = {"items", "keys", "values"}

#: Workload-config / file emission APIs. Order-unstable (or volatile) content
#: reaching one of these flaps the rendered config or on-disk file, which
#: triggers a spurious pebble replan / workload restart -- and, downstream,
#: relation-changed churn once the restarted workload re-publishes. Databag
#: writes are not the only churn sink: a flapping config file or pebble layer
#: re-runs commands and bounces the workload on every reconcile.
#:
#: Each entry maps the (well-known, stable) framework method name to the
#: argument carrying the *content*: ``(positional index, keyword aliases)``.
CONFIG_WRITE_METHODS: Dict[str, "tuple[int, tuple[str, ...]]"] = {
    "push": (1, ("source",)),  # ops.Container.push(path, source)
    "add_layer": (1, ("layer",)),  # ops.Container.add_layer(label, layer)
    "write_text": (0, ()),  # pathlib.Path.write_text(data, ...)
    "write_bytes": (0, ()),  # pathlib.Path.write_bytes(data)
}

#: Human-readable sink descriptions for the config-write methods above, keyed by
#: method name, used in the finding message.
CONFIG_WRITE_DESCS: Dict[str, str] = {
    "push": "container push (pebble replan / workload restart)",
    "add_layer": "pebble layer (replan / workload restart)",
    "write_text": "config file write",
    "write_bytes": "config file write",
}

#: Serializers whose *return value* is a rendered config/data blob. A function
#: that ``return``s ``yaml.dump(x)`` / ``json.dumps(x)`` is a config-render
#: boundary: the bytes it produces are handed off to a consumer (a workload
#: push, a databag write, a file) that diffs them, so instability that survives
#: key-sorting -- an ``"element"`` pick or a ``"volatile"`` value -- flaps the
#: output. Benign dict-key-order (``"local"``) instability is laundered by the
#: very key-sorting the serializer applies, so a return-render sink never fires
#: on it (the taint engine returns an empty origin set for that case).
RENDER_SERIALIZERS: Set[str] = {"dump", "safe_dump", "dumps"}

#: Inline comment that suppresses a finding on its line.
SUPPRESS_COMMENT = "databag-order: ignore"

#: Ordering of confidence levels, lowest first.
CONFIDENCE_RANK: Dict[str, int] = {"low": 0, "medium": 1, "high": 2}

#: Relative criticality of the finding kinds (lower sorts first). A ``caller``
#: finding pins a concrete bug to the exact line that serializes an unstable
#: value; a ``sink`` finding is advisory -- a helper that *would* churn if a
#: caller forgets to sort -- so it ranks below an equally-confident caller.
KIND_RANK: Dict[str, int] = {"caller": 0, "sink": 1}
