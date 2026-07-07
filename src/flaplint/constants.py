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
    # NOTE: ops Container.list_files / pebble list_files is deliberately NOT here.
    # Unlike ``os.listdir`` (Python, arbitrary order), pebble's server lists the
    # directory with Go's ``os.ReadDir``, which returns entries *sorted by
    # filename*. That order is stable across calls, so a config built by iterating
    # a listing does not flap -- flagging it would be a false positive.
}

#: Callables that pass through the taint of their first argument. ``dict``/
#: ``copy``/``deepcopy`` preserve their input's iteration order, so an unordered
#: value survives them unchanged (``copy.deepcopy(dict(x))`` is exactly as
#: unordered as ``x``); they must propagate taint rather than launder it.
#: ``enumerate`` is a *pass-through* (deliberately NOT a sequence materializer): it
#: pairs each element with its index without changing element order, so iterating
#: ``enumerate(eps)`` carries ``eps``'s taint to whatever the loop builds -- the
#: ``{f"loki-{idx}": e for idx, e in enumerate(unstable_list)}`` shape, where the
#: index→element binding flaps even though the keys sort. It is *not* promoted to
#: ``itercaller`` (that would false-positive on a dict keyed by the *element*,
#: ``d[e] = ...``, whose keys a serializer sorts deterministically).
#: cryptography ``x509`` constructors that build an *order-significant* DER
#: ``SEQUENCE`` from an iterable of names. Building one from a ``set`` bakes the
#: set's hash-seeded iteration order into the certificate's DER/PEM bytes -- the
#: classic TLS flap: a charm passes a sorted/``frozenset`` of SANs, the lib
#: re-``set()``s them (``SubjectAlternativeName(set(sans))``), and the emitted
#: CSR/cert bytes reshuffle every hook. So -- exactly like ``list(some_set)`` --
#: these materialize ``local`` -> ``itercaller`` (value-position order a key-sorting
#: serializer can't launder).
X509_SEQUENCE_CONSTRUCTORS: Set[str] = {
    "SubjectAlternativeName",
    "IssuerAlternativeName",
    "GeneralNames",
}

PROPAGATE_CALLS: Set[str] = {
    "list",
    "tuple",
    "reversed",
    "join",
    "dict",
    "copy",
    "deepcopy",
    "enumerate",
} | X509_SEQUENCE_CONSTRUCTORS

#: Fluent-builder methods that return a *new* builder carrying the receiver's taint
#: **plus** the added value's -- the cryptography ``builder = builder.add_extension(
#: ext, critical=...)`` idiom. Without this the added extension (a SAN materialized
#: from a set) would be dropped as the immutable builder is reassigned, breaking the
#: ``add_extension(...) -> sign() -> public_bytes()`` chain to the eventual write.
BUILDER_ARG_PROPAGATORS: Set[str] = {"add_extension"}

#: Serializer *methods* that render an object to bytes/text whose stability follows
#: the object's own -- the cryptography ``csr.public_bytes(encoding)`` /
#: ``cert.public_bytes(encoding)``. Handled like ``.encode()``: only a genuinely
#: unstable receiver (a SAN built from a set -> ``itercaller``) survives, so the
#: DER/PEM bytes carry that instability to whatever diffs them.
BYTES_SERIALIZER_METHODS: Set[str] = {"public_bytes"}

#: Subset of :data:`PROPAGATE_CALLS` that materialize their argument into a
#: *sequence*. When the argument is a locally-born unordered collection (a
#: ``set`` / ``frozenset`` / ``relation.units``), the result's *element order*
#: is the source's hash-seeded iteration order -- value-position instability a
#: key-sorting serializer (``yaml.dump``, ``json.dumps(sort_keys=True)``) cannot
#: launder. So unlike the mapping-preserving propagators (``dict``/``copy``),
#: these promote ``local`` taint to the key-sort-surviving iteration flavor.
#: ``dict``/``copy``/``deepcopy`` are excluded (they preserve a mapping, whose
#: key disorder key-sorting *does* fix); ``join`` is excluded to avoid colliding
#: with ``os.path.join``.
SEQUENCE_MATERIALIZERS: Set[str] = {
    "list",
    "tuple",
    "reversed",
} | X509_SEQUENCE_CONSTRUCTORS

#: Callables that neutralize ordering taint.
SANITIZER_CALLS: Set[str] = {"sorted"}

#: Calls whose result is *order-independent* regardless of the input's order -- they
#: collapse a collection to a scalar (an aggregate, a boolean, a coerced number), so
#: any ordering instability is laundered. This is the bounded *sanitizer* list that
#: makes the default-propagate model safe: an unknown call carries its arguments'
#: taint forward UNLESS it is one of these (see the constructor/call propagation in
#: ``TaintEngine._call``). ``sorted``/``split``/``read`` are laundering too but are
#: handled by their own earlier branches. Deliberately *excludes* content-preserving
#: transforms (``format``/``encode``/``str``/a hash digest) -- those propagate.
ORDER_INDEPENDENT_CALLS: Set[str] = {
    "len",
    "min",
    "max",
    "sum",
    "any",
    "all",
    "count",
    "bool",
    "int",
    "float",
    "abs",
    "round",
    "ord",
    "index",
}

#: String-splitting methods (``str.split``/``rsplit``/``splitlines``). They return
#: a list whose element order is fixed by the *content* of the string -- left to
#: right -- not by any collection's iteration order. So iterating their result is
#: deterministic: a string parameter's "might be an unordered collection" worry is
#: laundered (you cannot ``.split()`` a set), and they introduce no order
#: instability. Any *content* volatility of the receiver (``str(uuid4()).split()``)
#: still passes through; only ordering/parameter taint is dropped.
STR_SPLIT_METHODS: Set[str] = {"split", "rsplit", "splitlines"}

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

#: File-read methods. ``path.read_text()`` / ``read_bytes()`` / ``f.read()`` return
#: the file's *content*, which is determined by the file, not by the receiver's
#: ordering. So they launder ordering taint: a path/handle parameter is a scalar,
#: and reading it yields a deterministic value (if the file's own content is
#: unstable, that's the fault of whatever *wrote* it, flagged at that write). This
#: is also the intended input to a content hash / file change-detector, so reading
#: a file must not look like an ordering source.
FILE_READ_METHODS: Set[str] = {
    "read",
    "read_text",
    "read_bytes",
    "readline",
    "readlines",
}

#: Pydantic model serializers. A model serializes its *field names* in definition
#: order, so ``<model>.model_dump_json()`` / ``<model>.model_dump()`` launder the
#: model's own field-name order -- and the contract-boundary uncertainty about an
#: *opaque model param* (``param.model_dump_json()`` to a databag is not a raw
#: unordered write). Membership here is what triggers that launder in
#: ``TaintEngine._call``.
#:
#: But the launder is *flavor-scoped*, NOT total: the dump fixes only the
#: top-level field-name order, never the order *within* a field value. A model with
#: an unstable list field (``dashboards: List[str]`` built from a glob) still flaps
#: -- pydantic emits a list in element order. So ``_call`` inherits the receiver's
#: *concrete* content taint (``local``/``element``/``itercaller``/``volatile``) and
#: drops only the field-name-order/param-boundary flavors (``param``/``iterparam``).
#: The v1 ``.json()`` / ``.dict()`` spellings are deliberately *not* listed here:
#: they inherit *all* receiver taint (including the param-boundary precaution), so
#: they stay even more conservative; on a fully opaque receiver the gap surfaces
#: under ``--explain-gaps``.
MODEL_SERIALIZERS: Set[str] = {"model_dump_json", "model_dump"}

#: Model field annotations that impose *positional* (element) order. When a
#: Pydantic model coerces an unordered value (a bare ``set``) into a field of one
#: of these types, its ``__init__`` runs ``list(value)`` internally -- so the
#: disorder moves from *key* order (``local``, laundered by a key-sorting
#: serializer such as ``model_dump_json`` / ``json.dumps(sort_keys=True)``) into
#: *element* positions (``itercaller``, which no key-sorting serializer can
#: reach). A ``set`` passed to such a field is therefore promoted ``local`` ->
#: ``itercaller`` at construction. ``set``/``dict`` fields are absent: their only
#: disorder stays key-order, which a key-sorting serializer legitimately fixes.
SEQUENCE_FIELD_ANNOTATIONS: Set[str] = {
    "list",
    "List",
    "tuple",
    "Tuple",
    "Sequence",
    "MutableSequence",
}

#: Digest/hash calls used as change-detectors. A charm hashes some content and
#: diffs the digest against the previous reconcile to decide whether to do
#: expensive work (restart, pebble replan, rule re-sync, databag re-publish, ...).
#: Hashing an unordered (or otherwise unstable) value yields a different digest
#: for the same logical content, so that gate trips on every reconcile. The
#: *hashing of unstable content* is the sink: the analyzer flags the digest call
#: itself and assumes the digest is used as a change-detector (its near-universal
#: purpose); it does not trace which specific effect the digest gates.
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
    "shake_128",
    "shake_256",
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

#: The subset of :data:`UNORDERED_ANNOTATIONS` that is *definitely* unordered: the
#: set family. A parameter of one of these types is unordered regardless of caller,
#: so a sequence built from it and written to a sink is a *high*-confidence contract
#: finding. The rest of :data:`UNORDERED_ANNOTATIONS` (``Iterable`` / ``Collection`` /
#: the dict views) merely *may* be unordered -- they admit ordered types (an
#: ``Iterable`` includes ``list``; a ``KeysView`` iterates in the dict's insertion
#: order), so a parameter of those types grades *medium*, like an unannotated one.
DEFINITELY_UNORDERED_ANNOTATIONS: Set[str] = {
    "set",
    "Set",
    "frozenset",
    "FrozenSet",
    "AbstractSet",
    "MutableSet",
}

#: Return annotations that assert the returned value is an *unordered collection*.
#: A function/property annotated ``-> set[str]`` (or ``frozenset`` / ``AbstractSet``
#: / ``MutableSet``) promises a set: iterating or serialising its result without
#: ``sorted()`` flaps, even when flaplint can't trace the body (an opaque helper, a
#: cross-object call). The set family only -- deliberately *not* the broad
#: ``Iterable`` / ``Collection`` / ``KeysView`` of :data:`UNORDERED_ANNOTATIONS`,
#: which as a *return* type is usually an ordered generator/view and would over-fire
#: (a return-type inference asserts the value *is* unordered and drives concrete
#: caller findings, so it must stay tight; a *parameter* of those types is only a
#: graded contract boundary, so the broader set is safe there).
UNORDERED_RETURN_ANNOTATIONS: Set[str] = set(DEFINITELY_UNORDERED_ANNOTATIONS)

#: Parameter annotations that are ordered/irrelevant: dumping them is the
#: caller's responsibility, so the helper itself is not at fault. Mappings live
#: here too: the only instability a ``Dict``/``Mapping`` can introduce at a sink
#: is *key* order, which every real databag serializer fixes (PyYAML sorts keys
#: by default; ``json.dumps(sort_keys=True)``; a Pydantic model dumps fields in
#: definition order). A bare mapping *parameter* therefore is not the helper's
#: fault -- if the caller passes order-shuffled *values*, that is a caller-side
#: ``caller`` finding, not a contract-boundary ``sink`` one.
ORDERED_ANNOTATIONS: Set[str] = {
    "list",
    "List",
    "tuple",
    "Tuple",
    "Sequence",
    "str",
    "bytes",
    # ``bytearray``/``memoryview``/``ByteString`` are ordered sequences of bytes,
    # indexed ``0..n`` exactly like ``bytes`` -- their serialization/write order is
    # deterministic, so a caller cannot (and need not) ``sorted()`` them. Left out
    # here, a ``data: bytearray`` param written to a file graded as an unknown
    # (medium) collection contract; it belongs with the ordered byte family.
    "bytearray",
    "memoryview",
    "ByteString",
    "int",
    "float",
    "bool",
    "dict",
    "Dict",
    "Mapping",
    "MutableMapping",
    "OrderedDict",
}

#: Runtime types that an ``isinstance(x, T)`` guard narrows ``x`` to an *ordered*
#: value. Inside such a guard the parameter's caller-uncertainty is resolved -- it
#: is provably one of these, all of which a serializer can keep stable (a mapping's
#: only disorder is key order, which key-sorting fixes) -- so the contract-boundary
#: "a caller might pass a set" worry no longer applies. The runtime twin of
#: :data:`ORDERED_ANNOTATIONS`. ``set``/``frozenset`` are deliberately absent: a
#: branch guarded by ``isinstance(x, set)`` is exactly the unordered case.
ISINSTANCE_ORDERED_TYPES: Set[str] = {
    "list",
    "tuple",
    "str",
    "bytes",
    "bytearray",
    "memoryview",
    "dict",
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

#: Dict methods that merge *another mapping's* items -- and its key-insertion
#: order -- into the receiver. A plain ``certs.update(other)`` / ``certs.setdefault(
#: k, v)`` outside a loop makes ``certs`` inherit the argument's instability, so a
#: later ``json.dumps(certs)`` (no ``sort_keys``) flaps. Kept narrow (mapping-only)
#: so it never absorbs a *list* ``.append``'s nested-field taint (which an
#: order-preserving pass-through would legitimately launder).
MAPPING_MERGE_METHODS: Set[str] = {"update", "setdefault"}

#: The subset of :data:`ACCUMULATOR_METHODS` that build a *list* (sequence). A list
#: filled by iterating an unordered source bakes the iteration order into its
#: *element* order -- value-position instability a key-sorting serializer cannot
#: launder, so it must be promoted ``local`` -> ``itercaller`` (exactly like a list
#: comprehension). ``add``/``update``/``setdefault`` build a ``set``/``dict`` whose
#: disorder *is* key-order and stays ``local`` (laundered by key-sorting), so they
#: are deliberately excluded. ``append``/``insert`` are list-only; ``extend`` is
#: list/deque (treated as a sequence either way).
LIST_ACCUMULATOR_METHODS: Set[str] = {"append", "extend", "insert"}

#: Mutating ``set`` methods that add elements. A ``set`` built up incrementally --
#: ``s = set(); ... s.update(x)`` / ``s.add(x)`` -- is still a ``set``, whose
#: iteration order is hash-seeded and therefore unstable *regardless of what was
#: inserted* (unlike a ``dict``, whose order follows insertion). So mutating a
#: known ``set`` variable makes it ``local``, even when the empty ``set()`` it
#: started from was treated as stable and the values came from an ordered source.
#: This is what catches the ``requested_protocols = set(); for ...: .update(...)``
#: idiom without needing ``--relations-unordered``.
SET_MUTATION_METHODS: Set[str] = {
    "add",
    "update",
    "difference_update",
    "intersection_update",
    "symmetric_difference_update",
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

#: Builtin collection *mutator* methods (``set.update`` / ``list.append`` / ...).
#: Same cross-class collision risk as the views: ``subnets.update(...)`` on a local
#: set would otherwise resolve, by bare name, to a charm's own ``update`` method and
#: inherit its (databag-writing) summary -- flagging the set as if it reached a sink.
#: So on a receiver whose class isn't known, these never resolve to a user method.
#: (``relation.data[...].update(...)`` is still caught as a databag write by the
#: separate, receiver-anchored mapping-write detection.)
BUILTIN_MUTATOR_METHODS: Set[str] = {
    "update",
    "setdefault",
    "add",
    "append",
    "extend",
    "insert",
    "discard",
    "remove",
    "pop",
}

#: Builtin mapping *accessor* methods that extract a single value by key
#: (``dict.get(k[, default])``). Like the views/mutators these carry the same
#: cross-class collision risk -- a non-self ``d.get(k)`` must not union in a
#: same-named user ``get`` method's summary -- but unlike a view they LAUNDER order:
#: the value at a key does not depend on the mapping's iteration order (the method
#: analogue of the ``d[k]`` subscript), handled in ``TaintEngine._call``.
BUILTIN_ACCESSOR_METHODS: Set[str] = {"get"}

#: Builtin collection method names (views + mutators + accessors) that must never
#: resolve to a same-named *user* method on a receiver of unknown class.
BUILTIN_COLLECTION_METHODS: Set[str] = (
    BUILTIN_VIEW_METHODS | BUILTIN_MUTATOR_METHODS | BUILTIN_ACCESSOR_METHODS
)

#: On-disk file / workload-config emission APIs (the ``file`` sink). Order-
#: unstable (or volatile) content reaching one of these writes a byte-unstable
#: file to a workload container or the charm container's disk. Like a content
#: hash, such a file is overwhelmingly used as a *change-detector*: the charm
#: (or a downstream consumer) diffs the file against its previous contents to
#: gate expensive work -- a pebble replan, a workload restart, a re-render, or
#: further file I/O. If the bytes reshuffle every reconcile, that gate trips
#: spuriously and the workload churns. The *write of unstable content to disk*
#: is the sink; flaplint flags it and assumes the file feeds a change-detector
#: (its near-universal purpose), without tracing which specific effect it gates.
#:
#: Each entry maps the (well-known, stable) framework/stdlib method name to the
#: argument carrying the *content*: ``(positional index, keyword aliases)``.
#: Directory/deletion ops (``make_dir``/``mkdir``/``remove_path``/``rmdir``/
#: ``unlink``) carry no content and are not flap sinks, so they are absent.
FILE_WRITE_METHODS: Dict[str, "tuple[int, tuple[str, ...]]"] = {
    # ops.Container (workload container).
    "push": (1, ("source",)),  # Container.push(path, source, ...)
    # pathlib.Path AND charmlibs.pathops (ContainerPath / LocalPath share the
    # same names + content-first signature): write_text(data)/write_bytes(data).
    "write_text": (0, ("data",)),
    "write_bytes": (0, ("data",)),
    # Open file handles: ``f.write(data)`` / ``f.writelines(lines)``.
    "write": (0, ("data",)),
    "writelines": (0, ("lines",)),
    # Low-level: ``os.write(fd, data)`` -- content is the *second* positional.
    "os_write": (1, ("data",)),
}

#: Human-readable sink descriptions for the file-write methods above, keyed by
#: method name, used in the finding message.
FILE_WRITE_DESCS: Dict[str, str] = {
    "push": "container push (file change-detector: replan / restart)",
    "write_text": "on-disk file write (change-detector gate)",
    "write_bytes": "on-disk file write (change-detector gate)",
    "write": "on-disk file write (change-detector gate)",
    "writelines": "on-disk file write (change-detector gate)",
    "os_write": "on-disk file write (change-detector gate)",
}

#: Juju secret writes (the ``secret`` sink): ``Secret.set_content(content)`` and
#: ``Application/Unit.add_secret(content, ...)``. Juju stores the content mapping
#: and creates a **new revision** whenever it differs from the current one, firing
#: ``secret-changed`` on every observer -- the same spurious-churn problem as a
#: databag write, just on a different Juju object. So an order-unstable value in the
#: content (a ``json.dumps(<unordered>)`` string, a set, a positional pick, a
#: volatile value) churns secret revisions every reconcile.
#:
#: Content is the first positional (``content`` keyword). Like a databag, the outer
#: mapping is compared by Juju structurally, but an unstable *value* string flaps.
SECRET_WRITE_METHODS: Dict[str, "tuple[int, tuple[str, ...]]"] = {
    "set_content": (0, ("content",)),  # Secret.set_content(content)
    "add_secret": (0, ("content",)),   # Application/Unit.add_secret(content, ...)
}

#: Human-readable sink description for a Juju secret write.
SECRET_WRITE_DESC = "juju secret write (new revision → secret-changed churn)"

#: Pebble-plan emission APIs (the ``plan`` sink): ``Container.add_layer(label,
#: layer)`` (and the lower-level ``pebble.Client.add_layer``). Unstable content in
#: a layer can make ``replan()`` see a changed plan and restart services for no
#: real reason -- the same spurious-churn problem as a databag write.
#:
#: It is *deliberately not* a byte-diffed :data:`FILE_WRITE_METHODS` entry. Pebble
#: does not diff the layer's YAML bytes: it parses the layer into plan structs,
#: merges them, and compares the merged service definitions to decide what to
#: restart. That comparison is **structural** -- mapping fields (``environment``,
#: ...) are order-insensitive, exactly as a key-sorting serializer would launder
#: them, while order-sensitive fields (a ``command`` string built by joining an
#: unordered set, a list-valued field) and nondeterministic values still flap. So
#: a plan write uses *key-sort* survival (see
#: ``TaintEngine.survives_structural_compare``), not raw-byte file survival: a bare
#: ``set``/dict-key-order in a layer is laundered by pebble and must not be flagged.
#:
#: Maps the method name to the ``(positional index, keyword aliases)`` of the
#: *layer* argument. ``replan()`` itself carries no content and is not a sink.
PLAN_WRITE_METHODS: Dict[str, "tuple[int, tuple[str, ...]]"] = {
    "add_layer": (1, ("layer",)),  # Container.add_layer(label, layer)
}

#: Human-readable sink description for a pebble-plan write.
PLAN_WRITE_DESC = "pebble plan (replan / service-restart gate)"

#: Serializers whose *return value* is a rendered config/data blob. A function
#: that ``return``s ``yaml.dump(x)`` / ``json.dumps(x)`` is a config-render
#: boundary: the bytes it produces are handed off to a consumer (a workload
#: push, a databag write, a file) that diffs them, so instability that survives
#: key-sorting -- an ``"element"`` pick or a ``"volatile"`` value -- flaps the
#: output. Benign dict-key-order (``"local"``) instability is laundered by the
#: very key-sorting the serializer applies, so a return-render sink never fires
#: on it (the taint engine returns an empty origin set for that case).
RENDER_SERIALIZERS: Set[str] = {"dump", "safe_dump", "dumps"}

#: Dotted-name serializers whose return value is a rendered config blob, but whose
#: bare method name is too common to live in :data:`RENDER_SERIALIZERS` (matched by
#: last component only). ``crossplane.build(directives)`` renders an nginx config
#: string from a list of directive dicts *preserving list order* -- so an unordered
#: source baked into that list (nginx upstream ``server`` lines built by iterating a
#: ``Set`` of worker addresses) survives, unsorted, into the config text and flaps the
#: file. Vendored fleet-wide by ``cos-coordinated-workers`` (every COS coordinator:
#: loki, mimir, tempo, parca...). Matched on the full ``receiver.method`` path so a
#: charm's own ``x.build()`` is unaffected.
RENDER_SERIALIZER_CALLS: Set[str] = {"crossplane.build"}

#: Template-render methods (Jinja2 ``template.render(**context)``). The analyzer
#: cannot see inside a ``.j2`` template, so it treats a render as building text out
#: of its arguments: if any argument is order-unstable (a set, a volatile value, or
#: a collection parameter), the rendered text is unstable too. This catches the
#: common charm pattern of rendering a config from a template and writing it to a
#: file -- a flow a plain dataflow check goes blind on, because the iteration lives
#: in the template rather than in the Python.
TEMPLATE_RENDER_METHODS: Set[str] = {"render"}

#: Inline comment that suppresses a finding on its line.
SUPPRESS_COMMENT = "databag-order: ignore"

#: Ordering of confidence levels, lowest first.
CONFIDENCE_RANK: Dict[str, int] = {"low": 0, "medium": 1, "high": 2}

#: Relative criticality of the finding kinds (lower sorts first). A ``caller``
#: finding pins a concrete bug to the exact line that serializes an unstable
#: value; a ``sink`` finding is advisory -- a helper that *would* churn if a
#: caller forgets to sort -- so it ranks below an equally-confident caller.
KIND_RANK: Dict[str, int] = {"caller": 0, "sink": 1}
