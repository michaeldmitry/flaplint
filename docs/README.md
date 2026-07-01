# flaplint docs

Deeper reading after the [project README](../README.md). Jump to the page that answers your question:

| I want to know… | Read |
|---|---|
| What kinds of instability does flaplint detect, and what makes each one flap? | [taint-model.md](taint-model.md) |
| What are the four write targets, and how does "a value reaches a write" become a finding? | [sinks-and-findings.md](sinks-and-findings.md) |
| How does flaplint work under the hood — the pipeline, the summary loop, the known gaps? | [architecture.md](architecture.md) |
| How do I tell flaplint about installed dependencies and vendored libraries? | [resolving-dependencies.md](resolving-dependencies.md) |
| Which ops version do the anchors target, and how is semantic drift caught? | [ops-version-anchoring.md](ops-version-anchoring.md) |

## Reading order

If you want to understand the tool thoroughly, read in this order:

1. **[taint-model.md](taint-model.md)** — the core idea: what makes a value unstable, the six instability kinds, which serializers fix which, and how instability changes as a value moves. *Everything else builds on this.*
2. **[sinks-and-findings.md](sinks-and-findings.md)** — the four write targets (databag, file, plan, hash), and how "an unstable value reaches a write" becomes a finding with a type, a confidence, and an owner.
3. **[architecture.md](architecture.md)** — how a run flows through the four stages, how the summary loop connects callers to callees across function boundaries, and where the analysis has known blind spots.
4. **[resolving-dependencies.md](resolving-dependencies.md)** — how to include vendored libraries and installed dependencies in the scan.
5. **[ops-version-anchoring.md](ops-version-anchoring.md)** — the machinery that keeps the ops/pebble anchors honest across ops versions.

For making changes to the tool, start with **[AGENTS.md](../AGENTS.md)**.
