# How flaplint works (the details)

Documentation for people who want to understand or change `flaplint`. For what the tool
is and how to run it, start with the [project README](../README.md).

Read in order, or jump to the part you're changing:

1. **[architecture.md](architecture.md)** — the four stages, the module map, how the
   summary loop works, a worked example, and what the analysis leans on (and how it can
   drift). *Start here to get oriented.*

2. **[taint-model.md](taint-model.md)** — the core idea: the six kinds of instability,
   which serializers fix which, how a value first becomes unstable, and how that changes
   as it's passed around. *Everything else builds on this.*

3. **[sinks-and-findings.md](sinks-and-findings.md)** — the four kinds of write target
   (databag, file, plan, hash), and how "an unstable value reaches a write" becomes a
   finding: whose-code-to-fix vs. how-to-fix, confidence, the four problem types, and
   errors vs. warnings.

4. **[resolving-dependencies.md](resolving-dependencies.md)** — how the tool finds
   vendored libraries and installed dependencies, and the `--venv` / `--auto-deps` /
   `--python` flags.

5. **[ops-version-anchoring.md](ops-version-anchoring.md)** — which ops version the
   ops/pebble anchors are valid for (the supported-Juju-LTS window), why flaplint's
   verdict is ops-version-invariant, and the labelled-corpus + oracle machinery that
   turns an ops drift into a loud test failure.

## Quick orientation

| If you want to… | Read |
|---|---|
| know **what technique** the tool is based on, and the standard term for each concept | [architecture.md → Background: this is taint analysis](architecture.md#background-this-is-taint-analysis) |
| add a new unordered **source** (a new set-like call) | [taint-model.md → Where unstable values come from](taint-model.md#where-unstable-values-come-from) |
| make the engine recognise a new **serializer** | [taint-model.md → What each serializer does](taint-model.md#what-each-serializer-does) |
| recognise a new **write target** (a new databag/file call) | [sinks-and-findings.md → The four kinds of write target](sinks-and-findings.md#the-four-kinds-of-write-target) |
| change how a finding's **confidence** is graded | [sinks-and-findings.md → When a helper trusts its caller](sinks-and-findings.md#when-a-helper-trusts-its-caller) |
| understand why a value crosses (or doesn't cross) a **function boundary** | [architecture.md → Following values across function calls](architecture.md#following-values-across-function-calls) |
| understand the `local` vs `element` vs `itercaller` distinction | [taint-model.md → The six kinds of instability](taint-model.md#the-six-kinds-of-instability) |
| know what the tool leans on, and its drift risk | [architecture.md → What the analysis anchors on](architecture.md#what-the-analysis-anchors-on) |
