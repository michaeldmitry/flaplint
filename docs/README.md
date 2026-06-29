# flaplint internals

Technical documentation for people who want to understand or change `flaplint`.
For what the tool is and how to run it, start with the [project README](../README.md).

Read in order, or jump to the part you're changing:

1. **[architecture.md](architecture.md)** — the four stages, the module map, how
   the summary loop works, a worked example, and what the analysis anchors on (and
   how it can drift). *Start here to get oriented.*

2. **[taint-model.md](taint-model.md)** — the core idea: the six kinds of
   instability, which serializers fix which, how a value first becomes unstable, and
   how that changes as it flows through calls. *Everything else builds on this.*

3. **[sinks-and-findings.md](sinks-and-findings.md)** — the four kinds of sink
   (databag, file, plan, hash), and how an unstable-value-reaches-a-sink flow becomes a
   finding: who-to-fix vs. how-to-fix, confidence, the four failure modes, and
   errors vs. warnings.

4. **[resolving-dependencies.md](resolving-dependencies.md)** — how the tool finds
   vendored libraries and installed dependencies, and the `--venv` / `--auto-deps`
   / `--python` flags.

## Quick orientation

| If you want to… | Read |
|---|---|
| add a new unordered **source** (a new set-like call) | [taint-model.md → Source discovery](taint-model.md#source-discovery-what-creates-an-origin) |
| make the engine recognise a new **serializer** | [taint-model.md → Serializer semantics](taint-model.md#serializer-semantics-in-detail) |
| recognise a new **sink** (a new databag/file API) | [sinks-and-findings.md → Sink discovery](sinks-and-findings.md#sink-discovery) |
| change how a finding's **confidence** is graded | [sinks-and-findings.md → Contract-boundary sink findings](sinks-and-findings.md#contract-boundary-sink-findings) |
| understand why a value crosses (or doesn't cross) a **function boundary** | [architecture.md → Inter-procedural summaries](architecture.md#inter-procedural-summaries) |
| understand the `local` vs `element` vs `itercaller` distinction | [taint-model.md → The origin taxonomy](taint-model.md#the-origin-taxonomy) |
| know what the tool depends on, and its drift risk | [architecture.md → What the analysis anchors on](architecture.md#what-the-analysis-anchors-on) |
