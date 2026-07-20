# flaplint task runner.
#
# Every recipe here is EXACTLY what CI runs -- there is no second definition of
# "the checks" hiding in a workflow file. If `just check` passes locally, CI passes.
#
# Env management stays with uv (a committed uv.lock); just is only a thin, memorable
# front door. `just --list` to see everything.

set shell := ["bash", "-euo", "pipefail", "-c"]

# The ops version matrix the drift suite is anchored on.
# Floor: oldest ops a supported Juju LTS can run (see docs/ops-version-anchoring.md).
OPS_FLOOR := "2.23"

_default:
    @just --list

# Provision the locked dev environment (pytest, ops, ruff, mypy).
sync:
    uv sync --locked

# --- the gate -------------------------------------------------------------

# Everything CI enforces as blocking, in one shot. Run this before pushing.
check: lint static test

# --- lint / types ---------------------------------------------------------

# Lint (blocking in CI).
lint:
    uv run ruff check .

# Apply the fixes ruff can make itself.
lint-fix:
    uv run ruff check . --fix

# Formatting. NOT enforced yet -- `ruff format` would reformat ~25 files, so it wants
# a deliberate one-time commit first. Run `just fmt` to do it, then wire fmt-check
# into `check` and CI.
fmt:
    uv run ruff format .

fmt-check:
    uv run ruff format --check .

static:
    uv run mypy src/flaplint --ignore-missing-imports

# --- tests ----------------------------------------------------------------

# The whole suite against the locked ops (what `just check` runs).
test *ARGS:
    uv run pytest {{ARGS}}

# Just the fast unit suite, while developing.
test-unit *ARGS:
    uv run pytest tests/unit {{ARGS}}

# The ops-drift/corpus guards against the locked ops.
test-drift *ARGS:
    uv run pytest tests/drift {{ARGS}}

# Drift/anchor suite against a SPECIFIC ops version. Deliberately steps OUTSIDE the
# committed lock -- that is the point: the lock keeps day-to-day runs reproducible,
# this proves the anchors still hold across the support window.
#   just drift 2.23      # the floor
#   just drift ""        # latest release (empty pin)
drift ops=OPS_FLOOR python="3.12":
    uv run --python {{python}} --group dev \
        --with "ops{{ if ops == '' { '' } else { '==' + ops } }}" \
        pytest tests/drift -v

# Drift against ops from git main -- the early-warning leg. Allowed to fail (CI marks
# it continue-on-error): a break here means an UPCOMING ops release will break an anchor.
drift-main python="3.12":
    uv run --python {{python}} --group dev \
        --with "ops @ git+https://github.com/canonical/operator" \
        pytest tests/drift -v

# --- dogfood --------------------------------------------------------------

# Run flaplint itself (e.g. `just run ../some-charm/src --own-only`).
run *ARGS:
    uv run flaplint {{ARGS}}
