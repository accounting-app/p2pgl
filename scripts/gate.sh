#!/usr/bin/env bash
# The gate every change passes before it is ready to commit: formatting,
# lints with warnings as errors, and every test in the workspace.
#
#   scripts/gate.sh            # everything (~10 min)
#   scripts/gate.sh --quick    # fmt + clippy only
#
# Full logs go to target/gate/; the summary below is what to read. Exits
# non-zero if any step fails. Run it with nothing else heavy on the machine:
# gl-node's QUIC tests have time limits, and a loaded machine can miss them.
set -uo pipefail
cd "$(dirname "$0")/.."
mkdir -p target/gate
failed=()

step() {
    local name=$1
    shift
    printf '== %s ... ' "$name"
    if "$@" >"target/gate/$name.log" 2>&1; then
        echo ok
    else
        echo FAILED
        failed+=("$name")
    fi
}

step fmt cargo fmt --all -- --check
step clippy cargo clippy --workspace --all-targets --locked -- -D warnings
if [ "${1:-}" != "--quick" ]; then
    step tests cargo test --workspace --locked --no-fail-fast
    passed=$(grep -E '^test result:' target/gate/tests.log | awk '{s += $4} END {print s + 0}')
    failing=$(grep -E '^test result:' target/gate/tests.log | awk '{s += $6} END {print s + 0}')
    ignored=$(grep -E '^test result:' target/gate/tests.log | awk '{s += $8} END {print s + 0}')
    echo "   tests: $passed passed, $failing failed, $ignored ignored"
    grep -E '^test .* FAILED$' target/gate/tests.log | sed 's/^/   /'
fi

if [ ${#failed[@]} -gt 0 ]; then
    echo "GATE FAILED: ${failed[*]} (logs in target/gate/)"
    exit 1
fi
echo "GATE PASSED"
