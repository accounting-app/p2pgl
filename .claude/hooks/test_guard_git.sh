#!/bin/bash
# The git guard against its cases (guard_git_cases.jsonl): each command is
# fed to the hook as Claude Code would, and the hook must deny exactly the
# ones marked "deny". Run by scripts/gate.sh.
#
#   .claude/hooks/test_guard_git.sh [HOOK] [--as-python]
#
# --as-python holds HOOK to the cases' "python" verdict where one is given:
# what the Python guard did (docs/build-log/004-no-python).
here=$(cd "$(dirname "$0")" && pwd)
hook=${1:-$here/guard_git.sh}
field=expect
[ "$2" = "--as-python" ] && field=python
failures=0
total=0
while IFS= read -r case; do
  [ -z "$case" ] && continue
  total=$((total + 1))
  command=$(printf '%s' "$case" | jq -r '.command')
  expect=$(printf '%s' "$case" | jq -r --arg field "$field" '.[$field] // .expect')
  verdict=allow
  if jq -n --arg command "$command" '{tool_input: {command: $command}}' | "$hook" | grep -q '"deny"'; then
    verdict=deny
  fi
  if [ "$verdict" != "$expect" ]; then
    failures=$((failures + 1))
    printf 'expected %s, got %s: %s\n' "$expect" "$verdict" "$command"
  fi
done < "$here/guard_git_cases.jsonl"
if [ "$total" -eq 0 ]; then
  echo "git guard: no cases read from guard_git_cases.jsonl"
  exit 1
fi

# It fails closed: with no jq (no PATH at all), the command is refused.
no_tools=$(printf '{"tool_input":{"command":"git status"}}' | env -i PATH=/nonexistent "$hook" 2>/dev/null)
case "$no_tools" in
  *'"deny"'*) ;;
  *) failures=$((failures + 1)); echo "without jq the hook did not refuse: ${no_tools:-no output}" ;;
esac

# It is linear: a 1 MiB command is decided in a few seconds of CPU (a
# quadratic reading spent 30-45 s). CPU, not the clock: a machine that sleeps
# or throttles mid-run stretches the clock and nothing else.
big=$(head -c 1048576 /dev/zero | tr '\0' 'a')
TIMEFORMAT='%U %S'
cpu=$( { time printf '{"tool_input":{"command":"echo %s && git push"}}' "$big" | "$hook" > "${TMPDIR:-/tmp}/guard_big_verdict.$$"; } 2>&1 )
big_verdict=$(cat "${TMPDIR:-/tmp}/guard_big_verdict.$$"); rm -f "${TMPDIR:-/tmp}/guard_big_verdict.$$"
seconds=$(printf '%s\n' "$cpu" | awk '{printf "%d", $1 + $2}')
if [ "$seconds" -gt 8 ]; then
  failures=$((failures + 1)); echo "a 1 MiB command took ${seconds} s of CPU"
fi
case "$big_verdict" in
  *'"deny"'*) ;;
  *) failures=$((failures + 1)); echo "a 1 MiB command ending in git push was not refused" ;;
esac

if [ "$failures" -gt 0 ]; then
  echo "git guard: $failures wrong ($total cases, and the fail-closed and size checks)"
  exit 1
fi
echo "git guard: $total of $total cases right; fails closed; linear"
