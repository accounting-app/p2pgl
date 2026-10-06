#!/bin/bash
# PreToolUse(Edit|Write): the dated audit reports are records of what each audit
# found, not living documents. Any edit asks the maintainer first (an addition
# they requested, such as a closing note, is approved; anything else is not).
file=$(jq -r '.tool_input.file_path // empty')
case "$file" in
  */docs/audits/SECURITY_AUDIT_*.md | */docs/audits/CLAUDE_SECURITY_AUDIT_0820.md)
    jq -n --arg file "$file" '{
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "ask",
        permissionDecisionReason: ($file + " is a dated audit report — a record of what that audit found. Approve only an addition you asked for (for example a closing note); trackers in docs/audits/OUTSTANDING_TASKS*.md are the living documents.")
      }
    }'
    ;;
esac
exit 0
