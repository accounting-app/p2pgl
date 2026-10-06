#!/bin/bash
# PostToolUse(Edit|Write): rustfmt the Rust file just written. rustfmt.toml at
# the repo root sets the edition and width, so this matches `cargo fmt`.
file=$(jq -r '.tool_response.filePath // .tool_input.file_path // empty')
case "$file" in
  *.rs) [ -f "$file" ] && rustfmt "$file" ;;
esac
exit 0
