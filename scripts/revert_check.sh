#!/bin/sh
# Revert checks (docs/build-log/004-no-python): `cargo xtask revert-check`.
# The first run compiles the tool (about a minute). No arguments: usage.
exec cargo run -q --locked --manifest-path "$(dirname "$0")/../xtask/Cargo.toml" -- revert-check "$@"
