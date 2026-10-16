#!/bin/sh
# Measure a gl-node serving many ledgers (docs/build-log/004-no-python):
# `cargo xtask measure-ledgers`. The first run compiles the tool. --help: usage.
exec cargo run -q --locked --manifest-path "$(dirname "$0")/../xtask/Cargo.toml" -- measure-ledgers "$@"
