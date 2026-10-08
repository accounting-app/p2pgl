#!/usr/bin/env bash
# Print a fingerprint of the source tree as it would be committed — every file
# git would take (tracked, plus untracked files that are not ignored), by path
# and content — together with the Rust toolchain that builds it.
#
# gate.sh records it when the full gate passes; release.sh skips the gate when
# the release commit's tree has the same fingerprint, since the gate already
# passed on exactly that code with that compiler. It only reads: nothing is
# staged and nothing is written to git.
set -euo pipefail
cd "$(dirname "$0")/.."
{
  rustc --version
  cargo --version
  git ls-files -z --cached --others --exclude-standard \
    | sort -zu \
    | while IFS= read -r -d '' path; do
        # A tracked file deleted from the working tree is not in the commit.
        [[ -f "$path" ]] && printf '%s\0' "$path"
      done \
    | xargs -0 shasum -a 256 --
} | shasum -a 256 | cut -d' ' -f1
