# Log: a one-command production install

Status: in progress (step 1 of 7).

One entry per commit-sized unit, newest last, written when the unit is ready
to commit. The commit hash is filled in once the maintainer has committed.

## 2026-10-19 — Step 1: release 0.2.0 (the tooling, the version, the notes)

- **What changed:** the workspace is version 0.2.0; the CHANGELOG's
  `[Unreleased]` entries are `[0.2.0] — 2026-10-19`, with a summary, the
  status (pilot) and the known limits (the n0 limit of 0.1.0 is gone: entry
  001); a misleading *Changed* line about `--node-id` is dropped (it is new
  since 0.1.0, under *Added*). `scripts/release.sh` now also ships the Linux
  architecture the Docker host is not — on this Mac, linux-amd64, which most
  servers are — cross-compiled by **`Dockerfile.cross`** from the same pinned
  Rust image (Debian trixie's `gcc-<arch>-linux-gnu` and `libc6-dev-<arch>-cross`,
  glibc 2.41 headers, for `ring`'s C; the build refuses a binary that needs a
  glibc symbol newer than bookworm's 2.36, the runtime base), and, where the Docker host emulates it, boots that binary from
  an empty directory and waits for its own `--health-check`; `RELEASE-INFO.txt`
  says whether it ran. RELEASE.md *Platforms*; README's sample output and
  OPERATIONS' upgrade heading name 0.2.0.
- **Tried here:** the cross build (6.5 min, nothing cached) gave an x86-64 ELF
  that, under Colima's emulation, reported `gl-node 0.2.0`, booted and passed
  its health check in 2 s. The first build failed: `--no-install-recommends`
  left out `libc6-dev-amd64-cross`, so `ring` found no target headers; it is
  installed by name. A bind mount from outside the home directory reaches
  Colima's VM as an empty directory — `release.sh` mounts from the repository.
- **The release itself** runs on the committed tree (`release.sh` refuses a
  dirty one): after this commit, `scripts/release.sh --previous
  <0.1.0 darwin-arm64 binary>`, then the maintainer tags `v0.2.0` and attaches
  the files.
- **Gate:** `scripts/gate.sh` — 1,618 passed, 0 failed, 0 ignored (7 min 47 s).
- **Revert checks:** none: no new mechanism in the node; the release run
  exercises the script.
- **Review round** (reviewer subagent). *Important:* with Docker's classic
  image store, the emulated check's pull of the other platform's base would
  re-point the pinned digest, and the next classic build would put the native
  binary on that platform's base — named, from the image's metadata, as the
  other architecture, with every check still passing. Not so here (containerd
  store: `debian:bookworm-slim@…` stays arm64), but each Linux binary is now
  named by its ELF header and must match its image. *Important:* the Rust
  image is trixie (glibc 2.41), not bookworm as first written: the binary ran
  on bookworm only because it uses no symbol past 2.34; `Dockerfile.cross` now
  checks (`objdump -T`, no emulation needed) — 2.34 passes, and
  `MAX_GLIBC=33` refuses it, rerunning only that layer. Also: a *Breaking*
  section for what can stop a 0.1.0 deployment (moved from *Changed*); the
  summary and known limits say `relayMode` still defaults to `"n0"`; the
  Format v2 line restated; the emulation wording qualified; an empty runtime
  base or a failed pull fails with its own reason instead of "no emulation";
  the throwaway key goes through the environment, not the command line; a
  failed `docker create`/`cp` stops with a reason; RELEASE.md says Colima
  shares only the home directory.
- **Departures from the plan:** the other architecture is a cross-compiled
  binary (`Dockerfile.cross`), not an emulated image build; the upgrade
  rehearsal from 0.1.0 runs with the release itself (`plan.md` step 1, *As
  built*).
- **Commit:** <hash>

## 2026-10-19 — Step 1, continued: rustls 0.23.46

- **What changed:** the release stopped at `cargo audit`: four advisories
  published 2026-10-14 against `rustls` 0.23.45 (RUSTSEC-2026-0346, medium:
  a client session's `Debug` output exposed TLS secrets; 0347–0349, low),
  which iroh, its relay and DNS clients, and noq use. `cargo update -p rustls`
  moves only it, to 0.23.46; the audit is clean but for the allowed `paste`
  warning. CHANGELOG 0.2.0 *Security*.
- **Gate:** `scripts/gate.sh` — 1,618 passed, 0 failed, 0 ignored (8 min 9 s).
- **Revert checks:** none (a dependency update).
- **Departures from the plan:** none; the release runs after this commit.
- **Commit:** <hash>
