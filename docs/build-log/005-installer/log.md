# Log: a one-command production install

Status: in progress (step 2 of 7).

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

## 2026-10-19 — Step 2: the node behind a proxy

- **Release 0.2.0** (step 1) was built and checked at d6a4abb after the
  rustls commit: gate, audit, MSRV 1.91, the shipped-binary tests with the
  upgrade and rollback from 0.1.0 (8 passed), the image, linux-arm64, and
  linux-amd64 cross-compiled and booted to a passing health check under
  emulation (`target/release-dist/0.2.0/`, kept beside 0.1.0's). Tag and
  publish: the maintainer.
- **What changed:** **`NodeConfig::is_public`** — a non-loopback bind, *or*
  `tls.mode: "terminated"`, *or* a `trustedProxies` entry — is what every
  public-node rule keys on: L-09's
  minimal `/health`, M-2's auth on, no GraphiQL, H-01's key given on purpose
  and a non-empty `allowedHosts` (one message for where they apply). Before,
  they keyed on the bind, so a loopback node behind a proxy on its own host —
  the installer's design — would have served GraphiQL, no auth, a generated
  key or the full `/health` to the internet. Only "a non-loopback bind must
  be terminated" keys on the bind. **`gl-node init --domain D [--data-dir]
  [--output]`** (`node_init.rs`) writes that node's config: `127.0.0.1:4000`,
  `trustedProxies: ["127.0.0.1"]`, `allowedHosts: [D]` (a DNS name, lower
  cased; no scheme, port, path or IP), `tls.mode: "terminated"`, auth on with
  no key in the file, GraphiQL off, `ledgersDir` under the data directory,
  signing and P2P off for its own ledger — created 0600 and never replacing a
  file, then loaded as the node loads it (with a throwaway key) and removed if
  it does not. README (the *public node* wording throughout, *Behind an HTTPS
  proxy on the same host*), CHANGELOG (*Breaking*, *Security*, *Added*).
- **Tests:** a loopback node behind a proxy is refused for each public rule
  and loads with all kept, a plain loopback node keeps its leeway; `init`
  writes a public node behind its proxy (0600, no key, loads); never replaces
  a config; leaves no config that does not load; takes a domain name only;
  on the shipped binary, a node set up by `init` boots and is public behind
  its proxy (`/health` is `{"status":"ok"}` without a key, the version with
  it; GraphQL without a key 401), and a second `init` exits 1. The L-51
  request-guard fixture (loopback, terminated, no key) now gives its key.
- **Gate:** `scripts/gate.sh` — 1,624 passed, 0 failed, 0 ignored (6 min 55 s).
- **Review round** (reviewer subagent; nothing Important). A loopback node
  that names its proxy in `trustedProxies` but leaves `tls.mode` at
  `"disabled"` has a proxy in front all the same, and escaped every public
  rule; `is_public` now counts it (the maintainer's call to confirm; I-R12),
  and the trusted-proxies fixture gives its key and host. `init` serializes
  before the file exists (an early return would have left an empty file every
  re-run refuses) and syncs the directory as well as the file; its refusal
  says an international name goes in its `xn--` form. The README's Health
  Check section, the handler's and the config fields' docs, and the L-37
  comment said "the bind"; they say "public" now, and the README says to run
  `init` where the node runs (its paths are checked from `init`'s working
  directory). `init`'s 0600, GraphiQL off and auth on are pinned (I-R13–I-R15).
  For step 3: the Caddyfile must pass `Host` through unchanged (L-51's port
  match and `allowedHosts`), and `company add` must write `relayMode:
  "custom"` (a folder's default is `"n0"`).
- **Revert checks:** `installer.json` — 15 of 15 bite: `/health` by the bind
  (I-R1, shipped binary), `tls.mode` not making a node public (I-R2), each
  rule by the bind (I-R3–I-R6), `init` replacing a config (I-R7), binding every
  interface (I-R8), trusting no proxy (I-R9), any domain (I-R10), keeping a
  config that does not load (I-R11), a trusted proxy not making a node public
  (I-R12), `init`'s file readable by others (I-R13), GraphiQL on (I-R14), auth
  off (I-R15). `h01_l23.json` H01-R5 re-anchored on
  `is_public` (still bites).
- **Departures from the plan:** recorded in `plan.md` step 2 (*As built*).
- **Commit:** <hash>
