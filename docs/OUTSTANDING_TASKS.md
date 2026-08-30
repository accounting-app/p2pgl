# Outstanding Security Tasks

Remediation backlog for the findings in [CLAUDE_SECURITY_AUDIT_0820.md](CLAUDE_SECURITY_AUDIT_0820.md).
Ordered by fix priority. Each task lists the source finding, the change, the files, and how to verify.

**Status legend:** ☐ not started · ◐ in progress · ☑ done

## Priority order at a glance

| # | Finding | Sev | Effort | Status |
|---|---------|-----|--------|--------|
| T1 | H1 — Decimal overflow panics | High | S | ☑ |
| T2 | M3 — Lamport-clock overflow | Med | S | ☑ |
| T3 | H3 — Author spoofable / signing off by default | High | M | ☑ |
| T4 | H2 — Signature doesn't cover envelope | High | M | ☑ |
| T5 | M4 / L8 — Orphan memory exhaustion | Med | S | ☑ |
| T6 | M5 — Recursive DFS stack overflow | Med | S | ☑ |
| T7 | M1 — GraphQL resolver amplification | Med | S | ☑ |
| T8 | M2 — Unauth mutations on public bind | Med | S | ☑ |
| T9 | M6 — Quadratic DAG insertion | Med | M | ☐ |
| T10 | M7 — Unpinned CI actions | Med | S | ☐ |
| T11 | L2 — Signature domain omits mesh id | Low | S | ☐ |
| T12 | L3 — Path leak in GraphQL errors | Low | S | ☐ |
| T13 | L6 — Temp-file symlink follow | Low | S | ☐ |
| T14 | L5 — Non-injective txid serialization | Low | S | ☐ |
| T15 | L4 — API-key length timing | Low | S | ☐ |
| T16 | L7 — File-watcher missed change | Low | S | ☐ |
| T17 | Add `overflow-checks` + fuzz/panic regression harness | — | M | ☐ |

Effort: S = <½ day, M = ~1–2 days.

---

## Tier 1 — Ship before any public / multi-node deployment

### ☑ T1 — Make ledger arithmetic overflow-safe (H1)
- **Change:** Replace `*`/`+` on `Decimal` with `checked_mul`/`checked_add` on every path that consumes parsed amounts; return a `WeightError`/validation error on overflow instead of panicking.
- **Files:** `crates/ledger/src/weights.rs:54,72,100`, `crates/ledger/src/read_model.rs:148,419` (audit the whole crate for other bare `Decimal` `*`/`+`).
- **Verify:** Add a unit test feeding two `79228162514264337593543950335 USD` postings and a `10 AAPL {792…335 USD}` cost posting; assert a clean `Err`, not a panic. Confirm `append_transaction`, `insert_remote_directive`, and `reconcile_file` all surface the error.

### ☑ T2 — Bound the Lamport clock update (M3)
- **Change:** Use `saturating_add(1)` and reject/clamp an out-of-range `openledger-lamport` in `validate_supply_entry` before it reaches the clock.
- **Files:** `crates/ledger/src/service.rs:1080-1085`; validation in the supply-entry path (`anti_entropy_alpn.rs:267`).
- **Verify:** Test a remote directive with `openledger-lamport = u64::MAX`; assert no panic (debug) and no wrap-to-zero (release).

### ☑ T3 — Require signing under P2P (H3)
- **Resolved via option (a) only.** Option (b) — bind `openledger-author` to the connection's `EndpointId` — was **rejected as incorrect for this architecture**: anti-entropy legitimately relays third-party authors' directives (`collect_supply`/Want/Supply), so requiring author == connection peer would break convergence. The cryptographic signature (required by this task + covered by T4) is the correct origin proof for relayed directives.
- **Change:** Two parts — (a) at boot, refuse to start if `p2p.enabled && !signing.enabled` (or auto-enable signing); (b) ~~verify the `openledger-author` matches the connection's authenticated `EndpointId`~~ — NOT DONE (see above).
- **Files:** `crates/gl-node/src/config.rs:450` (boot validation), `crates/p2p/src/union_merge.rs:180-221` (`verify_author_allowlisted`), `crates/gl-node/src/anti_entropy_alpn.rs:246`. Also flip `deploy/gl-node.docker.json` `signing.enabled` to `true` (**L1**).
- **Verify:** Test that a directive whose `openledger-author` is a different allowlisted peer than the connection identity is rejected; test that boot fails when P2P is on and signing is off.

### ☑ T4 — Extend signature coverage to the envelope (H2)
- **Change:** Include `openledger-parents` and `openledger-lamport` (canonically serialized) in the signed message. Domain prefix is `openledger-sig-v2`. v1 signatures are not accepted (mesh upgrade together with T3).
- **Files:** `crates/security/src/signing.rs` (`SignableMessage` / `build_sign_message`), `crates/p2p/src/union_merge.rs` (`verify_remote_signature`), ledger sign-before-persist callbacks, GraphQL mutations.
- **Verify:** Rewriting `parents` or `lamport` on a validly-signed directive fails verification. CT-10 still asserts envelope keys stay out of the *content hash* — the hash and the signed message are different scopes.

---

## Tier 2 — DoS hardening (do before exposing to untrusted load)

### ☑ T5 — Cap parent count and envelope value length (M4, L8)
- **Change:** Enforce a max parent count and a max per-value byte length in `validate_supply_envelope`; consider lowering `MAX_ORPHANS_PER_PEER` / `MAX_ORPHAN_AGE` or making orphan memory a byte-budget rather than an entry count.
- **Files:** `crates/p2p/src/union_merge.rs:155-169`, `crates/p2p/src/orphan_buffer.rs:14-19,84-89`, `crates/ledger/src/model.rs:92-102` (parent parsing).
- **Verify:** Test that a `Supply` with a ~16 MiB `openledger-parents` blob is rejected before it reaches the orphan buffer; assert bounded `waiting_on` growth.

### ☑ T6 — Convert cycle detection to an explicit stack (M5)
- **Change:** Rewrite `detect_cycles` DFS iteratively (explicit work-stack) so DAG depth no longer maps to native stack frames.
- **Files:** `crates/ledger/src/verify.rs:126-150`.
- **Verify:** Test `verify_dag` on a single chain of ~1M transactions; assert it completes without stack overflow.

### ☑ T7 — Weight expensive GraphQL resolvers (M1)
- **Change:** Add `#[graphql(complexity = …)]` to `verify`, `trial_balance`, `balance_sheet`, `journal` reflecting real cost; re-tune the global complexity cap.
- **Files:** `crates/gl-node/src/graphql/mod.rs:34-44`, `crates/gl-node/src/graphql/query.rs:207-223`.
- **Verify:** Test that a ~4000-alias `verify` query is rejected by the complexity limiter.

### ☑ T8 — Fail closed on public bind without auth (M2)
- **Change:** In `validate()`, make auth-disabled + non-loopback bind a hard error, not a warning.
- **Files:** `crates/gl-node/src/main.rs:287-292`, `crates/gl-node/src/config.rs:250-336`.
- **Verify:** Test that `bindAddress: "0.0.0.0"` with `auth.enabled = false` refuses to boot.

### ☐ T9 — Bound DAG insertion cost (M6)
- **Change:** Memoize ancestor reachability (or cap chain depth) so `would_create_cycle` is not O(N) per insert.
- **Files:** `crates/ledger/src/dag.rs:122,162`.
- **Verify:** Benchmark loading a 100k chained-transaction ledger; confirm sub-quadratic scaling.

---

## Tier 3 — CI / hardening / lower-severity

### ☐ T10 — Pin CI actions to commit SHAs (M7)
- **Files:** `.github/workflows/ci.yml:15,18,30` — pin `dtolnay/rust-toolchain`, `Swatinem/rust-cache`, `rustsec/audit-check` to full SHAs.
- **Verify:** CI still green; refs are 40-hex SHAs.

### ☐ T11 — Bind signature domain to mesh/ledger identity (L2)
- **Change:** Add the swarm topic / mesh id into the signed message so directives can't be replayed across meshes. Fold into the T4 domain bump.
- **Files:** `crates/security/src/signing.rs:64-71`.

### ☐ T12 — Stop leaking filesystem paths in GraphQL errors (L3)
- **Change:** Map `ServiceError::Io` to a generic client message; log the detailed error server-side only.
- **Files:** `crates/gl-node/src/graphql/mutation.rs:81-84,136-139,165-168`.

### ☐ T13 — Open persist temp file with `O_EXCL` (L6)
- **Change:** Add `.custom_flags(O_EXCL)` (or create-new semantics) when opening `<name>.tmp` so a pre-planted symlink isn't followed.
- **Files:** `crates/ledger/src/service.rs:66-71`.

### ☐ T14 — Make txid serialization injective (L5)
- **Change:** Distinguish payee-only vs narration-only in the canonical form (e.g. always emit both slots with explicit empties).
- **Files:** `crates/ledger/src/serialize.rs:133-136`.
- **Verify:** Test that the two transactions hash to different txids.

### ☐ T15 — Remove API-key length timing side-channel (L4)
- **Change:** Compare against a fixed-length hash of the key (e.g. compare SHA-256 digests) so response time is independent of guess length.
- **Files:** `crates/gl-node/src/auth.rs:58-66`.

### ☐ T16 — Harden file-watcher change detection (L7)
- **Change:** Add a content hash (or nanosecond mtime + inode) to `detect_change` so same-size, same-second edits aren't missed.
- **Files:** `crates/ledger/src/file_watcher.rs:76-88`. Low priority while `external_edits_enabled` defaults false.

### ☐ T17 — Defense-in-depth: overflow-checks + panic regression harness
- **Change:** Add `[profile.release] overflow-checks = true` to `Cargo.toml` (turns silent wraps into panics), then ensure T1/T2 mean those panics are unreachable. Add a fuzz/property harness feeding malformed `.bean` and CBOR supply entries to the parser and merge paths.
- **Files:** `Cargo.toml`, new fuzz target under `crates/ledger`.
- **Verify:** Fuzzer runs clean; overflow-checks build passes the existing test suite.

---

## Suggested sequencing
1. **T1, T2** first — smallest changes, remove the cheapest remote crash/DoS.
2. **T3 + T4 + L1/T11** as one coordinated integrity release (wire-format/domain change; upgrade the mesh together).
3. **T5–T9** DoS hardening before any exposure to untrusted load.
4. **T10–T17** as follow-up hardening.
