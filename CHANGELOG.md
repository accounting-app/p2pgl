# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). No versioned release
has been cut yet.

## [Unreleased] — security hardening (audits 0922, 0922-v2)

This release fixes the findings in two audits:
[SECURITY_AUDIT_0922.md](SECURITY_AUDIT_0922.md), tracked in
[docs/OUTSTANDING_TASKS_09_22.md](docs/OUTSTANDING_TASKS_09_22.md) (T46–T60),
and [SECURITY_AUDIT_0922-v2.md](SECURITY_AUDIT_0922-v2.md), tracked in
[docs/OUTSTANDING_TASKS_09_22_v2.md](docs/OUTSTANDING_TASKS_09_22_v2.md)
(T61–T71). Each entry names its finding ID and task. For the detail and any
known residuals, see that task's "Done" note in the tracker.

> **Upgrading:** read *Breaking* first. Config files are parsed with
> `deny_unknown_fields`, so an **older binary refuses a config that uses any key
> added here**. Upgrade the binary before you edit the config. To roll back,
> remove the new keys first.

### Breaking

**Configuration**

- `externalFileEdits` is removed, and a config that still carries it is refused at boot by name. It only ever gated the file watcher, so use `watchLedgerFile: true` for that. Hand edits are always adopted (M-19, T52).
- Older binaries reject every new key listed under *Added* (`deny_unknown_fields`). That includes `watchLedgerFile`, `http.maxConnectionsPerIp` and the eight `p2p.antiEntropy*` keys (R-13).
- `auth.apiKey`, from the file or `GL_NODE_API_KEY`, must be printable ASCII with no surrounding whitespace. Boot refuses any other key and does not echo it. A key like that could never match an `X-Api-Key` header, so every request got `401` (L-50, T55).
- `"null"` in `cors.allowedOrigins` is refused at boot, and the guard refuses `Origin: null` whatever the config says (L-52, T55).
- `p2p.swarmTopic` now follows the `meshId` rules: non-empty, no surrounding whitespace, only ASCII letters, digits and `- _ . : /`, and at most 128 bytes. A topic containing a space or `|` no longer boots (M-31, T57).
- `allowedHosts` entries with a port, IPv6 brackets or a trailing dot are refused at boot, and the error names the spelling to use. Such entries never matched a request, so every request got `403` (0922-v2 §5, T71).

**HTTP**

- The node serves HTTP/1.1 only. Cleartext HTTP/2 (h2c, the `PRI * HTTP/2.0` preface) and HTTP upgrades are gone (M-22, T55).
- A request head over 64 KiB gets `431`. Because of buffer growth, a head that arrives in one burst can reach about 112 KiB before the check (M-41, T66).
- `/health` now sits behind the Host guard: an unlisted `Host` gets `403`. It also has its own limit of 120 requests a minute, with `429` past it (H-01 residual, L-42, T55).
- One IPv4 address or IPv6 /64 may hold at most `http.maxConnectionsPerIp` connections (default 64). Over-cap connections are closed before anything is read. Clients behind an unlisted proxy share one allowance, and so do Docker host-published ports. List the proxy in `trustedProxies` (M-33, T55).
- A connection that sends no request head within `http.headerReadTimeoutSeconds` of accept is dropped (T55).
- Under `tls.mode: "terminated"`, a plain `http://` `Origin` is no longer same-origin, except for loopback names (L-51, T55).

**Ledger files**

- A `.bean` that does not parse blocks every write with `PARSE_ERROR` until it is repaired. The node records nothing about the broken file (H-14, T61).
- Directives in the `.bean` with no envelope are adopted at boot as operator input. This covers hand-typed records and `open`/`close` lines from very old builds. They get this node's author, lamport and parents and are signed before the startup compaction. Entries that fail validation are quarantined, never dropped (H-13, T61).
- A block that starts with U+FEFF in the middle of the file is refused (L-62, T61). The parser refuses trailing tokens it cannot read instead of silently dropping them (M-25, T52).
- If the `.bean` is missing but a `.journal` exists beside it, boot refuses (H-15, T62).
- A FIFO, socket, device, directory or dangling symlink at the `.bean` or journal path refuses boot. A symlinked `.bean` is followed to a regular file, and the first compaction replaces the link with a regular file (M-36, T67).
- The journal, `.lock` and key file must be regular files owned by the node's uid, with a single link. The lock and key must be `0600`, and the journal must not be group- or world-writable. A key file over 4 KiB is refused (M-36, L-58, L-59, T67; L-49, T60).
- Damage anywhere in the journal except its final record refuses boot, and the error names the byte offset. A record length above the journal budget also refuses boot (M-43, T68).
- Every amount that is summed into a balance (posting units, cost, price, and the resolved elided leg) must have magnitude at most 10^21 (`MAX_AMOUNT_MAGNITUDE`), at any precision. The limit is inclusive, and trailing zeros no longer count against it. It is enforced identically by the API, the GraphQL scalar, peers, the journal and the file. A directive past it that is already on disk is quarantined at boot. `balance` and `price` directive amounts are not capped. More than 28 fractional digits are still refused instead of rounded (H-17, T65; M-50, T76).
- A directive a T65–T75 build quarantined for the old 21-significant-digit cap (for example `1.00000000 BTC @ 100000.00000000 USD`, or a `10^21` posting) loads again. It keeps the same content id and envelope, its children's parents resolve, and `verify` no longer reports `MissingParent`. Upgraded peers accept it (M-50, T76).
- Boot verifies the signature of every directive in the `.bean` that carries an envelope: with this node's own key for its own records as soon as the signer is installed, and with the author's key for everyone's once signing is enabled. A record whose signature does not verify — or that carries an author and lamport but no signature — is quarantined, never dropped: it stays in the file, out of the DAG and out of every balance, and the banner names it. A history this node wrote before enabling signing is quarantined the same way at its first signing boot; delete the `openledger-*` lines from those blocks to re-adopt them as signed operator input (H-20, T73).
- A directive with only one of `openledger-author` / `openledger-lamport` is operator input on both file paths, not history: the lamport is re-stamped, this node's author is stamped when absent, a hand-typed signature is discarded and a new one made. A foreign author on such a line is kept and the entry adopted unsigned with a warning, as before (M-47, T73).
- A hand-typed `openledger-parents` line must name records the ledger holds (DAG or quarantine); one naming a parent that exists nowhere is quarantined at boot and rejected by the live reconcile (L-75, T73).
- A hand-typed `open` of an account that is already open is refused on both file paths exactly as the API refuses it (L-77, T73).
- An unparsable block that follows a parsed block with no blank line between them is held together with that block as raw text, and a salvaged transaction that does not balance is quarantined; a split node-written transaction is never loaded truncated. The boot banner no longer says "nothing is lost" for a held block (H-20 door (b), T73).
- An `open` may list at most 64 currencies (`MAX_CURRENCIES_PER_OPEN`). Longer lists are refused with `RESOURCE_LIMIT_EXCEEDED` by the local API, by hand-edit reconcile and by peers. Existing history over the cap still loads, but upgraded peers refuse it (L-78, T75).
- A transaction's postings may carry at most 100 metadata keys in total (`MAX_POSTING_METADATA_KEYS_PER_TRANSACTION`). The local API never writes posting metadata, so this affects only hand edits and peers (M-48, T75).

**Replication**

- A lamport value of `2^53−1` is refused everywhere, and the largest value the node stamps is `CEILING−2`. `LAMPORT_CEILING` errors name the author and the mesh-wide remedy (H-12, T63; H-07, T46).
- A directive that would advance this node's clock by `2^32` or more in one step is refused with the new error `LAMPORT_ADVANCE`. The refusal is retried, not cached (H-12, T63). Since T72 the id is not re-fetched from the same peer until this node's clock has reached the point where the verdict can change (L-69). The message no longer promises acceptance "once the intervening directives have arrived": that never happens when the gap was made by a directive this node refuses (H-19).
- **The per-author unmerged-head bound is removed** and the error code `UNMERGED_HEAD_LIMIT` is gone: a peer's transaction is never refused for the number of heads its author holds on this node. That bound was judged against this replica's heads, so two replicas served disjoint 256-subsets of one 257-transaction flood held permanently different DAGs (H-21, T72; decision (2) of 2026-09-23). A local append still names at most 256 parents (`MAX_PARENTS`), which alone closes H-16's brick (T64).
- Removing an author from the allowlist while its directives are in the history means every **later** joiner, and every node rebuilt from an empty disk, must be joined by bootstrap — copy a current peer's compacted `.bean` and boot it under the joiner's own key — because anti-entropy alone cannot cross the lamport gap such a directive leaves, and anything authored on top of a removed author's transaction is refused for a missing parent. The ratchet itself is unchanged. README §Mesh identity, "Joining a mesh / removing a peer" (H-19, T72; decision (1) of 2026-09-23, revised).
- The server closes an inbound anti-entropy connection after `p2p.antiEntropySessionSeconds` (default 300 s) with close code 5, `session-deadline` (M-40, T70).
- Each peer has an inbound accept rate: a burst of 8, then one connection per 2 s. Refused connections close with code 6, `accept-rate-limit` (M-40, T70).
- A Supply entry with a malformed id is refused before it is parsed (H-18, T66).

**Rust API (`gl-node` modules; it is a binary crate, so this affects forks and in-tree code only)**

- `AntiEntropyHandler` has a new public field, `supply_backoff: SupplyBackoff` (T69), and `AntiEntropyTimeouts` has `supply_backoff: Duration` (T71). Struct literals without `..Default::default()` must add them.

### Changed

- `verify.errors` has one entry per offending node, capped at the first 1,000. The new `truncated` field counts the rest (L-63, T69).
- `journal` query complexity now scales with `limit` and the selection: `max(512, (limit/100) × (1 + child))`. Large aliased requests may be refused (M-45, T69). `verify` weighs 2048, and a request may contain at most 2 (M-23, T54).
- A peer batch that would not fit under the 64 MiB ledger cap is deferred without staging. That peer's Supply is then paused for `p2p.antiEntropySupplyBackoffSeconds` (default 60 s), with one warning (M-39, T69).
- At most `p2p.antiEntropyMaxConcurrentExchanges` outbound exchanges run at once (default 8). Other peers queue in order (R-5, T69).
- An outbound session is capped at 300 s, 512 advert pages and 64 MiB of advertised ids. A 64-hex id form is required (H-10, M-26, M-27, M-28, T49).
- Each peer may have 32 MiB of inbound frame bodies in flight, and all peers together 256 MiB. Excess is refused, not queued (L-39, T58).
- The byte-budget note now gives measured multiples: honest maximal `Supply` frames are about 6× their size in memory while being applied, and the densest frames inside every cap about 13×, so size hosts for about 2–3.5 GiB under the 256 MiB default (L-65, T75).
- Content-determined peer refusals are cached per `(peer, id)` for 10 minutes (L-34, T58).
- The file watcher re-reads the `.bean` only when its stat changes, or every 10 s. It runs off the async runtime (M-42, T69).
- A failed prepare reloads the ledger off the write lock (M-39, L-43, T69, T59).
- Boot quarantines what it refuses instead of dropping it. The boot banner lists all four quarantine reasons (H-08, T47; R-12, T55).
- A reconcile that rejects any entry forces the canonical rewrite, so refused lines do not stay on disk (M-37, T61).
- Canonical order breaks ties by content id. A file with same-date ties may be reordered once, at its first rewrite (M-24, T53).
- A mixed-scale balance may print with different trailing zeros than before (H-17, T65).
- `journal` and `transaction` agree on a boot-adopted hand record's envelope immediately after boot; the finalised copy is re-indexed instead of waiting for a restart (L-74, T73).
- The boot cycle quarantine keeps the enveloped spelling of a record when the file also holds an envelope-less copy of it, so the compaction writes the signed copy back and the next boot does not re-author it (L-76, T73).
- `LedgerService` gains `set_verifier(DirectiveVerifier)` and `verify_own_history()`; `gl-node` installs the verifier right after the signer when signing is enabled and runs the pass before the startup compaction (T73).
- A local append's parents are chosen for author diversity: at most `max(1, 256 / distinct head authors)` heads per author, smallest id first, then the remaining slots by smallest id. Still a pure function of the head set, so every replica holding the same heads names the same parents. Smallest-id-only let a peer that grinds content ids keep every honest head unmerged forever (L-68, T72).
- Boot, and any adoption, logs a WARN when the lamport clock is above `4 × directive count + 1024` — a clock is bounded by the events it has folded, so this is a jump in the history — naming the author whose directive carried it highest and the bootstrap join. Once per boot, then once per `2^20` of clock advance (H-19, T72).
- `LAMPORT_CEILING` errors and the boot ceiling warnings name the highest-lamport author **other than this node** when one exists; after the victim had authored on top of the poison they named the victim (T72).
- The "rejected remote directive from ALPN" warning is logged at most once per 10 s per peer, with `suppressed=N` on the next line (L-69, T72).
- A torn journal tail is kept as `<ledger>.journal.torn-<unix-seconds>`, never deleted. A zero-filled final record is torn, not corrupt (M-43, M-44, T68).
- A failed commit's recovery reload no longer installs a rebuild that lacks any record this node had already written. Only records staged since the last commit, and lines adopted from the file since the last compaction, may be missing. A backup copied over the live `.bean` followed by a failed write keeps every acknowledged record, and the next write puts the union on disk. The install log reports `discarded_staged` and `discarded_file_adopted` separately (M-46, T74).
- After a recovery reload that fails, the next commit is always a full rewrite, and the journal is kept as `<ledger>.journal.torn-<unix-seconds>` instead of being deleted. A refused reload that saw a torn journal renames it the same way (M-49, T74).
- `LedgerService::uncommitted_count()` counts only directives this node staged. Directives adopted from the `.bean` (boot's operator input, a live reconcile) are not counted, so it is 0 right after any boot. `LedgerDag::ids()` is new (ledger crate API; M-46, T74).
- Temporary files are named `<name>.tmp.<pid>.<nonce>`, and stale ones are swept at start (L-57, T67).
- Log echoes of attacker-supplied values are bounded. Guard refusals are logged at most once per 10 s, with `suppressed=N` (M-41, T66). The swarm topic is logged redacted (M-32, T57).
- A padded `swarmTopic` or `meshId` boot error shows the length, prefix and whitespace offset, never the value (L-56, T71).
- A signing node with `p2p.meshId` unset logs a WARN whose remedy is to set it to the current `swarmTopic` verbatim. `meshId` becomes required in a later release (R-9, T71).
- `GL_NODE_API_KEY` set while `auth.enabled: false` logs a boot warning without the key (0922-v2 §5, T71).
- GraphiQL assets are pinned to graphiql 4.1.2 instead of the floating `4`. No SRI yet (L-66, T71).
- `deploy/gl-node.docker.json` sets `"meshId": "openledger/docker-dev"`, its own `swarmTopic`, so the stack's signed history stays valid (R-9, T71).
- Balances are exact sums, in any arrival order. A figure that does not fit a `Decimal` at its usual scale is rounded once, half to even, instead of at each scale. This is reachable only through amounts at widely different scales, such as `1000` plus `0.0000000000000000000000000001`. Such figures print up to one unit in the last place differently from before (L-79, T76).
- `balance` assertions and `verify` compare against the exact sum. A claim that matches only the rounded figure now fails (L-79, T76).
- The balance sheet's `Equity:Net-Income` prints `0.00` instead of `-0.00` for a currency whose net is exactly zero (T76).

### Added

- `watchLedgerFile` (default `false`): poll the `.bean` every 250 ms and fold hand edits in promptly (M-19, T52).
- `http.maxConnectionsPerIp` (default 64, range `8`–`65536`, clamped to `maxConnections`; M-33, T55).
- `p2p.antiEntropySessionSeconds` (300, `30`–`3600`), `p2p.antiEntropyMaxAdvertPages` (512, `256`–`1024`), `p2p.antiEntropyMaxAdvertIdBytes` (64 MiB, 16–64 MiB) and `p2p.antiEntropyMaxSessionFrames` (100000, `10000`–`1000000`) (R-7, T70).
- `p2p.antiEntropyAcceptBurst` (8, `2`–`256`) and `p2p.antiEntropyAcceptRefillMilliseconds` (2000, `100`–`30000`) (M-40, R-7, T70).
- `p2p.antiEntropyMaxConcurrentExchanges` (8, `1`–`64`) and `p2p.antiEntropySupplyBackoffSeconds` (60, `5`–`3600`) (R-5, M-39, T71).
- GraphQL `exact: Boolean!` on `AccountBalance`, `TrialBalanceRow`, `TrialBalance`, `BalanceSheet` and `IncomeStatement`, and `actualExact: Boolean!` on `BalanceAssertionFailure`: `false` when the figure was rounded (L-79, T76).
- GraphQL `VerifyResult.truncated` (L-63, T69), and the error code `LAMPORT_ADVANCE` (T63). (`UNMERGED_HEAD_LIMIT`, added by T64, was removed again by T72 before any release.)
- `ledger::service::select_parents`, `clock_is_far_above_history` and the constants `CLOCK_HISTORY_WARN_FACTOR`, `CLOCK_HISTORY_WARN_SLACK`, `CLOCK_HISTORY_WARN_REPEAT_ADVANCE` and `BOOTSTRAP_JOIN_REMEDY` (T72).
- `.cargo/audit.toml`, which ignores exactly one advisory (`RUSTSEC-2026-0235`, `rkyv`, not compiled) and records the evidence (M-34, T56).
- This changelog (R-13, T71).

### Removed

- The `externalFileEdits` config key (M-19, T52).
- h2c and HTTP upgrade handling on the GraphQL port (M-22, T55).
- `graphql::query::domain_txn_to_graphql`. Callers pass the txid instead of re-hashing each row (M-45, T69).
- The hand-written `unsafe extern "C"` `geteuid` declaration. `libc` is now a direct dependency of `ledger` (R-17, T67).
- `ledger::service::MAX_UNMERGED_HEADS_PER_AUTHOR`, `ServiceError::UnmergedHeadLimit`, `LedgerDag::heads_authored_by` and the `UNMERGED_HEAD_LIMIT` error code (H-21, T72).

### Security

- **H-07 / H-12:** one lamport-ceiling rule on every path, plus a `2^32` adoption ratchet. One peer directive can no longer make a node author records nobody accepts, or brick it on restart (T46, T63).
- **H-08:** a lossy boot no longer reaches a rewrite. Refused records are quarantined, and compaction keeps them (T47).
- **H-09 / H-18:** Supply decoding and validation are bounded. A 1 MiB hostile entry costs 136 B of error text instead of 195 MB and a 55 MB log line (T48, T66).
- **H-10 / M-40 / M-06:** anti-entropy sessions have deadlines on both sides and a per-peer accept rate. A few peers can no longer pin every slot (T49, T70).
- **H-11:** a cancelled mutation no longer wedges every write path (T50).
- **H-13 / H-14 / M-37 / M-38:** the stop → edit → start workflow produces signed records. A failed reconcile no longer overwrites the operator's edit (T61).
- **H-15 / M-35:** removing the `.bean` under a running node, or crashing mid-compaction, can no longer install an emptier ledger or brick boot (T62).
- **M-46 / M-49:** a live file replacement plus one failed commit can no longer drop acknowledged records, and a failed recovery reload can no longer leave the next commit appending behind a torn journal tail, which bricked the next boot (T74).
- **M-48 / L-78:** peer `Supply` entries are held to the §3.12 caps while they are parsed and again right after, before a batch can queue them. A 1 MiB body of 41,941 postings used to peak at 42× its size and be refused only at stage; a 15 MiB frame of them held 546 MB. Both now peak under 0.1× and nothing is queued (T75).
- **H-16:** an allowlisted peer can no longer inflate the head set until this node's own appends are refused everywhere (T64).
- **H-19 / H-21 / L-68 / L-69:** replication rules are stated on the content, not on the replica. The per-replica head bound that let one peer's split delivery leave two honest replicas with permanently different committed DAGs is gone; parent choice can no longer be gamed to starve honest heads; the one bound that remains relative to this node's clock (the ratchet) is diagnosed at boot and on adoption instead of partitioning later joiners silently, with the bootstrap join documented and pinned by the convergence harness; and manufactured ratchet refusals cost one fetch per clock step, not one per tick (T72).
- **H-17:** balances are exact and independent of arrival order, so replicas, `verify` and reboots agree (T65).
- **M-50 / L-79:** balances are exact integer sums that no ingress can overflow, a history written before T65 loads whole again and a fresh replica can sync it, and `balance` assertions compare against the exact sum (T76).
- **H-20 / M-47 / L-74 / L-75 / L-76 / L-77:** boot verifies what it loads. An edited or split node-written record, a half envelope, a dangling hand-typed parent or a re-open can no longer be served under a signature no peer accepts and become the parent of everything the node authors afterwards (T73).
- **M-36 / M-43 / M-44:** ledger-side opens enforce file-type discipline, and journal policy fails closed (T67, T68).
- **Known residuals** remain listed in the trackers. They include the IPv6 /48 reach of the per-IP cap (L-61) and GraphiQL's CDN assets without SRI (L-66).
