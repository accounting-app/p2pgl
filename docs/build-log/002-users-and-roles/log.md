# Log: people, keys and roles

Status: in progress.

One entry per commit-sized unit, newest last, written when the unit is ready
to commit. The commit hash is filled in once the maintainer has committed.

## 2026-10-11 — Step 1: roles on one node

- **What changed:** `crates/gl-node/src/access_control.rs` — `Role` (read <
  write < admin), `Caller`, and `AccessControl`, a schema extension that judges
  the parsed request before anything runs: queries and subscriptions need read,
  any mutation write, any field in `ADMIN_FIELDS` (empty until step 3) admin —
  the strictest across every operation, alias and fragment. The auth
  middleware attaches the caller (the operator key, admin; or anyone on a
  loopback node with auth off, as before) and the GraphQL handler passes it to
  the schema; a request with no caller is refused. Errors carry code
  `FORBIDDEN`. CHANGELOG *Security*.
- **Review round** (reviewer subagent; nothing Important), all taken: the
  first version let test builds fall back to the operator when no caller was
  attached, which no test could pin — removed: the schema has no fallback, and
  tests attach the operator themselves (`ExecuteAsOperator`, 54 test call
  sites), so the no-caller refusal is now tested through the real schema; the
  auth-off path's caller is pinned by a shipped-binary test (auth off, the
  operator still writes); a subscription is in the role test; the error no
  longer carries a made-up location; named fragments have their own revert.
- **Gate:** `scripts/gate.sh` — 1,554 passed, 0 failed, 0 ignored (6 min 43 s).
- **Revert checks:** `scripts/revert_specs/users.json` — 9 of 9 bite; the
  middleware → handler → schema link (U-R6, U-R6b, U-R7) is proven through
  the shipped binary.
- **Departures from the plan:** a role refusal is HTTP 200 with a GraphQL
  error coded `FORBIDDEN`, not a 403 — the check runs inside the GraphQL
  execution, and GraphQL reports per-request errors in the body (a missing or
  wrong key is still a 401, before GraphQL). No subscription is sent end to
  end: no transport serves subscriptions; the role rule for them is in the
  unit test.
- **Commit:** d84083a (amended together with 001 step 3)

## 2026-10-12 — Step 2: access records

- **What changed:** ledger — `access_record` (the `openledger-access` event
  type), an index of access records in the DAG (`access_records()`, filled on
  every insert, so peers' records too, and rebuilt at boot), the authoring call
  `record_access_event_staged` (stamped and signed like an `open`; no
  `openledger-` field), and the refusal of an access record typed into the
  `.bean` (operator input, both paths; a full envelope stays, as history).
  gl-node — `access_list`: the fold (lamport then content id; grant, rotation
  by a later grant, revoke; malformed records and records from nodes outside
  `auth.adminNodes` skipped) and the lookup by the key's SHA-256 with expiry;
  `AuthState::authenticate` accepts the operator key or a person's key from
  the access list, folded from the ledger on each request (a revocation needs
  no restart); `CallerId::User`; `auth.adminNodes` (EndpointIds, normalised).
  README (config table), CHANGELOG (*Added*).
- **Review round** (reviewer subagent): two Important findings, both fixed.
  (I-1) An access record's id hashes its body, not its lamport, so a second
  revocation of one person on one day was the *same* record — silently
  dropped (`Duplicate` reported as success), and on a Format v1 mesh two nodes
  could keep different copies under one id. Now every access record carries a
  random `record` nonce (required by the ledger and by the fold), and a
  duplicate is an error. (I-2) On a node with signing off, a line typed into
  the `.bean` with a made-up envelope reads as history, and nothing checks its
  author — so people's keys are honoured only on a signing node
  (`access_source_for`; boot warns if access records exist on a signing-off
  node), and `auth.adminNodes` needs signing. Also: access records get the
  peer path's string checks (`validate_body_strings`); the folded list is
  cached against the DAG's `access_generation`, so a request costs a comparison
  however many records exist; the key hash is compared in constant time and a
  hash two people hold belongs to neither; `AccessEntry`'s `Debug` redacts the
  hash; the `/health` change is documented; `dag.rs` doc order fixed.
- **Gate:** `scripts/gate.sh` — 1,563 passed, 0 failed, 0 ignored.
- **Revert checks:** `scripts/revert_specs/users.json` — 31 of 31 bite (steps
  1–2). Two did not bite at first, each because of the test, not the code:
  U-R14 (a malformed hash that two checks refused) and U-R22 (the cache test
  built a fresh state, so a fresh cache, on every call). The U-R14 test now
  has a case for each check (U-R14, U-R14b).
- **Departures from the plan:** people's keys only on a signing node, and a
  `record` nonce in every access record (the review round). The cache keyed
  by `access_generation` replaces the plan's "fold on each request".
- **Commit:** c39c9a7

## 2026-10-12 — Step 3: the admin API and `gl-node user`

- **What changed:** gl-node — `graphql/access.rs`: `grantAccess` (a new
  person, or a new role, expiry and key for one on the list; the key — 32
  random bytes — is in the payload once, the record keeps its SHA-256),
  `revokeAccess`, `renameUser` and the query `accessList`, all four in
  `ADMIN_FIELDS`. A change is judged under the write lock against the list as
  it stands (someone not on the list, a blank or over-long name, a past expiry:
  `INVALID_INPUT`), refused on a node that keeps no access list
  (`NO_ACCESS_LIST`: signing or auth off) or whose records no node would count
  (`NOT_AN_ADMIN_NODE`), checked against the ledger's size cap before staging
  (`LocalWrite::Access`, T77), then written, committed and gossiped as every
  mutation is. The record names the admin in `by` (`operator` or their user
  id). `access_list`: names in the fold (decision 2, revised) and the `rename`
  action, which counts only for someone on the list at that point in the
  order. `user_cli.rs`: `gl-node user add | list | rename | revoke`, a client
  of that API on the node's own port with the operator key — read from the
  config, `GL_NODE_API_KEY` or the key file, which it never creates
  (`auth::read_existing_api_key`). README *People and keys*, CHANGELOG
  (*Added*); plan.md's risk and alternatives updated for names.
- **Tests:** the API through the real router and auth middleware (grant,
  write with the new key, refused the admin API; list without keys or hashes;
  rename keeps the key; regrant replaces role and key; an admin person's grant
  names them; revoke → 401); the refusals, with nothing written; the size-cap
  refusal before staging; a name with quotes, a backslash and accents
  surviving a reboot; the fold's rename rules; the CLI's parsing, role enum and
  HTTP framing; the CLI against the router on a loopback port; and the
  shipped binary — `gl-node user` against a running signing node, across a
  restart (the signed access records verify at boot).
- **Review round** (reviewer subagent): one Important finding, fixed. (I-1)
  With auth off, every local process is the operator; with signing on, such a
  node kept an access list, so anything on the machine could mint admin keys
  that every node of the mesh honours — the access list (and so the admin
  API) now needs auth on as well as signing (`NO_ACCESS_LIST`), pinned by the
  shipped binary's auth-off test. Also taken: a revoke is final in the fold (a
  rotation on one node racing a revoke on another brought the person back);
  the caller is judged again under the write lock (an admin revoked while
  their request waited); the size-cap test runs in Format v2 too; a test that
  a key granted through one node's API works on another and its revoke
  follows; names refuse bidi and zero-width characters; chunked detection
  parses the header; Bug-catch wording matched to what the reverts do, with
  checks for the two claims that had none; README says to `user list` before
  retrying a lost `user add`; intent decision 5 updated for names.
- **Gate:** `scripts/gate.sh` — 1,576 passed, 0 failed, 0 ignored (6 min 25 s).
- **Revert checks:** `scripts/revert_specs/users.json` — 54 of 54 bite (U-R30
  to U-R52 new; U-R23, U-R25 and U-R42 re-anchored). Two did not bite at
  first, after the review round: U-R25 (revoke ignored), because the final
  revoke made the fold's `remove` dead — removed, and the check now reverts
  the revoked set; and U-R30 (`grantAccess` not admin-only), because the
  under-the-lock caller check also refuses a write key — the test now
  requires the role check's own message, so each has a case only it catches.
- **Departures from the plan:** a revoke is final (above). `grantAccess` takes an optional `userId`, so a
  person's role or key changes without a new id (and `entered-by` history
  stays theirs); `gl-node user add --user` is its CLI form. The CLI speaks
  HTTP/1.1 itself (as `--health-check` does) rather than adding an HTTP client
  dependency.
- **Commit:** (pending)
