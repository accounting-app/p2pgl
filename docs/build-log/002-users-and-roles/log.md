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
- **Commit:** (pending)
