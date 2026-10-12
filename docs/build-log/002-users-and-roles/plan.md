# Plan: people, keys and roles (from intent.md, 2026-10-09)

## Design

**The user list lives in the ledger, as `event` records.** Events are already
parsed, serialized, signed, replicated, quarantined and audited like every other
record, and change no balance. So a grant or a revocation reaches every node of
the mesh through the machinery the audits hardened — no new store, no new
protocol — and the books keep a permanent account of who had what access when.

```
2026-10-09 event "openledger-access" "grant"
  user: "u_7f3a9c21d4e8b605"
  role: "write"
  key-sha256: "<sha-256 of the key, hex>"
  expires: "2026-11-09"            ; optional
  by: "u_02b1…"                    ; the admin who granted it ("operator": the node's own key)
2026-10-20 event "openledger-access" "revoke"
  user: "u_7f3a9c21d4e8b605"
  by: "u_02b1…"
```

- **The access list** is a fold over every `openledger-access` event the node
  serves, in the ledger's deterministic order (lamport, then content id): a
  grant sets a user's role, key hash and expiry (a new grant replaces the old
  key — rotation); a revoke ends the user. Every node folds the same records
  in the same order, so every node reaches the same list; a concurrent grant
  and revoke resolve the same way everywhere.
- **Keys:** 32 random bytes, shown once; only the SHA-256 is stored (safe for a
  256-bit random secret) and only the hash is compared, in constant time. A
  grant carries the person's `name` (decision 2, revised 2026-10-12: no EU
  scope); a `rename` record changes it, keeping role and key.
- **Who may change the list.** A node writes an access record only when an
  admin asked it to (checked locally), and peers accept access records on the
  same trust as every other record: signed by a node they admit. A node the
  mesh admits can already write any transaction, so this adds no new trust; the
  record's `by` field names the admin for the audit trail. `auth.adminNodes`
  (optional) narrows which nodes' access records count. Hand-typed access
  events in the `.bean` are refused: the list changes only through an admin.
- **Roles, deny by default:** a GraphQL extension classifies every operation —
  queries and subscriptions need **read**, every mutation needs **write**,
  access operations need **admin** — so a mutation added later is closed to
  read keys without anyone remembering to guard it.
- **Compatibility:** `auth.apiKey` / `GL_NODE_API_KEY` / the generated key
  file keep working as the node's **operator** key: admin on this node only,
  never replicated, and the root that issues the first grants.
- **Who entered it:** writes made through the API carry `entered-by: "u_…"`
  (an ordinary metadata key, not the audited `openledger-` envelope); the
  journal shows the id, and the name where this node knows it.
- **Expiry and revocation** are judged by each node at request time. A revoke
  reaches the other nodes as fast as replication does (seconds); a node cut
  off from the mesh honours a revoked key until it hears of it — documented.

## Order of work

1. **Roles on one node.** The caller's identity from the key (the operator key
   only, for now), the deny-by-default role check, 401/403 errors. Tests: each
   role against queries, mutations, subscriptions.
2. **Access records.** The event shape and its validation (boot, file,
   peers), the fold into the access list, keys from the list accepted by the
   middleware, `auth.adminNodes`. Tests: grant, rotate, revoke, expiry;
   two nodes converging on the same list; a concurrent grant and revoke; a
   forged or hand-typed record refused.
3. **The admin API and CLI.** `grantAccess`, `revokeAccess`, `renameUser`,
   `accessList` (admin only); `gl-node user add | list | revoke | rename` as a
   thin client of that API on loopback, with the operator key. Names live in
   the access records (decision 2 revised); the fold carries them.
4. **Who entered it, and docs.** `entered-by` on API writes; the journal shows
   it; README (*Using Auth* rewritten), OPERATIONS (*People and keys*),
   CHANGELOG.

## Risks

- **Access records are part of the books.** Anyone who receives the `.bean`
  (an auditor, an export) sees user ids, roles, expiry and key hashes — not
  names, not keys. The hashes are of 256-bit random keys: not reversible.
- **A compromised admitted node can grant itself access** — as it can already
  write any transaction. `auth.adminNodes` limits it to named nodes.
- **Revocation on a partitioned node** waits for replication (above).
- **Deny by default must cover subscriptions and batched operations**
  (several root fields, aliases): the extension judges the operation, not one
  field. Tests send batches mixing allowed and forbidden fields.
- **Order matters:** the fold must use exactly the order every node computes;
  the convergence test feeds the same records in many arrival orders.

## Alternatives rejected

- A separate replicated user store with its own protocol: a second trust and
  replication path to secure, for what the ledger already does.
- Names in the records: not erasable (decision 2).
- Users per node: decision 5.
- A `custom` record type: the parser refuses `custom` today; `event` exists
  and is valid Beancount.

## Proof

- Tests per step as above; revert checks in `scripts/revert_specs/users.json`
  for the role check, the deny-by-default classification, the fold's order,
  revoke, expiry, hand-typed refusal, `adminNodes`, and the operator key.
- Docs: README, OPERATIONS, CHANGELOG (*Added*; the operator key in *Changed*).
