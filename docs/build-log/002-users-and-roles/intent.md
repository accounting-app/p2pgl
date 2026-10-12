# Intent: people, keys and roles

Author: Claude, with the maintainer. Status: **approved** (2026-10-09).

## Problem

A node has one API key, and whoever holds it can do everything: write any
transaction, open and close accounts, read every report. A company and its
accountant cannot both use a ledger without sharing that key — so the owner
cannot be given read-only access, an auditor cannot be let in for a month and
out again, one person leaving means changing the key for everyone, and the
books cannot say which person entered a transaction (records name the *node*
that signed them, never a person).

## Proposed outcome

- **Each person has their own key**, issued by an administrator, shown once,
  and revocable on its own without touching anyone else's.
- **Each key has a role** that the node enforces on every request:
  - **admin** — everything, including managing people and keys;
  - **write** — read, and enter transactions and manage accounts (the
    accountant, the bookkeeper);
  - **read** — reports, balances, the journal, `verify`; no change of any kind
    (the owner, an auditor).
- **Every write says who made it**, and that is visible later (the journal,
  an audit export).
- Roles are per ledger, so that a node holding several companies' ledgers
  (entry 003) can give an accountant write access to one and none to another.

## Who it is for

Companies and their accountants sharing one ledger; auditors with temporary
read access; the operator (or our hosted service) who administers keys.

## Constraints

- Nothing in the security hardening weakens: keys are long random secrets,
  compared in constant time, stored only as hashes, never logged (the
  existing rules of `auth.rs`, T41/M-32).
- The existing `auth.apiKey` / `GL_NODE_API_KEY` keeps working, as an admin
  key, so no running node breaks on upgrade.
- What replicates is unchanged in meaning: a peer still trusts a record by the
  *node's* signature; who-entered-it is information inside the record, not a
  new trust path between nodes.
- Read-only means read-only everywhere: queries, subscriptions and `verify`,
  but no mutation of any kind, including ones added later (deny by default).

## How we will know it worked

- A read-only key gets every report and is refused every mutation; a write key
  can post; only an admin key can add, list or revoke keys.
- A revoked key is refused at once, and the other keys keep working.
- A transaction entered with a person's key carries that person's id on every
  node of the mesh, and shows their name wherever the name is known.
- A key works on every node of the mesh: issued or revoked on one admin node,
  it is accepted or refused on all of them once the change has replicated.
- A person's name shows on every node of the mesh, and a rename reaches every
  node like any other access record.
- The old single key still works after the upgrade, as admin.
- No key, and no hash of one, appears in a log, an error or `Debug` output.

## Decisions (maintainer, 2026-10-09)

1. **Key management:** both — `gl-node user add | list | revoke` on the node
   (self-hosting, and the first admin before any key exists), and GraphQL admin
   operations for an admin key (the hosted service, a future web UI).
2. **Who-entered-it:** the record carries a stable opaque user id.
   *Revised 2026-10-12:* GDPR is out of scope (no EU launch or customers), so
   the person's name travels in the access records and shows on every node of
   the mesh; a rename is a new access record, and earlier names stay in the
   books' history. (Before: names in a node-local, erasable file — which showed
   a name only on the node where it was entered.) Other privacy laws remain for
   the maintainer's legal check.
3. **Roles:** admin / write / read for now, checked per operation so finer
   permissions can come later without changing anyone's key.
4. **Expiry:** a key may carry an optional expiry date and is refused after
   it; most keys have none.
5. **Scope:** a key works on **every node of the mesh**, so a person is not
   locked out when one node is down. The list of people replicates across the
   mesh — user id, key hash, role, expiry, signed like ledger records — while
   names stay local to the nodes that hold them (decision 2), erasable.

## Not in this work

- Sign-in with accounts or SSO (passwords, sessions, identity providers).
- Several ledgers per node — entry 003; here roles are scoped to the node's one
  ledger, in a shape 003 extends.
- Permissions finer than the three roles.

## Open questions

None for the intent; the plan answers how — notably where the user id lives
in a record (the `openledger-` metadata prefix is the audited envelope), how
the user list replicates and who may change it (an admin's change is signed by
their node; a peer must refuse a change no admin made), and how fast a
revocation reaches every node.
