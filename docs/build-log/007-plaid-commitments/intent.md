# Intent: keep what we told Plaid

Author: Claude, with the maintainer. Status: draft.

## Problem

Plaid approved MILY LABS INC on 2026-11-09 on the strength of two policies (the
Information Security Policy and the Data Retention and Disposal Policy) and
answers about MFA. Several of those statements describe software or routines
that do not exist yet:

- **No Plaid integration exists.** The promises about it (access tokens kept
  server-side, encrypted, never logged; raw responses gone within 7 days; item
  removed at Plaid and token deleted within 30 days of a disconnect) have
  nothing to apply to until it is built — and must hold from its first line.
- **No MFA before Plaid Link.** A node authenticates every request with one
  API key. We told Plaid users pass MFA before Link is shown.
- **The installer falls short of the retention policy.** Server logs are
  rotated by size (5 × 10 MB per container), not kept 90 days; `company remove`
  moves a company's folder to `.removed/` and never deletes it; backups stay on
  the server, with no encrypted off-server copy.
- **Policy rows marked *Confirm* or *To set up*** (access reviews, risk
  register, restore tests, MFA on Company accounts, …) have no routine behind
  them.

## Proposed outcome

- **A company can connect a bank through Plaid.** One designated node per
  company holds the connection, fetches new transactions and posts them as
  ordinary signed ledger entries, so every other node of the mesh receives the
  entries, never the token.
- **The access token never leaves that node's secret store**: encrypted with a
  key kept outside the data folder, never in a `.bean` file, a record, a
  GraphQL response or a log line.
- **MFA guards Plaid Link.** Opening Link or connecting a bank needs an admin
  key *and* a passed MFA check.
- **Disconnecting a bank or removing a company** calls Plaid's item removal
  and deletes the token; a removed company's folder is deleted after 30 days.
- **The installer meets the retention schedule**: logs kept 90 days, backups
  copied off-server encrypted and deleted there after 30 days.
- **Every operational control has an owner, a date and a record**, and both
  policies' status columns read *In place*.

## Who it is for

Companies and accountants connecting their bank accounts; the maintainer as
operator of hosted servers and as the Company's Security Owner; Plaid, which
may ask for evidence.

## Constraints

- Nothing Plaid-specific enters the ledger format, the wire format or
  replication. Imported transactions are ordinary records; a token is never
  one.
- Exactly one node per company imports, or two nodes post the same bank
  transaction twice (their records differ by author).
- Tests never reach the real Plaid: a loopback mock (LuLu; CLAUDE.md).
- Plaid Link reaches no user before the MFA step is live (our answer to Plaid).

## How we will know it worked

- Against the mock: connect, sync, disconnect; the entries replicate to a
  second node and the token appears in no file, record, log or response there
  or on the importing node (searched for in all of them).
- Disconnect leaves no token on disk and the mock saw `/item/remove`.
- Link without a passed MFA check is refused.
- A removed company's folder is gone 30 days later; a log line older than 90
  days is gone; an off-server copy older than 30 days is gone.
- Every row of both evidence tables reads *In place*, each with a dated record.

## Open questions

1. **Where does Plaid run** — in the node (proposed: it is the server that
   already holds the books and keys) or in the separate client app's backend?
2. **How does the node know MFA passed?** (a) It trusts the client app, which
   alone does MFA; (b) the node checks a TOTP code itself on the Plaid
   mutations (proposed: holds whatever client calls it), with each person's
   TOTP secret kept on the Plaid node only, never replicated.
3. **Off-server backup target** — which storage (S3-compatible bucket? another
   server over SSH?) and who holds the encryption key?
4. **The date given to Plaid** for MFA — every step before Link ships fits
   inside it.
5. **Raw Plaid responses**: keep none at all (simplest), or up to 7 days for
   troubleshooting as the retention policy allows?
