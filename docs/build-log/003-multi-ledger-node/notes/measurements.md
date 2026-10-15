# Measurements: many ledgers on one node (step 3, 2026-10-15)

Taken with `scripts/measure_ledgers.py` on the release build, on the
maintainer's Mac (10 cores, 24 GiB), HTTP and every mesh on loopback. Rerun the
script to check a later build; the numbers below are this build's. Memory is
the process's resident size once every ledger answers (the script reads it
then, and again after one write per ledger; the two never differ by more than
2 MiB).

## One node, many ledgers

| Case | Boot | Memory | Open files | Stop (SIGTERM → exit) |
|---|---|---|---|---|
| 10 ledgers, empty, P2P off | 1.1 s | 18 MiB | 23 | 0.07 s |
| 100 ledgers, empty, P2P off | 1.4 s | 64 MiB | 113 | 0.57 s |
| 100 ledgers, empty, each with its own P2P endpoint | 2.1 s | 107 MiB | 466 | 0.51 s |
| 1 ledger, 10,000 entries | 0.6 s | 111 MiB | 14 | 0.13 s |
| 10 ledgers, 10,000 entries each | 1.9 s | 913 MiB | 23 | 0.43 s |
| 30 ledgers, 10,000 entries each | 4.5 s | 1,746 MiB | 43 | 1.23 s |

Before ledgers booted in parallel (one after another), the same cases took:

| Case | Boot | Memory |
|---|---|---|
| 100 ledgers, empty, each with P2P | 11.2 s | 102 MiB |
| 10 ledgers, 10,000 entries each | 5.8 s | 491 MiB |
| 30 ledgers, 10,000 entries each | 17.2 s | 1,238 MiB |

Parallel boot costs memory: up to one core's worth of ledgers boot at once, and
the memory their boots used stays with the process afterwards. On 10 cores
that is about +420 MiB at 10,000 entries per ledger; on 2 cores it would be
about a fifth of that.

Writing one entry into each of 100 ledgers took about 1 s.

## Two nodes, every ledger meshed with its pair

`--mesh`: two nodes, each ledger paired with its namesake on the other node in
a mesh of its own (own `meshId`, topic, key, direct loopback address, no
relay). One entry written into every ledger on node A.

| Ledgers per node | Replicated | Slowest, after the last write | Entries in the wrong ledger |
|---|---|---|---|
| 10 | 10 of 10 | 0.01 s | none |
| 100 | 100 of 100 (twice) | 0.07 s | none |

Two early runs had one ledger in 100 refused with "Failed to bind sockets": the
script freed each chosen UDP port before the node bound it, and on one node
another socket took it in between (on one run, two ledgers drew the same port
and the node refused the second, as it should). The script now picks ports
below the system's ephemeral range and checks both address families.

## What this says

- **Memory is the limit, not files or CPU.** A ledger costs about 1 MiB empty
  and about 41–49 MiB per 10,000 entries once booted one at a time — roughly
  50 times its `.bean` — because the whole DAG and read model live in memory.
  Parallel boot adds about one ledger's worth per core. A 2-core, 2 GiB server
  holds about 35 ledgers of 10,000 entries. OPERATIONS states the budget.
- **Open files need some headroom:** about 1 per ledger without P2P and about
  4.5 with, plus one per HTTP connection (up to `http.maxConnections`, default
  1,024). 100 P2P ledgers and a full set of connections come to about 1,500,
  over a 1,024 `ulimit -n`: OPERATIONS asks for at least 4,096 (Docker's
  default is far higher).
- **Boot and stop fit a container on this machine:** a stop compacts every
  ledger in parallel in about a second, within `docker stop`'s 10 s; boot is a
  few seconds. Both were measured on 10 cores; a large node on 2 cores takes
  longer, and OPERATIONS suggests a longer stop grace period for one.
- **The per-client rate limit was node-wide** (60 GraphQL requests a minute per
  client, across every ledger): one client working across many ledgers — an
  accountant's app syncing 40 companies — shared one budget, which is why the
  measurement gave each ledger's write its own client address. The maintainer
  chose a budget per client and ledger (log, step 3); it is now each ledger's
  own.
