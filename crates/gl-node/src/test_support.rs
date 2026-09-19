//! Shared scaffolding for `gl-node`'s tests. Compiled only under `cfg(test)`,
//! so nothing here exists in a real build.

use std::sync::LazyLock;

/// The ONE lock that serializes every wall-clock network test in this crate
/// (T22 follow-up, T41).
///
/// `anti_entropy_alpn` and `http_server` each used to keep a private lock of
/// this name. Each module was internally serialized and the two were not, so an
/// HTTP slowloris test measuring a 300 ms deadline ran concurrently with a
/// three-node QUIC convergence test binding real endpoints — and on a loaded
/// machine one starved the other's runtime and the deadline flaked. The failure
/// only ever appeared under full-suite parallelism, never in isolation, which is
/// the signature that made `three_node_alpn_convergence` untrustworthy in T18.
///
/// Both kinds of test hold this for their whole body, so any network test in
/// this crate excludes any other. That costs wall-clock time in exchange for a
/// convergence signal worth reading, which is the right trade for a suite whose
/// job is to catch regressions in replication.
///
/// It lives in its own module rather than in either test module because a lock
/// owned by one of the two participants is not a shared lock — it is a lock the
/// other one has to reach into, which is how the crate ended up with two.
pub(crate) static NET_TEST_LOCK: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));
