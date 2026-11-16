//! Shared scaffolding for `gl-node`'s tests. Compiled only under `cfg(test)`,
//! so nothing here exists in a real build.

use std::future::Future;
use std::sync::{Arc, LazyLock, Mutex};

use tracing::instrument::WithSubscriber;

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

/// Capture every `warn!` emitted while `body` runs on this thread, as plain
/// text.
///
/// `tracing::subscriber::with_default` installs a *thread-local* subscriber,
/// so a concurrent test's logs never land in this buffer.
pub(crate) fn capture_warnings<T>(body: impl FnOnce() -> T) -> (T, String) {
    let (subscriber, buffer) = warning_subscriber();
    let value = tracing::subscriber::with_default(subscriber, body);
    (value, buffer.text())
}

/// [`capture_warnings`] for a future (009): every `warn!` emitted while `body`
/// is polled, as plain text, prefixed by the `INFO` spans it was emitted in
/// as the node's default filter (`info`) prints them — a span's fields are
/// part of the line a caller might forge.
pub(crate) async fn capture_warnings_async<T>(body: impl Future<Output = T>) -> (T, String) {
    use tracing::Level;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::Layer;

    let buffer = SharedBuffer::default();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(buffer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::filter_fn(|metadata| {
                let shown = if metadata.is_span() {
                    Level::INFO
                } else {
                    Level::WARN
                };
                *metadata.level() <= shown
            })),
    );
    let value = body.with_subscriber(subscriber).await;
    (value, buffer.text())
}

/// A `WARN` subscriber writing plain text (no colour) into the buffer it
/// returns.
fn warning_subscriber() -> (impl tracing::Subscriber + Send + Sync, SharedBuffer) {
    let buffer = SharedBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buffer.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .finish();
    (subscriber, buffer)
}

#[derive(Clone, Default)]
struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl SharedBuffer {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl std::io::Write for SharedBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuffer {
    type Writer = SharedBuffer;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Everything logged while `body` runs under `directives` (an `EnvFilter`, as
/// `RUST_LOG` takes it), as plain text (009) — including what the tasks it
/// spawns log, which `capture_warnings_async` misses: the subscriber is this
/// thread's default for the duration, and a `#[tokio::test]` runtime runs
/// every task on this thread.
pub(crate) async fn capture_logs<T>(
    directives: &str,
    body: impl Future<Output = T>,
) -> (T, String) {
    let buffer = SharedBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buffer.clone())
        .with_ansi(false)
        .with_env_filter(tracing_subscriber::EnvFilter::new(directives))
        .finish();
    let default = tracing::subscriber::set_default(subscriber);
    let value = body.await;
    drop(default);
    (value, buffer.text())
}
