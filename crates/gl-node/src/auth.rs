use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;
use subtle::ConstantTimeEq;
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::access_control::Caller;

/// Shared auth state for the middleware layer.
#[derive(Clone)]
pub struct AuthState {
    pub enabled: bool,
    /// The node's operator key (`auth.apiKey`, `GL_NODE_API_KEY`, the key file).
    pub api_key: String,
    /// Where people's keys come from: the ledger's access records
    /// (`crate::access_list`). `None`: the operator key is the only key.
    pub access: Option<AccessSource>,
}

/// The folded access list and the `LedgerDag::access_generation` it was folded at.
type CachedAccessList = (u64, std::sync::Arc<crate::access_list::AccessList>);

/// The ledger whose access records hold people's keys, the nodes whose
/// records count (`auth.adminNodes`; `None` = every node the mesh admits), and
/// the last folded list, kept until the ledger's access records change.
#[derive(Clone)]
pub struct AccessSource {
    pub ledger: crate::graphql::SharedLedger,
    pub admin_nodes: Option<std::sync::Arc<std::collections::HashSet<String>>>,
    /// `(LedgerDag::access_generation, list)`: refolded only when it moves, so
    /// a request costs a comparison however many access records there are.
    cache: std::sync::Arc<std::sync::Mutex<Option<CachedAccessList>>>,
}

impl AccessSource {
    pub fn new(
        ledger: crate::graphql::SharedLedger,
        admin_nodes: Option<std::sync::Arc<std::collections::HashSet<String>>>,
    ) -> Self {
        AccessSource {
            ledger,
            admin_nodes,
            cache: std::sync::Arc::default(),
        }
    }

    /// The access list as the ledger's access records fold to now.
    pub async fn current(&self) -> std::sync::Arc<crate::access_list::AccessList> {
        let ledger = self.ledger.read().await;
        let generation = ledger.dag().access_generation();
        let mut cache = self.cache.lock().expect("access list cache lock");
        match &*cache {
            Some((cached, list)) if *cached == generation => list.clone(),
            _ => {
                let list = std::sync::Arc::new(crate::access_list::AccessList::fold(
                    ledger.dag().access_records(),
                    self.admin_nodes.as_deref(),
                ));
                *cache = Some((generation, list.clone()));
                list
            }
        }
    }
}

/// Whether this node honours people's keys, and from where (review I-2): only
/// on a node that signs and verifies. Without signing, nothing proves who wrote
/// a record, so a line typed into the `.bean` with a made-up envelope would
/// read as history and could grant itself admin; such a node accepts the
/// operator key alone. (A mesh always signs: `p2p.enabled` requires it.)
pub fn access_source_for(
    config: &crate::config::NodeConfig,
    ledger: crate::graphql::SharedLedger,
    admin_nodes: Option<std::sync::Arc<std::collections::HashSet<String>>>,
) -> Option<AccessSource> {
    config
        .signing
        .enabled
        .then(|| AccessSource::new(ledger, admin_nodes))
}

/// Hand-written so the API key is never printed (T41).
///
/// The derived `Debug` printed `api_key` in the clear, and this type is reachable
/// from axum's `State` extractor — so the key landed in any `{:?}` of the router
/// state, in a panic message, and in the failure output of every test that
/// asserted on auth. That last one is how it was noticed: a proof run in T36
/// printed a live-shaped key to the terminal. A `Debug` impl is the one place a
/// secret leaks without anyone choosing to log it.
///
/// `enabled` stays visible — it is policy, not a credential, and it is the field
/// anyone actually debugs.
impl std::fmt::Debug for AuthState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthState")
            .field("enabled", &self.enabled)
            .field("api_key", &redact(&self.api_key))
            // Whether people's keys are looked up, never what the list holds.
            .field("access_list", &self.access.is_some())
            .finish()
    }
}

/// Render a secret as a non-reversible summary for `Debug` output (T41).
///
/// Length plus a 4-character prefix, matching the shape T39 chose for the mesh-id
/// boot log: enough to tell "unset" from "set" and to match two values against
/// each other while triaging, never enough to replay. Short values get no prefix
/// at all — four characters of a six-character key is most of the key.
pub(crate) fn redact(secret: &str) -> String {
    if secret.is_empty() {
        return "<unset>".to_owned();
    }
    let length = secret.len();
    if length < 12 {
        return format!("<redacted, {length} bytes>");
    }
    let prefix: String = secret.chars().take(4).collect();
    format!("<redacted, {length} bytes, starts {prefix}…>")
}

impl AuthState {
    /// Who this request's `X-Api-Key` belongs to, if anyone (§3.8): the
    /// operator key (compared in constant time, as always), or a person's key
    /// from the access list the ledger's access records fold to — expired and
    /// revoked keys belong to no one (002-users-and-roles).
    ///
    /// This is the single decision [`auth_middleware`] makes, factored out so
    /// `/health` can ask the same question (L-09). Health is deliberately *not*
    /// behind the middleware — it must answer `200` to an unauthenticated
    /// prober — so it needs the check without the 401, and it must not grow a
    /// second, subtly different key comparison to get it.
    ///
    /// Note this answers "whose key is this", not "is allowed through":
    /// `enabled` is the middleware's policy, not part of the credential check.
    /// With auth disabled there is no key to match, so this is `None`, and the
    /// health handler's loopback branch is what keeps a local node informative.
    pub async fn authenticate(&self, headers: &axum::http::HeaderMap) -> Option<Caller> {
        if !self.enabled {
            return None;
        }
        let key = headers.get("x-api-key")?.to_str().ok()?;
        if api_key_matches(key, &self.api_key) {
            return Some(Caller::operator());
        }
        let source = self.access.as_ref()?;
        source
            .current()
            .await
            .authenticate(key, chrono::Utc::now().date_naive())
    }
}

/// Axum middleware that enforces `X-Api-Key` on protected routes (§3.8).
///
/// When `auth.enabled` is false, all requests pass through.
/// When enabled, missing or mismatched `X-Api-Key` header returns HTTP 401
/// with a GraphQL-shaped error body (§2.8 `UNAUTHORIZED`).
///
/// A request that gets through carries its [`Caller`] as a request extension,
/// which the GraphQL handler hands to the role check (002-users-and-roles):
/// the operator key is admin, and so is anyone on a loopback node with auth
/// turned off (as before — nothing to tell callers apart by).
pub async fn auth_middleware(
    axum::extract::State(auth_state): axum::extract::State<AuthState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    // Always allow CORS preflight requests through (OPTIONS).
    if request.method() == axum::http::Method::OPTIONS {
        return next.run(request).await;
    }

    if !auth_state.enabled {
        request.extensions_mut().insert(Caller::operator());
        return next.run(request).await;
    }

    match auth_state.authenticate(request.headers()).await {
        Some(caller) => {
            request.extensions_mut().insert(caller);
            next.run(request).await
        }
        None => {
            let error_body = json!({
                "errors": [{
                    "message": "Missing or invalid API key",
                    "extensions": { "code": "UNAUTHORIZED" }
                }]
            });
            (StatusCode::UNAUTHORIZED, Json(error_body)).into_response()
        }
    }
}

/// Upper bound on the API key file's size (H-01): 64 hex characters plus room
/// for whitespace, as for the node's secret key file (T67).
const MAX_API_KEY_FILE_BYTES: u64 = 4096;

/// The API key of a node with auth on and no key configured (H-01): read from
/// `path`, or generated there on the first boot.
///
/// The file is handled like the node's secret key. It is read through one
/// handle that never follows a symlink and must be a regular file owned by this
/// uid, with one link and mode 0600 ([`ledger::journal::FileTrust::NodePrivate`]).
/// It is created `O_EXCL`, 0600 and fsynced
/// ([`crate::p2p_service::write_secret_key_file`]). An empty file is a write
/// that died before filling it (L-32) and is replaced. A key someone wrote into
/// the file by hand must pass the same rules as a configured one. The key is
/// 32 bytes from the OS CSPRNG, hex-encoded, and is never logged.
pub(crate) fn load_or_create_api_key(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    match read_api_key_file(path)? {
        Some(key) if !key.is_empty() => {
            crate::config::check_api_key(&key)
                .map_err(|error| format!("API key file {}: {error}", path.display()))?;
            info!(
                path = %path.display(),
                "loaded the API key; clients send it as the X-Api-Key header (H-01)"
            );
            return Ok(key.to_string());
        }
        Some(_) => {
            warn!(
                path = %path.display(),
                "API key file is empty (a crashed write?) — generating a new key; a client \
                 holding an older key gets 401 until it reads the file again"
            );
            std::fs::remove_file(path)?;
        }
        None => {}
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    // 32 bytes from the OS CSPRNG: the same draw that makes the node's
    // identity key, so no second random source is needed.
    let key = hex::encode(Zeroizing::new(iroh::SecretKey::generate().to_bytes()).as_slice());
    crate::p2p_service::write_secret_key_file(path, &key)?;
    info!(
        path = %path.display(),
        "generated a new API key; clients send the file's contents as the X-Api-Key header (H-01)"
    );
    Ok(key)
}

/// The trimmed contents of the API key file, or `None` if nothing is at the
/// path.
fn read_api_key_file(path: &Path) -> Result<Option<Zeroizing<String>>, Box<dyn std::error::Error>> {
    let checked = match ledger::journal::open_checked(
        path,
        std::fs::OpenOptions::new().read(true),
        ledger::journal::FileTrust::NodePrivate,
        "API key file",
    ) {
        Ok(checked) => checked,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("{error} (H-01)").into()),
    };
    #[cfg(not(unix))]
    warn!(
        path = %path.display(),
        "API key file permissions are NOT verified on this platform (non-Unix) — restrict \
         access to it with the platform's own ACLs (L-05)"
    );
    let mut content = Zeroizing::new(String::new());
    (&checked.file)
        .take(MAX_API_KEY_FILE_BYTES + 1)
        .read_to_string(&mut content)?;
    if content.len() as u64 > MAX_API_KEY_FILE_BYTES {
        return Err(format!(
            "API key file {} is larger than {MAX_API_KEY_FILE_BYTES} bytes; a generated key is \
             64 hex characters",
            path.display()
        )
        .into());
    }
    Ok(Some(Zeroizing::new(content.trim().to_owned())))
}

/// Constant-time API key comparison (C-1).
///
/// Both keys are reduced to fixed-length SHA-256 digests before the constant-time
/// compare, so there is no length-mismatch branch: the comparison time is
/// independent of key length and the secret's length does not leak through timing.
/// (Hashing the provided key takes time proportional to *its* length, which the
/// attacker already controls and knows; the secret's length stays hidden.)
fn api_key_matches(provided: &str, expected: &str) -> bool {
    let provided_digest = Sha256::digest(provided.as_bytes());
    let expected_digest = Sha256::digest(expected.as_bytes());
    provided_digest
        .as_slice()
        .ct_eq(expected_digest.as_slice())
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// People's keys are honoured only on a node that signs (review I-2):
    /// without signatures nothing proves who wrote an access record, so a line
    /// typed into the `.bean` with a made-up envelope could grant itself admin.
    /// A signing-off node accepts the operator key alone.
    ///
    /// Bug-catch: build the access source regardless of signing and a node
    /// with signing off honours forged access records.
    #[tokio::test]
    async fn only_a_signing_node_honours_peoples_keys() {
        let dir = tempfile::tempdir().expect("tempdir");
        let service =
            ledger::service::LedgerService::boot(dir.path().join("node.bean"), "node-a".to_owned())
                .expect("boot");
        let ledger: crate::graphql::SharedLedger =
            std::sync::Arc::new(tokio::sync::RwLock::new(service));
        let config = |signing: bool| -> crate::config::NodeConfig {
            serde_json::from_str(&format!(
                r#"{{ "ledgerPath": "ledger.bean", "signing": {{ "enabled": {signing} }} }}"#
            ))
            .expect("config")
        };
        assert!(access_source_for(&config(false), ledger.clone(), None).is_none());
        assert!(access_source_for(&config(true), ledger, None).is_some());
    }

    /// `authenticate` (002-users-and-roles): the operator key is the operator;
    /// a person's key is that person, with the role their grant gives, read
    /// from the ledger's access records on each request; once they are
    /// revoked, or their key has expired, or their grant came from a node not
    /// in `auth.adminNodes`, the key belongs to no one.
    ///
    /// Bug-catch: look people's keys up only at boot and a revocation takes
    /// effect at the next restart; drop the expiry check and an auditor's
    /// month never ends.
    #[tokio::test]
    async fn a_persons_key_has_their_role_until_revoked_or_expired() {
        use crate::access_control::{CallerId, Role};
        let dir = tempfile::tempdir().expect("tempdir");
        let service =
            ledger::service::LedgerService::boot(dir.path().join("node.bean"), "node-a".to_owned())
                .expect("boot");
        let author = service.author_id().to_owned();
        let ledger: crate::graphql::SharedLedger =
            std::sync::Arc::new(tokio::sync::RwLock::new(service));
        let state = |admin_nodes: Option<&str>| AuthState {
            enabled: true,
            api_key: "operator-key-0123456789abcdef".to_owned(),
            access: Some(AccessSource::new(
                ledger.clone(),
                admin_nodes.map(|node| std::sync::Arc::new([node.to_owned()].into())),
            )),
        };
        let headers = |key: &str| {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert("x-api-key", key.parse().unwrap());
            headers
        };
        let record = |action: &str, pairs: &[(&str, &str)]| {
            let ledger = ledger.clone();
            let action = action.to_owned();
            let mut fields: std::collections::BTreeMap<String, String> = pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect();
            static NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
            fields.insert(
                "record".to_owned(),
                format!(
                    "{:032x}",
                    NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                ),
            );
            async move {
                ledger
                    .write()
                    .await
                    .record_access_event_staged(
                        chrono::NaiveDate::from_ymd_opt(2026, 10, 1).unwrap(),
                        &action,
                        fields,
                        |_, _, _| None,
                    )
                    .expect("recorded");
            }
        };
        let user = "u_0123456789abcdef";
        let key = "person-key-fedcba9876543210";
        let hash = crate::access_list::sha256_hex(key);
        // One state for the whole test, as the running node keeps one: its
        // cached access list must follow every new access record.
        let node = state(None);

        assert_eq!(
            state(None)
                .authenticate(&headers("operator-key-0123456789abcdef"))
                .await,
            Some(Caller::operator())
        );
        assert_eq!(node.authenticate(&headers(key)).await, None, "no grant yet");

        record(
            "grant",
            &[
                ("user", user),
                ("role", "read"),
                ("key-sha256", &hash),
                ("by", "operator"),
            ],
        )
        .await;
        let caller = node.authenticate(&headers(key)).await.expect("granted");
        assert_eq!(
            (caller.who, caller.role),
            (CallerId::User(user.to_owned()), Role::Read)
        );
        assert!(
            state(Some(&author))
                .authenticate(&headers(key))
                .await
                .is_some(),
            "this node is an admin node"
        );
        assert_eq!(
            state(Some("someone-else"))
                .authenticate(&headers(key))
                .await,
            None,
            "a grant from a node outside adminNodes counts for nothing"
        );

        record("revoke", &[("user", user), ("by", "operator")]).await;
        assert_eq!(
            node.authenticate(&headers(key)).await,
            None,
            "revoked at once"
        );

        let yesterday = (chrono::Utc::now().date_naive() - chrono::Duration::days(1)).to_string();
        record(
            "grant",
            &[
                ("user", user),
                ("role", "write"),
                ("key-sha256", &hash),
                ("expires", &yesterday),
                ("by", "operator"),
            ],
        )
        .await;
        assert_eq!(node.authenticate(&headers(key)).await, None, "expired");
    }

    /// Write `content` at `path` as a 0600 file, as the node would.
    #[cfg(unix)]
    fn write_private(path: &Path, content: &str) {
        crate::p2p_service::write_secret_key_file(path, content).expect("write key file");
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).expect("stat").permissions().mode() & 0o777
    }

    /// H-01: the first boot generates a 32-byte key into a 0600 file; every
    /// later boot reads the same key back.
    ///
    /// Bug-catch: generate a fresh key on every call, or create the file
    /// readable by others, and this fails.
    #[cfg(unix)]
    #[test]
    fn h01_the_api_key_file_is_created_owner_only_and_reused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("nested").join("api.key");
        let first = load_or_create_api_key(&path).expect("created");
        assert_eq!(first.len(), 64);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(std::fs::read_to_string(&path).expect("read"), first);
        assert_eq!(mode_of(&path), 0o600);
        let second = load_or_create_api_key(&path).expect("loaded");
        assert_eq!(second, first, "the key survives a restart");
    }

    /// H-01: a key file another account can read is refused, as the node's
    /// secret key is (C-2), rather than used or replaced.
    #[cfg(unix)]
    #[test]
    fn h01_an_api_key_file_others_can_read_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("api.key");
        write_private(&path, &"a".repeat(64));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let error = load_or_create_api_key(&path).expect_err("refused");
        assert!(error.to_string().contains("API key file"), "{error}");
        assert_eq!(mode_of(&path), 0o644, "left as found");
    }

    /// H-01: a symlink at the key path is never followed — the key would be
    /// one someone else chose (L-49's rule for the secret key).
    #[cfg(unix)]
    #[test]
    fn h01_a_symlink_at_the_api_key_path_is_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let target = directory.path().join("chosen.key");
        write_private(&target, &"b".repeat(64));
        let path = directory.path().join("api.key");
        std::os::unix::fs::symlink(&target, &path).expect("symlink");
        assert!(load_or_create_api_key(&path).is_err());
    }

    /// H-01 / L-32: an empty key file — a write that died before filling it —
    /// is replaced by a fresh key rather than refusing every boot.
    #[cfg(unix)]
    #[test]
    fn h01_an_empty_api_key_file_is_replaced() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("api.key");
        write_private(&path, "");
        let key = load_or_create_api_key(&path).expect("regenerated");
        assert_eq!(key.len(), 64);
        assert_eq!(std::fs::read_to_string(&path).expect("read"), key);
    }

    /// H-01: a key written into the file by hand meets the rules a configured
    /// key does (L-08), so the file is no way around them.
    ///
    /// Bug-catch: skip `check_api_key` on the file path and the published
    /// sample is accepted.
    #[cfg(unix)]
    #[test]
    fn h01_a_hand_written_api_key_meets_the_configured_key_rules() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("api.key");
        write_private(&path, crate::config::FORBIDDEN_SAMPLE_API_KEY);
        let error = load_or_create_api_key(&path).expect_err("the sample is refused");
        assert!(error.to_string().contains("sample"), "{error}");
        let short = directory.path().join("short.key");
        write_private(&short, "hunter2");
        assert!(load_or_create_api_key(&short).is_err());
        let chosen = directory.path().join("chosen.key");
        write_private(&chosen, "an-operator-chosen-key-0123456789\n");
        assert_eq!(
            load_or_create_api_key(&chosen).expect("a good key is used as written"),
            "an-operator-chosen-key-0123456789"
        );
    }
    use axum::body::Body;
    use axum::http::Request;
    use axum::middleware;
    use axum::routing::get;
    use axum::Router;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn ok_handler() -> &'static str {
        "ok"
    }

    /// T41: the derived `Debug` printed `api_key` verbatim. `AuthState` is axum
    /// router state, so that value reached any `{:?}` of the state, every panic
    /// message carrying it, and the failure output of every auth test — which is
    /// where it was actually spotted.
    #[test]
    fn debug_output_never_contains_the_api_key() {
        let secret = "s3cr3t-key-value-0123456789abcdef";
        let rendered = format!(
            "{:?}",
            AuthState {
                enabled: true,
                api_key: secret.to_owned(),
                access: None,
            }
        );
        assert!(
            !rendered.contains(secret),
            "the key must not appear in Debug output: {rendered}"
        );
        // Still useful for triage: policy, length, and a short prefix.
        assert!(rendered.contains("enabled: true"), "{rendered}");
        assert!(rendered.contains("33 bytes"), "{rendered}");

        // A short key gets no prefix at all — four characters of a six-character
        // key is most of the key.
        let short = format!(
            "{:?}",
            AuthState {
                enabled: true,
                api_key: "abcdef".to_owned(),
                access: None,
            }
        );
        assert!(!short.contains("abcd"), "{short}");

        // And an unset key says so rather than showing an empty string, which
        // reads as "redacted" and is the opposite of the truth.
        let unset = format!(
            "{:?}",
            AuthState {
                enabled: false,
                api_key: String::new(),
                access: None,
            }
        );
        assert!(unset.contains("<unset>"), "{unset}");
    }

    fn build_app(auth_state: AuthState) -> Router {
        Router::new()
            .route("/protected", get(ok_handler))
            .layer(middleware::from_fn_with_state(auth_state, auth_middleware))
    }

    #[tokio::test]
    async fn test_auth_disabled_passes_through() {
        let application = build_app(AuthState {
            enabled: false,
            api_key: String::new(),
            access: None,
        });
        let request = Request::get("/protected").body(Body::empty()).unwrap();
        let response = application.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_enabled_valid_key() {
        let application = build_app(AuthState {
            enabled: true,
            api_key: "test-secret".to_owned(),
            access: None,
        });
        let request = Request::get("/protected")
            .header("x-api-key", "test-secret")
            .body(Body::empty())
            .unwrap();
        let response = application.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_enabled_missing_key() {
        let application = build_app(AuthState {
            enabled: true,
            api_key: "test-secret".to_owned(),
            access: None,
        });
        let request = Request::get("/protected").body(Body::empty()).unwrap();
        let response = application.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body["errors"][0]["extensions"]["code"], "UNAUTHORIZED");
    }

    #[tokio::test]
    async fn test_auth_enabled_wrong_key() {
        let application = build_app(AuthState {
            enabled: true,
            api_key: "test-secret".to_owned(),
            access: None,
        });
        let request = Request::get("/protected")
            .header("x-api-key", "wrong-key")
            .body(Body::empty())
            .unwrap();
        let response = application.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_api_key_matches_equal() {
        assert!(api_key_matches("test-secret", "test-secret"));
    }

    #[test]
    fn test_api_key_matches_rejects_wrong_value() {
        assert!(!api_key_matches("wrong-key", "test-secret"));
    }

    #[test]
    fn test_api_key_matches_rejects_length_mismatch() {
        assert!(!api_key_matches("short", "test-secret"));
        assert!(!api_key_matches("test-secret-extra", "test-secret"));
    }

    #[test]
    fn test_api_key_matches_rejects_same_length_wrong_key() {
        // Same length as the secret but wrong value — exercises the digest
        // compare path (both are 11 bytes).
        assert!(!api_key_matches("test-secreX", "test-secret"));
    }
}
