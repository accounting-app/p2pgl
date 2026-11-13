//! Plaid's webhooks (`docs/build-log/007-plaid-commitments`, step 6d):
//! `POST /ledgers/<name>/plaid/webhook` (and `/plaid/webhook` for the config
//! file's ledger), where Plaid tells the node about a bank instead of being
//! asked.
//!
//! The route takes no API key — Plaid has none — so every call must prove it
//! is Plaid's: a `Plaid-Verification` JWT, ES256 only, signed by a key Plaid
//! publishes (`/webhook_verification_key/get`, by the JWT's key id), issued
//! within the last five minutes, carrying the SHA-256 of the exact body. A
//! call that does not is refused (401) and does nothing.
//!
//! What a verified call does, for a bank this ledger holds (one about no
//! bank it holds is refused, 401, as an unverified call is):
//!
//! - `TRANSACTIONS` `SYNC_UPDATES_AVAILABLE`, `ITEM` `LOGIN_REPAIRED` (which
//!   also clears the bank's consent notice): a `syncBank` of the bank, in the
//!   background, as one of the ledger's tasks, run as the node's operator —
//!   its entries carry no `enteredBy` (decision 12);
//! - `ITEM` `ERROR`: Plaid's error code kept on the bank (`lastErrorCode`);
//! - `ITEM` `PENDING_EXPIRATION`, `PENDING_DISCONNECT`,
//!   `USER_PERMISSION_REVOKED`, `USER_ACCOUNT_REVOKED`: that code kept as the
//!   bank's notice (`lastNotice`), for the app to act on;
//! - `ITEM` `NEW_ACCOUNTS_AVAILABLE`: the bank's accounts read again.
//!
//! Anything else is logged and acknowledged. Plaid gets its answer at once;
//! the work runs after it.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tracing::{info, warn, Instrument};

use crate::access_control::Caller;
use crate::graphql::AppSchema;
use crate::plaid::{KeyLookup, PlaidService};

/// A webhook body is a few hundred bytes; past this it is not Plaid's.
pub(crate) const MAX_WEBHOOK_BYTES: usize = 64 * 1024;

/// The header Plaid's signed JWT arrives in.
pub(crate) const VERIFICATION_HEADER: &str = "plaid-verification";

/// How old a JWT may be (Plaid: five minutes), and how far ahead of this
/// node's clock it may claim to be.
const MAX_AGE_SECONDS: i64 = 5 * 60;

/// Why a call was not taken for Plaid's. Answered as 401 with no detail; the
/// detail is logged.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Unverified {
    NoToken,
    Malformed(&'static str),
    Algorithm(String),
    Key(String),
    /// The key is being fetched: Plaid's redelivery is verified.
    KeyPending,
    Signature,
    Age,
    BodyHash,
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    kid: String,
}

#[derive(Deserialize)]
struct Claims {
    iat: i64,
    request_body_sha256: String,
}

fn decode(part: &str) -> Result<Vec<u8>, Unverified> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| Unverified::Malformed("a part that is not base64url"))
}

/// Check that `body`, as received, comes from Plaid at `now` (seconds).
pub(crate) async fn verify(
    plaid: &Arc<PlaidService>,
    token: Option<&str>,
    body: &[u8],
    now: i64,
    client: std::net::IpAddr,
) -> Result<(), Unverified> {
    let token = token.ok_or(Unverified::NoToken)?;
    let mut parts = token.split('.');
    let (Some(header), Some(claims), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Unverified::Malformed("not three parts"));
    };
    let parsed: Header = serde_json::from_slice(&decode(header)?)
        .map_err(|_| Unverified::Malformed("a header that does not read"))?;
    // ES256 only: never `none`, never a symmetric algorithm keyed by
    // something an attacker could know.
    if parsed.alg != "ES256" {
        return Err(Unverified::Algorithm(parsed.alg));
    }
    let key = match plaid.verification_key(&parsed.kid, client) {
        KeyLookup::Found(key) => key,
        KeyLookup::Pending => return Err(Unverified::KeyPending),
        KeyLookup::Refused => return Err(Unverified::Key(parsed.kid)),
    };
    let signed = &token[..header.len() + 1 + claims.len()];
    ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, &key)
        .verify(signed.as_bytes(), &decode(signature)?)
        .map_err(|_| Unverified::Signature)?;
    let claims: Claims = serde_json::from_slice(&decode(claims)?)
        .map_err(|_| Unverified::Malformed("claims that do not read"))?;
    if (now - claims.iat).abs() > MAX_AGE_SECONDS {
        return Err(Unverified::Age);
    }
    let digest = hex::encode(Sha256::digest(body));
    if !bool::from(
        digest
            .as_bytes()
            .ct_eq(claims.request_body_sha256.to_ascii_lowercase().as_bytes()),
    ) {
        return Err(Unverified::BodyHash);
    }
    Ok(())
}

#[derive(Deserialize)]
struct Webhook {
    webhook_type: String,
    webhook_code: String,
    #[serde(default)]
    item_id: Option<String>,
    #[serde(default)]
    error: Option<WebhookError>,
}

#[derive(Deserialize)]
struct WebhookError {
    #[serde(default)]
    error_code: Option<String>,
}

/// What a verified webhook asks of the node.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Action {
    Sync,
    /// The login works again: a sync, and the consent notice cleared.
    Repaired,
    RefreshAccounts,
    Note(String),
    /// A consent notice: kept apart from the error code, which a finished
    /// sync clears while the notice still stands.
    Notice(String),
    Nothing,
}

fn action(webhook: &Webhook) -> Action {
    match (webhook.webhook_type.as_str(), webhook.webhook_code.as_str()) {
        // Plaid sends its older update codes beside this one and asks a
        // `/transactions/sync` client to ignore them: each would be a second sync.
        ("TRANSACTIONS", "SYNC_UPDATES_AVAILABLE") => Action::Sync,
        ("ITEM", "LOGIN_REPAIRED") => Action::Repaired,
        ("ITEM", "NEW_ACCOUNTS_AVAILABLE") => Action::RefreshAccounts,
        ("ITEM", "ERROR") => Action::Note(
            webhook
                .error
                .as_ref()
                .and_then(|error| error.error_code.clone())
                .unwrap_or_else(|| "ERROR".to_owned()),
        ),
        (
            "ITEM",
            code @ ("PENDING_EXPIRATION"
            | "PENDING_DISCONNECT"
            | "USER_PERMISSION_REVOKED"
            | "USER_ACCOUNT_REVOKED"),
        ) => Action::Notice(code.to_owned()),
        _ => Action::Nothing,
    }
}

/// Answer a webhook for the ledger `plaid` and `schema` serve: verify it,
/// answer Plaid, and do what it asks in the background.
pub(crate) async fn handle(
    plaid: Arc<PlaidService>,
    schema: AppSchema,
    tasks: crate::ledger_runtime::Tasks,
    client: std::net::IpAddr,
    headers: &HeaderMap,
    body: Bytes,
) -> Response {
    let token = headers
        .get(VERIFICATION_HEADER)
        .and_then(|value| value.to_str().ok());
    if let Err(why) = verify(&plaid, token, &body, chrono::Utc::now().timestamp(), client).await {
        warn!(?why, "a Plaid webhook that is not Plaid's was refused");
        return StatusCode::UNAUTHORIZED.into_response();
    }
    // Plaid's signing keys are not known to be this company's alone, so a
    // webhook Plaid sent another customer may verify here too: one about no
    // bank this ledger holds is answered as an unverified call is, or a
    // replayed one would tell a stranger which names have Plaid on. Plaid
    // sends a ledger only its own banks' webhooks; a stray one is retried and
    // dropped.
    let Ok(webhook) = serde_json::from_slice::<Webhook>(&body) else {
        warn!("a verified Plaid webhook that does not read was refused");
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(item_id) = webhook.item_id.clone() else {
        info!(webhook_type = %webhook.webhook_type, webhook_code = %webhook.webhook_code, "a Plaid webhook about no bank was refused");
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if !plaid.holds(&item_id).await {
        info!(item_id = %item_id, "a Plaid webhook for a bank this ledger does not hold was refused");
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let action = action(&webhook);
    info!(item_id = %item_id, webhook_type = %webhook.webhook_type, webhook_code = %webhook.webhook_code, ?action, "a Plaid webhook");
    // A repaired login clears the notice at once, whatever the sync queue
    // says: the clearing is not to be lost with a sync already queued.
    if action == Action::Repaired {
        plaid.clear_notice(&item_id).await;
    }
    // One webhook sync of a bank queued at a time: one arriving while it is
    // queued or running marks it to go once more, so nothing Plaid has
    // since is left at Plaid.
    let queued = match action {
        Action::Sync | Action::Repaired => match plaid.queue_webhook_sync(&item_id) {
            Some(queued) => Some(queued),
            None => {
                info!(item_id = %item_id, "a webhook sync of this bank is queued already; it goes once more");
                return StatusCode::OK.into_response();
            }
        },
        _ => None,
    };
    let work = async move {
        if let Some(mut queued) = queued {
            loop {
                sync(&schema, &item_id).await;
                if !queued.go_again() {
                    break;
                }
            }
            return;
        }
        match action {
            Action::RefreshAccounts => {
                if let Err(error) = plaid.refresh_accounts(&item_id).await {
                    warn!(item_id = %item_id, %error, "a webhook's accounts refresh failed");
                }
            }
            Action::Note(code) => plaid.note_health(&item_id, Some(&code)).await,
            Action::Notice(code) => plaid.note_notice(&item_id, &code).await,
            Action::Sync | Action::Repaired | Action::Nothing => {}
        }
    };
    // One of the ledger's tasks: its stop ends it before the ledger is
    // compacted, so a stopped ledger is never written by it.
    let task = tokio::spawn(work.in_current_span());
    crate::ledger_runtime::track(&tasks, task.abort_handle());
    StatusCode::OK.into_response()
}

const SYNC: &str = "mutation($item: String!) { syncBank(itemId: $item) { imported alreadyImported needsReview { transactionId } stoppedBy } }";

/// A `syncBank` of `item_id` as the operator, through the ledger's own
/// schema, so it is the same sync an admin runs. One already running is
/// waited for: tried again up to three times, 30 seconds apart.
async fn sync(schema: &AppSchema, item_id: &str) {
    for attempt in 0..4 {
        let request = async_graphql::Request::new(SYNC)
            .variables(async_graphql::Variables::from_json(
                serde_json::json!({ "item": item_id }),
            ))
            .data(crate::graphql::types::NamesSnapshot::default())
            .data(Caller::operator());
        let response = schema.execute(request).await;
        let busy = response.errors.iter().any(|error| {
            error
                .extensions
                .as_ref()
                .and_then(|ext| ext.get("code"))
                .is_some_and(|code| *code == async_graphql::Value::from("SYNC_IN_PROGRESS"))
        });
        if busy && attempt < 3 {
            tokio::time::sleep(Duration::from_secs(30)).await;
            continue;
        }
        match response.errors.first() {
            None => info!(item_id = %item_id, "a webhook's sync ran"),
            Some(error) => {
                warn!(item_id = %item_id, error = %error.message, "a webhook's sync failed")
            }
        }
        return;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
    use serde_json::{json, Value};

    use crate::plaid::tests::{self as mock, MockPlaid};

    /// A key pair as Plaid would sign webhooks with, and its JWK.
    pub(crate) struct Signer {
        pair: EcdsaKeyPair,
        pub kid: String,
    }

    impl Signer {
        pub(crate) fn new(kid: &str) -> Self {
            let rng = ring::rand::SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
            let pair =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                    .unwrap();
            Self {
                pair,
                kid: kid.to_owned(),
            }
        }

        /// The JWK `/webhook_verification_key/get` gives for this key.
        pub(crate) fn jwk(&self, expired_at: Option<i64>) -> Value {
            let point = self.pair.public_key().as_ref();
            let b64 = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
            json!({
                "alg": "ES256", "crv": "P-256", "kid": self.kid, "kty": "EC", "use": "sig",
                "x": b64(&point[1..33]), "y": b64(&point[33..65]),
                "created_at": 1_700_000_000, "expired_at": expired_at,
            })
        }

        /// A `Plaid-Verification` JWT for `body`, issued at `iat`, header `alg`.
        pub(crate) fn token_with(&self, alg: &str, body: &[u8], iat: i64) -> String {
            let b64 = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
            let header = b64(json!({ "alg": alg, "kid": self.kid, "typ": "JWT" })
                .to_string()
                .as_bytes());
            let claims = b64(json!({
                "iat": iat,
                "request_body_sha256": hex::encode(Sha256::digest(body)),
            })
            .to_string()
            .as_bytes());
            let signed = format!("{header}.{claims}");
            let rng = ring::rand::SystemRandom::new();
            let signature = self.pair.sign(&rng, signed.as_bytes()).unwrap();
            format!("{signed}.{}", b64(signature.as_ref()))
        }

        pub(crate) fn token(&self, body: &[u8], iat: i64) -> String {
            self.token_with("ES256", body, iat)
        }
    }

    const NOW: i64 = 1_800_000_000;
    const BODY: &[u8] =
        br#"{"webhook_type":"TRANSACTIONS","webhook_code":"SYNC_UPDATES_AVAILABLE","item_id":"x"}"#;
    const CLIENT: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));
    const OTHER_CLIENT: std::net::IpAddr =
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 7));

    async fn plaid_with(
        signer: &Signer,
        expired_at: Option<i64>,
    ) -> (tempfile::TempDir, MockPlaid, Arc<PlaidService>) {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        *mock.webhook_key.lock().unwrap() = Some(signer.jwk(expired_at));
        let plaid = mock::service(&mock, dir.path(), &mock::env()).await;
        (dir, mock, plaid)
    }

    /// `verify` once the background fetch of its key has ended: the first
    /// answer for a key not cached is always `KeyPending`.
    pub(crate) async fn verify_settled(
        plaid: &Arc<PlaidService>,
        token: Option<&str>,
        body: &[u8],
        now: i64,
        client: std::net::IpAddr,
    ) -> Result<(), Unverified> {
        for _ in 0..200 {
            match verify(plaid, token, body, now, client).await {
                Err(Unverified::KeyPending) => tokio::time::sleep(Duration::from_millis(10)).await,
                settled => return settled,
            }
        }
        Err(Unverified::KeyPending)
    }

    fn key_fetches(mock: &MockPlaid) -> usize {
        mock.paths()
            .iter()
            .filter(|path| path.as_str() == "/webhook_verification_key/get")
            .count()
    }

    /// A body Plaid signed, as it came, is taken for Plaid's — once its key is
    /// fetched, which the first call starts and does not wait for.
    ///
    /// Bug-catch: a verifier that refuses Plaid's own calls drops every
    /// webhook; one that waits for Plaid to answer the key is slower for a
    /// company with Plaid than for one without, which tells strangers which.
    #[tokio::test]
    async fn a_body_plaid_signed_is_verified() {
        let signer = Signer::new("k1");
        let (_dir, mock, plaid) = plaid_with(&signer, None).await;
        let token = signer.token(BODY, NOW - 10);
        assert_eq!(
            verify(&plaid, Some(&token), BODY, NOW, CLIENT).await,
            Err(Unverified::KeyPending),
            "the key is fetched in the background"
        );
        assert_eq!(
            verify_settled(&plaid, Some(&token), BODY, NOW, CLIENT).await,
            Ok(())
        );
        assert_eq!(
            mock.body_of("/webhook_verification_key/get").unwrap()["key_id"],
            "k1"
        );
        assert_eq!(key_fetches(&mock), 1, "fetched once, then cached");
        verify(&plaid, Some(&token), BODY, NOW, CLIENT)
            .await
            .unwrap();
        assert_eq!(key_fetches(&mock), 1);
    }

    /// No token, another algorithm, another key, another body, an old or a
    /// future token, an unknown key, one Plaid sends under another id, one
    /// set to expire: each refused.
    ///
    /// Bug-catch: any one of these checks dropped lets anyone on the internet
    /// post a "Plaid" webhook — start syncs, mark banks broken — or replay a
    /// real one.
    #[tokio::test]
    async fn anything_but_plaids_signature_is_refused() {
        let signer = Signer::new("k1");
        let (_dir, _mock, plaid) = plaid_with(&signer, None).await;
        verify_settled(&plaid, Some(&signer.token(BODY, NOW)), BODY, NOW, CLIENT)
            .await
            .unwrap();
        let check = |token: Option<String>, body: &'static [u8]| {
            let plaid = Arc::clone(&plaid);
            async move { verify_settled(&plaid, token.as_deref(), body, NOW, CLIENT).await }
        };

        assert_eq!(check(None, BODY).await, Err(Unverified::NoToken));
        let none_alg = signer.token_with("none", BODY, NOW);
        assert!(matches!(
            check(Some(none_alg), BODY).await,
            Err(Unverified::Algorithm(_))
        ));
        let hs256 = signer.token_with("HS256", BODY, NOW);
        assert!(matches!(
            check(Some(hs256), BODY).await,
            Err(Unverified::Algorithm(_))
        ));
        let impostor = Signer::new("k1").token(BODY, NOW);
        assert_eq!(
            check(Some(impostor), BODY).await,
            Err(Unverified::Signature)
        );
        let token = signer.token(BODY, NOW);
        assert_eq!(check(Some(token), b"{}").await, Err(Unverified::BodyHash));
        let old = signer.token(BODY, NOW - MAX_AGE_SECONDS - 1);
        assert_eq!(check(Some(old), BODY).await, Err(Unverified::Age));
        let ahead = signer.token(BODY, NOW + MAX_AGE_SECONDS + 1);
        assert_eq!(check(Some(ahead), BODY).await, Err(Unverified::Age));
        let unknown = Signer::new("k2").token(BODY, NOW);
        assert!(matches!(
            check(Some(unknown), BODY).await,
            Err(Unverified::Key(_))
        ));
        assert!(matches!(
            check(Some("a.b".to_owned()), BODY).await,
            Err(Unverified::Malformed(_))
        ));

        // A key Plaid sends for another id than the one asked for.
        let other = Signer::new("k9");
        let (_dir, wrong, misled) = plaid_with(&other, None).await;
        *wrong.webhook_key_any_id.lock().unwrap() = true;
        let token = Signer {
            kid: "k2".to_owned(),
            ..other
        }
        .token(BODY, NOW);
        assert!(matches!(
            verify_settled(&misled, Some(&token), BODY, NOW, CLIENT).await,
            Err(Unverified::Key(_))
        ));

        // A key Plaid has set to expire.
        let (_dir, _mock, expiring) =
            plaid_with(&signer, Some(chrono::Utc::now().timestamp() + 3600)).await;
        let token = signer.token(BODY, NOW);
        assert!(matches!(
            verify_settled(&expiring, Some(&token), BODY, NOW, CLIENT).await,
            Err(Unverified::Key(_))
        ));
    }

    /// Made-up key ids cost little: a key id Plaid refused is not asked again
    /// for a while, and one client — an IPv6 /64 being one, as for the rate
    /// limit — has the node ask Plaid at most ten times a minute, sixty in
    /// all; another client still has its own budget, so a stranger cannot
    /// spend Plaid's.
    ///
    /// Bug-catch: one budget for everyone lets ten made-up key ids a minute
    /// block every real key fetch after a restart or a key rotation; a budget
    /// for each IPv6 address lets one /64 do the same; no budget at all
    /// spends the company's Plaid rate limit.
    #[tokio::test]
    async fn made_up_key_ids_cost_little() {
        let signer = Signer::new("k1");
        let (_dir, mock, plaid) = plaid_with(&signer, None).await;

        let unknown = Signer::new("nope").token(BODY, NOW);
        for _ in 0..3 {
            assert!(verify_settled(&plaid, Some(&unknown), BODY, NOW, CLIENT)
                .await
                .is_err());
        }
        assert_eq!(key_fetches(&mock), 1, "refused once, then remembered");

        for n in 0..15 {
            let token = Signer::new(&format!("made-up-{n}")).token(BODY, NOW);
            assert!(verify_settled(&plaid, Some(&token), BODY, NOW, CLIENT)
                .await
                .is_err());
        }
        assert_eq!(key_fetches(&mock), 10, "ten a minute for one client");

        let real = signer.token(BODY, NOW);
        assert_eq!(
            verify_settled(&plaid, Some(&real), BODY, NOW, OTHER_CLIENT).await,
            Ok(()),
            "another client still has its budget"
        );

        // Addresses of one IPv6 /64 are one client, as for the rate limit.
        let before = key_fetches(&mock);
        for n in 0..15u16 {
            let client = std::net::IpAddr::from([0x2001, 0xdb8, 0, 1, 0, 0, 0, n]);
            let token = Signer::new(&format!("made-up-v6-{n}")).token(BODY, NOW);
            assert!(verify_settled(&plaid, Some(&token), BODY, NOW, client)
                .await
                .is_err());
        }
        assert_eq!(key_fetches(&mock) - before, 10, "ten for the /64");

        // However many clients, sixty a minute in all.
        for c in 0..6u8 {
            let client = std::net::IpAddr::from([10, 0, 0, c]);
            for n in 0..10 {
                let token = Signer::new(&format!("made-up-{c}-{n}")).token(BODY, NOW);
                assert!(verify_settled(&plaid, Some(&token), BODY, NOW, client)
                    .await
                    .is_err());
            }
        }
        assert_eq!(key_fetches(&mock), 60, "sixty in all");
    }

    /// A key fetch that fails for a while (a timeout, Plaid's 5xx) is asked
    /// again at the next call, not remembered as refused.
    ///
    /// Bug-catch: remembering a passing failure as a refusal turns away every
    /// real webhook for five minutes.
    #[tokio::test]
    async fn a_passing_key_failure_is_not_remembered() {
        let signer = Signer::new("k1");
        let (_dir, mock, plaid) = plaid_with(&signer, None).await;
        mock.fail(
            "/webhook_verification_key/get",
            500,
            "INTERNAL_SERVER_ERROR",
        );
        let token = signer.token(BODY, NOW);
        verify(&plaid, Some(&token), BODY, NOW, CLIENT)
            .await
            .unwrap_err();
        settle(&plaid).await;
        assert_eq!(key_fetches(&mock), 1);
        mock.fail.lock().unwrap().clear();
        assert_eq!(
            verify_settled(&plaid, Some(&token), BODY, NOW, CLIENT).await,
            Ok(())
        );
    }

    /// A stale key is asked about again whatever strangers have spent — at
    /// most once a minute — and a key Plaid has not confirmed for a day is
    /// refused until it does.
    ///
    /// Bug-catch: asking about a stale key from the callers' budgets lets
    /// made-up key ids keep it from ever being asked, so a key Plaid rotated
    /// out is trusted forever; no pacing asks Plaid at every call while its
    /// key endpoint fails; no limit on an unconfirmed key trusts it as long
    /// as Plaid cannot be reached.
    #[tokio::test]
    async fn a_stale_key_is_asked_about_whatever_was_spent() {
        let signer = Signer::new("k1");
        let (_dir, mock, plaid) = plaid_with(&signer, None).await;
        let token = signer.token(BODY, NOW);
        verify_settled(&plaid, Some(&token), BODY, NOW, CLIENT)
            .await
            .unwrap();
        // Strangers spend all sixty of this minute.
        for c in 0..6u8 {
            let client = std::net::IpAddr::from([10, 0, 0, c]);
            for n in 0..10 {
                let made_up = Signer::new(&format!("made-up-{c}-{n}")).token(BODY, NOW);
                let _ = verify_settled(&plaid, Some(&made_up), BODY, NOW, client).await;
            }
        }
        let spent = key_fetches(&mock);
        assert_eq!(spent, 60, "the budget is spent");

        mock.fail(
            "/webhook_verification_key/get",
            500,
            "INTERNAL_SERVER_ERROR",
        );
        plaid.age_webhook_key("k1", Duration::from_secs(2 * 60 * 60));
        assert_eq!(
            verify(&plaid, Some(&token), BODY, NOW, CLIENT).await,
            Ok(())
        );
        settle(&plaid).await;
        assert_eq!(key_fetches(&mock), spent + 1, "asked, past the budget");
        assert_eq!(
            verify(&plaid, Some(&token), BODY, NOW, CLIENT).await,
            Ok(())
        );
        settle(&plaid).await;
        assert_eq!(key_fetches(&mock), spent + 1, "once a minute at most");

        plaid.age_webhook_key("k1", Duration::from_secs(24 * 60 * 60));
        assert_eq!(
            verify(&plaid, Some(&token), BODY, NOW, CLIENT).await,
            Err(Unverified::KeyPending),
            "a day unconfirmed: refused until Plaid answers"
        );
        settle(&plaid).await;
        assert_eq!(key_fetches(&mock), spent + 2);
        mock.fail.lock().unwrap().clear();
        plaid.age_webhook_key("k1", Duration::from_secs(60));
        assert_eq!(
            verify_settled(&plaid, Some(&token), BODY, NOW, CLIENT).await,
            Ok(()),
            "confirmed again"
        );
    }

    /// A stopped ledger asks Plaid for no key: a fetch set going before the
    /// stop ends without a call.
    ///
    /// Bug-catch: a fetch that does not look at the stop keeps the stopped
    /// ledger's service — its open secret store — alive behind a Plaid that
    /// hangs, up to half an hour with fetches queued.
    #[tokio::test]
    async fn a_stopped_ledger_fetches_no_key() {
        let signer = Signer::new("k1");
        let (_dir, mock, plaid) = plaid_with(&signer, None).await;
        plaid.close().await;
        let token = signer.token(BODY, NOW);
        assert_eq!(
            verify(&plaid, Some(&token), BODY, NOW, CLIENT).await,
            Err(Unverified::KeyPending)
        );
        settle(&plaid).await;
        assert_eq!(key_fetches(&mock), 0);
    }

    /// Until no key fetch is under way.
    async fn settle(plaid: &PlaidService) {
        for _ in 0..200 {
            if !plaid.key_fetch_under_way() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("a key fetch that does not end");
    }

    /// A key cached for an hour is asked of Plaid again, in the background,
    /// and used meanwhile: kept through a passing failure, dropped once Plaid
    /// says it is set to expire.
    ///
    /// Bug-catch: a key checked for expiry only when first fetched is trusted
    /// until the node restarts, however long after Plaid rotated it out.
    #[tokio::test]
    async fn a_cached_key_is_asked_about_again() {
        let signer = Signer::new("k1");
        let (_dir, mock, plaid) = plaid_with(&signer, None).await;
        let token = signer.token(BODY, NOW);
        verify_settled(&plaid, Some(&token), BODY, NOW, CLIENT)
            .await
            .unwrap();
        assert_eq!(key_fetches(&mock), 1);

        plaid.age_webhook_key("k1", Duration::from_secs(2 * 60 * 60));
        mock.fail(
            "/webhook_verification_key/get",
            500,
            "INTERNAL_SERVER_ERROR",
        );
        assert_eq!(
            verify(&plaid, Some(&token), BODY, NOW, CLIENT).await,
            Ok(()),
            "the stale key answers while it is asked again"
        );
        settle(&plaid).await;
        assert_eq!(key_fetches(&mock), 2);
        assert_eq!(
            verify(&plaid, Some(&token), BODY, NOW, OTHER_CLIENT).await,
            Ok(()),
            "kept through a passing failure"
        );
        settle(&plaid).await;

        mock.fail.lock().unwrap().clear();
        *mock.webhook_key.lock().unwrap() =
            Some(signer.jwk(Some(chrono::Utc::now().timestamp() + 3600)));
        plaid.age_webhook_key("k1", Duration::from_secs(2 * 60 * 60));
        verify(&plaid, Some(&token), BODY, NOW, CLIENT)
            .await
            .unwrap();
        settle(&plaid).await;
        assert!(matches!(
            verify(&plaid, Some(&token), BODY, NOW, CLIENT).await,
            Err(Unverified::Key(_))
        ));
    }

    /// Each webhook Plaid sends maps to what the node does with it.
    ///
    /// Bug-catch: a sync not started for `SYNC_UPDATES_AVAILABLE` leaves
    /// webhooks doing nothing; a consent notice kept as an error is wiped by
    /// the next sync; the older update codes each start a second sync.
    #[test]
    fn each_webhook_maps_to_its_action() {
        let of = |kind: &str, code: &str, error: Option<&str>| {
            let mut body = json!({ "webhook_type": kind, "webhook_code": code, "item_id": "i" });
            if let Some(error) = error {
                body["error"] = json!({ "error_code": error });
            }
            action(&serde_json::from_value(body).unwrap())
        };
        assert_eq!(
            of("TRANSACTIONS", "SYNC_UPDATES_AVAILABLE", None),
            Action::Sync
        );
        assert_eq!(of("ITEM", "LOGIN_REPAIRED", None), Action::Repaired);
        assert_eq!(of("TRANSACTIONS", "DEFAULT_UPDATE", None), Action::Nothing);
        assert_eq!(
            of("TRANSACTIONS", "HISTORICAL_UPDATE", None),
            Action::Nothing
        );
        assert_eq!(
            of("ITEM", "NEW_ACCOUNTS_AVAILABLE", None),
            Action::RefreshAccounts
        );
        assert_eq!(
            of("ITEM", "ERROR", Some("ITEM_LOGIN_REQUIRED")),
            Action::Note("ITEM_LOGIN_REQUIRED".to_owned())
        );
        assert_eq!(
            of("ITEM", "PENDING_EXPIRATION", None),
            Action::Notice("PENDING_EXPIRATION".to_owned())
        );
        assert_eq!(
            of("ITEM", "WEBHOOK_UPDATE_ACKNOWLEDGED", None),
            Action::Nothing
        );
        assert_eq!(of("AUTH", "AUTOMATICALLY_VERIFIED", None), Action::Nothing);
    }
}
