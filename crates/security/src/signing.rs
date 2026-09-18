//! Transaction and directive signing (§3.8.1).
//!
//! Provides the `SignatureProvider` trait with two implementations:
//! - `NoopSignatureProvider` — signing disabled (default).
//! - `PeerKeySignatureProvider` — Ed25519 signing using the node's key.

// `Verifier` is deliberately not imported: verification goes through
// `VerifyingKey::verify_strict`, an inherent method, so the permissive trait
// method cannot be reached by accident (L-07).
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

/// Domain-separated message prefix (§3.8.1 / H2).
///
/// v1 covered only kind + content id. v2 added envelope parents and Lamport so a
/// relay cannot rewrite causal order under a valid signature. v3 also binds the
/// mesh/ledger identity so a directive signed for one mesh cannot be replayed
/// into another where the same key is allowlisted (L2).
///
/// The prefix is unchanged by L-23: v3 always bound *a* mesh id, and all that
/// changed is which configured value the caller resolves it from (`p2p.meshId`
/// when set, `p2p.swarmTopic` otherwise). A deployment that adopts no mesh id
/// therefore keeps producing and accepting byte-identical signed messages.
const SIG_PREFIX: &str = "openledger-sig-v3";

/// Fields covered by an `openledger-sig-v3` signature.
///
/// `content_id` is the economic hash (I5). `parents` and `lamport` are
/// envelope values excluded from that hash, so they must be in the signed
/// message (H2). Use the canonical stored strings: sorted comma-joined
/// parent hex (empty for genesis / non-transactions) and the decimal
/// `openledger-lamport` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignableMessage<'a> {
    /// Economic content id (64-char hex).
    pub content_id: &'a str,
    /// Selects `txid` vs `directiveId` in the domain prefix.
    pub is_transaction: bool,
    /// Canonical `openledger-parents` value.
    pub parents: &'a str,
    /// Canonical `openledger-lamport` value.
    pub lamport: &'a str,
}

/// Trait for signing and verifying directives.
///
/// Implementations are selected by `signing.enabled` config.
pub trait SignatureProvider: Send + Sync {
    /// Sign a directive. Returns hex-encoded signature or None if signing disabled.
    fn sign(&self, message: &SignableMessage<'_>) -> Option<String>;

    /// Verify a signature against a signable message and author public key (hex).
    /// Returns Ok(()) if valid, Err with reason if invalid.
    fn verify(
        &self,
        message: &SignableMessage<'_>,
        signature_hex: &str,
        author_public_key_hex: &str,
    ) -> Result<(), SignatureError>;

    /// Whether signing is enabled.
    fn is_enabled(&self) -> bool;
}

/// Errors from signature operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    /// Signature is invalid.
    InvalidSignature(String),
    /// Could not decode hex.
    HexDecodeError(String),
    /// Invalid public key.
    InvalidPublicKey(String),
    /// Signing not enabled.
    SigningDisabled,
}

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignatureError::InvalidSignature(msg) => write!(f, "Invalid signature: {msg}"),
            SignatureError::HexDecodeError(msg) => write!(f, "Hex decode error: {msg}"),
            SignatureError::InvalidPublicKey(msg) => write!(f, "Invalid public key: {msg}"),
            SignatureError::SigningDisabled => write!(f, "Signing is disabled"),
        }
    }
}

impl std::error::Error for SignatureError {}

/// Build the domain-separated message for signing (§3.8.1).
///
/// `mesh_id` is the node's mesh/ledger identity. It is bound into the signature
/// but not carried in the directive: a verifier reconstructs the message with
/// its *own* mesh id, so a signature made for another mesh fails to verify (L2).
/// Signing/verifying nodes on the same mesh share the value.
///
/// L-23: this is deliberately an opaque string chosen by the caller, not the
/// gossip swarm topic. Deriving it from the topic made "can join this overlay"
/// and "is this mesh" the same claim, so two meshes that picked the same custom
/// topic accepted each other's directives. `gl-node` resolves it from
/// `p2p.meshId`, falling back to `p2p.swarmTopic` so a deployment that adopts
/// no mesh id can still verify the signatures it has already persisted.
///
/// Format:
/// `openledger-sig-v3|{txid|directiveId}|{content_id}|parents|{parents}|lamport|{lamport}|mesh|{mesh_id}`
pub fn build_sign_message(message: &SignableMessage<'_>, mesh_id: &str) -> String {
    let kind = if message.is_transaction {
        "txid"
    } else {
        "directiveId"
    };
    format!(
        "{SIG_PREFIX}|{kind}|{content_id}|parents|{parents}|lamport|{lamport}|mesh|{mesh_id}",
        content_id = message.content_id,
        parents = message.parents,
        lamport = message.lamport,
    )
}

// ─── Noop provider ───────────────────────────────────────────────────────────

/// Signing disabled — the default (§3.8).
pub struct NoopSignatureProvider;

impl SignatureProvider for NoopSignatureProvider {
    fn sign(&self, _message: &SignableMessage<'_>) -> Option<String> {
        None // No signature when disabled.
    }

    fn verify(
        &self,
        _message: &SignableMessage<'_>,
        _signature_hex: &str,
        _author_public_key_hex: &str,
    ) -> Result<(), SignatureError> {
        // When signing is disabled, unsigned entries are accepted (§3.8.1).
        Ok(())
    }

    fn is_enabled(&self) -> bool {
        false
    }
}

// ─── PeerKey provider ────────────────────────────────────────────────────────

/// Ed25519 signing using the node's Iroh key (§3.8.1).
pub struct PeerKeySignatureProvider {
    signing_key: SigningKey,
    /// Mesh/ledger identity bound into every signature (L2, L-23). Resolved by
    /// the caller — see [`build_sign_message`].
    mesh_id: String,
}

impl PeerKeySignatureProvider {
    /// Create from an Ed25519 signing key and the node's resolved mesh id.
    pub fn new(signing_key: SigningKey, mesh_id: String) -> Self {
        PeerKeySignatureProvider {
            signing_key,
            mesh_id,
        }
    }

    /// Create from raw secret key bytes (32 bytes) and the node's mesh id.
    pub fn from_bytes(secret_key_bytes: &[u8; 32], mesh_id: String) -> Self {
        let signing_key = SigningKey::from_bytes(secret_key_bytes);
        PeerKeySignatureProvider {
            signing_key,
            mesh_id,
        }
    }

    /// Generate a new random key pair with an empty mesh id (for testing).
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        PeerKeySignatureProvider {
            signing_key,
            mesh_id: String::new(),
        }
    }

    /// The public key (hex-encoded, for `openledger-author`).
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().as_bytes())
    }
}

impl SignatureProvider for PeerKeySignatureProvider {
    fn sign(&self, message: &SignableMessage<'_>) -> Option<String> {
        let encoded = build_sign_message(message, &self.mesh_id);
        let signature = self.signing_key.sign(encoded.as_bytes());
        Some(hex::encode(signature.to_bytes()))
    }

    fn verify(
        &self,
        message: &SignableMessage<'_>,
        signature_hex: &str,
        author_public_key_hex: &str,
    ) -> Result<(), SignatureError> {
        verify_signature(message, signature_hex, author_public_key_hex, &self.mesh_id)
    }

    fn is_enabled(&self) -> bool {
        true
    }
}

/// Standalone verification function — usable without a provider instance.
///
/// Envelope fields on `message` and `mesh_id` must match those used when
/// signing (§3.8.1 / L2).
pub fn verify_signature(
    message: &SignableMessage<'_>,
    signature_hex: &str,
    author_public_key_hex: &str,
    mesh_id: &str,
) -> Result<(), SignatureError> {
    // Decode signature.
    let sig_bytes = hex::decode(signature_hex)
        .map_err(|e| SignatureError::HexDecodeError(format!("signature: {e}")))?;

    let signature = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|e| SignatureError::InvalidSignature(e.to_string()))?;

    // Decode public key. Iroh `EndpointId` Display is lowercase hex of these
    // same 32 bytes, so `openledger-author` verifies directly (C-3).
    let pk_bytes = hex::decode(author_public_key_hex)
        .map_err(|e| SignatureError::HexDecodeError(format!("public key: {e}")))?;

    let pk_array: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| SignatureError::InvalidPublicKey("Expected 32 bytes".to_owned()))?;

    let verifying_key = VerifyingKey::from_bytes(&pk_array)
        .map_err(|e| SignatureError::InvalidPublicKey(e.to_string()))?;

    let encoded = build_sign_message(message, mesh_id);
    // `verify_strict`, not `verify` (L-07). The permissive check is the
    // cofactorless equation alone, which accepts a signature whose `R` — or
    // whose *author key* — is a small-order point, and such a pair verifies
    // against **every** message: `A = R = identity, s = 0` satisfies it for any
    // content id, parents, lamport and mesh. Strict verification additionally
    // refuses small-order `A`/`R` and non-canonical encodings, so a signature is
    // bound to the one message it was made over. Nothing legitimate is lost —
    // keys produced by `SigningKey`/Iroh are never small-order, and a real
    // signature's `R` is not either.
    verifying_key
        .verify_strict(encoded.as_bytes(), &signature)
        .map_err(|e| SignatureError::InvalidSignature(e.to_string()))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_message<'a>(content_id: &'a str, is_transaction: bool) -> SignableMessage<'a> {
        SignableMessage {
            content_id,
            is_transaction,
            parents: "",
            lamport: "1",
        }
    }

    #[test]
    fn test_noop_provider_returns_none() {
        let provider = NoopSignatureProvider;
        assert!(!provider.is_enabled());
        assert!(provider.sign(&sample_message("abc", true)).is_none());
    }

    #[test]
    fn test_noop_verify_always_ok() {
        let provider = NoopSignatureProvider;
        let result = provider.verify(&sample_message("abc", true), "deadbeef", "pubkey");
        assert!(result.is_ok());
    }

    #[test]
    fn test_peer_key_sign_and_verify() {
        let provider = PeerKeySignatureProvider::generate();
        let message = sample_message(
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            true,
        );

        assert!(provider.is_enabled());

        let sig = provider.sign(&message).unwrap();
        assert_eq!(
            sig.len(),
            128,
            "Ed25519 signature should be 128 hex chars (64 bytes)"
        );

        // Verify with the provider's own public key.
        let result = provider.verify(&message, &sig, &provider.public_key_hex());
        assert!(result.is_ok(), "Signature should verify: {result:?}");
    }

    #[test]
    fn test_verify_wrong_content_id() {
        let provider = PeerKeySignatureProvider::generate();
        let original = sample_message("original_content_id", true);
        let sig = provider.sign(&original).unwrap();

        let result = provider.verify(
            &sample_message("different_content_id", true),
            &sig,
            &provider.public_key_hex(),
        );
        assert!(
            matches!(result, Err(SignatureError::InvalidSignature(_))),
            "Wrong content ID should fail"
        );
    }

    #[test]
    fn test_verify_wrong_key() {
        let provider1 = PeerKeySignatureProvider::generate();
        let provider2 = PeerKeySignatureProvider::generate();
        let message = sample_message("test123", true);

        let sig = provider1.sign(&message).unwrap();

        // Verify with a different key should fail.
        let result = provider1.verify(&message, &sig, &provider2.public_key_hex());
        assert!(
            matches!(result, Err(SignatureError::InvalidSignature(_))),
            "Wrong key should fail"
        );
    }

    #[test]
    fn test_verify_bad_hex() {
        let provider = PeerKeySignatureProvider::generate();
        let result = provider.verify(
            &sample_message("id", true),
            "not-hex!",
            &provider.public_key_hex(),
        );
        assert!(matches!(result, Err(SignatureError::HexDecodeError(_))));
    }

    #[test]
    fn test_verify_bad_public_key() {
        let result = verify_signature(
            &sample_message("id", true),
            &hex::encode([0u8; 64]),
            "deadbeef",
            "",
        );
        assert!(matches!(result, Err(SignatureError::InvalidPublicKey(_))));
    }

    #[test]
    fn test_build_sign_message_transaction() {
        let msg = build_sign_message(&sample_message("abc123", true), "my-org/ledger");
        assert_eq!(
            msg,
            "openledger-sig-v3|txid|abc123|parents||lamport|1|mesh|my-org/ledger"
        );
    }

    #[test]
    fn test_build_sign_message_directive() {
        let msg = build_sign_message(&sample_message("abc123", false), "my-org/ledger");
        assert_eq!(
            msg,
            "openledger-sig-v3|directiveId|abc123|parents||lamport|1|mesh|my-org/ledger"
        );
    }

    #[test]
    fn test_mesh_mismatch_fails_verification() {
        // L2 regression: a signature made for mesh A must not verify against mesh
        // B, blocking cross-mesh replay when the same key is allowlisted on both.
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let pk_hex = hex::encode(signing_key.verifying_key().as_bytes());
        let provider_a = PeerKeySignatureProvider::new(signing_key, "mesh-A".to_owned());
        let message = sample_message("cross-mesh", true);
        let sig = provider_a.sign(&message).unwrap();

        // Same key, same message, different mesh → must fail.
        assert!(matches!(
            verify_signature(&message, &sig, &pk_hex, "mesh-B"),
            Err(SignatureError::InvalidSignature(_))
        ));
        // Correct mesh still verifies.
        assert!(verify_signature(&message, &sig, &pk_hex, "mesh-A").is_ok());
    }

    #[test]
    fn test_tampered_parents_fails_verification() {
        let provider = PeerKeySignatureProvider::generate();
        let original = SignableMessage {
            content_id: "same-economic-id",
            is_transaction: true,
            parents: "",
            lamport: "5",
        };
        let sig = provider.sign(&original).unwrap();
        let tampered = SignableMessage {
            parents: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ..original
        };
        let result = provider.verify(&tampered, &sig, &provider.public_key_hex());
        assert!(
            matches!(result, Err(SignatureError::InvalidSignature(_))),
            "rewritten parents must fail verification"
        );
    }

    #[test]
    fn test_tampered_lamport_fails_verification() {
        let provider = PeerKeySignatureProvider::generate();
        let original = SignableMessage {
            content_id: "same-economic-id",
            is_transaction: true,
            parents: "",
            lamport: "5",
        };
        let sig = provider.sign(&original).unwrap();
        let tampered = SignableMessage {
            lamport: "999",
            ..original
        };
        let result = provider.verify(&tampered, &sig, &provider.public_key_hex());
        assert!(
            matches!(result, Err(SignatureError::InvalidSignature(_))),
            "rewritten lamport must fail verification"
        );
    }

    // ── L-07: strict verification ───────────────────────────────────────

    /// The Ed25519 identity point, compressed: y = 1, sign bit clear. Order 1,
    /// so it is small-order by definition.
    fn identity_point_hex() -> String {
        format!("01{}", "00".repeat(31))
    }

    #[test]
    fn test_small_order_universal_forgery_is_rejected() {
        // L-07 regression, and the reason `verify_strict` is not cosmetic.
        //
        // The permissive check is only the cofactorless equation
        // `R == [s]B - [k]A`. Take the identity point I for both the author key
        // A and the signature's R, and s = 0: `[0]B - [k]I == I == R` holds for
        // *every* k, i.e. for every message. So one fixed 64-byte blob verifies
        // against any content id / parents / lamport / mesh under a key an
        // attacker publishes as `openledger-author` — a universal forgery, not a
        // malleation of some existing signature.
        //
        // `verify_strict` refuses small-order A and R, so the blob verifies
        // against nothing.
        let identity = identity_point_hex();
        let forged_signature = format!("{identity}{}", "00".repeat(32)); // R = I, s = 0

        for content_id in ["anything-at-all", "a-completely-different-directive"] {
            let result = verify_signature(
                &sample_message(content_id, true),
                &forged_signature,
                &identity,
                "mesh-A",
            );
            assert!(
                matches!(result, Err(SignatureError::InvalidSignature(_))),
                "small-order universal forgery must be refused for {content_id}: {result:?}"
            );
        }
    }

    #[test]
    fn test_strict_verification_still_accepts_real_signatures() {
        // The other half of L-07: strictness must not cost us any honest
        // signature. Round-trip a batch of freshly generated keys over both
        // domain kinds and a populated envelope.
        for i in 0..32u8 {
            let provider = PeerKeySignatureProvider::new(
                SigningKey::from_bytes(&[i; 32]),
                "mesh-round-trip".to_owned(),
            );
            for is_transaction in [true, false] {
                let message = SignableMessage {
                    content_id: "3f1c0a2b3f1c0a2b3f1c0a2b3f1c0a2b3f1c0a2b3f1c0a2b3f1c0a2b3f1c0a2b",
                    is_transaction,
                    parents: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    lamport: "12345",
                };
                let sig = provider.sign(&message).unwrap();
                assert!(
                    provider
                        .verify(&message, &sig, &provider.public_key_hex())
                        .is_ok(),
                    "strict verification must accept an honestly produced signature"
                );
            }
        }
    }

    #[test]
    fn test_public_key_hex_format() {
        let provider = PeerKeySignatureProvider::generate();
        let pk = provider.public_key_hex();
        assert_eq!(pk.len(), 64, "Public key should be 64 hex chars (32 bytes)");
        assert!(pk.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_standalone_verify() {
        let provider = PeerKeySignatureProvider::generate();
        let message = sample_message("standalone_test", true);
        let sig = provider.sign(&message).unwrap();

        let result = verify_signature(&message, &sig, &provider.public_key_hex(), "");
        assert!(result.is_ok());
    }

    // ── CT-10: signing toggle (§3.8) ────────────────────────────────────

    #[test]
    fn ct10_signing_toggle_does_not_change_txid() {
        use ledger::hash::compute_content_id;
        use ledger::model::*;
        use rust_decimal_macros::dec;
        use std::collections::BTreeMap;

        // Create a transaction with no envelope metadata.
        let txn_unsigned = Transaction {
            date: chrono::NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            flag: Flag::Complete,
            payee: Some("Acme Corp".to_owned()),
            narration: Some("CT-10 test".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                Posting {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
                Posting {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
            ],
            metadata: BTreeMap::new(),
        };
        let txid_unsigned = compute_content_id(&Directive::Transaction(txn_unsigned.clone()));

        // Same transaction WITH envelope metadata (signing on). The v2 signed
        // message covers parents + lamport; those fields still must not enter
        // the economic hash (I5 / CT-10). Hash and signed message are different scopes.
        let provider = PeerKeySignatureProvider::generate();
        let signable = SignableMessage {
            content_id: &txid_unsigned,
            is_transaction: true,
            parents: "",
            lamport: "42",
        };
        let sig = provider.sign(&signable).unwrap();
        let mut signed_metadata = BTreeMap::new();
        signed_metadata.insert("openledger-author".to_owned(), "test-peer".to_owned());
        signed_metadata.insert("openledger-lamport".to_owned(), "42".to_owned());
        signed_metadata.insert("openledger-parents".to_owned(), "".to_owned());
        signed_metadata.insert("openledger-signature".to_owned(), sig.clone());

        let txn_signed = Transaction {
            metadata: signed_metadata,
            ..txn_unsigned.clone()
        };
        let txid_signed = compute_content_id(&Directive::Transaction(txn_signed));

        // KEY ASSERTION: txid must be identical whether signing is on or off.
        // This proves envelope keys never enter the economic hash (I5 / CT-10).
        assert_eq!(
            txid_unsigned, txid_signed,
            "Toggling signing must not change txid (envelope excluded from hash)"
        );
        assert!(
            provider
                .verify(&signable, &sig, &provider.public_key_hex())
                .is_ok(),
            "signature over envelope must still verify"
        );
    }

    #[test]
    fn ct10_verify_accepts_valid_signature() {
        let provider = PeerKeySignatureProvider::generate();
        let message = sample_message("ct10_valid", true);
        let sig = provider.sign(&message).unwrap();

        let result = provider.verify(&message, &sig, &provider.public_key_hex());
        assert!(result.is_ok(), "Valid signature must be accepted");
    }

    #[test]
    fn ct10_verify_rejects_forged_signature() {
        let provider = PeerKeySignatureProvider::generate();
        let message = sample_message("ct10_forged", true);
        let sig = provider.sign(&message).unwrap();

        // Forge by using a different key's public key.
        let attacker = PeerKeySignatureProvider::generate();
        let result = provider.verify(&message, &sig, &attacker.public_key_hex());
        assert!(result.is_err(), "Forged signature must be rejected");
    }

    #[test]
    fn test_directive_signature_does_not_verify_as_transaction() {
        let provider = PeerKeySignatureProvider::generate();
        let content_id = "kind-mismatch";
        let directive_message = sample_message(content_id, false);
        let directive_sig = provider.sign(&directive_message).unwrap();
        let result = verify_signature(
            &sample_message(content_id, true),
            &directive_sig,
            &provider.public_key_hex(),
            "",
        );
        assert!(
            matches!(result, Err(SignatureError::InvalidSignature(_))),
            "txid domain must not accept a directiveId signature"
        );
        let result = verify_signature(
            &directive_message,
            &directive_sig,
            &provider.public_key_hex(),
            "",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn ct10_noop_provider_leaves_txid_unaffected() {
        let noop = NoopSignatureProvider;
        assert!(!noop.is_enabled());
        assert_eq!(
            noop.sign(&sample_message("any-id", true)),
            None,
            "Noop should return None"
        );
    }
}
