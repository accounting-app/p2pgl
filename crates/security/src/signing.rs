//! Transaction and directive signing (§3.8.1).
//!
//! Provides the `SignatureProvider` trait with two implementations:
//! - `NoopSignatureProvider` — signing disabled (default).
//! - `PeerKeySignatureProvider` — Ed25519 signing using the node's key.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

/// Domain-separated message prefix (§3.8.1).
const SIG_PREFIX: &str = "openledger-sig-v1";

/// Trait for signing and verifying directives.
///
/// Implementations are selected by `signing.enabled` config.
pub trait SignatureProvider: Send + Sync {
    /// Sign a content ID. Returns hex-encoded signature or None if signing disabled.
    fn sign(&self, content_id: &str) -> Option<String>;

    /// Verify a signature against a content ID and author public key (hex).
    /// Returns Ok(()) if valid, Err with reason if invalid.
    fn verify(
        &self,
        content_id: &str,
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
/// Format: `openledger-sig-v1|txid|<64-hex-id>` (for transactions)
///         `openledger-sig-v1|directiveId|<64-hex-id>` (for other directives)
pub fn build_sign_message(content_id: &str, is_transaction: bool) -> String {
    let kind = if is_transaction {
        "txid"
    } else {
        "directiveId"
    };
    format!("{SIG_PREFIX}|{kind}|{content_id}")
}

// ─── Noop provider ───────────────────────────────────────────────────────────

/// Signing disabled — the default (§3.8).
pub struct NoopSignatureProvider;

impl SignatureProvider for NoopSignatureProvider {
    fn sign(&self, _content_id: &str) -> Option<String> {
        None // No signature when disabled.
    }

    fn verify(
        &self,
        _content_id: &str,
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
}

impl PeerKeySignatureProvider {
    /// Create from an Ed25519 signing key.
    pub fn new(signing_key: SigningKey) -> Self {
        PeerKeySignatureProvider { signing_key }
    }

    /// Create from raw secret key bytes (32 bytes).
    pub fn from_bytes(secret_key_bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(secret_key_bytes);
        PeerKeySignatureProvider { signing_key }
    }

    /// Generate a new random key pair (for testing).
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        PeerKeySignatureProvider { signing_key }
    }

    /// The public key (hex-encoded, for `openledger-author`).
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().as_bytes())
    }
}

impl SignatureProvider for PeerKeySignatureProvider {
    fn sign(&self, content_id: &str) -> Option<String> {
        let message = build_sign_message(content_id, true);
        let signature = self.signing_key.sign(message.as_bytes());
        Some(hex::encode(signature.to_bytes()))
    }

    fn verify(
        &self,
        content_id: &str,
        signature_hex: &str,
        author_public_key_hex: &str,
    ) -> Result<(), SignatureError> {
        verify_signature(content_id, signature_hex, author_public_key_hex)
    }

    fn is_enabled(&self) -> bool {
        true
    }
}

/// Standalone verification function — usable without a provider instance.
pub fn verify_signature(
    content_id: &str,
    signature_hex: &str,
    author_public_key_hex: &str,
) -> Result<(), SignatureError> {
    // Decode signature.
    let sig_bytes = hex::decode(signature_hex)
        .map_err(|e| SignatureError::HexDecodeError(format!("signature: {e}")))?;

    let signature = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|e| SignatureError::InvalidSignature(e.to_string()))?;

    // Decode public key.
    let pk_bytes = hex::decode(author_public_key_hex)
        .map_err(|e| SignatureError::HexDecodeError(format!("public key: {e}")))?;

    let pk_array: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| SignatureError::InvalidPublicKey("Expected 32 bytes".to_owned()))?;

    let verifying_key = VerifyingKey::from_bytes(&pk_array)
        .map_err(|e| SignatureError::InvalidPublicKey(e.to_string()))?;

    // Build the domain-separated message and verify.
    let message = build_sign_message(content_id, true);
    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|e| SignatureError::InvalidSignature(e.to_string()))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noop_provider_returns_none() {
        let provider = NoopSignatureProvider;
        assert!(!provider.is_enabled());
        assert!(provider.sign("abc").is_none());
    }

    #[test]
    fn test_noop_verify_always_ok() {
        let provider = NoopSignatureProvider;
        let result = provider.verify("abc", "deadbeef", "pubkey");
        assert!(result.is_ok());
    }

    #[test]
    fn test_peer_key_sign_and_verify() {
        let provider = PeerKeySignatureProvider::generate();
        let content_id = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

        assert!(provider.is_enabled());

        let sig = provider.sign(content_id).unwrap();
        assert_eq!(sig.len(), 128, "Ed25519 signature should be 128 hex chars (64 bytes)");

        // Verify with the provider's own public key.
        let result = provider.verify(content_id, &sig, &provider.public_key_hex());
        assert!(result.is_ok(), "Signature should verify: {result:?}");
    }

    #[test]
    fn test_verify_wrong_content_id() {
        let provider = PeerKeySignatureProvider::generate();
        let sig = provider.sign("original_content_id").unwrap();

        let result = provider.verify("different_content_id", &sig, &provider.public_key_hex());
        assert!(
            matches!(result, Err(SignatureError::InvalidSignature(_))),
            "Wrong content ID should fail"
        );
    }

    #[test]
    fn test_verify_wrong_key() {
        let provider1 = PeerKeySignatureProvider::generate();
        let provider2 = PeerKeySignatureProvider::generate();
        let content_id = "test123";

        let sig = provider1.sign(content_id).unwrap();

        // Verify with a different key should fail.
        let result = provider1.verify(content_id, &sig, &provider2.public_key_hex());
        assert!(
            matches!(result, Err(SignatureError::InvalidSignature(_))),
            "Wrong key should fail"
        );
    }

    #[test]
    fn test_verify_bad_hex() {
        let provider = PeerKeySignatureProvider::generate();
        let result = provider.verify("id", "not-hex!", &provider.public_key_hex());
        assert!(matches!(result, Err(SignatureError::HexDecodeError(_))));
    }

    #[test]
    fn test_verify_bad_public_key() {
        let result = verify_signature("id", &hex::encode([0u8; 64]), "deadbeef");
        assert!(matches!(result, Err(SignatureError::InvalidPublicKey(_))));
    }

    #[test]
    fn test_build_sign_message_transaction() {
        let msg = build_sign_message("abc123", true);
        assert_eq!(msg, "openledger-sig-v1|txid|abc123");
    }

    #[test]
    fn test_build_sign_message_directive() {
        let msg = build_sign_message("abc123", false);
        assert_eq!(msg, "openledger-sig-v1|directiveId|abc123");
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
        let content_id = "standalone_test";
        let sig = provider.sign(content_id).unwrap();

        let result = verify_signature(content_id, &sig, &provider.public_key_hex());
        assert!(result.is_ok());
    }
}
