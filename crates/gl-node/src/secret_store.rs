//! The node's encrypted secret store (build-log 007, step 3): values that must
//! never leave this node, such as Plaid access tokens.
//!
//! One file per ledger folder, [`SECRET_STORE_FILE`], node-private: opened
//! through [`ledger::journal::open_checked`] with
//! [`ledger::journal::FileTrust::NodePrivate`], the checks the node key gets
//! (no symlink, a regular file owned by this uid, one link, mode 0600). Each
//! value is sealed with AES-256-GCM under a key that lives outside the data
//! folder, in [`SECRETS_KEY_ENV_VAR`], so the file alone decrypts nothing. The
//! associated data binds each value to its name: a value copied under another
//! name fails to open instead of being served as that other secret. It does not
//! bind the ledger's name, so the store follows its folder when a removed
//! ledger is moved back under a new name (`ledger_admin`); copying a store into
//! another ledger's folder takes write access to the data folder, which already
//! holds every ledger's keys.
//!
//! Nothing here is a record. The store is never journaled, replicated or
//! written to a `.bean` file, and [`Secret`] prints as `[redacted]`, so a value
//! cannot reach a log through `{}` or `{:?}`.
//!
//! One [`SecretStore`] per folder at a time: each write replaces the whole
//! file with the instance's map, so two instances on one folder lose each
//! other's writes. `crate::plaid::PlaidService` holds the one instance of a
//! ledger, behind a mutex, for as long as the ledger runs.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use ledger::journal::{open_checked, read_to_end_capped, FileTrust};

/// The environment variable holding the store key: 64 hex characters
/// (`openssl rand -hex 32`). Kept out of the data folder, like the operator key.
pub(crate) const SECRETS_KEY_ENV_VAR: &str = "GL_NODE_SECRETS_KEY";

/// The store's file name inside a ledger folder.
pub(crate) const SECRET_STORE_FILE: &str = "secrets.json";

const FORMAT_VERSION: u32 = 1;

/// Domain prefix of the associated data, so a ciphertext made for anything
/// else under the same key never opens here. Fixed into every stored value.
const AAD_DOMAIN: &[u8] = b"openledger/secret-store/v1";

/// A store holds a handful of tokens; anything this large is not ours. Both
/// [`SecretStore::open`] and the write path hold to it.
const MAX_FILE_BYTES: u64 = 1024 * 1024;

const MAX_NAME_BYTES: usize = 256;

const NONCE_BYTES: usize = 12;

/// A secret value. Wiped on drop; `{}` and `{:?}` print `[redacted]`. The only
/// way to the value is [`Secret::expose`], which names the act at the call site.
pub(crate) struct Secret(Zeroizing<String>);

impl Secret {
    pub(crate) fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// The 32-byte key every value in the store is sealed under.
pub(crate) struct StoreKey(Zeroizing<[u8; 32]>);

impl StoreKey {
    /// Parse the value of [`SECRETS_KEY_ENV_VAR`] (`crate::plaid::PlaidEnv`
    /// reads it, an empty one as unset): 64 hex characters, surrounding whitespace ignored. A refusal never
    /// repeats the value.
    pub(crate) fn from_hex(text: &str) -> Result<Self, SecretStoreError> {
        let refused = || {
            SecretStoreError::Key(format!(
                "{SECRETS_KEY_ENV_VAR} must be 64 hex characters (32 bytes), as \
                 `openssl rand -hex 32` prints"
            ))
        };
        let mut key = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(text.trim(), key.as_mut_slice()).map_err(|_| refused())?;
        Ok(Self(key))
    }

    #[cfg(test)]
    pub(crate) fn generate() -> Self {
        Self(crate::access_list::random_bytes())
    }
}

impl fmt::Debug for StoreKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StoreKey([redacted])")
    }
}

#[derive(Debug)]
pub(crate) enum SecretStoreError {
    /// The store key is missing or malformed. Never carries the key.
    Key(String),
    /// A file operation failed; `path` is the file it failed on (the store, or
    /// the temp file a write goes through).
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// Sealing a value failed (the cipher refused it).
    Seal {
        path: PathBuf,
        name: String,
    },
    /// Writing would make a file larger than [`SecretStore::open`] reads.
    TooLarge {
        path: PathBuf,
    },
    /// The file is not a store this build reads.
    Corrupt {
        path: PathBuf,
        detail: String,
    },
    /// A value failed authentication: the wrong key, a value moved from another
    /// name, or one altered.
    WontOpen {
        path: PathBuf,
        name: String,
    },
    BadName(String),
}

impl fmt::Display for SecretStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key(message) => f.write_str(message),
            Self::Io { path, source } => {
                write!(f, "secret store {}: {source}", path.display())
            }
            Self::Seal { path, name } => {
                write!(
                    f,
                    "secret store {}: sealing {name:?} failed",
                    path.display()
                )
            }
            Self::TooLarge { path } => write!(
                f,
                "secret store {}: refusing to write more than {MAX_FILE_BYTES} bytes",
                path.display()
            ),
            Self::Corrupt { path, detail } => {
                write!(f, "secret store {} is unreadable: {detail}", path.display())
            }
            Self::WontOpen { path, name } => write!(
                f,
                "secret store {}: the value {name:?} does not open with this key — \
                 {SECRETS_KEY_ENV_VAR} is not the key it was written with, or the value \
                 was moved or altered",
                path.display()
            ),
            Self::BadName(detail) => write!(f, "secret name refused: {detail}"),
        }
    }
}

impl std::error::Error for SecretStoreError {}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreFile {
    version: u32,
    entries: BTreeMap<String, SealedEntry>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedEntry {
    nonce: String,
    ciphertext: String,
}

/// One ledger's secrets, decrypted only on [`SecretStore::get`].
pub(crate) struct SecretStore {
    path: PathBuf,
    ledger: String,
    cipher: Aes256Gcm,
    entries: BTreeMap<String, SealedEntry>,
}

impl fmt::Debug for SecretStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretStore")
            .field("path", &self.path)
            .field("ledger", &self.ledger)
            .field("names", &self.entries.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl SecretStore {
    /// Open `folder`'s store for `ledger` (the name is for messages only). Temp
    /// files a crashed write left are deleted first. No file is an empty store
    /// (nothing is written until a [`Self::put`]). Every value is opened once
    /// here, so a wrong key or a moved value is refused now, not at first use.
    pub(crate) fn open(
        folder: &Path,
        ledger: &str,
        key: &StoreKey,
    ) -> Result<Self, SecretStoreError> {
        sweep_leftover_temp_files(folder);
        let path = folder.join(SECRET_STORE_FILE);
        let cipher = Aes256Gcm::new_from_slice(key.0.as_slice())
            .map_err(|_| SecretStoreError::Key("the store key is not 32 bytes".to_owned()))?;
        let store = Self {
            entries: read_store_file(&path)?.unwrap_or_default(),
            path,
            ledger: ledger.to_owned(),
            cipher,
        };
        for name in store.entries.keys() {
            store.unseal(name)?;
        }
        Ok(store)
    }

    /// The names stored in `folder`'s store, without the key: names are not
    /// secret (`plaid/items/<item id>/…`), so a node can tell a store holds
    /// bank connections even where it cannot open them (company removal, 007).
    pub(crate) fn stored_names(folder: &Path) -> Result<Vec<String>, SecretStoreError> {
        Ok(read_store_file(&folder.join(SECRET_STORE_FILE))?
            .map(|entries| entries.into_keys().collect())
            .unwrap_or_default())
    }

    pub(crate) fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    pub(crate) fn get(&self, name: &str) -> Result<Option<Secret>, SecretStoreError> {
        if !self.entries.contains_key(name) {
            return Ok(None);
        }
        self.unseal(name).map(Some)
    }

    /// Seal `secret` under `name` with a fresh nonce and write the file. On a
    /// failed write the store is unchanged.
    pub(crate) fn put(&mut self, name: &str, secret: &Secret) -> Result<(), SecretStoreError> {
        check_name(name)?;
        let random = crate::access_list::random_bytes();
        let nonce = &random[..NONCE_BYTES];
        let aad = self.associated_data(name);
        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: secret.expose().as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| SecretStoreError::Seal {
                path: self.path.clone(),
                name: name.to_owned(),
            })?;
        let sealed = SealedEntry {
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ciphertext),
        };
        let previous = self.entries.insert(name.to_owned(), sealed);
        if let Err(error) = self.persist() {
            match previous {
                Some(previous) => self.entries.insert(name.to_owned(), previous),
                None => self.entries.remove(name),
            };
            return Err(error);
        }
        Ok(())
    }

    /// Remove `name` and rewrite the file without it. `Ok(false)` when it was
    /// not there.
    pub(crate) fn remove(&mut self, name: &str) -> Result<bool, SecretStoreError> {
        let Some(previous) = self.entries.remove(name) else {
            return Ok(false);
        };
        if let Err(error) = self.persist() {
            self.entries.insert(name.to_owned(), previous);
            return Err(error);
        }
        Ok(true)
    }

    fn unseal(&self, name: &str) -> Result<Secret, SecretStoreError> {
        let wont_open = || SecretStoreError::WontOpen {
            path: self.path.clone(),
            name: name.to_owned(),
        };
        let sealed = self.entries.get(name).ok_or_else(wont_open)?;
        let nonce = hex::decode(&sealed.nonce).map_err(|_| wont_open())?;
        let ciphertext = hex::decode(&sealed.ciphertext).map_err(|_| wont_open())?;
        if nonce.len() != NONCE_BYTES {
            return Err(wont_open());
        }
        let aad = self.associated_data(name);
        let plaintext = self
            .cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| wont_open())?;
        match String::from_utf8(plaintext) {
            Ok(value) => Ok(Secret::new(value)),
            Err(error) => {
                error.into_bytes().zeroize();
                Err(wont_open())
            }
        }
    }

    /// The domain, then the name, length-prefixed.
    fn associated_data(&self, name: &str) -> Vec<u8> {
        let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + 4 + name.len());
        aad.extend_from_slice(AAD_DOMAIN);
        aad.extend_from_slice(&(name.len() as u32).to_be_bytes());
        aad.extend_from_slice(name.as_bytes());
        aad
    }

    /// Write the whole file through a fresh node-private temp file in the same
    /// folder, fsync it, rename it over the store, then fsync the folder. The
    /// rename replaces whatever entry is at the path (a symlink included)
    /// without following it. A file larger than [`Self::open`] reads is refused.
    fn persist(&self) -> Result<(), SecretStoreError> {
        let file = StoreFile {
            version: FORMAT_VERSION,
            entries: self.entries.clone(),
        };
        let bytes =
            serde_json::to_vec_pretty(&file).map_err(|error| self.corrupt(error.to_string()))?;
        if bytes.len() as u64 > MAX_FILE_BYTES {
            return Err(SecretStoreError::TooLarge {
                path: self.path.clone(),
            });
        }
        let folder = match self.path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        let random = crate::access_list::random_bytes();
        let temp = folder.join(format!(
            ".{SECRET_STORE_FILE}.{}.tmp",
            hex::encode(&random[..8])
        ));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let written = open_checked(&temp, &options, FileTrust::NodePrivate, "secret store")
            .and_then(|mut checked| {
                checked.file.write_all(&bytes)?;
                checked.file.sync_all()?;
                std::fs::rename(&temp, &self.path)
            });
        if let Err(source) = written {
            let _ = std::fs::remove_file(&temp);
            return Err(SecretStoreError::Io { path: temp, source });
        }
        if let Ok(directory) = std::fs::File::open(folder) {
            let _ = directory.sync_all();
        }
        Ok(())
    }

    fn corrupt(&self, detail: String) -> SecretStoreError {
        SecretStoreError::Corrupt {
            path: self.path.clone(),
            detail,
        }
    }
}

/// Read and parse the store file at `path`, node-private; `Ok(None)` when
/// there is none. Nothing is decrypted here.
fn read_store_file(path: &Path) -> Result<Option<BTreeMap<String, SealedEntry>>, SecretStoreError> {
    let io_error = |source| SecretStoreError::Io {
        path: path.to_owned(),
        source,
    };
    let corrupt = |detail| SecretStoreError::Corrupt {
        path: path.to_owned(),
        detail,
    };
    let checked = match open_checked(
        path,
        std::fs::OpenOptions::new().read(true),
        FileTrust::NodePrivate,
        "secret store",
    ) {
        Ok(checked) => checked,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(io_error(source)),
    };
    let bytes = read_to_end_capped(checked.file, checked.metadata.len(), MAX_FILE_BYTES)
        .map_err(io_error)?;
    let file: StoreFile =
        serde_json::from_slice(&bytes).map_err(|error| corrupt(error.to_string()))?;
    if file.version != FORMAT_VERSION {
        return Err(corrupt(format!(
            "format version {} (this build reads {FORMAT_VERSION})",
            file.version
        )));
    }
    Ok(Some(file.entries))
}

/// The name of a temp file a crashed write left: `.secrets.json.<hex>.tmp`.
fn is_leftover_temp_file(name: &str) -> bool {
    name.strip_prefix(&format!(".{SECRET_STORE_FILE}."))
        .and_then(|rest| rest.strip_suffix(".tmp"))
        .is_some_and(|middle| !middle.is_empty() && middle.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Delete the temp files a crashed write left in `folder`. Each is an encrypted
/// copy of the store as it was, which would outlive a later
/// [`SecretStore::remove`]. Only regular files this uid owns; a failure is
/// logged and the open goes on.
fn sweep_leftover_temp_files(folder: &Path) {
    let Ok(entries) = std::fs::read_dir(folder) else {
        return;
    };
    for entry in entries.flatten() {
        if !entry
            .file_name()
            .to_str()
            .is_some_and(is_leftover_temp_file)
        {
            continue;
        }
        let path = entry.path();
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !metadata.file_type().is_file() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != ledger::journal::effective_uid() {
                continue;
            }
        }
        if let Err(error) = std::fs::remove_file(&path) {
            tracing::warn!(
                path = %path.display(),
                %error,
                "could not delete a temp file a crashed secret store write left"
            );
        }
    }
}

fn check_name(name: &str) -> Result<(), SecretStoreError> {
    if name.is_empty() || name.len() > MAX_NAME_BYTES {
        return Err(SecretStoreError::BadName(format!(
            "a name is 1 to {MAX_NAME_BYTES} bytes"
        )));
    }
    if name.chars().any(char::is_control) {
        return Err(SecretStoreError::BadName(
            "a name has no control characters".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "access-sandbox-3f9c1e2a-7b44-4c1d-9e0f-5a6b7c8d9e01";

    fn store(folder: &Path, ledger: &str, key: &StoreKey) -> SecretStore {
        SecretStore::open(folder, ledger, key).expect("open the store")
    }

    fn file_text(folder: &Path) -> String {
        std::fs::read_to_string(folder.join(SECRET_STORE_FILE)).expect("read the store file")
    }

    fn same_key(key: &StoreKey) -> StoreKey {
        StoreKey::from_hex(&hex::encode(key.0.as_slice())).expect("hex round trip")
    }

    #[cfg(unix)]
    fn set_owner_only(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(not(unix))]
    fn set_owner_only(_path: &Path) {}

    /// A value put in the store comes back after the store is reopened.
    ///
    /// Bug-catch: `put` that only updates memory (no `persist`) loses every
    /// token at restart.
    #[test]
    fn secret_store_round_trips_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let key = StoreKey::generate();
        let mut first = store(dir.path(), "acme", &key);
        first.put("plaid/item-1", &Secret::new(TOKEN)).unwrap();
        first.put("plaid/item-2", &Secret::new("second")).unwrap();

        let reopened = store(dir.path(), "acme", &same_key(&key));
        assert_eq!(
            reopened.get("plaid/item-1").unwrap().unwrap().expose(),
            TOKEN
        );
        assert_eq!(
            reopened.get("plaid/item-2").unwrap().unwrap().expose(),
            "second"
        );
        assert!(reopened.get("plaid/item-3").unwrap().is_none());
        assert_eq!(
            reopened.names().collect::<Vec<_>>(),
            ["plaid/item-1", "plaid/item-2"]
        );
    }

    /// `{}` and `{:?}` of a secret, the key and the store never show a value.
    ///
    /// Bug-catch: a derived `Debug` on `Secret` puts the token in any log line
    /// or error that formats it (007: tokens are never logged).
    #[test]
    fn secret_store_values_print_redacted() {
        let dir = tempfile::tempdir().unwrap();
        let key = StoreKey::generate();
        let key_hex = hex::encode(key.0.as_slice());
        let secret = Secret::new(TOKEN);
        let mut opened = store(dir.path(), "acme", &key);
        opened.put("plaid/item-1", &secret).unwrap();

        for printed in [
            format!("{secret}"),
            format!("{secret:?}"),
            format!("{key:?}"),
            format!("{opened:?}"),
        ] {
            assert!(!printed.contains(TOKEN), "token printed: {printed}");
            assert!(!printed.contains(&key_hex), "key printed: {printed}");
        }
        assert_eq!(format!("{secret}"), "[redacted]");
    }

    /// The file on disk holds neither the value nor the key.
    ///
    /// Bug-catch: writing the plaintext (or the key) next to the ciphertext.
    #[test]
    fn secret_store_file_holds_no_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let key = StoreKey::generate();
        store(dir.path(), "acme", &key)
            .put("plaid/item-1", &Secret::new(TOKEN))
            .unwrap();
        let text = file_text(dir.path());
        assert!(!text.contains(TOKEN));
        assert!(!text.contains(&hex::encode(TOKEN)));
        assert!(!text.contains(&hex::encode(key.0.as_slice())));
    }

    /// A store opened with another key is refused at open, naming the variable
    /// and not the key.
    ///
    /// Bug-catch: skipping the open-time check defers a wrong key to the first
    /// sync, hours after boot reported success.
    #[test]
    fn secret_store_refuses_the_wrong_key_at_open() {
        let dir = tempfile::tempdir().unwrap();
        store(dir.path(), "acme", &StoreKey::generate())
            .put("plaid/item-1", &Secret::new(TOKEN))
            .unwrap();
        let other = StoreKey::generate();
        let error = SecretStore::open(dir.path(), "acme", &other).unwrap_err();
        assert!(
            matches!(error, SecretStoreError::WontOpen { .. }),
            "{error}"
        );
        let message = error.to_string();
        assert!(message.contains(SECRETS_KEY_ENV_VAR), "{message}");
        assert!(
            !message.contains(&hex::encode(other.0.as_slice())),
            "{message}"
        );
    }

    /// A sealed value copied under another name does not open.
    ///
    /// Bug-catch: associated data without the name lets one item's token be
    /// served as another's.
    #[test]
    fn secret_store_value_moved_to_another_name_does_not_open() {
        let dir = tempfile::tempdir().unwrap();
        let key = StoreKey::generate();
        let mut opened = store(dir.path(), "acme", &key);
        opened.put("plaid/item-1", &Secret::new(TOKEN)).unwrap();
        opened.put("plaid/item-2", &Secret::new("second")).unwrap();

        let mut file: StoreFile = serde_json::from_str(&file_text(dir.path())).unwrap();
        let moved = file.entries["plaid/item-1"].clone();
        file.entries.insert("plaid/item-2".to_owned(), moved);
        std::fs::write(
            dir.path().join(SECRET_STORE_FILE),
            serde_json::to_vec(&file).unwrap(),
        )
        .unwrap();

        let error = SecretStore::open(dir.path(), "acme", &key).unwrap_err();
        assert!(
            matches!(&error, SecretStoreError::WontOpen { name, .. } if name == "plaid/item-2"),
            "{error}"
        );
    }

    /// A removed ledger's folder moved back under a new name keeps its store,
    /// as `ledger_admin` supports for the ledger itself.
    ///
    /// Bug-catch: binding values to the ledger's name strands a restored
    /// ledger's tokens, so its Plaid items can no longer be removed at Plaid.
    #[test]
    fn secret_store_follows_its_folder_to_a_new_ledger_name() {
        let root = tempfile::tempdir().unwrap();
        let acme = root.path().join("acme");
        let restored = root.path().join("acme-restored");
        std::fs::create_dir(&acme).unwrap();
        let key = StoreKey::generate();
        store(&acme, "acme", &key)
            .put("plaid/item-1", &Secret::new(TOKEN))
            .unwrap();
        std::fs::rename(&acme, &restored).unwrap();

        let reopened = store(&restored, "acme-restored", &key);
        assert_eq!(
            reopened.get("plaid/item-1").unwrap().unwrap().expose(),
            TOKEN
        );
    }

    /// The store is created owner-only, and one readable by group or other is
    /// refused.
    ///
    /// Bug-catch: opening as `NodeRead` (or any trust without the mode check)
    /// accepts a store other accounts can copy.
    #[cfg(unix)]
    #[test]
    fn secret_store_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let key = StoreKey::generate();
        store(dir.path(), "acme", &key)
            .put("plaid/item-1", &Secret::new(TOKEN))
            .unwrap();
        let path = dir.path().join(SECRET_STORE_FILE);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let error = SecretStore::open(dir.path(), "acme", &key).unwrap_err();
        assert!(matches!(error, SecretStoreError::Io { .. }), "{error}");
    }

    /// A removed value is gone from the file, not only from memory.
    ///
    /// Bug-catch: `remove` without a rewrite keeps a disconnected bank's token
    /// on disk, against the 30-day deletion promise.
    #[test]
    fn secret_store_remove_leaves_no_ciphertext() {
        let dir = tempfile::tempdir().unwrap();
        let key = StoreKey::generate();
        let mut opened = store(dir.path(), "acme", &key);
        opened.put("plaid/item-1", &Secret::new(TOKEN)).unwrap();
        let file: StoreFile = serde_json::from_str(&file_text(dir.path())).unwrap();
        let ciphertext = file.entries["plaid/item-1"].ciphertext.clone();

        assert!(opened.remove("plaid/item-1").unwrap());
        assert!(!opened.remove("plaid/item-1").unwrap());
        let text = file_text(dir.path());
        assert!(!text.contains(&ciphertext));
        assert!(!text.contains("plaid/item-1"));
        assert!(store(dir.path(), "acme", &key)
            .get("plaid/item-1")
            .unwrap()
            .is_none());
    }

    /// Temp files a crashed write left are deleted at open; other files stay.
    ///
    /// Bug-catch: without the sweep, an encrypted copy of a removed token
    /// outlives the removal for good.
    #[test]
    fn secret_store_open_deletes_leftover_temp_files() {
        let dir = tempfile::tempdir().unwrap();
        let leftover = dir
            .path()
            .join(format!(".{SECRET_STORE_FILE}.0123abcd.tmp"));
        let unrelated = dir.path().join(format!(".{SECRET_STORE_FILE}.notes.tmp"));
        for path in [&leftover, &unrelated] {
            std::fs::write(path, "{}").unwrap();
            set_owner_only(path);
        }

        store(dir.path(), "acme", &StoreKey::generate());
        assert!(!leftover.exists());
        assert!(unrelated.exists());
    }

    /// Two puts of the same value seal it differently.
    ///
    /// Bug-catch: a fixed nonce reuses (key, nonce) pairs, which breaks
    /// AES-GCM's confidentiality and authenticity.
    #[test]
    fn secret_store_seals_each_put_with_a_fresh_nonce() {
        let dir = tempfile::tempdir().unwrap();
        let key = StoreKey::generate();
        let mut opened = store(dir.path(), "acme", &key);
        opened.put("a", &Secret::new(TOKEN)).unwrap();
        opened.put("b", &Secret::new(TOKEN)).unwrap();
        let file: StoreFile = serde_json::from_str(&file_text(dir.path())).unwrap();
        assert_ne!(file.entries["a"].nonce, file.entries["b"].nonce);
    }

    /// A put that would make the file larger than `open` reads is refused, and
    /// the store is unchanged.
    ///
    /// Bug-catch: without the write-side cap, one large value writes a store
    /// the next boot refuses.
    #[test]
    fn secret_store_refuses_to_write_past_the_size_cap() {
        let dir = tempfile::tempdir().unwrap();
        let key = StoreKey::generate();
        let mut opened = store(dir.path(), "acme", &key);
        opened.put("small", &Secret::new(TOKEN)).unwrap();

        let large = "x".repeat(600 * 1024);
        let error = opened.put("large", &Secret::new(large)).unwrap_err();
        assert!(
            matches!(error, SecretStoreError::TooLarge { .. }),
            "{error}"
        );
        assert_eq!(opened.names().collect::<Vec<_>>(), ["small"]);
        assert_eq!(
            store(dir.path(), "acme", &key).names().collect::<Vec<_>>(),
            ["small"]
        );
    }

    /// The key is exactly 64 hex characters, and a refusal does not echo it.
    ///
    /// Bug-catch: echoing a mistyped key into the boot log.
    #[test]
    fn store_key_parses_only_64_hex_characters() {
        let good = "ab".repeat(32);
        assert!(StoreKey::from_hex(&good).is_ok());
        assert!(StoreKey::from_hex(&format!("  {good}\n")).is_ok());
        for bad in ["", "ab", &"ab".repeat(33), &"zz".repeat(32)] {
            let message = StoreKey::from_hex(bad).unwrap_err().to_string();
            assert!(message.contains(SECRETS_KEY_ENV_VAR), "{message}");
            if !bad.is_empty() {
                assert!(!message.contains(bad), "{message}");
            }
        }
    }

    /// A file of another version or with unknown fields is refused, not
    /// half-read.
    ///
    /// Bug-catch: skipping the version check reads a newer build's store as
    /// this one's.
    #[test]
    fn secret_store_refuses_an_unknown_format() {
        let dir = tempfile::tempdir().unwrap();
        let key = StoreKey::generate();
        let path = dir.path().join(SECRET_STORE_FILE);
        for text in [
            r#"{"version":2,"entries":{}}"#,
            r#"{"version":1,"entries":{},"extra":true}"#,
        ] {
            std::fs::write(&path, text).unwrap();
            set_owner_only(&path);
            let error = SecretStore::open(dir.path(), "acme", &key).unwrap_err();
            assert!(matches!(error, SecretStoreError::Corrupt { .. }), "{error}");
        }
    }

    /// Names are 1–256 bytes without control characters.
    ///
    /// Bug-catch: an empty or newline-bearing name written into the file.
    #[test]
    fn secret_store_refuses_bad_names() {
        let dir = tempfile::tempdir().unwrap();
        let mut opened = store(dir.path(), "acme", &StoreKey::generate());
        for name in ["", "a\nb", &"x".repeat(257)] {
            let error = opened.put(name, &Secret::new(TOKEN)).unwrap_err();
            assert!(matches!(error, SecretStoreError::BadName(_)), "{error}");
        }
        assert!(!dir.path().join(SECRET_STORE_FILE).exists());
    }
}
