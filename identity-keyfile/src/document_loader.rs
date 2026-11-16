//! DocumentLoader: persisted high-water mark, hooks, expiry on every current().
//!
//! The loader reads a signed document from disk and installs it only after it
//! passes signature, time, lifetime, version, successor, decode and structure
//! checks. The highest accepted version is persisted in a private state file
//! so that a restart cannot be rolled back to an older document.
//!
//! State file format (mode 0600, read with the private-file reader):
//! `{"version":1,"document_type":"…","highest_version":N,"document_id":"<64 lowercase hex>"}`.
//! A missing state file means first boot. A corrupt, wrong-version,
//! wrong-type, bad-hex, loose-mode or wrong-owner state file refuses every
//! reload until it is fixed.
//!
//! Owner reset: delete the state file. That deliberately forgets the
//! high-water mark and is documented in this module and the README.

use crate::error::KeyfileError;
use crate::private_fs::{read_private_file, read_regular_file, write_private_atomic};
use identity_crypto::{
    check_document_time, pb, verify_signed_document, AuthorityChain, VerifiedDocument,
};
use prost::Message;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

/// The largest document file the loader will read.
pub const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

/// The state file is a small JSON object; anything larger is refused.
const MAX_STATE_BYTES: usize = 4096;

/// The state file format version this crate writes and reads.
const STATE_VERSION: u64 = 1;

/// Where the loader reads its document and state, and what it accepts.
pub struct LoaderConfig {
    pub document_path: PathBuf,
    pub state_path: PathBuf,
    pub authority: AuthorityChain,
    pub document_type: String,
}

/// The document currently accepted: its version and id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Accepted {
    pub version: u64,
    pub id: [u8; 32],
}

type Decode<T> = Box<dyn Fn(&[u8]) -> Result<T, String> + Send + Sync>;
type Successor =
    Box<dyn Fn(Option<Accepted>, &VerifiedDocument) -> Result<(), String> + Send + Sync>;
type Structure<T> = Box<dyn Fn(&T) -> Result<(), String> + Send + Sync>;

/// Loads, verifies and serves one signed document of type `T`.
pub struct DocumentLoader<T> {
    config: LoaderConfig,
    decode: Decode<T>,
    successor: Option<Successor>,
    structure: Option<Structure<T>>,
    max_lifetime: Option<i64>,
    inner: Mutex<Inner<T>>,
}

struct Inner<T> {
    /// The highest version this process has ever accepted. Never lowered.
    highest: Option<Accepted>,
    /// The installed document, if any.
    current: Option<Installed<T>>,
}

struct Installed<T> {
    accepted: Accepted,
    verified: VerifiedDocument,
    value: Arc<T>,
}

/// The result of one [`DocumentLoader::reload`].
#[must_use]
#[derive(Debug)]
pub enum Reload {
    /// A new document was installed.
    Loaded {
        accepted: Accepted,
        state: StateWrite,
    },
    /// The document in force is still the one on disk.
    Unchanged,
    /// The document was refused. Any document in force is cleared.
    Refused(DocumentError),
}

/// Whether the high-water mark reached the state file.
/// `Failed` keeps the in-memory high-water mark; the caller MUST log it at error level.
#[must_use]
#[derive(Debug)]
pub enum StateWrite {
    Written,
    Failed(KeyfileError),
}

/// Why a reload was refused.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DocumentError {
    #[error("cannot read document: {0}")]
    Read(KeyfileError),
    #[error("malformed document: {0}")]
    Malformed(String),
    #[error("document failed verification: {0}")]
    Verify(identity_crypto::Error),
    #[error("document is not valid at this time: {0}")]
    Time(identity_crypto::Error),
    #[error("document lifetime {lifetime}s exceeds the maximum {max}s")]
    LifetimeTooLong { lifetime: i64, max: i64 },
    #[error("document version {found} is older than accepted version {highest}")]
    Rollback { highest: u64, found: u64 },
    #[error("a different document with version {version} was already accepted")]
    Equivocation { version: u64 },
    #[error("successor check refused the document: {0}")]
    Successor(String),
    #[error("cannot decode document body: {0}")]
    Body(String),
    #[error("document structure refused: {0}")]
    Structure(String),
    #[error("state file {} is corrupt: {reason}", path.display())]
    StateCorrupt { path: PathBuf, reason: &'static str },
}

impl<T: Send + Sync + 'static> DocumentLoader<T> {
    /// A loader that decodes document bodies with `decode`.
    pub fn new(
        config: LoaderConfig,
        decode: impl Fn(&[u8]) -> Result<T, String> + Send + Sync + 'static,
    ) -> Self {
        Self {
            config,
            decode: Box::new(decode),
            successor: None,
            structure: None,
            max_lifetime: None,
            inner: Mutex::new(Inner {
                highest: None,
                current: None,
            }),
        }
    }

    /// Runs `check` before accepting a version above the high-water mark.
    /// It receives the previously accepted document, if any.
    pub fn successor(
        mut self,
        check: impl Fn(Option<Accepted>, &VerifiedDocument) -> Result<(), String>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.successor = Some(Box::new(check));
        self
    }

    /// Refuses documents whose validity window is longer than `seconds`.
    pub fn max_lifetime(mut self, seconds: i64) -> Self {
        self.max_lifetime = Some(seconds);
        self
    }

    /// Runs `check` on the decoded body before installing it.
    pub fn structure(
        mut self,
        check: impl Fn(&T) -> Result<(), String> + Send + Sync + 'static,
    ) -> Self {
        self.structure = Some(Box::new(check));
        self
    }

    fn lock(&self) -> MutexGuard<'_, Inner<T>> {
        // A poisoned lock still holds a consistent value: every write is a single assignment.
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Re-reads the state and the document, and installs the document if it
    /// passes every check. `now` is the Unix time used for the validity check.
    pub fn reload(&self, now: i64) -> Reload {
        let mut inner = self.lock();
        match self.reload_locked(&mut inner, now) {
            Ok(outcome) => outcome,
            Err(error) => {
                inner.current = None;
                Reload::Refused(error)
            }
        }
    }

    fn reload_locked(&self, inner: &mut Inner<T>, now: i64) -> Result<Reload, DocumentError> {
        let state = self.read_state()?;
        let highest = max_accepted(inner.highest, state.as_ref().map(|s| s.accepted));

        let bytes = read_regular_file(&self.config.document_path, MAX_DOCUMENT_BYTES)
            .map_err(DocumentError::Read)?;
        let signed = pb::SignedDocument::decode(bytes.as_slice())
            .map_err(|e| DocumentError::Malformed(e.to_string()))?;
        let verified =
            verify_signed_document(&signed, &self.config.document_type, &self.config.authority)
                .map_err(DocumentError::Verify)?;
        check_document_time(&verified, now).map_err(DocumentError::Time)?;
        self.check_lifetime(&verified)?;

        let accepted = Accepted {
            version: verified.version(),
            id: *verified.id(),
        };
        match highest {
            Some(h) if accepted.version < h.version => {
                return Err(DocumentError::Rollback {
                    highest: h.version,
                    found: accepted.version,
                });
            }
            Some(h) if accepted.version == h.version => {
                if accepted.id != h.id {
                    return Err(DocumentError::Equivocation {
                        version: accepted.version,
                    });
                }
                // Same document as the high-water mark (restart): no successor check.
            }
            // The previous document: from memory, else from the state file.
            Some(_) => self.run_successor(
                inner.highest.or(state.as_ref().map(|s| s.accepted)),
                &verified,
            )?,
            None => self.run_successor(None, &verified)?,
        }

        if let Some(current) = &inner.current {
            if current.accepted == accepted {
                return Ok(Reload::Unchanged);
            }
        }

        let value = (self.decode)(verified.body()).map_err(DocumentError::Body)?;
        if let Some(check) = &self.structure {
            check(&value).map_err(DocumentError::Structure)?;
        }

        let outcome_state = match write_state(&self.config, &accepted) {
            Ok(()) => StateWrite::Written,
            Err(error) => StateWrite::Failed(error),
        };
        inner.highest = Some(accepted);
        inner.current = Some(Installed {
            accepted,
            verified: verified.clone(),
            value: Arc::new(value),
        });
        Ok(Reload::Loaded {
            accepted,
            state: outcome_state,
        })
    }

    fn check_lifetime(&self, verified: &VerifiedDocument) -> Result<(), DocumentError> {
        let Some(max) = self.max_lifetime else {
            return Ok(());
        };
        let lifetime = verified.expires_at().saturating_sub(verified.issued_at());
        if verified.expires_at() == i64::MAX || lifetime > max {
            return Err(DocumentError::LifetimeTooLong { lifetime, max });
        }
        Ok(())
    }

    fn run_successor(
        &self,
        prev: Option<Accepted>,
        verified: &VerifiedDocument,
    ) -> Result<(), DocumentError> {
        match &self.successor {
            Some(check) => check(prev, verified).map_err(DocumentError::Successor),
            None => Ok(()),
        }
    }

    fn read_state(&self) -> Result<Option<StoredState>, DocumentError> {
        let path = &self.config.state_path;
        let bytes = match read_private_file(path, MAX_STATE_BYTES) {
            Ok(bytes) => bytes,
            Err(KeyfileError::Missing(_)) => return Ok(None),
            Err(error) => {
                return Err(corrupt(path, state_reason(&error)));
            }
        };
        parse_state(&bytes, &self.config.document_type)
            .map(Some)
            .map_err(|reason| corrupt(path, reason))
    }

    /// The document currently in force, or `None` when nothing is loaded or it
    /// has expired at `now`. Checked on every call.
    pub fn current(&self, now: i64) -> Option<Arc<T>> {
        let inner = self.lock();
        let installed = inner.current.as_ref()?;
        if check_document_time(&installed.verified, now).is_err() {
            return None;
        }
        Some(Arc::clone(&installed.value))
    }

    /// The document currently in force, as its version and id.
    pub fn accepted(&self) -> Option<Accepted> {
        self.lock().current.as_ref().map(|c| c.accepted)
    }
}

/// The larger of two optional high-water marks, by version.
fn max_accepted(a: Option<Accepted>, b: Option<Accepted>) -> Option<Accepted> {
    match (a, b) {
        (Some(x), Some(y)) => Some(if y.version > x.version { y } else { x }),
        (x, None) => x,
        (None, y) => y,
    }
}

fn corrupt(path: &std::path::Path, reason: &'static str) -> DocumentError {
    DocumentError::StateCorrupt {
        path: path.to_path_buf(),
        reason,
    }
}

/// Maps a private-file read failure to a fixed reason, so no file content leaks into the error.
fn state_reason(error: &KeyfileError) -> &'static str {
    match error {
        KeyfileError::InsecureFile(_) => "state file mode is not 0600 or 0400",
        KeyfileError::WrongOwner(_) => "state file is owned by another user",
        KeyfileError::NotAFile(_) => "state path is not a regular file",
        KeyfileError::TooLarge { .. } => "state file is too large",
        _ => "state file cannot be read",
    }
}

/// The in-memory form of the state file.
struct StoredState {
    accepted: Accepted,
}

fn parse_state(bytes: &[u8], document_type: &str) -> Result<StoredState, &'static str> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| "state file is not valid JSON")?;
    let version = value
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .ok_or("state file has no version")?;
    if version != STATE_VERSION {
        return Err("state file version is not supported");
    }
    let ty = value
        .get("document_type")
        .and_then(serde_json::Value::as_str)
        .ok_or("state file has no document type")?;
    if ty != document_type {
        return Err("state file is for another document type");
    }
    let highest = value
        .get("highest_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or("state file has no highest version")?;
    let id_hex = value
        .get("document_id")
        .and_then(serde_json::Value::as_str)
        .ok_or("state file has no document id")?;
    let id = parse_hex32(id_hex).ok_or("state file document id is not 64 lowercase hex digits")?;
    Ok(StoredState {
        accepted: Accepted {
            version: highest,
            id,
        },
    })
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let raw = s.as_bytes();
    if raw.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in raw.chunks(2).enumerate() {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

fn hex_lower(b: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push(DIGITS[(byte >> 4) as usize] as char);
        s.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    s
}

/// Writes the high-water mark to the state file. The parent directory must exist.
fn write_state(config: &LoaderConfig, accepted: &Accepted) -> Result<(), KeyfileError> {
    let body = serde_json::json!({
        "version": STATE_VERSION,
        "document_type": config.document_type,
        "highest_version": accepted.version,
        "document_id": hex_lower(&accepted.id),
    });
    let bytes = serde_json::to_vec(&body).map_err(|e| KeyfileError::Serialize {
        path: config.state_path.clone(),
        msg: e.to_string(),
    })?;
    write_private_atomic(&config.state_path, &bytes, 0o600)
}
