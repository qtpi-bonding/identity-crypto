use crate::{AuthError, Clock};
use identity_crypto::{jwk_duo::SigningKeyPair, pb, PublicKey, SessionCredential};
use std::sync::{Arc, Mutex};

/// Lifetime of a minted session credential, in seconds (5 minutes).
pub const SESSION_SECONDS: i64 = 300;

/// The credential is renewed once 60% of its life has passed.
const RENEW_AFTER_SECONDS: i64 = SESSION_SECONDS * 3 / 5;

/// Mints session credentials for a [`RequestSigner`].
pub trait CredentialSource: Send + Sync {
    fn mint(&self, not_before: i64, not_after: i64) -> Result<SessionCredential, AuthError>;
}

/// Mints each session under one device key for one principal.
pub struct DeviceCredentials {
    device: SigningKeyPair,
    principal_genesis: PublicKey,
}

impl DeviceCredentials {
    pub fn new(device: SigningKeyPair, principal_genesis: PublicKey) -> Self {
        Self {
            device,
            principal_genesis,
        }
    }
}

impl CredentialSource for DeviceCredentials {
    fn mint(&self, not_before: i64, not_after: i64) -> Result<SessionCredential, AuthError> {
        identity_crypto::mint_session(&self.device, &self.principal_genesis, not_before, not_after)
            .map_err(AuthError::Credential)
    }
}

/// Signs outgoing requests with a session credential that renews itself.
pub struct RequestSigner {
    source: Box<dyn CredentialSource>,
    clock: Arc<dyn Clock>,
    held: Mutex<Option<Held>>,
}

struct Held {
    credential: SessionCredential,
    /// When the session becomes valid. A clock that goes back before it makes
    /// the session not yet valid, so it is replaced rather than signed with.
    not_before: i64,
    renew_at: i64,
}

impl RequestSigner {
    pub fn new(source: impl CredentialSource + 'static, clock: Arc<dyn Clock>) -> Self {
        Self {
            source: Box::new(source),
            clock,
            held: Mutex::new(None),
        }
    }
}

/// Seals one request: a `SignedMessage` over `body`, bound to `audience` and
/// `body_type`, under the current session. A fresh 16-byte nonce is drawn
/// per call; the session renews at 60% of its life, after expiry, or when the
/// clock has gone back to before the session's start.
pub fn seal_request(
    signer: &RequestSigner,
    audience: &str,
    body_type: &str,
    body: &[u8],
) -> Result<pb::SignedMessage, AuthError> {
    let now = signer.clock.now_unix();
    let mut guard = signer.held.lock().unwrap_or_else(|p| p.into_inner());
    // Renew at 60% of the life, once the held session is past its renew point,
    // or when the clock has gone back to before the session's start.
    let held = match guard.take() {
        Some(held) if held.not_before <= now && now < held.renew_at => held,
        _ => {
            let credential = signer.source.mint(now, now + SESSION_SECONDS)?;
            Held {
                credential,
                not_before: now,
                renew_at: now + RENEW_AFTER_SECONDS,
            }
        }
    };
    let mut nonce = [0u8; 16];
    if let Err(e) = getrandom::fill(&mut nonce) {
        *guard = Some(held);
        return Err(AuthError::Entropy(e.to_string()));
    }
    // A `None` device delegation: the trusted-device verifier does not read it.
    let signed = held
        .credential
        .sign_message(None, audience, nonce, now, None, body_type, body)
        .map_err(AuthError::Credential);
    *guard = Some(held);
    signed
}
