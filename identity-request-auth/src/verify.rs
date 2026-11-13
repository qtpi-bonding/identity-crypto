use crate::nonce::Insert;
use crate::{AuthError, ClockTolerance, NonceCache};
use identity_crypto::{
    pb, verify_signed_message, verify_signed_message_trusted_devices, AuthorDevices, PrincipalId,
    PublicKey, Resolver, VerifiedChain, When,
};

/// 4 MiB: the tonic layer's default body limit, in bytes. The core applies no
/// limit of its own; a caller passes `max_body` to [`precheck_request`],
/// [`check_request`] and [`open_signed_request`] (`None` for no limit).
pub const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// The caller of an accepted request. Layers put it in request extensions.
#[derive(Clone, Debug)]
pub struct VerifiedCaller {
    principal: PrincipalId,
    device: PublicKey,
    session_not_after: i64,
    issued_at: i64,
    chain: Option<VerifiedChain>,
}

impl PartialEq for VerifiedCaller {
    fn eq(&self, other: &Self) -> bool {
        self.principal == other.principal
            && self.device == other.device
            && self.session_not_after == other.session_not_after
            && self.issued_at == other.issued_at
            && match (&self.chain, &other.chain) {
                (None, None) => true,
                (Some(a), Some(b)) => {
                    a.principal() == b.principal()
                        && a.kind() == b.kind()
                        && a.host() == b.host()
                        && a.subject() == b.subject()
                        && a.device() == b.device()
                        && a.session_key() == b.session_key()
                        && a.session_not_after() == b.session_not_after()
                }
                _ => false,
            }
    }
}

impl Eq for VerifiedCaller {}

impl VerifiedCaller {
    /// When the request was issued (Unix seconds, by the caller's clock).
    pub fn issued_at(&self) -> i64 {
        self.issued_at
    }

    pub fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    pub fn device(&self) -> &PublicKey {
        &self.device
    }

    /// The end of the session certificate's window. A long-lived stream may
    /// end here; the caller decides.
    pub fn session_not_after(&self) -> i64 {
        self.session_not_after
    }

    /// The verified chain behind this caller: `Some` when a [`Resolver`]
    /// verified the request, `None` when a [`TrustedDeviceSet`] did, because
    /// that form checks one author's device keys and never builds a chain.
    pub fn chain(&self) -> Option<&VerifiedChain> {
        self.chain.as_ref()
    }
}

/// Who signed an accepted message, as a [`SignerVerifier`] reports it.
#[derive(Clone, Debug)]
pub struct VerifiedSigner {
    pub principal: PrincipalId,
    pub device: PublicKey,
    pub session_key: PublicKey,
    pub session_not_after: i64,
    pub nonce: Vec<u8>,
    pub issued_at: i64,
    /// The chain the verifier built. `Some` when the [`Resolver`] verifier ran
    /// (it has the chain from `verify_signed_message`); `None` for the
    /// [`TrustedDeviceSet`] form, which checks device keys and never builds one.
    pub chain: Option<VerifiedChain>,
}

/// Judges who signed a message: the signature, the signer's chain, the audience
/// and identity-crypto's 30 s window (`when`). Synchronous, with no `Send`,
/// `Sync` or lock requirement, so a transport that has its own way of waiting
/// (or none) can use it as it is.
///
/// Implemented for identity-crypto's [`Resolver`] (the full chain),
/// for [`TrustedDeviceSet`] (one author's device keys), for `&V` and for
/// `Option<V>` (`None` is [`AuthError::NotSetUp`]).
pub trait SignerVerifier {
    fn verify(
        &self,
        msg: &pb::SignedMessage,
        expected_audience: &str,
        when: When,
    ) -> Result<VerifiedSigner, AuthError>;
}

impl SignerVerifier for Resolver {
    fn verify(
        &self,
        msg: &pb::SignedMessage,
        expected_audience: &str,
        when: When,
    ) -> Result<VerifiedSigner, AuthError> {
        let checked =
            verify_signed_message(msg, expected_audience, self, when).map_err(AuthError::Verify)?;
        let chain = checked.chain();
        Ok(VerifiedSigner {
            principal: chain.principal().clone(),
            device: chain.device().clone(),
            session_key: chain.session_key().clone(),
            session_not_after: chain.session_not_after(),
            nonce: checked.nonce().to_vec(),
            issued_at: checked.issued_at(),
            chain: Some(chain.clone()),
        })
    }
}

impl<V: SignerVerifier + ?Sized> SignerVerifier for &V {
    fn verify(
        &self,
        msg: &pb::SignedMessage,
        expected_audience: &str,
        when: When,
    ) -> Result<VerifiedSigner, AuthError> {
        (**self).verify(msg, expected_audience, when)
    }
}

impl<V: SignerVerifier> SignerVerifier for Option<V> {
    fn verify(
        &self,
        msg: &pb::SignedMessage,
        expected_audience: &str,
        when: When,
    ) -> Result<VerifiedSigner, AuthError> {
        match self {
            Some(inner) => inner.verify(msg, expected_audience, when),
            None => Err(AuthError::NotSetUp),
        }
    }
}

/// One author's trusted device keys. A request signed under a session of any
/// other device is [`AuthError::UnknownAuthor`]: removing a device from the set
/// revokes it at the next call.
pub struct TrustedDeviceSet {
    author_genesis: PublicKey,
    devices: Vec<PublicKey>,
}

impl TrustedDeviceSet {
    pub fn new(author_genesis: PublicKey, devices: Vec<PublicKey>) -> Self {
        Self {
            author_genesis,
            devices,
        }
    }
}

impl SignerVerifier for TrustedDeviceSet {
    fn verify(
        &self,
        msg: &pb::SignedMessage,
        expected_audience: &str,
        when: When,
    ) -> Result<VerifiedSigner, AuthError> {
        let checked = verify_signed_message_trusted_devices(
            msg,
            expected_audience,
            AuthorDevices {
                author_genesis: &self.author_genesis,
                devices: &self.devices,
            },
            when,
        )
        .map_err(|e| match e {
            // A device that is not bound to the principal is an unknown author.
            identity_crypto::Error::NotBound => AuthError::UnknownAuthor,
            other => AuthError::Verify(other),
        })?;
        Ok(VerifiedSigner {
            principal: PrincipalId::from_genesis(self.author_genesis.clone()),
            device: checked.device().clone(),
            session_key: checked.session_key().clone(),
            session_not_after: checked.session_not_after(),
            nonce: checked.nonce().to_vec(),
            issued_at: checked.issued_at(),
            chain: None,
        })
    }
}

/// The principal a message claims to be signed for, read before any check, so a
/// service can fetch that principal's device keys. [`TrustedDeviceSet`] then
/// requires the message's session certificate to name the same principal.
pub fn claimed_genesis(signed: &pb::SignedMessage) -> Result<PublicKey, AuthError> {
    let chain = signed
        .signer
        .as_ref()
        .and_then(|s| s.chain.as_ref())
        .ok_or(AuthError::Malformed("signer chain"))?;
    let session = match chain {
        pb::signer_chain::Chain::SelfRooted(s) => s
            .session
            .as_ref()
            .ok_or(AuthError::Malformed("session certificate"))?,
        _ => return Err(AuthError::Malformed("signer chain is not self-rooted")),
    };
    let genesis = session
        .principal_genesis
        .as_ref()
        .ok_or(AuthError::Malformed("principal genesis"))?;
    PublicKey::try_from(genesis).map_err(|_| AuthError::Malformed("principal genesis"))
}

/// The checks that need no key and no state, in this order: the body is within
/// `max_body` bytes (`None`: no size check; this crate applies no limit of its
/// own, and [`MAX_BODY_BYTES`] is only the tonic layer's default); the audience and the body type equal the expected
/// strings (compared for equality, never parsed); the signature is not empty;
/// the nonce is 16 bytes. Each has its own [`AuthError`].
pub fn precheck_request(
    signed: &pb::SignedMessage,
    expected_audience: &str,
    expected_body_type: &str,
    received_body: &[u8],
    max_body: Option<usize>,
) -> Result<(), AuthError> {
    if let Some(max) = max_body {
        if received_body.len() > max {
            return Err(AuthError::BodyTooLarge {
                len: received_body.len(),
                max,
            });
        }
    }
    if signed.audience != expected_audience {
        return Err(AuthError::Audience);
    }
    if signed.body_type != expected_body_type {
        return Err(AuthError::BodyType);
    }
    if signed.signature.is_empty() {
        return Err(AuthError::EmptySignature);
    }
    if signed.nonce.len() != 16 {
        return Err(AuthError::NonceLength(signed.nonce.len()));
    }
    Ok(())
}

/// A request that passed every check but the replay cache.
///
/// Holding one has consumed nothing: [`check_request`] is side-effect free, so
/// it may be called any number of times on one message, and a `Checked` that is
/// dropped leaves no trace. Only [`Checked::accept`] writes the nonce to a
/// [`NonceCache`]. A caller with its own replay store reads
/// [`nonce`](Self::nonce), [`issued_at`](Self::issued_at) and
/// [`session_key`](Self::session_key) and decides for itself.
#[derive(Debug)]
pub struct Checked {
    caller: VerifiedCaller,
    session_key: PublicKey,
    nonce: Vec<u8>,
    issued_at: i64,
}

impl Checked {
    /// Who signed the request.
    pub fn caller(&self) -> &VerifiedCaller {
        &self.caller
    }

    /// The request's nonce, as signed.
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    /// When the request was issued (Unix seconds, by the caller's clock).
    pub fn issued_at(&self) -> i64 {
        self.issued_at
    }

    /// The session key that signed the request: the replay cache's key.
    pub fn session_key(&self) -> &PublicKey {
        &self.session_key
    }

    /// Remembers the request's nonce. Only a request that verified is
    /// remembered, so an unauthenticated sender cannot fill the cache.
    pub fn accept(self, nonces: &mut NonceCache, now: i64) -> Result<VerifiedCaller, AuthError> {
        match nonces.insert(&self.session_key, &self.nonce, self.issued_at, now) {
            Insert::Fresh => Ok(self.caller),
            Insert::Replayed => Err(AuthError::Replayed),
            Insert::Busy => Err(AuthError::Busy),
        }
    }
}

/// [`precheck_request`], then the signer check under `When::Live { now }`
/// (identity-crypto's 30 s window), then this verifier's `tolerance` on
/// `issued_at`, then that the request that arrived is the request that was
/// signed. Everything but the replay cache: [`Checked::accept`] does that.
#[allow(clippy::too_many_arguments)] // the wire fields and the verifier's settings, one per argument
pub fn check_request<V: SignerVerifier + ?Sized>(
    signed: &pb::SignedMessage,
    expected_audience: &str,
    expected_body_type: &str,
    received_body: &[u8],
    max_body: Option<usize>,
    signers: &V,
    tolerance: ClockTolerance,
    now: i64,
) -> Result<Checked, AuthError> {
    precheck_request(
        signed,
        expected_audience,
        expected_body_type,
        received_body,
        max_body,
    )?;
    let who = signers.verify(signed, expected_audience, When::Live { now })?;
    if (now - who.issued_at).abs() > tolerance.seconds() {
        return Err(AuthError::Skew);
    }
    if signed.body != received_body {
        return Err(AuthError::BodyMismatch);
    }
    Ok(Checked {
        caller: VerifiedCaller {
            principal: who.principal,
            device: who.device,
            session_not_after: who.session_not_after,
            issued_at: who.issued_at,
            chain: who.chain,
        },
        session_key: who.session_key,
        nonce: who.nonce,
        issued_at: who.issued_at,
    })
}

/// Accepts a request or says why not: [`check_request`], then the replay
/// cache. `now` is the verifier's clock, in Unix seconds. The cache is the
/// caller's, so it is one `&mut` with no lock inside this crate.
#[allow(clippy::too_many_arguments)] // the wire fields and the verifier's settings, one per argument
pub fn open_signed_request<V: SignerVerifier + ?Sized>(
    signed: &pb::SignedMessage,
    expected_audience: &str,
    expected_body_type: &str,
    received_body: &[u8],
    max_body: Option<usize>,
    signers: &V,
    nonces: &mut NonceCache,
    tolerance: ClockTolerance,
    now: i64,
) -> Result<VerifiedCaller, AuthError> {
    check_request(
        signed,
        expected_audience,
        expected_body_type,
        received_body,
        max_body,
        signers,
        tolerance,
        now,
    )?
    .accept(nonces, now)
}
