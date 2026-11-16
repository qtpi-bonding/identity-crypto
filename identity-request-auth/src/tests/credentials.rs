//! `DeviceCredentials` takes any `Signer`; a refusing signer surfaces as a credential error.

use crate::testkit::FakeClock;
use crate::{seal_request, AuthError, DeviceCredentials, RequestSigner};
use identity_crypto::jwk_duo::{GenerationService, SigningKeyPair};
use identity_crypto::{pb, PublicKey, Signature, Signer, SignerError};

const T0: i64 = 1_800_000_000;
const BODY_TYPE: &str = "type.googleapis.com/acme.v1.ListItemsRequest";

struct Cancelling(PublicKey);

impl Signer for Cancelling {
    fn public_key(&self) -> PublicKey {
        self.0.clone()
    }
    fn sign(&self, _message: &[u8]) -> Result<Signature, SignerError> {
        Err(SignerError::Cancelled)
    }
}

fn seal(credentials: DeviceCredentials) -> Result<pb::SignedMessage, AuthError> {
    let signer = RequestSigner::new(credentials, FakeClock::new(T0));
    seal_request(&signer, "aud", BODY_TYPE, b"\x0a\x03abc")
}

#[test]
fn device_credentials_take_any_signer() {
    let genesis = PublicKey::from(&SigningKeyPair::generate());

    let duo = GenerationService::generate_key_duo();
    seal(DeviceCredentials::new(duo, genesis.clone())).expect("a KeyDuo mints");
    seal(DeviceCredentials::new(
        SigningKeyPair::generate(),
        genesis.clone(),
    ))
    .expect("a SigningKeyPair mints");

    let cancelled = Cancelling(PublicKey::from(&SigningKeyPair::generate()));
    let err = seal(DeviceCredentials::new(cancelled, genesis)).expect_err("cancelled");
    assert!(
        matches!(
            err,
            AuthError::Credential(identity_crypto::Error::Signer(SignerError::Cancelled))
        ),
        "{err:?}"
    );
}
