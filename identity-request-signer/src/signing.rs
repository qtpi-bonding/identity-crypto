//! Signing: the plain "sign what the caller gives" API.

use crate::config::Config;
use crate::error::SignerError;
use crate::keys::DeviceState;
use serde::Serialize;
use std::sync::Arc;

/// What to sign. The signer signs exactly this; it names no service.
pub struct SignParams<'a> {
    pub method_path: &'a str,
    pub body_type: &'a str,
    pub body: &'a [u8],
    pub audience: Option<&'a str>,
}

/// One signed request: the base64 header and how long the delegation lives.
pub struct SignOutcome {
    pub header_b64: String,
    pub days_left: i64,
}

#[derive(Serialize)]
pub struct Info {
    pub principal: String,
    pub version: String,
    pub days_left: i64,
    pub renewal_due: bool,
}

pub struct Signing {
    _config: Config,
    _device: Arc<DeviceState>,
}

impl Signing {
    pub fn new(config: &Config, device: Arc<DeviceState>) -> Result<Signing, SignerError> {
        config.validate()?;
        Ok(Signing {
            _config: config.clone(),
            _device: device,
        })
    }

    pub fn sign_request(&self, params: &SignParams) -> Result<SignOutcome, SignerError> {
        let _ = params;
        unimplemented!()
    }

    pub fn info(&self) -> Info {
        unimplemented!()
    }
}
