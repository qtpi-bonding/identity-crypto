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
    config: Config,
    device: Arc<DeviceState>,
}

impl Signing {
    pub fn new(config: &Config, device: Arc<DeviceState>) -> Result<Signing, SignerError> {
        config.validate()?;
        Ok(Signing {
            config: config.clone(),
            device,
        })
    }

    pub fn sign_request(&self, params: &SignParams) -> Result<SignOutcome, SignerError> {
        if params.method_path.is_empty() || params.body_type.is_empty() {
            return Err(SignerError::BadRequest(String::from(
                "the method path and body type must not be empty",
            )));
        }
        if let Some(audience) = params.audience {
            if audience.is_empty() {
                return Err(SignerError::BadRequest(String::from(
                    "the audience must not be empty",
                )));
            }
        }
        if params.body.len() > self.config.max_body() {
            return Err(SignerError::BodyTooLarge);
        }
        // The path is validated always, not only when it is used to build an
        // audience: the header records it verbatim.
        identity_request_auth::split_path(params.method_path)
            .ok_or_else(|| SignerError::BadRequest(String::from("the method path is malformed")))?;
        self.device.ensure_valid()?;
        let audience = match params.audience {
            Some(audience) => audience.to_string(),
            None => {
                let (service, method) = identity_request_auth::split_path(params.method_path)
                    .ok_or_else(|| {
                        SignerError::BadRequest(String::from("the method path is malformed"))
                    })?;
                let server_id = self.config.server_id.as_deref().ok_or_else(|| {
                    SignerError::BadRequest(String::from(
                        "no audience supplied and no server id configured",
                    ))
                })?;
                identity_request_auth::audience_for(service, method, server_id)
            }
        };
        let signed = identity_request_auth::seal_request(
            self.device.request_signer(),
            &audience,
            params.body_type,
            params.body,
        )
        .map_err(|_| SignerError::Internal(String::from("the request could not be signed")))?;
        let bytes = prost::Message::encode_to_vec(&signed);
        use base64::Engine;
        Ok(SignOutcome {
            header_b64: base64::engine::general_purpose::STANDARD.encode(bytes),
            days_left: self.device.status().days_left,
        })
    }

    pub fn info(&self) -> Info {
        let status = self.device.status();
        Info {
            principal: self.device.principal(),
            version: String::from(env!("CARGO_PKG_VERSION")),
            days_left: status.days_left,
            renewal_due: status.renewal_due,
        }
    }
}
