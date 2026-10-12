//! P-256 key types, principal ids, canonical transcripts and the one
//! signature check for the concordium/structmux identity design
//! (structmux `docs/superpowers/specs/2026-10-11-daemon-mesh-schema-design.md`).
//! Pure: no I/O, no runtime, no key storage. Every primitive comes from
//! `rust_jwk_duo` (re-exported as [`jwk_duo`]); this crate owns byte layouts
//! and validation.

mod error;
pub mod transcripts;

pub use error::{Error, Result};
pub use rust_jwk_duo as jwk_duo;

/// The absolute path to this crate's `proto/` directory, resolved at this
/// crate's compile time so it is right for path and git dependencies alike.
/// A consumer importing `identitycrypto/v1/identity.proto` lists this crate
/// under `[build-dependencies]` and passes this to `compile_protos`.
pub fn proto_include_dir() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/proto")
}

/// Generated from `proto/identitycrypto/v1/identity.proto`. Private: the
/// only public path to these types is [`pb`].
mod proto {
    pub mod identitycrypto {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/identitycrypto.v1.rs"));
            include!(concat!(env!("OUT_DIR"), "/identitycrypto.v1.serde.rs"));
        }
    }
}

/// The wire types. `PublicKey` at the crate root is the validated Rust type;
/// `pb::PublicKey` is the proto.
pub use proto::identitycrypto::v1 as pb;

#[cfg(test)]
mod proto_tests {
    use super::*;

    #[test]
    fn proto_include_dir_points_at_the_real_proto_file() {
        let path = std::path::Path::new(proto_include_dir()).join("identitycrypto/v1/identity.proto");
        assert!(path.exists(), "{} should exist", path.display());
    }
}
