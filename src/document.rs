//! Signing and checking documents: the builder for a `SignedDocument` that
//! `verify_signed_document` accepts, the document id, and the time window check.

use crate::authority::AuthorityChain;
use crate::transcripts::signed_document_transcript;
use crate::{pb, Error, Result, Signer, VerifiedDocument, SKEW_SECONDS};
use sha2::{Digest, Sha256};

/// The fields a caller chooses for a new document. `expires_at` of `i64::MAX` means never.
pub struct DocumentDraft<'a> {
    pub document_type: &'a str,
    pub version: u64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub body: &'a [u8],
}

/// Signs `draft` as `authority`'s head root. `signer` must be that head key;
/// otherwise the result is `NotCurrentRoot`. Callers using a prompting
/// signer should unlock it before choosing `issued_at`; this function builds
/// the document and then calls `sign_for`.
pub fn sign_document<S: Signer + ?Sized>(
    signer: &S,
    authority: &AuthorityChain,
    draft: DocumentDraft<'_>,
) -> Result<pb::SignedDocument> {
    let signing = signer.public_key();
    if &signing != authority.head() {
        return Err(Error::NotCurrentRoot);
    }
    if draft.expires_at == 0 || draft.expires_at <= draft.issued_at {
        return Err(Error::InvalidField {
            field: "expires_at_unix_seconds",
            reason: "must be after issued_at; 0 is not an expiry",
        });
    }
    let mut document = pb::SignedDocument {
        signer_genesis: Some(pb::PublicKey::from(authority.principal().genesis())),
        signing: Some(pb::PublicKey::from(&signing)),
        document_type: draft.document_type.to_string(),
        version: draft.version,
        issued_at_unix_seconds: draft.issued_at,
        expires_at_unix_seconds: draft.expires_at,
        body: draft.body.to_vec(),
        signature: vec![],
        signer_rotations: authority.rotations().to_vec(),
    };
    let transcript = signed_document_transcript(&document)?;
    let reason = format!("sign {} version {}", draft.document_type, draft.version);
    let signature = signer
        .sign_for(&transcript, &reason)
        .map_err(Error::Signer)?;
    document.signature = signature.into_bytes();
    Ok(document)
}

/// The document id: SHA-256 of its signed transcript. Equal to `VerifiedDocument::id`.
pub fn document_id(document: &pb::SignedDocument) -> Result<[u8; 32]> {
    let transcript = signed_document_transcript(document)?;
    let mut id = [0u8; 32];
    id.copy_from_slice(&Sha256::digest(&transcript));
    Ok(id)
}

/// Checks the document's validity window at `now`. A document issued more
/// than `SKEW_SECONDS` in the future is not yet valid; it expires at `expires_at`
/// (exclusive).
pub fn check_document_time(document: &VerifiedDocument, now: i64) -> Result<()> {
    if document.issued_at() > now.saturating_add(SKEW_SECONDS) {
        return Err(Error::NotYetValid("document"));
    }
    if now >= document.expires_at() {
        return Err(Error::Expired("document"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::testkit::{Principal, DOC_TYPE, T0};
    use crate::transcripts::signed_document_transcript;
    use crate::{
        check_document_time, document_id, now_unix, sign_document, verify_signed_document,
        AuthorityChain, DocumentDraft, Error, VerifiedDocument, SKEW_SECONDS,
    };
    use sha2::{Digest, Sha256};

    fn draft(version: u64, body: &[u8]) -> DocumentDraft<'_> {
        DocumentDraft {
            document_type: DOC_TYPE,
            version,
            issued_at: now_unix(),
            expires_at: i64::MAX,
            body,
        }
    }

    fn verified(p: &Principal, issued_at: i64, expires_at: i64) -> VerifiedDocument {
        let chain = AuthorityChain::from_rotations(p.genesis(), &p.rotations).unwrap();
        let d = DocumentDraft {
            document_type: DOC_TYPE,
            version: 1,
            issued_at,
            expires_at,
            body: &[1],
        };
        let doc = sign_document(p.root(), &chain, d).unwrap();
        verify_signed_document(&doc, DOC_TYPE, &chain).unwrap()
    }

    #[test]
    fn sign_document_round_trips_through_verify_signed_document() {
        let mut p = Principal::new();
        let genesis_chain = AuthorityChain::genesis(p.genesis());
        let doc = sign_document(p.root(), &genesis_chain, draft(3, &[9])).unwrap();
        assert!(doc.signer_rotations.is_empty());
        let v = verify_signed_document(&doc, DOC_TYPE, &genesis_chain).unwrap();
        assert_eq!((v.version(), v.body()), (3, &[9u8][..]));
        assert_eq!(v.authority(), p.id());

        p.rotate(T0);
        let rotated = AuthorityChain::from_rotations(p.genesis(), &p.rotations).unwrap();
        let doc = sign_document(p.root(), &rotated, draft(3, &[9])).unwrap();
        assert_eq!(doc.signer_rotations, p.rotations);
        let v = verify_signed_document(&doc, DOC_TYPE, &rotated).unwrap();
        assert_eq!(
            (v.version(), v.body(), v.document_type()),
            (3, &[9u8][..], DOC_TYPE)
        );
        assert_eq!(v.expires_at(), i64::MAX);
        assert_eq!(v.authority_chain().head(), &p.root().public());
    }

    #[test]
    fn sign_document_refuses_a_non_head_signer() {
        let mut p = Principal::new();
        p.rotate(T0);
        let rotated = AuthorityChain::from_rotations(p.genesis(), &p.rotations).unwrap();
        let err = sign_document(p.root_at(0), &rotated, draft(1, &[])).unwrap_err();
        assert_eq!(err, Error::NotCurrentRoot);
        assert!(sign_document(p.root(), &rotated, draft(1, &[])).is_ok());
    }

    #[test]
    fn document_id_equals_verified_id() {
        let p = Principal::new();
        let chain = AuthorityChain::genesis(p.genesis());
        let doc = sign_document(p.root(), &chain, draft(1, &[1, 2, 3])).unwrap();
        let v = verify_signed_document(&doc, DOC_TYPE, &chain).unwrap();
        assert_eq!(&document_id(&doc).unwrap(), v.id());
    }

    #[test]
    fn document_id_is_sha256_of_the_transcript() {
        let p = Principal::new();
        let chain = AuthorityChain::genesis(p.genesis());
        let doc = sign_document(p.root(), &chain, draft(1, &[1, 2, 3])).unwrap();
        let transcript = signed_document_transcript(&doc).unwrap();
        let want: [u8; 32] = Sha256::digest(&transcript).into();
        assert_eq!(document_id(&doc).unwrap(), want);
        let v = verify_signed_document(&doc, DOC_TYPE, &chain).unwrap();
        assert_eq!(v.id(), &want);
    }

    #[test]
    fn check_document_time_skew_edge() {
        let p = Principal::new();
        let now = T0 + 1000;
        let ok = verified(&p, now + SKEW_SECONDS, i64::MAX);
        assert_eq!(SKEW_SECONDS, 30);
        assert!(check_document_time(&ok, now).is_ok());
        let early = verified(&p, now + SKEW_SECONDS + 1, i64::MAX);
        assert_eq!(
            check_document_time(&early, now).unwrap_err(),
            Error::NotYetValid("document")
        );
    }

    #[test]
    fn check_document_time_expiry_exclusive() {
        let p = Principal::new();
        let expires_at = T0 + 5000;
        let v = verified(&p, T0, expires_at);
        assert!(check_document_time(&v, expires_at - 1).is_ok());
        assert_eq!(
            check_document_time(&v, expires_at).unwrap_err(),
            Error::Expired("document")
        );
        assert_eq!(
            check_document_time(&v, expires_at + 1).unwrap_err(),
            Error::Expired("document")
        );
        let never = verified(&p, T0, i64::MAX);
        assert!(check_document_time(&never, i64::MAX - 1).is_ok());
    }

    #[test]
    fn sign_document_refuses_zero_and_backwards_expiry() {
        let p = Principal::new();
        let chain = AuthorityChain::genesis(p.genesis());
        let bad = |issued_at: i64, expires_at: i64| {
            let d = DocumentDraft {
                document_type: DOC_TYPE,
                version: 1,
                issued_at,
                expires_at,
                body: &[],
            };
            sign_document(p.root(), &chain, d)
        };
        for (issued, expires) in [(T0, 0), (T0, T0 - 1), (T0, T0)] {
            assert!(
                matches!(
                    bad(issued, expires),
                    Err(Error::InvalidField {
                        field: "expires_at_unix_seconds",
                        ..
                    })
                ),
                "issued {issued} expires {expires}"
            );
        }
        assert!(bad(T0, T0 + 1).is_ok());
    }
}
