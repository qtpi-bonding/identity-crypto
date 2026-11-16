//! The `identity-enrol` tool: `identity-enrol enrol --machine-dir D --key K --dir X`
//! records the identity directory `X` under the service key `K` in the machine
//! directory `D`'s enrolment index, through [`EnrolmentIndex::enrol`]. It never
//! reads a key file itself and never prints key material.
//!
//! Enrolling the same entry again is a no-op (exit 0). A refusal is a coded
//! line on stderr, `identity.keyfile.enrol.<code>: <message>`, and exit 1.
//! `--owner P` names the owner principal the
//! index refuses to enrol; without one no principal is refused as the owner.

use crate::{enrolment_for, Enrolment, EnrolmentIndex, KeyfileError, MachineDir};
use identity_crypto::PrincipalId;
use std::path::PathBuf;

/// What a successful run did.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The index now holds the entry.
    Enrolled,
    /// The index already held exactly this entry; nothing was written.
    Unchanged,
}

/// Why a run failed, with a stable code.
#[derive(Debug, thiserror::Error)]
pub enum EnrolCliError {
    #[error("{0}")]
    Usage(String),
    #[error("a service key is required: pass --key")]
    MissingKey,
    #[error("{0}")]
    Keyfile(#[from] KeyfileError),
}

impl EnrolCliError {
    /// The stable code, in the `identity.keyfile.enrol` namespace.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Usage(_) => "identity.keyfile.enrol.usage",
            Self::MissingKey => "identity.keyfile.enrol.missing_key",
            Self::Keyfile(KeyfileError::InvalidEnrolmentKey(_)) => {
                "identity.keyfile.enrol.invalid_key"
            }
            Self::Keyfile(KeyfileError::OwnerEnrolment) => "identity.keyfile.enrol.owner_principal",
            Self::Keyfile(KeyfileError::EnrolmentMismatch { .. }) => {
                "identity.keyfile.enrol.mismatch"
            }
            Self::Keyfile(_) => "identity.keyfile.enrol.failed",
        }
    }
}

struct Args {
    machine_dir: PathBuf,
    key: Option<String>,
    dir: PathBuf,
    owner: Option<String>,
    endpoint: Option<String>,
}

fn parse(args: &[String], owner_env: Option<String>) -> Result<Args, EnrolCliError> {
    let usage = |m: &str| EnrolCliError::Usage(m.to_string());
    let mut it = args.iter();
    match it.next().map(String::as_str) {
        Some("enrol") => {}
        _ => {
            return Err(usage(
                "usage: identity-enrol enrol --machine-dir D --key K --dir X",
            ))
        }
    }
    let (mut machine_dir, mut key, mut dir, mut owner, mut endpoint) =
        (None, None, None, owner_env, None);
    while let Some(flag) = it.next() {
        let mut value = |name: &str| {
            it.next()
                .cloned()
                .ok_or_else(|| EnrolCliError::Usage(format!("{name} needs a value")))
        };
        match flag.as_str() {
            "--machine-dir" => machine_dir = Some(PathBuf::from(value("--machine-dir")?)),
            "--key" => key = Some(value("--key")?),
            "--dir" => dir = Some(PathBuf::from(value("--dir")?)),
            "--owner" => owner = Some(value("--owner")?),
            "--endpoint" => endpoint = Some(value("--endpoint")?),
            other => return Err(EnrolCliError::Usage(format!("unknown argument {other}"))),
        }
    }
    Ok(Args {
        machine_dir: machine_dir.ok_or_else(|| usage("--machine-dir is required"))?,
        key,
        dir: dir.ok_or_else(|| usage("--dir is required"))?,
        owner,
        endpoint,
    })
}

/// Runs the tool with `args` (without the program name). `owner_env` is the
/// owner default, when the caller has one (the binary passes none).
pub fn run(args: &[String], owner_env: Option<String>) -> Result<Outcome, EnrolCliError> {
    let args = parse(args, owner_env)?;
    let key = args.key.ok_or(EnrolCliError::MissingKey)?;
    let machine = MachineDir::at(args.machine_dir);
    let entry = enrolment_for(&args.dir, args.endpoint)?;
    let owner = match args.owner {
        Some(text) => PrincipalId::parse_canonical(&text)
            .map_err(|_| EnrolCliError::Usage("--owner is not a canonical principal".into()))?,
        // No owner named: a fresh principal that no entry can equal.
        None => identity_crypto::principal_id(&crate::generate()),
    };
    if already_enrolled(&machine, &key, &entry)? {
        return Ok(Outcome::Unchanged);
    }
    EnrolmentIndex::enrol(&machine, &key, entry, &owner)?;
    Ok(Outcome::Enrolled)
}

fn already_enrolled(
    machine: &MachineDir,
    key: &str,
    entry: &Enrolment,
) -> Result<bool, KeyfileError> {
    let index = EnrolmentIndex::read(machine)?;
    let found = index.services().any(|(k, e)| k == key && e == entry);
    Ok(found)
}
