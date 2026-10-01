//! Typed profile drafts and exact signed publications. Guard owns admission;
//! Envelope owns encryption; Vault owns custody and atomic persistence.
mod draft;
mod publication;
pub use draft::*;
pub use publication::*;

/// Value-free refusal, suitable for device doors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Malformed, stale or mismatched context.
    Invalid,
    /// Input exceeds a documented bound.
    Limit,
    /// Current schema or personal rules refuse the draft.
    Schema,
    /// Current signed credential/pins/policy/device do not admit it.
    Admission,
    /// A signing, entropy, wrapping or encryption capability failed.
    Crypto,
    /// Compression or bounded expansion failed.
    Codec,
    /// Durable storage refused or has an uncertain outcome; reconcile before retry.
    Storage,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "profile: {self:?}")
    }
}
impl std::error::Error for Error {}
/// All owner payloads and signed transcripts are bounded before parsing.
pub const MAX_PROFILE_BYTES: usize = 256 * 1024;
/// Opaque Mesh descriptor limit; no IP/address interpretation is performed here.
pub const MAX_REACHABILITY_BYTES: usize = 4096;

pub(crate) fn encode(value: &impl serde::Serialize) -> Result<Vec<u8>, Error> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::Invalid)?;
    if bytes.len() > MAX_PROFILE_BYTES {
        return Err(Error::Limit);
    }
    Ok(bytes)
}
pub(crate) fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    if bytes.len() > MAX_PROFILE_BYTES {
        return Err(Error::Limit);
    }
    serde_json::from_slice(bytes).map_err(|_| Error::Invalid)
}
