//! Ed25519 keypair derivation from a BIPỌ̀N39 master seed.
//!
//! The first 32 bytes of the seed are used as the Ed25519 secret scalar.

use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::error::BiponError;

/// Derive an Ed25519 signing keypair from a seed.
///
/// The first 32 bytes of `seed` are interpreted as the Ed25519 secret scalar.
/// Returns `(SigningKey, VerifyingKey)`.
///
/// # Errors
/// Returns [`BiponError::InvalidSeedLength`] if `seed` is shorter than 32 bytes.
pub fn ed25519_keypair_from_seed(seed: &[u8]) -> Result<(SigningKey, VerifyingKey), BiponError> {
    if seed.len() < 32 {
        return Err(BiponError::InvalidSeedLength(seed.len()));
    }
    let secret_bytes: [u8; 32] = seed[..32]
        .try_into()
        .map_err(|_| BiponError::InvalidSeedLength(seed.len()))?;
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();
    Ok((signing_key, verifying_key))
}

/// Returns the 32-byte Ed25519 public key (verifying key) as a lowercase hex string.
///
/// # Errors
/// Returns [`BiponError::InvalidSeedLength`] if `seed` is shorter than 32 bytes.
pub fn public_key_hex(seed: &[u8]) -> Result<String, BiponError> {
    let (_, vk) = ed25519_keypair_from_seed(seed)?;
    Ok(hex::encode(vk.as_bytes()))
}
