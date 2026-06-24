use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::ZeroizeOnDrop;

use crate::constants::{MASTER_KEY_BIP32, MASTER_KEY_NATIVE};
use crate::crypto::hmac_sha512;
use crate::error::BiponError;

/// Master key derivation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivationMode {
    /// Native BIPỌ̀N39 derivation.
    Native,
    /// BIP-32 compatible derivation.
    Bip32,
}

impl DerivationMode {
    fn key_string(self) -> &'static str {
        match self {
            DerivationMode::Native => MASTER_KEY_NATIVE,
            DerivationMode::Bip32 => MASTER_KEY_BIP32,
        }
    }
}

/// Master private key and chain code derived from a 64-byte seed.
#[derive(ZeroizeOnDrop)]
pub struct MasterKey {
    /// Private key material (IL).
    pub key: [u8; 32],
    /// Chain code material (IR).
    pub chain_code: [u8; 32],
}

impl MasterKey {
    /// Hex-encode the private key.
    pub fn key_hex(&self) -> String {
        hex::encode(self.key)
    }

    /// Hex-encode the chain code.
    pub fn chain_code_hex(&self) -> String {
        hex::encode(self.chain_code)
    }
}

/// Derive a master key from a 64-byte seed.
pub fn master_from_seed(seed: &[u8], mode: DerivationMode) -> Result<MasterKey, BiponError> {
    if seed.len() != 64 {
        return Err(BiponError::DerivationError(format!(
            "seed must be 64 bytes, got {}",
            seed.len()
        )));
    }
    let digest = hmac_sha512(mode.key_string().as_bytes(), seed);
    let mut key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    key.copy_from_slice(&digest[..32]);
    chain_code.copy_from_slice(&digest[32..]);
    Ok(MasterKey { key, chain_code })
}

/// Derive a child key from a parent key using HMAC-SHA512 (BIP-32 CKDpriv style).
///
/// `index`: child key index.  Set `index | 0x8000_0000` for hardened derivation.
/// Returns `(child_key, child_chain_code)`, each 32 bytes.
pub fn derive_child_key(
    parent_key: &[u8; 32],
    parent_chain_code: &[u8; 32],
    index: u32,
) -> ([u8; 32], [u8; 32]) {
    let mut mac = Hmac::<Sha512>::new_from_slice(parent_chain_code)
        .expect("HMAC accepts any key length");

    if index >= 0x8000_0000 {
        // Hardened: 0x00 || parent_key || index_be
        mac.update(&[0x00]);
        mac.update(parent_key);
    } else {
        // Normal: parent_key || index_be  (simplified — uses raw key as stand-in for pubkey)
        mac.update(parent_key);
    }
    mac.update(&index.to_be_bytes());

    let result = mac.finalize().into_bytes();
    let mut child_key = [0u8; 32];
    let mut child_chain = [0u8; 32];
    child_key.copy_from_slice(&result[..32]);
    child_chain.copy_from_slice(&result[32..]);
    (child_key, child_chain)
}

/// Derive a key at a BIP-32-style path, e.g. `&[44 | 0x8000_0000, 0x8000_0000, 0x8000_0000, 0, 0]`.
///
/// `seed` must be at least 64 bytes; the first 32 bytes become the root key and
/// bytes 32–63 become the root chain code.
/// Returns `(derived_key, derived_chain_code)`, each 32 bytes.
pub fn derive_path(seed: &[u8], path: &[u32]) -> Result<([u8; 32], [u8; 32]), BiponError> {
    if seed.len() < 64 {
        return Err(BiponError::InvalidSeedLength(seed.len()));
    }
    let mut key: [u8; 32] = seed[..32]
        .try_into()
        .map_err(|_| BiponError::InvalidSeedLength(seed.len()))?;
    let mut chain: [u8; 32] = seed[32..64]
        .try_into()
        .map_err(|_| BiponError::InvalidSeedLength(seed.len()))?;
    for &index in path {
        (key, chain) = derive_child_key(&key, &chain, index);
    }
    Ok((key, chain))
}
