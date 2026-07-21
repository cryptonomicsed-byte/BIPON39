//! GIX-KDF-v1 — the GlyphIndex key hierarchy rooted in BIPỌ̀N39 identity.
//!
//! This is the identity-root leg of the ecosystem GlyphIndex contract
//! (spec: OSOVM/GLYPHINDEX_SPEC.md; canonical reference implementation:
//! Vantage/backend/glyph_index.py). A sovereign seed — normally
//! [`crate::seed::mnemonic_to_seed`] output — expands via HKDF-SHA256
//! (salt `"GLYPHINDEX/v1"`) into per-owner, per-purpose subkeys:
//!
//! ```text
//! enc    key: info = "gix:enc:"    + owner + ":" + purpose
//! mac    key: info = "gix:mac:"    + owner + ":" + purpose
//! duress key: info = "gix:duress:" + owner + ":" + purpose
//! ```
//!
//! The duress key shares no material with the primary enc key: a coerced
//! passphrase opens a disjoint decoy vault (Cloakseed panic mode). The
//! passphrase fallback is PBKDF2-HMAC-SHA256 with salt `"GIX1" + owner`,
//! 600,000 iterations, 64 bytes — matching every other leg byte-for-byte
//! (frozen vectors in the tests below).

use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::BiponError;

/// HKDF salt fixed by the spec.
pub const GIX_HKDF_SALT: &[u8] = b"GLYPHINDEX/v1";
/// PBKDF2 iterations for the passphrase fallback.
pub const GIX_PBKDF2_ITERATIONS: u32 = 600_000;
/// Default derivation purpose.
pub const GIX_DEFAULT_PURPOSE: &str = "glyph-memory";

type HmacSha256 = Hmac<Sha256>;

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// HKDF-SHA256 (extract + expand) producing `N` bytes.
fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let prk = hmac_sha256(salt, ikm);
    // One expand block suffices for 32-byte output.
    let mut block = Vec::with_capacity(info.len() + 1);
    block.extend_from_slice(info);
    block.push(1u8);
    hmac_sha256(&prk, &block)
}

/// GIX-KDF-v1 key hierarchy bound to an owner (wallet) and purpose.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct GlyphKeyring {
    #[zeroize(skip)]
    pub owner: String,
    #[zeroize(skip)]
    pub purpose: String,
    pub enc_key: [u8; 32],
    pub mac_key: [u8; 32],
}

impl GlyphKeyring {
    /// Derive from a sovereign master seed (>= 32 bytes).
    pub fn from_seed(
        seed: &[u8],
        owner: &str,
        purpose: &str,
        duress: bool,
    ) -> Result<Self, BiponError> {
        if seed.len() < 32 {
            return Err(BiponError::InvalidSeedLength(seed.len()));
        }
        let ctx = format!("{owner}:{purpose}");
        let enc_label: &[u8] = if duress { b"gix:duress:" } else { b"gix:enc:" };
        let mut enc_info = enc_label.to_vec();
        enc_info.extend_from_slice(ctx.as_bytes());
        let mut mac_info = b"gix:mac:".to_vec();
        mac_info.extend_from_slice(ctx.as_bytes());
        Ok(Self {
            owner: owner.to_string(),
            purpose: purpose.to_string(),
            enc_key: hkdf_sha256(seed, GIX_HKDF_SALT, &enc_info),
            mac_key: hkdf_sha256(seed, GIX_HKDF_SALT, &mac_info),
        })
    }

    /// Passphrase fallback: PBKDF2-HMAC-SHA256, salt `"GIX1" + owner`,
    /// 600,000 iterations, 64-byte intermediate seed.
    pub fn from_passphrase(
        passphrase: &str,
        owner: &str,
        purpose: &str,
        duress: bool,
    ) -> Result<Self, BiponError> {
        let mut salt = b"GIX1".to_vec();
        salt.extend_from_slice(owner.as_bytes());
        let mut seed = Zeroizing::new(vec![0u8; 64]);
        pbkdf2_hmac::<Sha256>(
            passphrase.as_bytes(),
            &salt,
            GIX_PBKDF2_ITERATIONS,
            &mut seed,
        );
        Self::from_seed(&seed, owner, purpose, duress)
    }

    /// Derive directly from a BIPỌ̀N39 mnemonic — the identity-root path.
    pub fn from_mnemonic(
        words: &[&str],
        passphrase: &str,
        owner: &str,
        purpose: &str,
        duress: bool,
    ) -> Result<Self, BiponError> {
        let seed = crate::seed::mnemonic_to_seed(words, passphrase)?;
        Self::from_seed(&seed, owner, purpose, duress)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Frozen cross-language vectors (OSOVM/GLYPHINDEX_SPEC.md §6):
    // seed = bytes 0x00..0x3f, owner "0xabc123", purpose "glyph-memory".
    // Asserted identically by Vantage (Python) and mnemopi (TypeScript).
    const FROZEN_ENC: &str = "39a5e39cb799872fa548f02b6b60a3876dd085016f389ebee2c3ad03b80512ed";
    const FROZEN_MAC: &str = "8004b049f4e1f8df5f8afa7b1005c471c2dace0640b2103bc6b78fd5d9808d24";
    const FROZEN_DURESS: &str = "ad80c87d330d59d6efb8d9283c839e0db8b74f5693ff2ed85bfac8a9401caf3e";

    fn frozen_seed() -> Vec<u8> {
        (0u8..64).collect()
    }

    #[test]
    fn derives_frozen_key_vectors() {
        let keyring =
            GlyphKeyring::from_seed(&frozen_seed(), "0xabc123", GIX_DEFAULT_PURPOSE, false)
                .unwrap();
        assert_eq!(hex::encode(keyring.enc_key), FROZEN_ENC);
        assert_eq!(hex::encode(keyring.mac_key), FROZEN_MAC);

        let duress =
            GlyphKeyring::from_seed(&frozen_seed(), "0xabc123", GIX_DEFAULT_PURPOSE, true).unwrap();
        assert_eq!(hex::encode(duress.enc_key), FROZEN_DURESS);
        // Duress shares the MAC lineage but never the enc key.
        assert_eq!(hex::encode(duress.mac_key), FROZEN_MAC);
        assert_ne!(duress.enc_key, keyring.enc_key);
    }

    #[test]
    fn owner_and_purpose_domain_separate() {
        let a = GlyphKeyring::from_seed(&frozen_seed(), "0xabc123", "glyph-memory", false).unwrap();
        let b = GlyphKeyring::from_seed(&frozen_seed(), "0xother", "glyph-memory", false).unwrap();
        let c =
            GlyphKeyring::from_seed(&frozen_seed(), "0xabc123", "other-purpose", false).unwrap();
        assert_ne!(a.enc_key, b.enc_key);
        assert_ne!(a.enc_key, c.enc_key);
    }

    #[test]
    fn passphrase_path_is_deterministic_and_rejects_short_seeds() {
        let x =
            GlyphKeyring::from_passphrase("àṣẹ", "0xabc123", GIX_DEFAULT_PURPOSE, false).unwrap();
        let y =
            GlyphKeyring::from_passphrase("àṣẹ", "0xabc123", GIX_DEFAULT_PURPOSE, false).unwrap();
        assert_eq!(x.enc_key, y.enc_key);
        assert!(
            GlyphKeyring::from_seed(&[0u8; 16], "0xabc123", GIX_DEFAULT_PURPOSE, false).is_err()
        );
    }

    #[test]
    fn mnemonic_root_matches_seed_root() {
        let words: Vec<&str> = vec!["Àṣẹ"; 24];
        let via_mnemonic =
            GlyphKeyring::from_mnemonic(&words, "", "0xabc123", GIX_DEFAULT_PURPOSE, false)
                .unwrap();
        let seed = crate::seed::mnemonic_to_seed(&words, "").unwrap();
        let via_seed =
            GlyphKeyring::from_seed(&seed, "0xabc123", GIX_DEFAULT_PURPOSE, false).unwrap();
        assert_eq!(via_mnemonic.enc_key, via_seed.enc_key);
        assert_eq!(via_mnemonic.mac_key, via_seed.mac_key);
    }
}
