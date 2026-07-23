//! GlyphIndex key domain — GIX-KDF-v1 and GIX-FOLD-v1.
//!
//! This is the identity-root leg of the ecosystem GlyphIndex contract (spec:
//! OSOVM/GLYPHINDEX_SPEC.md; canonical reference implementation:
//! Vantage/backend/glyph_index.py). BIPỌ̀N39 is the sovereign identity root of
//! the Ọmọ Kọ́dà ecosystem, so the GlyphIndex memory layer derives *all* of its
//! keys here: a sovereign seed (normally [`crate::seed::mnemonic_to_seed`]
//! output, or any wallet seed) expands via HKDF-SHA256 (salt
//! `"GLYPHINDEX/v1"`) into per-owner, per-purpose subkeys:
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
//! 600,000 iterations, 64 bytes.
//!
//! Wire compatibility: byte-for-byte identical to the canonical Python
//! reference in `Vantage/backend/glyph_index.py` — the frozen vectors in the
//! test module below are shared across every language in the ecosystem.
//!
//! GIX-FOLD-v1 (`content_hash`/`glyph_fold`/`odu_link`) is the companion
//! addressing scheme: any chunk of content gets a canonical SHA-256 address,
//! folded onto one displayable BMP glyph (a display alias, never the real
//! address) and linked into the Digital Calabash's base/composed Odù space.

use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::BiponError;

/// HKDF salt fixed by the spec, shared by every GlyphIndex implementation.
pub const GIX_HKDF_SALT: &[u8] = b"GLYPHINDEX/v1";
/// PBKDF2-HMAC-SHA256 iterations for the passphrase fallback.
pub const GIX_PBKDF2_ITERATIONS: u32 = 600_000;
/// Default derivation purpose.
pub const GIX_DEFAULT_PURPOSE: &str = "glyph-memory";

type HmacSha256 = Hmac<Sha256>;

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// HKDF-SHA256 (extract + expand) producing 32 bytes.
fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let prk = hmac_sha256(salt, ikm);
    // One expand block suffices for 32-byte output.
    let mut block = Vec::with_capacity(info.len() + 1);
    block.extend_from_slice(info);
    block.push(1u8);
    hmac_sha256(&prk, &block)
}

// ─── GIX-FOLD-v1: content addressing ───────────────────────────────────────

/// GIX-FOLD-v1 code-point ranges: (start, count). Surrogates, controls, and
/// BMP noncharacters are excluded so a folded glyph is always a valid,
/// encodable `char` in every language runtime.
const FOLD_RANGES: [(u32, u32); 3] = [
    (0x0020, 0xD7FF - 0x0020 + 1), // 55,264
    (0xE000, 0xFDCF - 0xE000 + 1), //  7,632
    (0xFDF0, 0xFFFD - 0xFDF0 + 1), //    526
];

fn fold_total() -> u32 {
    FOLD_RANGES.iter().map(|(_, c)| c).sum()
}

/// SHA-256 of the chunk — the canonical (collision-free) glyph address.
pub fn content_hash(text: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(text.as_bytes());
    h.finalize().into()
}

/// GIX-FOLD-v1: fold a 32-byte content hash onto one valid BMP glyph.
/// The glyph is a display alias; the hash remains the true address.
pub fn glyph_fold(digest: &[u8; 32]) -> char {
    // n mod total, computed incrementally so we never need a big-int dep.
    let total = fold_total() as u64;
    let mut rem: u64 = 0;
    for byte in digest {
        rem = (rem << 8 | *byte as u64) % total;
    }
    let mut idx = rem as u32;
    for (start, count) in FOLD_RANGES {
        if idx < count {
            // Safe by construction: every point in FOLD_RANGES is a valid char.
            return char::from_u32(start + idx).expect("fold ranges exclude invalid points");
        }
        idx -= count;
    }
    unreachable!("idx < fold_total by construction")
}

/// Digital Calabash linkage: (base Odù 0..=255, composed Odù 0..=65535).
pub fn odu_link(digest: &[u8; 32]) -> (u8, u16) {
    (digest[0], (digest[0] as u16) << 8 | digest[1] as u16)
}

// ─── GIX-KDF-v1: key hierarchy ──────────────────────────────────────────────

/// GIX-KDF-v1 key hierarchy bound to an owner (wallet) and purpose, zeroized
/// on drop.
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
    /// Derive from a sovereign master seed (≥32 bytes; BIPỌ̀N39 seeds are 64).
    /// `duress = true` yields the Cloakseed decoy-vault keyring, which shares
    /// no key material with the primary vault.
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

    /// Passphrase fallback (no mnemonic available): PBKDF2-HMAC-SHA256, salt
    /// `"GIX1" + owner`, 600,000 iterations, 64-byte intermediate seed.
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

    /// Frozen cross-language vectors (generated by the canonical Python
    /// reference implementation in Vantage). Do not regenerate casually —
    /// every repo in the ecosystem embeds these same values.
    const FOLD_VECTORS: &[(&str, &str, u32, u8, u16)] = &[
        (
            "Àṣẹ",
            "e32866670f27c0ccaeda5facc74fcfc3f8c17b18bcae2fb9dc150d91c601db1b",
            21841,
            227,
            58152,
        ),
        (
            "hello",
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            23636,
            44,
            11506,
        ),
        (
            "GlyphIndex",
            "44bb6336e45b2f5daf764930ac1d1f2798ad92c34048f0395686ac4509a0a7ec",
            13726,
            68,
            17595,
        ),
        (
            "😊🚀 Unicode test",
            "bdf299182a61f04e31c6445f96a6a68d927d7e6cd9c56f883c8f1cc7cfac8683",
            64591,
            189,
            48626,
        ),
        (
            "Ọ̀rúnmìlà",
            "cca6a38cbd2874b7f2b4809ba11ee5177660c4ad5fb4851991414722729fd523",
            17963,
            204,
            52390,
        ),
    ];

    #[test]
    fn fold_matches_canonical_vectors() {
        for (text, cid, codepoint, base, composed) in FOLD_VECTORS {
            let digest = content_hash(text);
            assert_eq!(hex::encode(digest), *cid, "hash mismatch for {text}");
            assert_eq!(
                glyph_fold(&digest) as u32,
                *codepoint,
                "fold mismatch for {text}"
            );
            assert_eq!(
                odu_link(&digest),
                (*base, *composed),
                "odu mismatch for {text}"
            );
        }
    }

    #[test]
    fn fold_never_produces_invalid_scalar() {
        // char::from_u32 inside glyph_fold would panic on a surrogate; walking
        // many digests exercises all three ranges.
        for i in 0..5000u32 {
            let digest = content_hash(&format!("probe-{i}"));
            let cp = glyph_fold(&digest) as u32;
            assert!((0x20..=0xFFFD).contains(&cp));
            assert!(!(0xFDD0..=0xFDEF).contains(&cp));
        }
    }
}
