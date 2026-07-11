//! GlyphIndex key domain — GIX-KDF-v1 and GIX-FOLD-v1.
//!
//! BIPỌ̀N39 is the sovereign identity root of the Ọmọ Kọ́dà ecosystem, so the
//! GlyphIndex memory layer derives *all* of its keys here: a 64-byte seed
//! (from [`crate::seed::mnemonic_to_seed`] or any wallet seed) is bound to an
//! owner + purpose context through HKDF-SHA256, yielding disjoint encryption,
//! MAC, and duress (Cloakseed decoy-vault) subkeys.
//!
//! Wire compatibility: byte-for-byte identical to the canonical Python
//! reference in `Vantage/backend/glyph_index.py` — the frozen vectors in the
//! test module below are shared across every language in the ecosystem.
//!
//! ```text
//! subkey = HKDF-SHA256(ikm = seed, salt = "GLYPHINDEX/v1",
//!                      info = label || owner || ":" || purpose)
//! labels: "gix:enc:"  |  "gix:mac:"  |  "gix:duress:"
//! ```

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::BiponError;

/// HKDF salt shared by every GlyphIndex implementation.
pub const HKDF_SALT: &[u8] = b"GLYPHINDEX/v1";
/// PBKDF2-HMAC-SHA256 iteration count for passphrase-derived seeds.
pub const PBKDF2_ITERATIONS: u32 = 600_000;

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

fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    type HmacSha256 = Hmac<Sha256>;
    let mut prk_mac = <HmacSha256 as Mac>::new_from_slice(salt).expect("any key size");
    prk_mac.update(ikm);
    let prk = prk_mac.finalize().into_bytes();
    // Single-block expand (32 bytes = one SHA-256 output).
    let mut okm_mac = <HmacSha256 as Mac>::new_from_slice(&prk).expect("any key size");
    okm_mac.update(info);
    okm_mac.update(&[1u8]);
    okm_mac.finalize().into_bytes().into()
}

/// GIX-KDF-v1 key hierarchy, zeroized on drop.
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
        let enc_info = [enc_label, ctx.as_bytes()].concat();
        let mac_info = [b"gix:mac:".as_slice(), ctx.as_bytes()].concat();
        Ok(Self {
            owner: owner.to_string(),
            purpose: purpose.to_string(),
            enc_key: hkdf_sha256(seed, HKDF_SALT, &enc_info),
            mac_key: hkdf_sha256(seed, HKDF_SALT, &mac_info),
        })
    }

    /// Passphrase fallback (no mnemonic available): PBKDF2-HMAC-SHA256,
    /// 600k iterations, salt = "GIX1" || owner, 64-byte intermediate seed.
    pub fn from_passphrase(
        passphrase: &str,
        owner: &str,
        purpose: &str,
        duress: bool,
    ) -> Result<Self, BiponError> {
        let salt = [b"GIX1".as_slice(), owner.as_bytes()].concat();
        let mut seed = [0u8; 64];
        pbkdf2::pbkdf2_hmac::<Sha256>(
            passphrase.as_bytes(),
            &salt,
            PBKDF2_ITERATIONS,
            &mut seed,
        );
        let keyring = Self::from_seed(&seed, owner, purpose, duress);
        seed.zeroize();
        keyring
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            assert_eq!(glyph_fold(&digest) as u32, *codepoint, "fold mismatch for {text}");
            assert_eq!(odu_link(&digest), (*base, *composed), "odu mismatch for {text}");
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

    #[test]
    fn keyring_matches_canonical_vectors() {
        let seed: Vec<u8> = (0u8..64).collect();
        let k = GlyphKeyring::from_seed(&seed, "0xabc123", "glyph-memory", false).unwrap();
        let kd = GlyphKeyring::from_seed(&seed, "0xabc123", "glyph-memory", true).unwrap();
        assert_eq!(
            hex::encode(k.enc_key),
            "39a5e39cb799872fa548f02b6b60a3876dd085016f389ebee2c3ad03b80512ed"
        );
        assert_eq!(
            hex::encode(k.mac_key),
            "8004b049f4e1f8df5f8afa7b1005c471c2dace0640b2103bc6b78fd5d9808d24"
        );
        assert_eq!(
            hex::encode(kd.enc_key),
            "ad80c87d330d59d6efb8d9283c839e0db8b74f5693ff2ed85bfac8a9401caf3e"
        );
    }

    #[test]
    fn keyring_domains_are_disjoint() {
        let seed: Vec<u8> = (0u8..64).collect();
        let a = GlyphKeyring::from_seed(&seed, "0xabc123", "glyph-memory", false).unwrap();
        let b = GlyphKeyring::from_seed(&seed, "0xother", "glyph-memory", false).unwrap();
        let c = GlyphKeyring::from_seed(&seed, "0xabc123", "other", false).unwrap();
        assert_ne!(a.enc_key, b.enc_key);
        assert_ne!(a.enc_key, c.enc_key);
        assert_ne!(a.enc_key, a.mac_key);
    }

    #[test]
    fn short_seed_rejected() {
        assert!(GlyphKeyring::from_seed(&[0u8; 16], "o", "p", false).is_err());
    }
}
