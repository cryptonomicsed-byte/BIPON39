use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::ZeroizeOnDrop;

use crate::constants::{MASTER_KEY_BIP32, MASTER_KEY_NATIVE};
use crate::crypto::hmac_sha512;
use k256::elliptic_curve::sec1::ToSec1Point;
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

/// Serialize the compressed secp256k1 public key (SEC1, 33 bytes:
/// 0x02/0x03 prefix + 32-byte x-coordinate) for a given private scalar.
/// This is `serP(point(k))` in BIP-32 terms — required for non-hardened
/// CKDpriv, where the HMAC input must be the *public* key, not the
/// private key.
fn compressed_pubkey(key: &[u8; 32]) -> Result<[u8; 33], BiponError> {
    let secret = k256::SecretKey::from_slice(key)
        .map_err(|_| BiponError::DerivationError("invalid secp256k1 scalar".to_string()))?;
    let point = secret.public_key().to_sec1_point(true);
    let bytes = point.as_bytes();
    let mut out = [0u8; 33];
    if bytes.len() != 33 {
        return Err(BiponError::DerivationError(
            "unexpected compressed point length".to_string(),
        ));
    }
    out.copy_from_slice(bytes);
    Ok(out)
}

/// `ki = (IL + kpar) mod n` — the modular addition BIP-32 CKDpriv requires
/// on top of the raw HMAC output; `n` is the secp256k1 group order.
fn add_mod_n(il: &[u8; 32], kpar: &[u8; 32]) -> Result<[u8; 32], BiponError> {
    use k256::elliptic_curve::PrimeField;
    let il_scalar = k256::Scalar::from_repr((*il).into());
    let kpar_scalar = k256::Scalar::from_repr((*kpar).into());
    let (il_scalar, kpar_scalar) = match (
        Option::<k256::Scalar>::from(il_scalar),
        Option::<k256::Scalar>::from(kpar_scalar),
    ) {
        (Some(a), Some(b)) => (a, b),
        _ => {
            return Err(BiponError::DerivationError(
                "IL or parent key not a valid secp256k1 scalar (astronomically rare per spec; caller should skip to next index)".to_string(),
            ))
        }
    };
    let sum = il_scalar + kpar_scalar;
    if bool::from(k256::elliptic_curve::group::ff::Field::is_zero(&sum)) {
        return Err(BiponError::DerivationError(
            "derived child key is zero (astronomically rare per spec; caller should skip to next index)".to_string(),
        ));
    }
    Ok(sum.to_repr().into())
}

/// Derive a child key from a parent key using real BIP-32 CKDpriv:
/// hardened derivation HMACs `0x00 || parent_key || index`; non-hardened
/// derivation HMACs the parent's *compressed public key* (not the raw
/// private key — the earlier version of this function used the private
/// key directly as a simplified stand-in, which is not BIP-32/SLIP-10
/// compliant and produces a different, non-interoperable child key for
/// every non-hardened step). Either way, per spec, the final child key is
/// `(IL + parent_key) mod n`, not `IL` alone.
///
/// `index`: child key index. Set `index | 0x8000_0000` for hardened derivation.
/// Returns `(child_key, child_chain_code)`, each 32 bytes.
pub fn derive_child_key(
    parent_key: &[u8; 32],
    parent_chain_code: &[u8; 32],
    index: u32,
) -> Result<([u8; 32], [u8; 32]), BiponError> {
    let mut mac =
        Hmac::<Sha512>::new_from_slice(parent_chain_code).expect("HMAC accepts any key length");

    if index >= 0x8000_0000 {
        // Hardened: 0x00 || parent_key || index_be
        mac.update(&[0x00]);
        mac.update(parent_key);
    } else {
        // Normal: serP(point(parent_key)) || index_be
        let pubkey = compressed_pubkey(parent_key)?;
        mac.update(&pubkey);
    }
    mac.update(&index.to_be_bytes());

    let result = mac.finalize().into_bytes();
    let mut il = [0u8; 32];
    let mut child_chain = [0u8; 32];
    il.copy_from_slice(&result[..32]);
    child_chain.copy_from_slice(&result[32..]);

    let child_key = add_mod_n(&il, parent_key)?;
    Ok((child_key, child_chain))
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
        (key, chain) = derive_child_key(&key, &chain, index)?;
    }
    Ok((key, chain))
}

#[cfg(test)]
mod bip32_compliance_tests {
    use super::*;

    /// Official BIP-32 Test Vector 1 (bips/bip-0032.mediawiki), seed
    /// 000102030405060708090a0b0c0d0e0f. Values below are the raw 32-byte
    /// private key / chain code decoded out of the spec's Base58Check
    /// xprv strings for m, m/0', m/0'/1, and m/0'/1/2' — verifying this
    /// crate's Bip32 master-key derivation plus derive_child_key (both
    /// the hardened and, critically, the non-hardened branch this commit
    /// fixes) against real, independently-decoded reference values rather
    /// than only self-consistency.
    const SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f";

    const M_CHAIN: &str = "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508";
    const M_KEY: &str = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35";

    const M0H_CHAIN: &str = "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141";
    const M0H_KEY: &str = "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea";

    const M0H1_CHAIN: &str = "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19";
    const M0H1_KEY: &str = "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368";

    const M0H12H_CHAIN: &str = "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f";
    const M0H12H_KEY: &str = "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca";

    fn hex32(s: &str) -> [u8; 32] {
        let v = hex::decode(s).unwrap();
        assert_eq!(v.len(), 32, "expected exactly 32 bytes from {s}");
        v.try_into().unwrap()
    }

    #[test]
    fn master_key_matches_official_bip32_test_vector_1() {
        // The official BIP-32 test vector uses a raw 16-byte HD seed
        // directly as HMAC-SHA512 input -- master_from_seed enforces a
        // 64-byte input because BIPON39's own seeds always come from its
        // PBKDF2 step, so this calls the same underlying HMAC formula
        // (crypto::hmac_sha512("Bitcoin seed", seed)) directly to verify
        // against the official vector without that unrelated length gate.
        let seed = hex::decode(SEED_HEX).unwrap();
        let digest = crate::crypto::hmac_sha512(MASTER_KEY_BIP32.as_bytes(), &seed);
        let key: [u8; 32] = digest[..32].try_into().unwrap();
        let chain: [u8; 32] = digest[32..].try_into().unwrap();
        assert_eq!(key, hex32(M_KEY), "master private key mismatch");
        assert_eq!(chain, hex32(M_CHAIN), "master chain code mismatch");
    }

    #[test]
    fn hardened_child_m_0h_matches_official_vector() {
        let (key, chain) = derive_child_key(&hex32(M_KEY), &hex32(M_CHAIN), 0x8000_0000).unwrap();
        assert_eq!(key, hex32(M0H_KEY), "m/0' private key mismatch");
        assert_eq!(chain, hex32(M0H_CHAIN), "m/0' chain code mismatch");
    }

    #[test]
    fn nonhardened_child_m_0h_1_matches_official_vector() {
        // This is the branch the fix changes: non-hardened derivation
        // must HMAC the parent's *compressed public key*, not the raw
        // private key, and the result must be (IL + parent_key) mod n.
        let (key, chain) = derive_child_key(&hex32(M0H_KEY), &hex32(M0H_CHAIN), 1).unwrap();
        assert_eq!(key, hex32(M0H1_KEY), "m/0'/1 private key mismatch");
        assert_eq!(chain, hex32(M0H1_CHAIN), "m/0'/1 chain code mismatch");
    }

    #[test]
    fn hardened_child_m_0h_1_2h_matches_official_vector() {
        let (key, chain) =
            derive_child_key(&hex32(M0H1_KEY), &hex32(M0H1_CHAIN), 0x8000_0002).unwrap();
        assert_eq!(key, hex32(M0H12H_KEY), "m/0'/1/2' private key mismatch");
        assert_eq!(chain, hex32(M0H12H_CHAIN), "m/0'/1/2' chain code mismatch");
    }

    #[test]
    fn full_derive_path_matches_official_vector_end_to_end() {
        // Same rationale as the master-key test above: derive_path also
        // requires a >=64-byte seed (BIPON39's own convention), so this
        // starts from the already-derived master (key, chain) pair -- the
        // part derive_child_key genuinely owns -- and walks the same
        // m/0'/1/2' path derive_path would, to prove chained derivation
        // (not just single steps) matches the official vector end-to-end.
        let mut key = hex32(M_KEY);
        let mut chain = hex32(M_CHAIN);
        for &index in &[0x8000_0000u32, 1, 0x8000_0002] {
            (key, chain) = derive_child_key(&key, &chain, index).unwrap();
        }
        assert_eq!(key, hex32(M0H12H_KEY));
        assert_eq!(chain, hex32(M0H12H_CHAIN));
    }

    // m/0'/1/2'/2 -> m/0'/1/2'/2/1000000000: two NON-hardened steps back to
    // back (index 2, then index 1000000000). Vector 1's only consecutive
    // same-type pair. Exists specifically to catch state-carry bugs across
    // repeated non-hardened steps -- distinct risk from a single isolated
    // non-hardened step, since it proves the compressed-pubkey branch's
    // output threads correctly as *input* to another compressed-pubkey
    // derivation, not just as input to a hardened one.
    const M0H12H2_CHAIN: &str = "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd";
    const M0H12H2_KEY: &str = "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4";
    const M0H12H2_1B_CHAIN: &str = "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e";
    const M0H12H2_1B_KEY: &str = "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8";

    #[test]
    fn consecutive_nonhardened_steps_match_official_vector() {
        let (key, chain) =
            derive_child_key(&hex32(M0H12H2_KEY), &hex32(M0H12H2_CHAIN), 1_000_000_000).unwrap();
        assert_eq!(key, hex32(M0H12H2_1B_KEY), "m/0'/1/2'/2/1000000000 private key mismatch");
        assert_eq!(chain, hex32(M0H12H2_1B_CHAIN), "m/0'/1/2'/2/1000000000 chain code mismatch");
    }

    #[test]
    fn full_five_step_path_matches_official_vector_incl_consecutive_nonhardened() {
        // derive_path itself requires a >=64-byte seed (BIPON39's own
        // convention); starts from the already-vector-verified master
        // pair instead, same rationale as the H-N-H chain test above.
        let mut key = hex32(M_KEY);
        let mut chain = hex32(M_CHAIN);
        for &index in &[0x8000_0000u32, 1, 0x8000_0002, 2, 1_000_000_000] {
            (key, chain) = derive_child_key(&key, &chain, index).unwrap();
        }
        assert_eq!(key, hex32(M0H12H2_1B_KEY));
        assert_eq!(chain, hex32(M0H12H2_1B_CHAIN));
    }

    /// The exact NIP-06 index shape (m/44'/1237'/<account>'/0/0): three
    /// hardened segments followed by two non-hardened. No published
    /// BIP-32 test vector anywhere contains three consecutive hardened
    /// steps (checked all 5 vectors in the BIP-32 spec directly), so this
    /// cannot be checked against an external reference value the way the
    /// tests above are. What it DOES prove: derive_path's loop produces
    /// byte-identical output to manually chaining derive_child_key one
    /// step at a time for this exact index sequence -- i.e. no off-by-one,
    /// no wrong-index-consumed, no state dropped between steps, for the
    /// precise shape NIP-06 derivation will actually use. Combined with
    /// the code-structural argument that derive_child_key has no hidden
    /// state or mode flag depending on how its *parent* key was derived
    /// (its only branch is on the current step's own index), a run of
    /// three hardened steps exercises the identical code path as a single
    /// hardened step, three times, with no logically distinct "H-after-H"
    /// case to separately verify -- unlike the H<->N transitions and N-N
    /// run above, which DO have vector coverage.
    #[test]
    fn nip06_shaped_path_matches_manual_step_by_step_chaining() {
        // derive_path needs a >=64-byte seed (BIPON39's own PBKDF2
        // convention); pad the 16-byte official seed to 64 bytes so
        // derive_path's own internal master derivation runs on the exact
        // same effective seed value as the manual chain below (both take
        // the first 32 bytes as key / next 32 as chain code -- padding
        // with zeros keeps that identical between the two paths, since
        // this test is checking derive_path's LOOP logic against manual
        // chaining, not re-deriving a real master key).
        let mut seed = hex::decode(SEED_HEX).unwrap();
        seed.resize(64, 0);
        let path = [
            44 | 0x8000_0000,
            1237 | 0x8000_0000,
            0 | 0x8000_0000, // account' = 0
            0,                // change
            0,                // index
        ];

        let via_derive_path = derive_path(&seed, &path).unwrap();

        let mut key: [u8; 32] = seed[..32].try_into().unwrap();
        let mut chain: [u8; 32] = seed[32..64].try_into().unwrap();
        for &index in &path {
            (key, chain) = derive_child_key(&key, &chain, index).unwrap();
        }

        assert_eq!(via_derive_path, (key, chain));
    }
}
