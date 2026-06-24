//! # bipon39
//!
//! BIPỌ̀N39 — Sovereign Base-256 mnemonic library for the Ọmọ Kọ́dà ecosystem.
//!
//! Provides entropy-to-mnemonic encoding, mnemonic-to-seed derivation,
//! master key derivation, Ed25519 keypair generation, BIP-32-style child key
//! derivation, and Ifáscript metadata over a 256-token
//! culturally-rooted Yorùbá wordlist.

pub mod constants;
pub mod crypto;
pub mod derivation;
pub mod display;
pub mod dualmode;
pub mod error;
pub mod identity;
pub mod ifascript;
pub mod mnemonic;
pub mod seed;
pub mod wordlist;

pub use constants::{
    BITS_PER_WORD, ENTROPY_WORD_TABLE, MASTER_KEY_BIP32, MASTER_KEY_NATIVE, MERKLE_ROOT,
    PBKDF2_ITERATIONS, PBKDF2_OUTPUT_BYTES, PBKDF2_PASSPHRASE_PREFIX, PBKDF2_SALT_BASE,
    WORDLIST_SIZE,
};
pub use crypto::{compute_wordlist_merkle_root, ct_eq, hmac_sha512, sha256, sha256_merkle_root};
pub use derivation::{derive_child_key, derive_path, master_from_seed, DerivationMode, MasterKey};
pub use display::{
    canonical_for_encoding, canonical_to_encoding, encoding_for_canonical, format_numbered,
    format_numbered_canonical, mnemonic_to_canonical,
};
pub use dualmode::{
    decode_2048, encode_2048, entropy_to_mnemonic_2048, mnemonic_2048_to_entropy, SUBTONES,
};
pub use error::BiponError;
pub use identity::{ed25519_keypair_from_seed, public_key_hex};
pub use ifascript::{
    dominant_macro, elemental_signature, entries_for, macro_distribution, odu_primary_index,
    personality_profile, ritual_cue_for, ElementalVector, Macro, MacroDistribution,
    PersonalityProfile,
};
pub use mnemonic::{
    entropy_to_mnemonic, join_mnemonic, mnemonic_to_entropy, split_mnemonic, validate_mnemonic,
};
pub use seed::mnemonic_to_seed;
pub use wordlist::{
    all_encoding_tokens, entries_for_macro, entry_by_canonical, entry_by_encoding, entry_by_index,
    index_of_encoding, lookup_meta, verify_wordlist_integrity, TokenMeta, WordlistEntry,
};
