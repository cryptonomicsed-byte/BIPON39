use bipon39::{
    decode_2048, encode_2048, entropy_to_mnemonic, entropy_to_mnemonic_2048,
    mnemonic_2048_to_entropy, mnemonic_to_entropy, personality_profile, BiponError,
    ElementalVector, Macro,
};

#[test]
fn mode_256_to_2048_to_256_roundtrip_all_entropy_sizes() {
    for bits in [128usize, 160, 192, 224, 256] {
        let entropy = vec![0xA5; bits / 8];
        let mnemonic_256 = entropy_to_mnemonic(&entropy).unwrap().join(" ");
        let mnemonic_2048 = encode_2048(&mnemonic_256).unwrap();
        let decoded = decode_2048(&mnemonic_2048).unwrap();

        assert_eq!(decoded, mnemonic_256, "{bits}-bit roundtrip failed");
        assert!(mnemonic_2048
            .split_whitespace()
            .all(|word| word.contains('~')));
    }
}

#[test]
fn mode_2048_matches_entropy_direct_encoding() {
    let entropy = [0u8; 16];
    let mnemonic_256 = entropy_to_mnemonic(&entropy).unwrap().join(" ");
    let via_reencode = encode_2048(&mnemonic_256).unwrap();
    let direct = entropy_to_mnemonic_2048(&entropy).unwrap().join(" ");

    assert_eq!(via_reencode, direct);
    assert_eq!(direct.split_whitespace().count(), 12);
}

#[test]
fn mode_2048_to_entropy_roundtrip() {
    let entropy = vec![0x5Au8; 32];
    let mnemonic_2048 = entropy_to_mnemonic_2048(&entropy).unwrap();
    let words = mnemonic_2048.iter().map(String::as_str).collect::<Vec<_>>();
    let recovered = mnemonic_2048_to_entropy(&words).unwrap();

    assert_eq!(&*recovered, entropy.as_slice());
}

#[test]
fn mode_2048_rejects_unknown_subtone() {
    let entropy = [0u8; 16];
    let mut words = entropy_to_mnemonic_2048(&entropy).unwrap();
    words[0] = words[0].replace("alpha", "omega");
    let phrase = words.join(" ");

    assert!(matches!(
        decode_2048(&phrase),
        Err(BiponError::InvalidWord { .. })
    ));
}

#[test]
fn ifascript_profile_accepts_2048_mode_tokens() {
    let profile = personality_profile("esu-elegbara~alpha esu-elegba~beta sango~theta").unwrap();

    assert_eq!(profile.macro_distribution.total, 3);
    assert_eq!(profile.dominant_domain, Macro::Esu);
    assert!((profile.macro_percentages[0].1 - (100.0 * 2.0 / 3.0)).abs() < 1e-10);
    assert_eq!(profile.ritual_suggestions[0], "draw crossroads");
    assert!(profile.personality_summary.contains("Access leads"));
    assert_eq!(
        profile.elemental_signature,
        ElementalVector {
            fire: 1,
            water: 0,
            earth: 2,
            air: 0,
            ether: 0,
        }
    );
}

#[test]
fn entropy_roundtrip_matches_between_modes() {
    let entropy = vec![0x33u8; 24];
    let mnemonic_256 = entropy_to_mnemonic(&entropy).unwrap().join(" ");
    let mnemonic_2048 = encode_2048(&mnemonic_256).unwrap();
    let decoded_words = decode_2048(&mnemonic_2048).unwrap();
    let words = decoded_words.split_whitespace().collect::<Vec<_>>();
    let recovered = mnemonic_to_entropy(&words).unwrap();

    assert_eq!(&*recovered, entropy.as_slice());
}
