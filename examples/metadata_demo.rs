use bipon39::{
    elemental_signature, entropy_to_mnemonic, join_mnemonic, lookup_meta, personality_profile,
    BiponError,
};

fn main() -> Result<(), BiponError> {
    let mnemonic = entropy_to_mnemonic(&[0u8; 32])?;
    let phrase = join_mnemonic(&mnemonic);

    println!("Mnemonic: {phrase}");

    let meta = lookup_meta(15).expect("array index 15 is inside the 256-token wordlist");
    println!("Token 15 element: {}", meta.element);
    println!("Token 15 ritual cue: {}", meta.ritual_cue);
    println!("Token 15 ethical tag: {}", meta.ethical_tag);
    println!("Token 15 sigil seed: {}", meta.sigil_seed);

    let elements = elemental_signature(&phrase);
    println!(
        "Elemental signature: Fire={} Water={} Earth={} Air={} Ether={}",
        elements.fire, elements.water, elements.earth, elements.air, elements.ether
    );

    let profile = personality_profile(&phrase)?;
    println!("Dominant Domain: {}", profile.dominant_domain.universal_name());
    println!("Domain distribution:");
    for (macro_, count) in profile.macro_distribution.counts {
        println!("  {}: {count}", macro_.universal_name());
    }

    Ok(())
}
