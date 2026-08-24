use clap::{Parser, Subcommand, ValueEnum};

use bipon39::{
    decode_2048, elemental_signature, encode_2048, entropy_to_mnemonic, join_mnemonic,
    mnemonic_to_seed, personality_profile, BiponError,
};

#[derive(Debug, Parser)]
#[command(
    name = "bipon39",
    version,
    about = "BIPỌ̀N39 mnemonic, dual-mode conversion, seed, and Ifáscript inspection tool",
    after_long_help = "Examples:\n  bipon39 generate 256\n  bipon39 generate 128 --mode 2048\n  bipon39 inspect esu-elegbara esu-elegba sango\n  bipon39 convert --to-2048 esu-elegbara ...\n  bipon39 convert --to-256 esu-elegbara~alpha ...\n  bipon39 seed esu-elegbara ... --passphrase agency"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate a new mnemonic from OS randomness.
    Generate {
        /// Entropy size in bits: 128, 160, 192, 224, or 256.
        bits: usize,
        /// Output mnemonic mode.
        #[arg(long, value_enum, default_value_t = ModeArg::Mode256)]
        mode: ModeArg,
    },
    /// Inspect a 256- or 2048-mode mnemonic's Ifáscript profile.
    Inspect {
        /// Mnemonic words. Quote the whole phrase or pass words separately.
        #[arg(required = true, num_args = 1..)]
        mnemonic: Vec<String>,
    },
    /// Convert between 256-mode and 2048-mode mnemonic forms.
    Convert {
        /// Convert 256-mode input into 2048-mode output.
        #[arg(long, conflicts_with = "to_256")]
        to_2048: bool,
        /// Convert 2048-mode input into 256-mode output.
        #[arg(long, conflicts_with = "to_2048")]
        to_256: bool,
        /// Mnemonic words. Quote the whole phrase or pass words separately.
        #[arg(required = true, num_args = 1..)]
        mnemonic: Vec<String>,
    },
    /// Derive a BIPỌ̀N39 seed from a mnemonic phrase.
    Seed {
        /// Mnemonic words. Quote the whole phrase or pass words separately.
        #[arg(required = true, num_args = 1..)]
        mnemonic: Vec<String>,
        /// Optional passphrase inserted using the Ọ̀RÍ salt label.
        #[arg(long, default_value = "")]
        passphrase: String,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ModeArg {
    #[value(name = "256")]
    Mode256,
    #[value(name = "2048")]
    Mode2048,
}

fn main() -> Result<(), BiponError> {
    match Cli::parse().command {
        Command::Generate { bits, mode } => generate(bits, mode),
        Command::Inspect { mnemonic } => inspect(&phrase(mnemonic)),
        Command::Convert {
            to_2048,
            to_256,
            mnemonic,
        } => convert(to_2048, to_256, &phrase(mnemonic)),
        Command::Seed {
            mnemonic,
            passphrase,
        } => seed(&phrase(mnemonic), &passphrase),
    }
}

fn generate(bits: usize, mode: ModeArg) -> Result<(), BiponError> {
    if !matches!(bits, 128 | 160 | 192 | 224 | 256) {
        return Err(BiponError::InvalidEntropyLength { bits });
    }

    let mut entropy = vec![0u8; bits / 8];
    getrandom::getrandom(&mut entropy)
        .map_err(|err| BiponError::RandomGenerationError(err.to_string()))?;

    let mnemonic_256 = entropy_to_mnemonic(&entropy)?;
    let phrase_256 = join_mnemonic(&mnemonic_256);
    let phrase = match mode {
        ModeArg::Mode256 => phrase_256,
        ModeArg::Mode2048 => encode_2048(&phrase_256)?,
    };

    println!("{phrase}");
    Ok(())
}

fn inspect(mnemonic: &str) -> Result<(), BiponError> {
    let profile = personality_profile(mnemonic)?;
    let elements = elemental_signature(mnemonic);

    println!("Dominant Domain: {}", profile.dominant_domain.universal_name());
    println!("Summary: {}", profile.personality_summary);
    println!(
        "Elements: Fire={} Water={} Earth={} Air={} Ether={}",
        elements.fire, elements.water, elements.earth, elements.air, elements.ether
    );
    println!("Domain distribution:");
    for ((macro_, count), (_, pct)) in profile
        .macro_distribution
        .counts
        .into_iter()
        .zip(profile.macro_percentages)
    {
        println!("  {}: {count} ({pct:.1}%)", macro_.universal_name());
    }
    println!("Ritual suggestions:");
    for cue in profile.ritual_suggestions {
        println!("  - {cue}");
    }
    Ok(())
}

fn convert(to_2048: bool, to_256: bool, mnemonic: &str) -> Result<(), BiponError> {
    let converted = match (to_2048, to_256) {
        (true, false) => encode_2048(mnemonic)?,
        (false, true) => decode_2048(mnemonic)?,
        _ => {
            return Err(BiponError::DerivationError(
                "choose exactly one of --to-2048 or --to-256".to_string(),
            ))
        }
    };

    println!("{converted}");
    Ok(())
}

fn seed(mnemonic: &str, passphrase: &str) -> Result<(), BiponError> {
    let words = mnemonic.split_whitespace().collect::<Vec<_>>();
    let seed = mnemonic_to_seed(&words, passphrase)?;
    println!("{}", hex::encode(&*seed));
    Ok(())
}

fn phrase(words: Vec<String>) -> String {
    words.join(" ")
}
