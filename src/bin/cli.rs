use clap::{Parser, Subcommand};
use getrandom::getrandom;
use serde_json::{json, Value};
use std::io::Read;

use bipon39::{
    derive_path, dominant_macro, ed25519_keypair_from_seed, elemental_signature,
    entropy_to_mnemonic, macro_distribution, mnemonic_to_entropy, mnemonic_to_seed,
    odu_primary_index, BiponError,
};

#[derive(Parser)]
#[command(name = "bipon39", version = "0.1.0", about = "BIPỌ̀N39 CLI — identity + wallet")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new BIPỌ̀N39 mnemonic + derived seed + keys
    Generate {
        /// Entropy bits: 128, 160, 192, 224, or 256 (default: 256)
        #[arg(short, long, default_value = "256")]
        bits: usize,
        /// Optional passphrase for seed derivation
        #[arg(short, long, default_value = "")]
        passphrase: String,
    },
    /// Derive seed + keys from an existing mnemonic
    Derive {
        /// Passphrase used during generation
        #[arg(short, long, default_value = "")]
        passphrase: String,
        /// Read mnemonic from stdin instead of argument
        #[arg(long)]
        stdin: bool,
        /// The mnemonic phrase (omit if using --stdin)
        #[arg(required_unless_present = "stdin")]
        mnemonic: Option<Vec<String>>,
    },
    /// Show Ifáscript metadata for a mnemonic
    Info {
        /// Read mnemonic from stdin
        #[arg(long)]
        stdin: bool,
        /// The mnemonic phrase
        #[arg(required_unless_present = "stdin")]
        mnemonic: Option<Vec<String>>,
    },
}

fn read_mnemonic(
    mnemonic: Option<Vec<String>>, use_stdin: bool,
) -> Result<Vec<String>, BiponError> {
    if use_stdin {
        let mut input = String::new();
        std::io::stdin().read_to_string(&mut input).map_err(|e| {
            BiponError::InvalidWord { position: 0, word: format!("stdin error: {}", e) }
        })?;
        Ok(input.trim().split_whitespace().map(String::from).collect())
    } else {
        Ok(mnemonic.unwrap_or_default())
    }
}

fn get_entropy(bits: usize) -> Result<Vec<u8>, BiponError> {
    let bytes = bits / 8;
    let mut entropy = vec![0u8; bytes];
    getrandom(&mut entropy).map_err(|e| {
        BiponError::InvalidWord { position: 0, word: format!("getrandom: {}", e) }
    })?;
    Ok(entropy)
}

fn build_output(words: &[&str], seed: &[u8]) -> Value {
    let (sk, vk) = ed25519_keypair_from_seed(seed).unwrap_or_else(|_| {
        use ed25519_dalek::{SigningKey, VerifyingKey};
        (SigningKey::from_bytes(&[0u8; 32]), VerifyingKey::from_bytes(&[0u8; 32]).unwrap())
    });

    let odu = odu_primary_index(words).ok();
    let dominant = dominant_macro(words).ok();
    let distribution = macro_distribution(words).ok();
    let elements = elemental_signature(&words.join(" "));

    let sol_path = [44 | 0x8000_0000, 501 | 0x8000_0000, 0x8000_0000, 0, 0];
    let eth_path = [44 | 0x8000_0000, 60 | 0x8000_0000, 0x8000_0000, 0, 0];
    let sol_key = derive_path(seed, &sol_path).ok();
    let eth_key = derive_path(seed, &eth_path).ok();

    let mut macro_counts = Vec::new();
    if let Some(d) = distribution {
        for (m, c) in d.counts {
            macro_counts.push(json!({"macro": m.name(), "count": c}));
        }
    }

    json!({
        "mnemonic": words.join(" "),
        "word_count": words.len(),
        "seed_hex": hex::encode(seed),
        "seed_bytes": seed.len(),
        "keys": {
            "ed25519": {
                "secret_key_hex": hex::encode(sk.to_bytes()),
                "public_key_hex": hex::encode(vk.as_bytes()),
                "public_key_base58": bs58::encode(vk.as_bytes()).into_string(),
            },
            "bip44": {
                "solana": {
                    "path": "m/44'/501'/0'/0/0",
                    "private_key_hex": sol_key.clone().map(|(k,_)| hex::encode(k)).unwrap_or_default(),
                },
                "ethereum": {
                    "path": "m/44'/60'/0'/0/0",
                    "private_key_hex": eth_key.map(|(k,_)| hex::encode(k)).unwrap_or_default(),
                },
            }
        },
        "ifascript": {
            "odu_primary_index": odu,
            "dominant_macro": dominant.map(|m| m.name().to_string()),
            "macro_distribution": macro_counts,
            "elemental_signature": {
                "fire": elements.fire,
                "water": elements.water,
                "earth": elements.earth,
                "air": elements.air,
            },
        }
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Generate { bits, passphrase } => {
            let entropy = get_entropy(bits)?;
            let words = entropy_to_mnemonic(&entropy)?;
            let word_refs: Vec<&str> = words.iter().map(String::as_str).collect();
            let seed = mnemonic_to_seed(&word_refs, &passphrase)?;
            println!("{}", serde_json::to_string_pretty(&build_output(&word_refs, &seed))?);
        }
        Commands::Derive { mnemonic, stdin, passphrase } => {
            let words = read_mnemonic(mnemonic, stdin)?;
            let word_refs: Vec<&str> = words.iter().map(String::as_str).collect();
            let seed = mnemonic_to_seed(&word_refs, &passphrase)?;
            println!("{}", serde_json::to_string_pretty(&build_output(&word_refs, &seed))?);
        }
        Commands::Info { mnemonic, stdin } => {
            let words = read_mnemonic(mnemonic, stdin)?;
            let word_refs: Vec<&str> = words.iter().map(String::as_str).collect();
            let entropy = mnemonic_to_entropy(&word_refs)?;
            let seed = mnemonic_to_seed(&word_refs, "")?;
            let odu = odu_primary_index(&word_refs)?;
            let dominant = dominant_macro(&word_refs)?;
            let distribution = macro_distribution(&word_refs)?;
            let elements = elemental_signature(&word_refs.join(" "));

            let mut macro_counts = Vec::new();
            for (m, c) in distribution.counts {
                macro_counts.push(json!({"macro": m.name(), "count": c}));
            }

            println!("{}", serde_json::to_string_pretty(&json!({
                "word_count": words.len(),
                "entropy_hex": hex::encode(&*entropy),
                "seed_hex": hex::encode(&*seed),
                "odu_primary_index": odu,
                "dominant_macro": dominant.name(),
                "macro_distribution": macro_counts,
                "elemental_signature": {
                    "fire": elements.fire, "water": elements.water,
                    "earth": elements.earth, "air": elements.air,
                },
            }))?);
        }
    }
    Ok(())
}
