use std::collections::HashSet;

use crate::dualmode::{entry_by_mode_token, mode_index_of_token};
use crate::error::BiponError;
use crate::wordlist::entries_for_macro;

/// The seven Macro groupings of the BIPỌ̀N39 wordlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Macro {
    /// ÈṢÙ — flat indices 1–88.
    Esu,
    /// ṢÀNGÓ — flat indices 89–108.
    Sango,
    /// Ọ̀ṢUN — flat indices 109–136.
    Osun,
    /// YEMỌJA — flat indices 137–164.
    Yemoja,
    /// ỌYA — flat indices 165–196.
    Oya,
    /// ÒGÚN — flat indices 197–228.
    Ogun,
    /// ỌBÀTÁLÁ — flat indices 229–256.
    Obatala,
}

impl Macro {
    /// Canonical internal display name (Yorùbá anchor). Never surface this at
    /// a public/user-facing boundary — use [`Macro::universal_name`] there.
    pub fn name(&self) -> &'static str {
        match self {
            Macro::Esu => "ÈṢÙ",
            Macro::Sango => "ṢÀNGÓ",
            Macro::Osun => "Ọ̀ṢUN",
            Macro::Yemoja => "YEMỌJA",
            Macro::Oya => "ỌYA",
            Macro::Ogun => "ÒGÚN",
            Macro::Obatala => "ỌBÀTÁLÁ",
        }
    }

    /// Public-facing name — universal wording per OSOVM_CODEX §42. Use this
    /// (not [`Macro::name`]) for any CLI output, JSON API field, or other
    /// surface a caller/user can see.
    pub fn universal_name(&self) -> &'static str {
        match self {
            Macro::Esu => "Access",
            Macro::Sango => "Score",
            Macro::Osun => "History",
            Macro::Yemoja => "Spawn",
            Macro::Oya => "Sync",
            Macro::Ogun => "Run",
            Macro::Obatala => "Policy",
        }
    }

    /// Inclusive 1-based flat_index range.
    pub fn index_range(&self) -> (usize, usize) {
        match self {
            Macro::Esu => (1, 88),
            Macro::Sango => (89, 108),
            Macro::Osun => (109, 136),
            Macro::Yemoja => (137, 164),
            Macro::Oya => (165, 196),
            Macro::Ogun => (197, 228),
            Macro::Obatala => (229, 256),
        }
    }

    /// Number of tokens in this Macro.
    pub fn count(&self) -> usize {
        let (start, end) = self.index_range();
        end - start + 1
    }

    /// Parse a Macro from canonical or simplified ASCII form.
    pub fn from_name(s: &str) -> Option<Macro> {
        match s {
            "ÈṢÙ" | "esu" => Some(Macro::Esu),
            "ṢÀNGÓ" | "sango" => Some(Macro::Sango),
            "Ọ̀ṢUN" | "osun" => Some(Macro::Osun),
            "YEMỌJA" | "yemoja" => Some(Macro::Yemoja),
            "ỌYA" | "oya" => Some(Macro::Oya),
            "ÒGÚN" | "ogun" => Some(Macro::Ogun),
            "ỌBÀTÁLÁ" | "obatala" => Some(Macro::Obatala),
            _ => None,
        }
    }

    /// Return the Macro containing a 1-based flat_index.
    pub fn from_flat_index(flat_index: usize) -> Option<Macro> {
        Self::all().into_iter().find(|macro_| {
            let (start, end) = macro_.index_range();
            (start..=end).contains(&flat_index)
        })
    }

    fn all() -> [Macro; 7] {
        [
            Macro::Esu,
            Macro::Sango,
            Macro::Osun,
            Macro::Yemoja,
            Macro::Oya,
            Macro::Ogun,
            Macro::Obatala,
        ]
    }
}

/// Distribution of mnemonic words across Macros.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacroDistribution {
    /// Counts in Macro order.
    pub counts: [(Macro, usize); 7],
    /// Sum of all counts.
    pub total: usize,
}

/// Balance of the five elemental metadata families across a mnemonic.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ElementalVector {
    /// Fire-associated tokens.
    pub fire: usize,
    /// Water-associated tokens.
    pub water: usize,
    /// Earth-associated tokens.
    pub earth: usize,
    /// Air-associated tokens.
    pub air: usize,
    /// Ether-associated tokens.
    pub ether: usize,
}

impl ElementalVector {
    fn add_element(&mut self, element: &str) {
        match element {
            "Fire" => self.fire += 1,
            "Water" => self.water += 1,
            "Earth" => self.earth += 1,
            "Air" => self.air += 1,
            "Ether" => self.ether += 1,
            _ => {}
        }
    }
}

/// Combined Ifáscript profile for a mnemonic phrase.
#[derive(Debug, Clone, PartialEq)]
pub struct PersonalityProfile {
    /// Count of words across the seven Macro/Orisha groupings.
    pub macro_distribution: MacroDistribution,
    /// Percentage share for each Macro in Macro order.
    pub macro_percentages: [(Macro, f64); 7],
    /// Count of words across Fire, Water, Earth, Air, and Ether metadata.
    pub elemental_signature: ElementalVector,
    /// Dominant Macro/Orisha after deterministic tie-breaking.
    pub dominant_domain: Macro,
    /// Ordered, deduplicated ritual cues suggested by the mnemonic tokens.
    pub ritual_suggestions: Vec<String>,
    /// Short human-readable personality summary suitable for CLI/UI display.
    pub personality_summary: String,
}

/// XOR-reduce all 256-mode array indices or 2048-mode expanded indices.
pub fn odu_primary_index(words: &[&str]) -> Result<u8, BiponError> {
    let mut result = 0u8;
    for word in words {
        result ^= mode_index_of_token(word)? as u8;
    }
    Ok(result)
}

/// Count how many words belong to each Macro.
pub fn macro_distribution(words: &[&str]) -> Result<MacroDistribution, BiponError> {
    let mut counts = Macro::all().map(|macro_| (macro_, 0usize));
    for word in words {
        let entry = entry_by_mode_token(word)?;
        let macro_ = Macro::from_name(entry.macro_name).ok_or_else(|| {
            BiponError::WordlistIntegrity(format!("unknown macro {}", entry.macro_name))
        })?;
        let (_, count) = counts
            .iter_mut()
            .find(|(candidate, _)| *candidate == macro_)
            .expect("all macros are present in counts");
        *count += 1;
    }
    Ok(MacroDistribution {
        counts,
        total: words.len(),
    })
}

/// Return the Macro with the highest word count.
pub fn dominant_macro(words: &[&str]) -> Result<Macro, BiponError> {
    let distribution = macro_distribution(words)?;
    Ok(dominant_macro_from_distribution(&distribution))
}

/// Entries for a Macro.
pub fn entries_for(macro_: Macro) -> Vec<&'static crate::wordlist::WordlistEntry> {
    entries_for_macro(macro_.name())
}

/// Compute an elemental signature from a whitespace-separated mnemonic.
///
/// Unknown tokens are ignored to match the permissive TypeScript reference
/// helper. Use [`personality_profile`] when invalid tokens should return an
/// error instead.
pub fn elemental_signature(mnemonic: &str) -> ElementalVector {
    let mut signature = ElementalVector::default();
    for word in mnemonic.split_whitespace() {
        if let Ok(entry) = entry_by_mode_token(word) {
            signature.add_element(&entry.meta.element);
        }
    }
    signature
}

/// Build a complete Ifáscript personality profile for a mnemonic phrase.
pub fn personality_profile(mnemonic: &str) -> Result<PersonalityProfile, BiponError> {
    let words = mnemonic.split_whitespace().collect::<Vec<_>>();
    let macro_distribution = macro_distribution(&words)?;
    let macro_percentages = macro_percentages(&macro_distribution);
    let elemental_signature = elemental_signature_for_words(&words)?;
    let dominant_domain = dominant_macro_from_distribution(&macro_distribution);
    let ritual_suggestions = ritual_cue_for(mnemonic)?;
    let personality_summary = build_personality_summary(
        dominant_domain,
        &elemental_signature,
        ritual_suggestions.first(),
    );

    Ok(PersonalityProfile {
        macro_distribution,
        macro_percentages,
        elemental_signature,
        dominant_domain,
        ritual_suggestions,
        personality_summary,
    })
}

/// Return ordered, deduplicated ritual cues for either 256- or 2048-mode tokens.
pub fn ritual_cue_for(mnemonic: &str) -> Result<Vec<String>, BiponError> {
    let mut seen = HashSet::new();
    let mut cues = Vec::new();
    for word in mnemonic.split_whitespace() {
        let cue = entry_by_mode_token(word)?.meta.ritual_cue.clone();
        if seen.insert(cue.clone()) {
            cues.push(cue);
        }
    }
    Ok(cues)
}

fn elemental_signature_for_words(words: &[&str]) -> Result<ElementalVector, BiponError> {
    let mut signature = ElementalVector::default();
    for word in words {
        let entry = entry_by_mode_token(word)?;
        signature.add_element(&entry.meta.element);
    }
    Ok(signature)
}

fn macro_percentages(distribution: &MacroDistribution) -> [(Macro, f64); 7] {
    distribution.counts.map(|(macro_, count)| {
        let percentage = if distribution.total == 0 {
            0.0
        } else {
            (count as f64 / distribution.total as f64) * 100.0
        };
        (macro_, percentage)
    })
}

fn build_personality_summary(
    dominant_domain: Macro,
    elements: &ElementalVector,
    first_ritual: Option<&String>,
) -> String {
    let element = dominant_element(elements).unwrap_or("balanced");
    match first_ritual {
        Some(cue) => format!(
            "{} leads with a {element} elemental tone; begin with \"{cue}\".",
            dominant_domain.universal_name()
        ),
        None => format!(
            "{} leads with a {element} elemental tone.",
            dominant_domain.universal_name()
        ),
    }
}

fn dominant_element(elements: &ElementalVector) -> Option<&'static str> {
    [
        ("Fire", elements.fire),
        ("Water", elements.water),
        ("Earth", elements.earth),
        ("Air", elements.air),
        ("Ether", elements.ether),
    ]
    .into_iter()
    .max_by_key(|(_, count)| *count)
    .and_then(|(element, count)| (count > 0).then_some(element))
}

fn dominant_macro_from_distribution(distribution: &MacroDistribution) -> Macro {
    if distribution.total == 0 {
        return Macro::Esu;
    }

    distribution
        .counts
        .into_iter()
        .max_by(|(left_macro, left_count), (right_macro, right_count)| {
            left_count
                .cmp(right_count)
                .then_with(|| right_macro.count().cmp(&left_macro.count()))
                .then_with(|| right_macro.index_range().0.cmp(&left_macro.index_range().0))
        })
        .map(|(macro_, _)| macro_)
        .unwrap_or(Macro::Esu)
}
