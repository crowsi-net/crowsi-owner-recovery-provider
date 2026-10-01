use getrandom::getrandom;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const ENTROPY_BYTES: usize = 32;
const WORD_COUNT: usize = 24;
const WORDS: &str = include_str!("../assets/bip39-english.txt");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryError {
    EntropyUnavailable,
    InvalidMnemonic,
    InvalidApproval,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecoveryMnemonic(Zeroizing<String>);

impl RecoveryMnemonic {
    #[must_use]
    pub fn expose_for_owner_ceremony(&self) -> &str {
        self.0.as_str()
    }

    pub(crate) fn entropy(&self) -> Result<Zeroizing<[u8; ENTROPY_BYTES]>, RecoveryError> {
        decode(self.0.as_str())
    }
}

pub struct GeneratedRecoveryRoot {
    pub mnemonic: RecoveryMnemonic,
}

/// Generates a fresh 256-bit recovery root and its checksummed mnemonic.
///
/// # Errors
///
/// Returns [`RecoveryError::EntropyUnavailable`] when the operating-system
/// cryptographic random source is unavailable.
pub fn generate() -> Result<GeneratedRecoveryRoot, RecoveryError> {
    let mut entropy = Zeroizing::new([0_u8; ENTROPY_BYTES]);
    getrandom(entropy.as_mut()).map_err(|_| RecoveryError::EntropyUnavailable)?;
    Ok(GeneratedRecoveryRoot {
        mnemonic: RecoveryMnemonic(Zeroizing::new(encode(&entropy))),
    })
}

/// Parses and verifies an English 24-word BIP39 mnemonic.
///
/// # Errors
///
/// Returns [`RecoveryError::InvalidMnemonic`] for an unknown word, invalid
/// shape, or checksum mismatch.
pub fn parse(value: &str) -> Result<RecoveryMnemonic, RecoveryError> {
    let mnemonic = RecoveryMnemonic(Zeroizing::new(value.nfkd().collect::<String>()));
    mnemonic.entropy()?;
    Ok(mnemonic)
}

fn encode(entropy: &[u8; ENTROPY_BYTES]) -> String {
    let checksum = Sha256::digest(entropy)[0];
    let words = word_list();
    (0..WORD_COUNT)
        .map(|word| {
            let mut index = 0_u16;
            for offset in 0..11 {
                let bit = word * 11 + offset;
                let value = if bit < ENTROPY_BYTES * 8 {
                    (entropy[bit / 8] >> (7 - bit % 8)) & 1
                } else {
                    (checksum >> (7 - (bit - ENTROPY_BYTES * 8))) & 1
                };
                index = (index << 1) | u16::from(value);
            }
            words[usize::from(index)]
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn decode(value: &str) -> Result<Zeroizing<[u8; ENTROPY_BYTES]>, RecoveryError> {
    if value.trim() != value || value.split_ascii_whitespace().count() != WORD_COUNT {
        return Err(RecoveryError::InvalidMnemonic);
    }
    let words = word_list();
    let mut bits = [0_u8; ENTROPY_BYTES + 1];
    for (word_offset, word) in value.split_ascii_whitespace().enumerate() {
        let index = words
            .binary_search(&word)
            .map_err(|_| RecoveryError::InvalidMnemonic)?;
        for offset in 0..11 {
            let bit = word_offset * 11 + offset;
            let value = ((index >> (10 - offset)) & 1) == 1;
            bits[bit / 8] |= u8::from(value) << (7 - bit % 8);
        }
    }
    let mut entropy = Zeroizing::new([0_u8; ENTROPY_BYTES]);
    entropy.copy_from_slice(&bits[..ENTROPY_BYTES]);
    if bits[ENTROPY_BYTES] != Sha256::digest(*entropy)[0] {
        return Err(RecoveryError::InvalidMnemonic);
    }
    Ok(entropy)
}

fn word_list() -> Vec<&'static str> {
    WORDS.lines().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bip39_zero_entropy_vector_round_trips() {
        let expected = format!("{} art", vec!["abandon"; 23].join(" "));
        let encoded = encode(&[0_u8; 32]);
        assert_eq!(encoded, expected);
        assert_eq!(
            *parse(&encoded).expect("vector").entropy().expect("entropy"),
            [0_u8; 32]
        );
    }

    #[test]
    fn checksum_and_shape_are_closed() {
        let valid = format!("{} art", vec!["abandon"; 23].join(" "));
        assert_eq!(
            parse(&valid.replace("art", "ability")).err(),
            Some(RecoveryError::InvalidMnemonic)
        );
        assert_eq!(
            parse(&format!(" {valid}")).err(),
            Some(RecoveryError::InvalidMnemonic)
        );
        assert_eq!(
            parse(&valid.replace("abandon", "unknown")).err(),
            Some(RecoveryError::InvalidMnemonic)
        );
    }

    #[test]
    fn english_word_list_is_the_frozen_bip39_release() {
        assert_eq!(
            hex::encode(Sha256::digest(WORDS.as_bytes())),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
        let words = word_list();
        assert_eq!(words.len(), 2_048);
        assert!(words.windows(2).all(|pair| pair[0] < pair[1]));
    }
}
