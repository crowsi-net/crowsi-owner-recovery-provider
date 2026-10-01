use crowsi_credential_authority_contracts::{
    OWNER_RECOVERY_CUSTODY_RECEIPT_SCHEMA_V1, OwnerRecoveryCustodyReceiptV1,
    OwnerRecoveryCustodyStateV1,
};
use ed25519_dalek::{Signer, SigningKey};
use ihat_identity_assertion_contracts::{
    SIGNED_EVIDENCE_MAX_TTL_SECONDS, SIGNED_EVIDENCE_SCHEMA, SignedEvidenceV1, VerificationRole,
    canonical_signed_evidence,
};
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

use crate::{RecoveryError, RecoveryMnemonic};

pub const OWNER_RECOVERY_PROFILE_V1: &str =
    "ihat://identity/owner-recovery-profile/bip39-ed25519-v1";
const DERIVATION_DOMAIN: &[u8] = b"ihat-owner-recovery-ed25519-v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRootDescriptorV1 {
    pub schema: String,
    pub profile: String,
    pub authority_id: String,
    pub authority_device_id: String,
    pub key_id: String,
    pub key_fingerprint: String,
    pub public_key_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryApprovalInputV1 {
    pub approval_id: String,
    pub binding_sha256: String,
    pub key_id: String,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
}

/// Verifies that a public descriptor maps exactly to an iHAT recovery key.
///
/// # Errors
///
/// Returns [`RecoveryError::InvalidApproval`] for a profile, identifier,
/// public-key or fingerprint mismatch.
pub fn validate_descriptor(value: &RecoveryRootDescriptorV1) -> Result<(), RecoveryError> {
    let public = hex::decode(&value.public_key_hex).map_err(|_| RecoveryError::InvalidApproval)?;
    if value.schema != "crowsi://owner-recovery/root-descriptor/v1"
        || value.profile != OWNER_RECOVERY_PROFILE_V1
        || value.authority_device_id != "offline-owner-recovery-root"
        || public.len() != 32
    {
        return Err(RecoveryError::InvalidApproval);
    }
    let fingerprint = hex::encode(Sha256::digest(public));
    if value.key_fingerprint != fingerprint
        || value.authority_id != format!("owner-recovery-{fingerprint}")
        || value.key_id != format!("owner-recovery-key-{fingerprint}")
    {
        return Err(RecoveryError::InvalidApproval);
    }
    Ok(())
}

#[must_use]
pub fn descriptor(mnemonic: &RecoveryMnemonic) -> RecoveryRootDescriptorV1 {
    let key = signing_key(mnemonic);
    let public = key.verifying_key().to_bytes();
    let fingerprint = hex::encode(Sha256::digest(public));
    let value = RecoveryRootDescriptorV1 {
        schema: "crowsi://owner-recovery/root-descriptor/v1".into(),
        profile: OWNER_RECOVERY_PROFILE_V1.into(),
        authority_id: format!("owner-recovery-{fingerprint}"),
        authority_device_id: "offline-owner-recovery-root".into(),
        key_id: format!("owner-recovery-key-{fingerprint}"),
        key_fingerprint: fingerprint,
        public_key_hex: hex::encode(public),
    };
    debug_assert!(validate_descriptor(&value).is_ok());
    value
}

/// Issues an iHAT-compatible, short-lived recovery approval.
///
/// # Errors
///
/// Returns [`RecoveryError::InvalidApproval`] when the request is malformed,
/// not bound to this root, or exceeds the iHAT evidence lifetime.
pub fn issue_approval(
    mnemonic: &RecoveryMnemonic,
    input: &RecoveryApprovalInputV1,
) -> Result<SignedEvidenceV1, RecoveryError> {
    if input.approval_id.is_empty()
        || input.key_id != descriptor(mnemonic).key_id
        || input.binding_sha256.len() != 64
        || !input
            .binding_sha256
            .bytes()
            .all(|value| value.is_ascii_hexdigit() && !value.is_ascii_uppercase())
        || input.issued_at_epoch_s == 0
        || input.expires_at_epoch_s <= input.issued_at_epoch_s
        || input.expires_at_epoch_s - input.issued_at_epoch_s > SIGNED_EVIDENCE_MAX_TTL_SECONDS
    {
        return Err(RecoveryError::InvalidApproval);
    }
    let key = signing_key(mnemonic);
    let mut evidence = SignedEvidenceV1 {
        schema: SIGNED_EVIDENCE_SCHEMA.into(),
        role: VerificationRole::RecoveryApproval,
        proof_id: input.approval_id.clone(),
        key_id: input.key_id.clone(),
        issued_at_epoch_s: input.issued_at_epoch_s,
        expires_at_epoch_s: input.expires_at_epoch_s,
        binding_sha256: input.binding_sha256.clone(),
        signature: String::new(),
    };
    let canonical =
        canonical_signed_evidence(&evidence).map_err(|_| RecoveryError::InvalidApproval)?;
    evidence.signature = hex::encode(key.sign(&canonical).to_bytes());
    Ok(evidence)
}

/// Creates the public custody projection consumed by the Zixcel ceremony.
///
/// # Errors
///
/// Returns [`RecoveryError::InvalidApproval`] when the public receipt fields
/// do not satisfy the closed Crowsi contract.
pub fn custody_receipt(
    mnemonic: &RecoveryMnemonic,
    recovery_id: &str,
    subject_ref: &str,
    custody_provider_ref: &str,
    key_revision: u64,
    state: OwnerRecoveryCustodyStateV1,
    observed_at_epoch_s: u64,
) -> Result<OwnerRecoveryCustodyReceiptV1, RecoveryError> {
    let value = OwnerRecoveryCustodyReceiptV1 {
        schema: OWNER_RECOVERY_CUSTODY_RECEIPT_SCHEMA_V1.into(),
        recovery_id: recovery_id.into(),
        subject_ref: subject_ref.into(),
        custody_provider_ref: custody_provider_ref.into(),
        root_fingerprint_sha256: format!("sha256:{}", descriptor(mnemonic).key_fingerprint),
        key_revision,
        state,
        observed_at_epoch_s,
    };
    value
        .validate()
        .map_err(|_| RecoveryError::InvalidApproval)?;
    Ok(value)
}

fn signing_key(mnemonic: &RecoveryMnemonic) -> SigningKey {
    let phrase = Zeroizing::new(
        mnemonic
            .expose_for_owner_ceremony()
            .nfkd()
            .collect::<String>(),
    );
    let mut seed = Zeroizing::new([0_u8; 64]);
    pbkdf2_hmac::<Sha512>(phrase.as_bytes(), b"mnemonic", 2_048, seed.as_mut());
    let mut input = Zeroizing::new(Vec::with_capacity(DERIVATION_DOMAIN.len() + seed.len()));
    input.extend_from_slice(DERIVATION_DOMAIN);
    input.extend_from_slice(seed.as_ref());
    let digest = Sha512::digest(&input[..]);
    let mut secret = [0_u8; 32];
    secret.copy_from_slice(&digest[..32]);
    let key = SigningKey::from_bytes(&secret);
    secret.zeroize();
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse;
    use ihat_identity_assertion_contracts::{SignedEvidenceBinding, verify_signed_evidence_at};

    fn vector() -> RecoveryMnemonic {
        parse(&format!("{} art", vec!["abandon"; 23].join(" "))).expect("vector")
    }

    #[test]
    fn frozen_vector_and_approval_verify_with_ihat_contract() {
        let mnemonic = vector();
        let descriptor = descriptor(&mnemonic);
        assert_eq!(
            descriptor.key_fingerprint,
            "eb91fc3e6bae7c31e1f3734378752113f6a1df1740cbedcaa08a7fe7a59f6ead"
        );
        let input = RecoveryApprovalInputV1 {
            approval_id: "recovery-proof-1".into(),
            binding_sha256: "ab".repeat(32),
            key_id: descriptor.key_id.clone(),
            issued_at_epoch_s: 100,
            expires_at_epoch_s: 120,
        };
        let evidence = issue_approval(&mnemonic, &input).expect("approval");
        verify_signed_evidence_at(
            &evidence,
            &SignedEvidenceBinding {
                role: VerificationRole::RecoveryApproval,
                proof_id: &input.approval_id,
                binding_sha256: &input.binding_sha256,
            },
            &descriptor.key_id,
            &descriptor.public_key_hex,
            110,
        )
        .expect("iHAT verification");
    }

    #[test]
    fn approval_never_serializes_mnemonic_or_private_material() {
        let mnemonic = vector();
        let descriptor = descriptor(&mnemonic);
        let evidence = issue_approval(
            &mnemonic,
            &RecoveryApprovalInputV1 {
                approval_id: "recovery-proof-1".into(),
                binding_sha256: "ab".repeat(32),
                key_id: descriptor.key_id,
                issued_at_epoch_s: 100,
                expires_at_epoch_s: 120,
            },
        )
        .expect("approval");
        let wire = serde_json::to_string(&evidence).expect("wire");
        assert!(!wire.contains("abandon"));
        assert!(!wire.contains("private"));
        assert!(!wire.contains("seed"));
    }

    #[test]
    fn custody_receipt_is_secret_free_and_contract_valid() {
        let mnemonic = vector();
        let receipt = custody_receipt(
            &mnemonic,
            "recovery:1",
            "owner:1",
            "crowsi:owner-recovery",
            1,
            OwnerRecoveryCustodyStateV1::Verified,
            100,
        )
        .expect("receipt");
        receipt.validate().expect("contract");
        let wire = serde_json::to_string(&receipt).expect("wire");
        assert!(!wire.contains("abandon"));
        assert!(wire.contains("eb91fc3e6bae7c31"));
    }

    #[test]
    fn public_descriptor_rejects_profile_key_and_identity_substitution() {
        let descriptor = descriptor(&vector());
        validate_descriptor(&descriptor).expect("descriptor");
        for case in 0..4 {
            let mut changed = descriptor.clone();
            match case {
                0 => changed.profile = "future-profile".into(),
                1 => changed.public_key_hex = "00".repeat(32),
                2 => changed.key_id = "other-key".into(),
                _ => changed.authority_device_id = "device-a".into(),
            }
            assert_eq!(
                validate_descriptor(&changed),
                Err(RecoveryError::InvalidApproval)
            );
        }
    }
}
