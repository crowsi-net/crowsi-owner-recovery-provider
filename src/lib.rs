//! Owner-local mnemonic generation and short-lived iHAT recovery approvals.

#![forbid(unsafe_code)]

mod mnemonic;
mod proof;

pub use mnemonic::{GeneratedRecoveryRoot, RecoveryError, RecoveryMnemonic, generate, parse};
pub use proof::{
    OWNER_RECOVERY_PROFILE_V1, RecoveryApprovalInputV1, RecoveryRootDescriptorV1, custody_receipt,
    descriptor, issue_approval, validate_descriptor,
};
