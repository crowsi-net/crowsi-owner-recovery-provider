use std::fs::OpenOptions;
use std::io::{self, IsTerminal, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::process::ExitCode;

use crowsi_credential_authority_contracts::OwnerRecoveryCustodyStateV1;
use crowsi_owner_recovery_provider::{
    RecoveryApprovalInputV1, RecoveryRootDescriptorV1, custody_receipt, descriptor, generate,
    issue_approval, parse, validate_descriptor,
};
use serde::Serialize;
use zeroize::Zeroizing;

const MAXIMUM_SECRET_BYTES: u64 = 1_024;

fn main() -> ExitCode {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match run(&arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            eprintln!("crowsi-owner-recovery-provider: {reason}");
            ExitCode::FAILURE
        }
    }
}

fn run(arguments: &[String]) -> Result<(), &'static str> {
    match arguments {
        [
            command,
            descriptor_path,
            recovery,
            subject,
            provider,
            revision,
            observed,
        ] if command == "create" => create(
            descriptor_path,
            recovery,
            subject,
            provider,
            number(revision)?,
            number(observed)?,
        ),
        [command, recovery, subject, provider, revision, observed] if command == "verify-stdin" => {
            verify(
                recovery,
                subject,
                provider,
                number(revision)?,
                number(observed)?,
            )
        }
        [command, approval, binding, key, issued, expires] if command == "approve-stdin" => {
            approve(approval, binding, key, number(issued)?, number(expires)?)
        }
        [command, path] if command == "inspect-descriptor" => inspect_descriptor(path),
        _ => Err("usage-invalid"),
    }
}

fn create(
    descriptor_path: &str,
    recovery: &str,
    subject: &str,
    provider: &str,
    revision: u64,
    observed: u64,
) -> Result<(), &'static str> {
    if !io::stderr().is_terminal() {
        return Err("owner-display-terminal-required");
    }
    let generated = generate().map_err(|_| "entropy-unavailable")?;
    let descriptor = descriptor(&generated.mnemonic);
    let receipt = custody_receipt(
        &generated.mnemonic,
        recovery,
        subject,
        provider,
        revision,
        OwnerRecoveryCustodyStateV1::Provisioned,
        observed,
    )
    .map_err(|_| "request-invalid")?;
    write_descriptor(descriptor_path, &descriptor)?;
    eprintln!("Owner recovery phrase (write it down offline; it is shown once):");
    eprintln!("{}", generated.mnemonic.expose_for_owner_ceremony());
    output(&receipt)
}

fn verify(
    recovery: &str,
    subject: &str,
    provider: &str,
    revision: u64,
    observed: u64,
) -> Result<(), &'static str> {
    let mnemonic = secret_from_stdin()?;
    let receipt = custody_receipt(
        &mnemonic,
        recovery,
        subject,
        provider,
        revision,
        OwnerRecoveryCustodyStateV1::Verified,
        observed,
    )
    .map_err(|_| "request-invalid")?;
    output(&receipt)
}

fn approve(
    approval_id: &str,
    binding_sha256: &str,
    key_id: &str,
    issued_at_epoch_s: u64,
    expires_at_epoch_s: u64,
) -> Result<(), &'static str> {
    let mnemonic = secret_from_stdin()?;
    let evidence = issue_approval(
        &mnemonic,
        &RecoveryApprovalInputV1 {
            approval_id: approval_id.into(),
            binding_sha256: binding_sha256.into(),
            key_id: key_id.into(),
            issued_at_epoch_s,
            expires_at_epoch_s,
        },
    )
    .map_err(|_| "approval-invalid")?;
    output(&evidence)
}

fn secret_from_stdin() -> Result<crowsi_owner_recovery_provider::RecoveryMnemonic, &'static str> {
    if io::stdin().is_terminal() {
        return Err("protected-stdin-required");
    }
    let mut value = Zeroizing::new(String::new());
    io::stdin()
        .take(MAXIMUM_SECRET_BYTES)
        .read_to_string(&mut value)
        .map_err(|_| "secret-read-failed")?;
    let trimmed = value.trim_end_matches(['\r', '\n']);
    parse(trimmed).map_err(|_| "mnemonic-invalid")
}

fn number(value: &str) -> Result<u64, &'static str> {
    value.parse().map_err(|_| "number-invalid")
}

fn output(value: &impl Serialize) -> Result<(), &'static str> {
    serde_json::to_writer(io::stdout().lock(), value).map_err(|_| "output-failed")?;
    println!();
    Ok(())
}

fn write_descriptor(path: &str, value: &impl Serialize) -> Result<(), &'static str> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).map_err(|_| "descriptor-create-failed")?;
    serde_json::to_writer(&mut file, value).map_err(|_| "descriptor-write-failed")?;
    file.write_all(b"\n")
        .map_err(|_| "descriptor-write-failed")?;
    file.sync_all().map_err(|_| "descriptor-sync-failed")
}

fn inspect_descriptor(path: &str) -> Result<(), &'static str> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| "descriptor-unavailable")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 16_384 {
        return Err("descriptor-invalid");
    }
    let file = std::fs::File::open(path).map_err(|_| "descriptor-unavailable")?;
    let value: RecoveryRootDescriptorV1 =
        serde_json::from_reader(file).map_err(|_| "descriptor-invalid")?;
    validate_descriptor(&value).map_err(|_| "descriptor-invalid")?;
    output(&value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_shape_never_accepts_a_secret_argument() {
        assert_eq!(
            run(&["approve-stdin".into(), "phrase".into()]),
            Err("usage-invalid")
        );
        assert_eq!(
            run(&["verify".into(), "secret".into()]),
            Err("usage-invalid")
        );
    }

    #[test]
    fn public_number_parser_is_closed() {
        assert_eq!(number("42"), Ok(42));
        assert_eq!(number("-1"), Err("number-invalid"));
    }

    #[test]
    fn descriptor_file_is_newline_terminated_and_never_overwritten() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("descriptor.json");
        write_descriptor(
            path.to_str().expect("path"),
            &serde_json::json!({"revision": 1}),
        )
        .expect("first write");
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            "{\"revision\":1}\n"
        );
        assert_eq!(
            write_descriptor(
                path.to_str().expect("path"),
                &serde_json::json!({"revision": 2})
            ),
            Err("descriptor-create-failed")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path)
                    .expect("metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
}
