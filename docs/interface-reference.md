# crowsi-owner-recovery-provider interface reference

Use the [usage guide](getting-started.md) for the first steps. This reference preserves the current interface details and operational limits. Run command examples from the repository root, after preparing the exact declared dependencies and registered configuration.

## Native protocol

`create DESCRIPTOR_PATH RECOVERY SUBJECT PROVIDER REVISION OBSERVED` creates the
public descriptor at a new owner-only file and writes the provisioned receipt
as JSON to stdout. It never overwrites an existing descriptor. It displays the phrase only when
stderr is an attached terminal, so redirected or service logs fail closed.

`verify-stdin RECOVERY SUBJECT PROVIDER REVISION OBSERVED` and
`approve-stdin APPROVAL BINDING_SHA256 KEY_ID ISSUED EXPIRES` accept the phrase
only through protected stdin and reject an interactive, echoing stdin. Native
callers must obtain it with an OS-protected secret prompt. These commands never
accept the phrase through JSON, argv, environment variables, or browser input.

## Word-list provenance

`assets/bip39-english.txt` is the standard English list from the BIP-0039
specification. The fixed SHA-256 of the newline-delimited file is recorded in
the provider release test; changing its ordering is a cryptographic profile change,
not a localization update.
