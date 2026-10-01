# crowsi-owner-recovery-provider

Owner-local recovery provider for the iHAT identity root. It implements the
frozen `bip39-ed25519-v1` profile: 256-bit entropy, the 24-word English BIP39
list and checksum, PBKDF2-HMAC-SHA512 with 2048 rounds and a domain-separated
Ed25519 recovery approval key.

The mnemonic is returned only as a zeroizing value to the native ceremony. It
is never serialized, accepted through JSON, argv or an environment variable,
stored by Hatter, sent to a HAT/model/browser, or included in a receipt. The
only public outputs are a root descriptor and a signed evidence document with
a maximum lifetime of 120 seconds.

The mnemonic approval remains independent from the fresh, device-bound user
verification required by iHAT. A phrase alone cannot restore or move an owner.

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
