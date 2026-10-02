# Using crowsi-owner-recovery-provider

Create and verify owner-recovery proofs through the fixed recovery profile.

## Before you start

Recovery material is private registration data. The identity authority still decides whether a recovery operation is permitted.

## First steps

Run from the repository root:

```sh
cargo test --locked
```

## How to assess the result

- Use the released mnemonic and signing-key derivation rules.
- Verify recovery evidence through a narrow provider interface.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
