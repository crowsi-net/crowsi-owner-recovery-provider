# crowsi-owner-recovery-provider

Create and verify owner-recovery proofs through the fixed recovery profile.

## What you can do

- Use the released mnemonic and signing-key derivation rules.
- Verify recovery evidence through a narrow provider interface.

## Current scope

Recovery material is private registration data. The identity authority still decides whether a recovery operation is permitted.

Package distribution is not activated by this documentation. Use the checked-in source and the declared dependency versions; published availability must be verified separately.

## Getting started

Install Rust 1.97 or newer and make the declared dependencies available. Use the configured private registry when a dependency is not distributed publicly. Run from this repository:

```sh
cargo test --locked
```

## Documentation and source

[Interface reference](docs/interface-reference.md)

[Usage guide](docs/getting-started.md)

[Implementation and public interfaces](src) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)
