# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project intends to adhere to [Semantic Versioning](https://semver.org/) once a
first release is tagged.

## [Unreleased]

Nothing has shipped yet -- there is no tagged release, and no version below is a claim
that one exists. This section describes what is implemented on `main` today.

### Added

- **Crypto layer** (`gesundheitsid.crypto`): P-256 key generation, JWK/JWKS
  (de)serialization and self-signed mTLS certificates (`keys`); ES256 signing/
  verification and the sectoral IdP's ECDH-ES/A256GCM-wrapped-JWS ID token envelope
  (`jose`); an mTLS `httpx` client scoped to sectoral IdP PAR/token endpoints, kept
  strictly separate from the plain client used elsewhere (`mtls`).
- **Federation layer** (`gesundheitsid.federation`): building and parsing entity
  statements, verifying self-signed entity configurations, a `FederationMasterClient`
  for `federation/list`, `federation/listidps` and subordinate-statement lookups, and
  `resolve_trust_chain` -- resolving and verifying the chain from a sectoral IdP up to
  gematik's Federation Master, with the subordinate statement always taking precedence
  over the IdP's own self-signed claims about itself.
- **Storage layer** (`gesundheitsid.storage`): a pluggable `Store` protocol plus an
  `InMemoryStore` implementation for short-lived federation/OIDC state (authorization
  codes, PAR request URIs, cached entity statements), with an atomic `pop` to keep
  one-time values single-use.
- **Error hierarchy** (`gesundheitsid.errors`): a flat, payload-free exception tree
  (`CryptoError`, `EntityStatementError`, `TrustChainError`, `FederationMasterError`,
  `ProtocolError`) rooted at `GesundheitsIdError`.
- **CLI** (`gesundheitsid_cli`, installed as `gesundheitsid-cli`):
  - `keygen` -- generates the four P-256 keypairs a relying party needs (three
    published in the entity statement, one for signing tokens to downstream clients),
    plus the mTLS PEM pair.
  - `fedreg` -- generates the XML form for registering a Fachdienst with gematik's
    Federation Master.
- Local offline development federation via gematik's `app-gemSekIdp`
  (`docker-compose.yml`, documented in `docs/local-federation.md`), so trust-chain and
  federation tests can run without depending on gematik's IP-allowlisted reference
  environment.

[Unreleased]: https://github.com/avimedical/gesundheitsid-python/commits/main
