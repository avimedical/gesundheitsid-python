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
  that discovers gematik's actual Federation Master endpoints (`federation_fetch_
  endpoint`, `federation_list`, `.well-known/idp_list`) rather than assuming their
  shape, and `resolve_trust_chain` -- resolving and verifying the chain from a sectoral
  IdP up to gematik's Federation Master, with the subordinate statement always taking
  precedence over the IdP's own self-signed claims about itself. An optional
  `GESUNDHEITSID["FEDERATION_MASTER_URL"]` setting lets a deployment point at a
  Federation Master other than the closed TU|RU|PU enum (e.g. a local reference
  federation); production config cannot drift onto it without an explicit setting.
- **OIDC protocol layer** (`gesundheitsid.oidc`): talking to a sectoral IdP once a trust
  chain is resolved. PKCE (RFC 7636 S256) verifier/challenge pairs plus CSRF `state` and
  ID-token-replay `nonce` generation, all drawn from `secrets`, never `random`; RFC 9126
  Pushed Authorization Requests and the resulting browser redirect; authorization-code
  exchange at the token endpoint; and sectoral IdP ID token decrypt/verify/validate/
  extract into a `GesundheitsIdIdentity` (decrypt, then verify the inner JWS against
  `trust_chain.signing_keys` -- never the IdP's own self-declared keys --, then validate
  `iss`/`aud`/`nonce`/`exp`, then hard-reject anything but `acr=gematik-ehealth-loa-
  high`). PAR and token calls both go over the mTLS client with `self_signed_tls_client_
  auth`, never a `client_secret` or `client_assertion`.
- **Django integration** (`django_gesundheitsid`, optional `django` extra): turns the
  framework-agnostic core into a runnable relying-party service -- the federation-facing
  entity statement/sectoral-IdP-list endpoints, the downstream authorization<->callback
  pair that talks to a sectoral IdP, and this relying party's own downstream OIDC
  provider face (discovery, token, jwks) for its own clients, with `private_key_jwt`
  client assertions at `/auth/token` verified via Authlib's RFC 7523 primitives. Three
  `Store` backends (in-memory, database, Redis) behind one pluggable protocol;
  `DatabaseStore.pop()` is correct even on SQLite (whose `select_for_update()` is a
  silent no-op) because it is decided by the `DELETE`'s affected-row count, not the
  preceding `SELECT`. The downstream `sub` is a pairwise HMAC-SHA256 of the KVNR under a
  per-deployment `PAIRWISE_PEPPER` (never the raw KVNR, never a globally-correlatable
  identifier), pinned by a cross-language test vector; every minted downstream id_token
  carries a per-mint `jti` so a consumer such as avimedical's Keycloak grant can enforce
  single use.
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
  OIDC data-plane tests can run end to end -- PAR through token exchange through
  `parse_id_token` -- against a real counterparty instead of respx mocks alone, without
  depending on gematik's IP-allowlisted reference environment. Federation members are
  published on stable `.gsi.test` hostnames (not `localhost`, which resolves to a
  different loopback inside each container) with the token/PAR endpoints correctly
  advertised over TLS, and this relying party registers its own signing key with the
  local Federation Master rather than reusing gematik's keyless reference RP.

### Fixed

Real defects found only once the OIDC data plane was exercised against a real sectoral
IdP instead of respx-mocked fixtures that could previously only ever agree with
themselves:

- `decrypt_id_token` now tolerates gemSpec_IDP_Sek's non-standard `version` JWE header
  member instead of rejecting every real id_token outright.
- `parse_id_token` now resolves the id_token's actual signing key via the entity
  statement's `signed_jwks_uri` -- a separate keyset from the one used to verify the
  entity statement/configuration themselves -- instead of the wrong keys, which would
  have failed verification against every real sectoral IdP.
- `verify_compact`'s JWS header size cap is raised from joserfc's 512-byte default to
  8 KiB, enough for a real signing key's `x5c` certificate chain header.
- PAR and token endpoints reject a non-object JSON body (list/scalar) with a
  `ProtocolError` instead of raising a bare `AttributeError`.

[Unreleased]: https://github.com/avimedical/gesundheitsid-python/commits/main
