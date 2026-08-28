# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.0] - 2026-08-28

Found by validating a generated registration against gematik's real `RP_register.xsd` and
comparing it to the entity statement a deployed relying party actually serves.

### Fixed

- The entity statement now publishes `metadata.openid_relying_party.organization_name` and
  `metadata.federation_entity.name`. gematik's `RP_register.xsd` annotates `<organisationsname>`
  as covering the first, and `<fachdienstname>` as covering `openid_relying_party.client_name`
  **and** `federation_entity.name` — which it requires to be identical. Both were absent, so a
  registration declared two values gematik could not find in the statement it fetches.
  `federation_entity.name` is set from `client_name` rather than a new argument, so the two
  cannot drift apart. `federation_entity.organization_name` is unchanged: OpenID Federation 1.0
  defines it there, and it is now published in both places.
- `gesundheitsid-cli fedreg` no longer requires `--member-id`. gematik assigns the Member-ID on
  registration and asks for the tag present but empty, so requiring it contradicted the process
  it generates for.
- `fedreg`'s wiki URL no longer carries a trailing slash, which made gematik's own wiki return
  404. That URL is interpolated into the disclaimer comment of every generated registration, so
  the broken link was served to whoever at gematik opened the file.

### Changed

- Comments throughout are capped at three lines. No behaviour changed.

## [0.2.0] - 2026-08-21

First release informed by talking to gematik's real Federation Masters rather than only to a
local reference federation. Every change below came out of that.

### Added

- `SectoralIdp` now carries `pkv` and `user_type_supported`, and `/api/v1/idps` passes both
  through. gematik publishes them on every entry in TU, RU and PU, and they were previously
  parsed away. `pkv` is the one that matters today: 41 of RU's 116 entries and 23 of PU's 129
  are private insurers, and an insurer picker that cannot tell them apart cannot explain to a
  privately insured person why their experience differs. They are passed through rather than
  filtered, because whether to hide, label or ignore them is a product decision.
- `DEFAULT_TIMEOUT` on `mtls_client()` and `plain_client()`. Neither set a timeout, so every
  call inherited httpx's default -- a library default rather than a decision. Connect 5s,
  read 15s, overridable per call.
- `gesundheitsid-cli fedreg` requests `urn:telematik:email` by default. The scope list is part
  of the gematik registration, so adding it later means re-submitting; every sectoral IdP
  sampled in TU and RU advertises it.

### Fixed

- One malformed `idp_list` entry no longer blocks every login. `_parse_idps` raised on any entry
  missing `iss`/`organization_name`, and the caller uses that same list as its SSRF allowlist,
  so a single bad row in a 116-entry list would have taken down logins for every insurer rather
  than the broken one. Bad rows are skipped and logged. An empty result from a non-empty list
  still raises -- that is gematik changing the entry shape, not one bad row, and silently
  returning nothing would reject every login with a message pointing at the wrong cause.

## [0.1.0] - 2026-08-21

First public release. The library implements the relying-party half of gematik's
TI-Foederation end to end, and its OIDC data plane has been exercised against gematik's
own reference sectoral IdP rather than against mocks alone. It has not yet been
registered with a gematik Federation Master in TU, RU or PU, so treat it as alpha: the
wire contracts below are verified, the production operating experience behind them is
not.

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

[Unreleased]: https://github.com/avimedical/gesundheitsid-python/compare/v0.2.0...main
[0.2.0]: https://github.com/avimedical/gesundheitsid-python/releases/tag/v0.2.0
[0.1.0]: https://github.com/avimedical/gesundheitsid-python/releases/tag/v0.1.0
