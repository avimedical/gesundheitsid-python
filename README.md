# gesundheitsid-python

An OpenID Federation relying party for Germany's **GesundheitsID**, in Python.

GesundheitsID is the digital identity every German statutory health insurer must issue to its members on request. Applications authenticate users against the insurer's *sectoral IdP* through the gematik **TI-Föderation** — an OpenID Federation 1.0 trust network with gematik's Federation Master as the trust anchor.

Implementations already exist in [Java](https://github.com/oviva-ag/ehealthid-relying-party) and [C#](https://github.com/BAYOOMED/TI-RelyingParty). This is the Python one.

> **Status: alpha.** Under active development. Not yet used in production. See [Roadmap](#roadmap).

## What this is not

GesundheitsID is **TI 2.0** — pure internet. You do **not** need a Konnektor, an SMC-B card, or a TI-VPN to use it. Those are TI 1.0 components, required only for ePA, eRezept, KIM and VZD. If someone tells you a hardware procurement is a prerequisite for GesundheitsID, they are describing a different product.

What you *do* need: a publicly reachable HTTPS endpoint, four P-256 keypairs, and a registration with gematik's Federation Master.

## Packages

| Package | What it does |
|---|---|
| `gesundheitsid` | Framework-agnostic core: entity statements, trust-chain validation, Federation Master client, JOSE, PAR/token, mTLS. No web framework. |
| `gesundheitsid_cli` | `keygen` (the four P-256 keypairs) and `fedreg` (the gematik registration XML). |

A Django integration package is planned; see [Roadmap](#roadmap).

## Install

```shell
uv add gesundheitsid
```

## Quick start

### 1. Generate keys

A relying party needs four P-256 keypairs. Three are published in your entity statement and registered with gematik; the fourth signs tokens for your own downstream clients.

```shell
uv run gesundheitsid-cli keygen --issuer-uri=https://gesundheitsid.example.com --out-dir=./secrets
```

Never commit these. Load them from your secret manager at runtime.

### 2. Publish an entity statement

Serve the signed JWT at `<issuer-uri>/.well-known/openid-federation` with
`Content-Type: application/entity-statement+jwt`. It must be fetchable from the public
internet, without a bot challenge — gematik's Federation Master, the insurer IdPs and
the testsuites all fetch it non-interactively.

```python
from gesundheitsid.federation import build_entity_statement

jwt = build_entity_statement(
    issuer="https://gesundheitsid.example.com",
    federation_master="https://app-test.federationmaster.de",
    redirect_uris=["https://gesundheitsid.example.com/auth/callback"],
    scopes=["openid", "urn:telematik:display_name", "urn:telematik:versicherter"],
    ...
)
```

### 3. Register with gematik

Publishing the entity statement is a **precondition** for registration, not a consequence of it.

```shell
uv run gesundheitsid-cli fedreg \
    --environment=TU \
    --issuer-uri=https://gesundheitsid.example.com \
    --member-id=FDexample0112TU \
    --contact-email=you@example.com
```

Email the resulting XML to `idp-registrierung@gematik.de`. Expect about five business days.

Every later change to your entity statement must be re-notified to gematik. This is easy
to forget — wire it into your deployment checklist.

## Environments

| gematik environment | Federation Master | Reference sectoral IdP |
|---|---|---|
| TU (Testumgebung) | `app-test.federationmaster.de` | `gsi.dev.gematik.solutions` |
| RU (Referenzumgebung) | `app-ref.federationmaster.de` | `gsi-ref.dev.gematik.solutions` |
| PU (Produktivumgebung) | `app.federationmaster.de` | the insurers themselves |

gematik's reference IdP is IP-allowlisted; request access, or an `X-Auth-Header`, from
`diga@gematik.de`.

**You do not need any of that to develop.** gematik publishes
[`app-gemSekIdp`](https://github.com/gematik/app-gemSekIdp) (Apache-2.0) containing both a
reference sectoral IdP *and* a minimal Federation Master, so a complete federation runs
offline:

```shell
docker compose up -d          # gsi-fedmaster + gsi-server
uv run pytest -m integration
```

## Development

```shell
uv sync
uv run ruff check . && uv run ruff format --check . && uv run pytest
```

## Roadmap

- [x] Core: entity statements, trust chain, Federation Master client, JOSE, mTLS
- [x] CLI: keygen and registration XML
- [ ] PAR + token exchange against sectoral IdPs
- [ ] `django-gesundheitsid`: views, models, pluggable store (in-memory / database / Redis)
- [ ] Downstream OIDC provider face, so Keycloak and friends can broker to it

## Specifications

Written from [gemSpec_IDP_Sek, gemSpec_IDP_FD and gemSpec_IDP_FedMaster](https://gemspec.gematik.de/),
[OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html), RFC 9126 (PAR),
RFC 7636 (PKCE) and RFC 7515/7516/7517/7518 (JOSE).

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
