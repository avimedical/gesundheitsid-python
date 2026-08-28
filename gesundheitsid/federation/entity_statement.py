"""OpenID Federation entity statements: the relying party's own entity configuration, and
parsing/verification for statements published by anyone else in the federation.

An entity statement is just a signed JWT with a fixed set of required claims (`iss`,
`sub`, `iat`, `exp`, `jwks`) plus an OpenID-Federation-specific `metadata` object. This
module never decides on its own whether a statement's *signer* should be trusted --
`parse_entity_statement` is explicitly unverified, and `verify_self_signed` only proves
an entity controls the keys it published about itself. Anchoring trust in the Federation
Master is `trust_chain.resolve_trust_chain`'s job, not this module's.
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from dataclasses import dataclass

from joserfc.errors import JoseError
from joserfc.jwk import ECKey, KeySet

from gesundheitsid.crypto import assert_p256, load_jwks, public_jwks, sign_compact, unverified_claims, verify_compact
from gesundheitsid.errors import CryptoError, EntityStatementError

__all__ = [
    "EntityStatement",
    "build_entity_statement",
    "parse_entity_statement",
    "verify_entity_statement",
    "verify_self_signed",
]

#: header `typ` every entity statement in this federation is published with
_ENTITY_STATEMENT_TYP = "entity-statement+jwt"

#: claims OpenID Federation 1.0 requires on every entity statement, self-signed or not
_REQUIRED_CLAIMS = ("iss", "sub", "iat", "exp", "jwks")


@dataclass(frozen=True)
class EntityStatement:
    """A parsed entity statement (self-signed entity configuration, or subordinate
    statement). Fields are typed views over `claims`; `claims` itself is kept so callers
    needing something this dataclass does not surface can still get at the raw payload.
    """

    claims: dict
    iss: str
    sub: str
    iat: int
    exp: int
    jwks: dict
    authority_hints: list[str]
    metadata: dict

    @property
    def relying_party_metadata(self) -> dict | None:
        """`metadata.openid_relying_party`, or None if this statement does not carry one."""
        return self.metadata.get("openid_relying_party")

    @property
    def openid_provider_metadata(self) -> dict | None:
        """`metadata.openid_provider`, or None if this statement does not carry one."""
        return self.metadata.get("openid_provider")

    @classmethod
    def from_claims(cls, claims: dict) -> EntityStatement:
        missing = [name for name in _REQUIRED_CLAIMS if name not in claims]
        if missing:
            raise EntityStatementError(f"entity statement is missing required claim(s): {', '.join(missing)}")
        return cls(
            claims=claims,
            iss=claims["iss"],
            sub=claims["sub"],
            iat=claims["iat"],
            exp=claims["exp"],
            jwks=claims["jwks"],
            authority_hints=list(claims.get("authority_hints", [])),
            metadata=claims.get("metadata", {}),
        )


def parse_entity_statement(token: str) -> EntityStatement:
    """Decode `token`'s claims WITHOUT verifying its signature.

    Named `parse_*`, not `verify_*`, on purpose: the result must never be used to make a
    trust decision. Only useful for reading `iss`/`sub`/`jwks` before you know which key
    should verify the token -- e.g. reading the `jwks` a self-signed statement carries so
    `verify_self_signed` can then verify it against exactly those keys.
    """
    try:
        claims = unverified_claims(token)
    except CryptoError as exc:
        raise EntityStatementError(f"could not parse entity statement: {exc}") from exc
    return EntityStatement.from_claims(claims)


def verify_entity_statement(token: str, keys: KeySet | ECKey) -> EntityStatement:
    """Verify `token`'s ES256 signature against `keys` and return its parsed claims.

    `keys` must already be established as trustworthy by the caller -- this function does
    no trust-anchoring of its own, it only checks the cryptographic signature.
    """
    try:
        claims = verify_compact(token, keys)
    except CryptoError as exc:
        raise EntityStatementError(f"entity statement signature verification failed: {exc}") from exc
    return EntityStatement.from_claims(claims)


def verify_self_signed(token: str) -> EntityStatement:
    """Verify a self-signed entity configuration against the JWKS carried in its own payload.

    This is trust-chain step 1: it proves the entity controls the keys it published about
    itself, and NOTHING else -- it says nothing about whether those keys, or the entity
    itself, should be trusted by anyone. An attacker can self-sign any claims they like
    about themselves. Actual trust comes only from a Federation Master subordinate
    statement, verified separately in `trust_chain.resolve_trust_chain`.
    """
    unverified = parse_entity_statement(token)
    try:
        keys = load_jwks(unverified.jwks)
    except (JoseError, KeyError, TypeError, ValueError) as exc:
        raise EntityStatementError(f"self-signed entity statement carries an invalid jwks: {exc}") from exc
    return verify_entity_statement(token, keys)


def build_entity_statement(
    *,
    issuer: str,
    signing_key: ECKey,
    federation_master: str,
    redirect_uris: Iterable[str],
    scopes: Iterable[str],
    client_name: str,
    contacts: Iterable[str],
    organization_name: str,
    mtls_client_key: ECKey,
    idtoken_enc_key: ECKey,
    lifetime_seconds: int = 86400,
    now: int | None = None,
) -> str:
    """Build and sign the relying party's own entity configuration.

    `mtls_client_key` must already carry an `x5c` entry (see `crypto.attach_x5c`) -- this
    function does not mint a certificate itself, it only assembles and signs the
    statement. `signing_key`, `mtls_client_key` and `idtoken_enc_key` are ordinarily three
    of the four keypairs from `crypto.KeyPurpose` (ENTITY_STATEMENT_SIG, MTLS_CLIENT,
    IDTOKEN_ENC respectively), which is also where their `use`/`alg` JWK members come
    from -- this function does not set or override them.
    """
    for key in (signing_key, mtls_client_key, idtoken_enc_key):
        assert_p256(key)

    mtls_entry = mtls_client_key.as_dict(private=False)
    if "x5c" not in mtls_entry:
        raise EntityStatementError("mtls_client_key must carry an x5c entry; see crypto.attach_x5c")

    current = now if now is not None else int(time.time())
    scope_list = list(scopes)

    claims = {
        "iss": issuer,
        "sub": issuer,
        "iat": current,
        "exp": current + lifetime_seconds,
        "jwks": public_jwks([signing_key]),
        "authority_hints": [federation_master],
        "metadata": {
            "openid_relying_party": {
                "client_name": client_name,
                # gematik's RP_register.xsd annotates <organisationsname> as covering exactly this
                # field, so a registration whose statement omits it declares a value gematik cannot
                # find. OpenID Federation also defines organization_name on federation_entity below.
                "organization_name": organization_name,
                "redirect_uris": list(redirect_uris),
                "response_types": ["code"],
                "grant_types": ["authorization_code"],
                "scope": " ".join(scope_list),
                "client_registration_types": ["automatic"],
                "token_endpoint_auth_method": "self_signed_tls_client_auth",
                "default_acr_values": ["gematik-ehealth-loa-high"],
                "id_token_signed_response_alg": "ES256",
                "id_token_encrypted_response_alg": "ECDH-ES",
                "id_token_encrypted_response_enc": "A256GCM",
                "jwks": {"keys": [mtls_entry, idtoken_enc_key.as_dict(private=False)]},
            },
            "federation_entity": {
                # <fachdienstname> covers openid_relying_party.client_name AND this, and the XSD
                # says the two "muessen inhaltlich zueinander ident" - hence client_name, not a
                # separate argument that could drift away from it.
                "name": client_name,
                "organization_name": organization_name,
                "contacts": list(contacts),
            },
        },
    }
    return sign_compact(claims, signing_key, typ=_ENTITY_STATEMENT_TYP)
