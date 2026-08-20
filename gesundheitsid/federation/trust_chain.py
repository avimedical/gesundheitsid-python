"""Resolves and verifies the trust chain from a sectoral IdP up to the Federation Master.

THE rule this module exists to enforce: after resolution, an IdP's *authoritative* keys
and metadata are the ones from the Federation Master's subordinate statement about it --
never the ones from the IdP's own self-signed entity configuration. Self-signing only
proves the IdP controls those keys; it says nothing about whether gematik vouches for
them. The subordinate statement is what the Federation Master actually vouches for, and
if it ever disagrees with what the IdP publishes about itself (different keys, different
metadata), the subordinate statement wins -- an IdP cannot self-declare its way into more
trust than gematik granted it.

SSRF WARNING: `subject_issuer` is normally taken from the `idp_iss` authorization-request
parameter, which is attacker-controlled. Resolving a chain therefore makes a server-side
GET to a URL the caller supplied. `_validate_subject_issuer` rejects the obviously unsafe
shapes (non-https, userinfo, query, fragment), but that is not an SSRF defence on its own
-- it does nothing about an https URL pointing at an internal host. **Callers must
validate `idp_iss` against `FederationMasterClient.list_idps()` before calling this.**
That list is the federation's own allowlist, it is signed by the Federation Master, and
it is the only thing that actually constrains where this function will connect.

`signed_jwks_uri` (found against a real sectoral IdP, not anticipated by any fixture):
`metadata.openid_provider.signed_jwks_uri` names a SEPARATE endpoint serving a JWT (typ
`jwk-set+json`) whose payload is a JWKS of the IdP's *operational* keys -- confirmed
against a real gsi-server, its actual id_token-signing key (`kid=puk_fed_idp_token`) is
NOT the key in the subordinate statement's own `jwks` (`kid=puk_idp_sig`, which only
signs the entity statement/entity configuration themselves). Without fetching and
verifying `signed_jwks_uri`, `parse_id_token` cannot verify a real id_token at all --
every key it would try comes from the wrong keyset. The JWT at `signed_jwks_uri` is
itself signed by the subordinate statement's key (`puk_idp_sig` in the example above),
which is what makes its payload trustworthy without yet another out-of-band pin: it is
one more hop of the same chain, not a new root.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from gesundheitsid.crypto import load_jwks, plain_client, verify_compact
from gesundheitsid.errors import CryptoError, EntityStatementError, FederationMasterError, TrustChainError
from gesundheitsid.federation.entity_statement import verify_self_signed
from gesundheitsid.federation.fedmaster import FederationMasterClient

__all__ = ["TrustChain", "resolve_trust_chain"]


@dataclass(frozen=True)
class TrustChain:
    """The result of a resolved, verified trust chain for `subject`.

    `signing_keys` and `metadata` come from the Federation Master's subordinate
    statement, not `subject`'s own self-signed entity configuration -- see the module
    docstring. `signing_keys` additionally folds in `metadata.openid_provider.
    signed_jwks_uri`'s keys when the subject publishes one (also documented in the
    module docstring) -- both are "chain-resolved": the subordinate statement is vouched
    for directly by the Federation Master, and a `signed_jwks_uri` payload is vouched for
    by the subordinate statement's own key, never by anything the subject merely asserts
    unverified about itself.
    """

    subject: str
    trust_anchor: str
    signing_keys: dict
    metadata: dict
    expires_at: int


def resolve_trust_chain(
    *,
    subject_issuer: str,
    fedmaster_client: FederationMasterClient,
    http_client: httpx.Client | None = None,
    now: int | None = None,
) -> TrustChain:
    """Resolve and verify the trust chain from `subject_issuer` to the Federation Master
    behind `fedmaster_client`.

    `now` is injectable so expiry checks are deterministic in tests -- no `sleep` needed
    to exercise the expired-statement failure paths.
    """
    _validate_subject_issuer(subject_issuer)
    current = now if now is not None else int(time.time())
    client = http_client if http_client is not None else plain_client()
    owns_client = http_client is None
    try:
        return _resolve(subject_issuer, fedmaster_client, client, current)
    finally:
        if owns_client:
            client.close()


def _validate_subject_issuer(issuer: str) -> None:
    """Reject issuer URLs that are unsafe to fetch or that cannot be a federation entity.

    This is a shape check, not an SSRF defence -- see the module docstring. It exists so
    that the obviously-wrong cases fail before any network call, and because an entity
    identifier carrying a query string or fragment cannot round-trip through the
    `/.well-known/openid-federation` path concatenation below without silently changing
    meaning.
    """
    parts = urlsplit(issuer)
    if parts.scheme != "https":
        raise TrustChainError(f"issuer must be an https URL, got {issuer!r}")
    if not parts.netloc:
        raise TrustChainError(f"issuer has no host, got {issuer!r}")
    if parts.username or parts.password:
        raise TrustChainError(f"issuer must not contain userinfo, got {issuer!r}")
    if parts.query or parts.fragment:
        raise TrustChainError(f"issuer must not contain a query string or fragment, got {issuer!r}")
    if issuer.endswith("/"):
        raise TrustChainError(f"issuer must not end with a trailing slash, got {issuer!r}")


def _resolve(
    subject_issuer: str, fedmaster_client: FederationMasterClient, client: httpx.Client, now: int
) -> TrustChain:
    # Step 1: fetch and verify the leaf's own entity configuration. It is self-signed, so
    # this only proves the leaf controls the keys in its own payload -- it proves nothing
    # about whether the leaf should be trusted. See entity_statement.verify_self_signed.
    config_url = f"{subject_issuer}/.well-known/openid-federation"
    try:
        response = client.get(config_url)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise TrustChainError(
            f"could not reach entity configuration for '{subject_issuer}' at {config_url}: {exc}"
        ) from exc

    try:
        self_signed = verify_self_signed(response.text)
    except EntityStatementError as exc:
        raise TrustChainError(
            f"'{subject_issuer}' self-signed entity configuration failed verification: {exc}"
        ) from exc

    # Step 6 (self-signed half): iss == sub == subject_issuer, and not expired.
    if self_signed.iss != self_signed.sub or self_signed.iss != subject_issuer:
        raise TrustChainError(
            f"'{subject_issuer}' entity configuration has inconsistent iss/sub "
            f"(iss={self_signed.iss!r}, sub={self_signed.sub!r}, expected {subject_issuer!r})"
        )
    if now > self_signed.exp:
        raise TrustChainError(f"'{subject_issuer}' entity configuration has expired (exp={self_signed.exp}, now={now})")

    # Step 2: the Federation Master's own entity configuration, verified by
    # `fedmaster_client` against the pinned trust-anchor JWKS supplied by its caller --
    # never against keys embedded in the response itself, which would be circular.
    try:
        fm_statement = fedmaster_client.entity_configuration()
    except FederationMasterError as exc:
        raise TrustChainError(f"could not verify the Federation Master's entity configuration: {exc}") from exc

    # Step 5: the leaf must actually name this trust anchor as an authority.
    if fm_statement.iss not in self_signed.authority_hints:
        raise TrustChainError(
            f"'{subject_issuer}' does not list '{fm_statement.iss}' in its authority_hints "
            f"(has {self_signed.authority_hints!r})"
        )

    # Step 3: the subordinate statement about the leaf, signed by the now-verified FM.
    try:
        subordinate = fedmaster_client.fetch_subordinate_statement(subject_issuer)
    except FederationMasterError as exc:
        raise TrustChainError(f"could not fetch subordinate statement for '{subject_issuer}': {exc}") from exc

    # Step 6 (subordinate half): iss == FM, sub == leaf, and not expired.
    if subordinate.iss != fm_statement.iss:
        raise TrustChainError(
            f"subordinate statement for '{subject_issuer}' has iss={subordinate.iss!r}, "
            f"expected the Federation Master's iss={fm_statement.iss!r}"
        )
    if subordinate.sub != subject_issuer:
        raise TrustChainError(
            f"subordinate statement sub={subordinate.sub!r} does not match subject '{subject_issuer}'"
        )
    if now > subordinate.exp:
        raise TrustChainError(
            f"subordinate statement for '{subject_issuer}' has expired (exp={subordinate.exp}, now={now})"
        )

    # Step 4: keys come from the subordinate statement -- that is the property this module
    # exists to enforce (see module docstring) -- PLUS, if the subject publishes one, the
    # keys from its signed_jwks_uri, verified against the subordinate statement's own key
    # (see module docstring's `signed_jwks_uri` note for why a real sectoral IdP's actual
    # id_token-signing key lives there and nowhere else this module ever sees).
    #
    # Metadata is different, and taking it from the subordinate statement alone was wrong.
    # In OpenID Federation the superior's `metadata` is an overlay on top of what the leaf
    # publishes about itself, not a replacement for it: gematik's reference Federation Master
    # returns only `{"openid_provider": {"client_registration_types_supported": ["automatic"]}}`,
    # while the authorization, token and PAR endpoints live in the IdP's own entity
    # configuration. Replacing wholesale therefore produced a TrustChain with no endpoints at
    # all, so PAR had nothing to call. Merge with the superior winning per key, which keeps the
    # superior authoritative wherever it actually says something.
    metadata = _merge_metadata(self_signed.metadata, subordinate.metadata)
    signing_keys = _resolve_signing_keys(subordinate.jwks, metadata, client, subject_issuer)

    return TrustChain(
        subject=subject_issuer,
        trust_anchor=fm_statement.iss,
        signing_keys=signing_keys,
        metadata=metadata,
        expires_at=subordinate.exp,
    )


def _resolve_signing_keys(subordinate_jwks: dict, metadata: dict, client: httpx.Client, subject_issuer: str) -> dict:
    """`subordinate_jwks`, plus the keys from `metadata.openid_provider.signed_jwks_uri`
    when the subject publishes one -- see the module docstring's `signed_jwks_uri` note.

    Absent `signed_jwks_uri`, returns `subordinate_jwks` unchanged -- every fixture in
    this project's own unit tests predates this and has no such URI, so this stays a
    no-op for all of them; it was only ever missing against a REAL sectoral IdP.
    """
    provider_metadata = metadata.get("openid_provider") or {}
    signed_jwks_uri = provider_metadata.get("signed_jwks_uri")
    if not signed_jwks_uri:
        return subordinate_jwks

    try:
        response = client.get(signed_jwks_uri)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise TrustChainError(
            f"could not fetch signed_jwks_uri for '{subject_issuer}' at {signed_jwks_uri}: {exc}"
        ) from exc

    try:
        claims = verify_compact(response.text, load_jwks(subordinate_jwks))
    except CryptoError as exc:
        raise TrustChainError(f"signed_jwks_uri for '{subject_issuer}' failed verification: {exc}") from exc

    if claims.get("iss") != subject_issuer:
        raise TrustChainError(
            f"signed_jwks_uri for '{subject_issuer}' has iss={claims.get('iss')!r}, expected {subject_issuer!r}"
        )

    extra_keys = claims.get("keys")
    if not isinstance(extra_keys, list):
        raise TrustChainError(f"signed_jwks_uri for '{subject_issuer}' payload carries no 'keys' array")

    return {"keys": [*subordinate_jwks.get("keys", []), *extra_keys]}


def _merge_metadata(leaf: dict, superior: dict) -> dict:
    """Leaf metadata as the base, with the superior's entries overriding it per entity type
    and per key within an entity type.

    Deliberately a two-level merge and no deeper: entity type (`openid_provider`, ...) then
    the individual metadata parameters inside it, which is exactly how OpenID Federation
    layers these. Anything deeper would start merging the *values* of individual parameters,
    where a superior's list is meant to replace the leaf's, not extend it.
    """
    merged = {entity_type: dict(params) for entity_type, params in (leaf or {}).items()}
    for entity_type, params in (superior or {}).items():
        if isinstance(params, dict):
            merged.setdefault(entity_type, {}).update(params)
        else:
            merged[entity_type] = params
    return merged
