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
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from gesundheitsid.crypto import plain_client
from gesundheitsid.errors import EntityStatementError, FederationMasterError, TrustChainError
from gesundheitsid.federation.entity_statement import verify_self_signed
from gesundheitsid.federation.fedmaster import FederationMasterClient

__all__ = ["TrustChain", "resolve_trust_chain"]


@dataclass(frozen=True)
class TrustChain:
    """The result of a resolved, verified trust chain for `subject`.

    `signing_keys` and `metadata` come from the Federation Master's subordinate
    statement, not `subject`'s own self-signed entity configuration -- see the module
    docstring.
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

    # Step 4: THE authoritative keys/metadata are the subordinate statement's, never the
    # leaf's own self-signed ones. See module docstring.
    return TrustChain(
        subject=subject_issuer,
        trust_anchor=fm_statement.iss,
        signing_keys=subordinate.jwks,
        metadata=subordinate.metadata,
        expires_at=subordinate.exp,
    )
