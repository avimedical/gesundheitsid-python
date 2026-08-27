"""The federation trust plane, against gematik's own reference implementation.

Each test here corresponds to something a mocked counterparty structurally cannot check: not
"does our client behave as we specified", but "does our specification match what gematik's code
actually serves". Every assertion below is one that passed in unit-test form while being wrong
in production.
"""

from __future__ import annotations

import httpx
import pytest

from gesundheitsid.errors import TrustChainError
from gesundheitsid.federation import FederationMasterClient, resolve_trust_chain
from tests.integration.conftest import FEDMASTER_URL, IDP_URL

pytestmark = pytest.mark.integration


def test_federation_master_advertises_the_endpoints_this_client_depends_on(
    fedmaster_client: FederationMasterClient,
) -> None:
    """The three endpoints must be DISCOVERABLE, because their paths are not guessable.

    gematik serves `/federation_fetch_endpoint`, `/federation_list` and
    `/.well-known/idp_list`. This client used to assume `/federation/fetch`,
    `/federation/list` and `/federation/listidps` -- a layout that exists nowhere. Asserting
    the metadata is present is what keeps the client on discovery rather than back on a guess.
    """
    statement = fedmaster_client.entity_configuration()

    assert statement.claims["iss"] == FEDMASTER_URL
    federation_entity = statement.claims["metadata"]["federation_entity"]
    for endpoint in ("federation_fetch_endpoint", "federation_list_endpoint", "idp_list_endpoint"):
        assert federation_entity.get(endpoint), f"Federation Master advertises no {endpoint}"


def test_list_idps_parses_the_real_signed_idp_list(fedmaster_client: FederationMasterClient) -> None:
    """The insurer picker, and the allowlist that constrains `idp_iss` before any server-side
    fetch. A parse failure here is not a cosmetic bug: `views.auth` refuses every login when
    this raises, and it did raise -- the real payload keys its array `idp_entity`, not `idps`.
    """
    idps = fedmaster_client.list_idps()

    assert idps, "the reference federation should publish at least its own gsi-server"
    issuers = [idp.issuer for idp in idps]
    assert IDP_URL in issuers, f"{IDP_URL} missing from {issuers}"
    gsi = next(idp for idp in idps if idp.issuer == IDP_URL)
    assert gsi.organization_name


def test_list_members_includes_the_sectoral_idp(fedmaster_client: FederationMasterClient) -> None:
    assert IDP_URL in fedmaster_client.list_members()


def test_subordinate_statement_is_issued_by_the_federation_master_about_the_idp(
    fedmaster_client: FederationMasterClient,
) -> None:
    """The subordinate statement is what gematik actually vouches for, and it is verified
    against the Federation Master's own signing keys -- so reaching this assertion at all
    means a real ES256 signature over a real statement verified."""
    statement = fedmaster_client.fetch_subordinate_statement(IDP_URL)

    assert statement.claims["iss"] == FEDMASTER_URL
    assert statement.claims["sub"] == IDP_URL
    assert statement.jwks["keys"], "subordinate statement carries no keys to trust"


def test_trust_chain_resolves_and_yields_usable_idp_metadata(
    fedmaster_client: FederationMasterClient, http_client: httpx.Client
) -> None:
    """The whole point of resolution: authoritative keys AND an IdP you can actually talk to.

    Taking metadata from the subordinate statement alone -- which this code did -- yields a
    chain with no authorization, token or PAR endpoint at all, because gematik's subordinate
    statement carries only a small policy overlay. PAR then has nothing to call, so every
    login fails after a chain that looked perfectly valid.
    """
    chain = resolve_trust_chain(subject_issuer=IDP_URL, fedmaster_client=fedmaster_client, http_client=http_client)

    assert chain.subject == IDP_URL
    assert chain.trust_anchor == FEDMASTER_URL

    # chain.signing_keys is a real SUPERSET of the subordinate statement's own jwks, because
    # gsi-server publishes a signed_jwks_uri whose key (puk_fed_idp_token) actually signs the
    # id_token - not the subordinate statement's puk_idp_sig. An equality assertion would be wrong.
    subordinate = fedmaster_client.fetch_subordinate_statement(IDP_URL)
    subordinate_kids = {key["kid"] for key in subordinate.jwks["keys"]}
    chain_kids = {key["kid"] for key in chain.signing_keys["keys"]}
    assert subordinate_kids <= chain_kids, "chain.signing_keys must never drop a key the fedmaster vouches for"
    assert chain_kids > subordinate_kids, (
        "expected signed_jwks_uri to contribute at least one key beyond the subordinate statement's own"
    )

    # Metadata: the leaf's own endpoints survive the merge...
    provider = chain.metadata["openid_provider"]
    for endpoint in ("authorization_endpoint", "token_endpoint", "pushed_authorization_request_endpoint"):
        assert provider.get(endpoint), f"resolved chain has no {endpoint}; PAR would have nothing to call"

    # ...and the superior's overlay still wins where it says anything.
    superior_overlay = subordinate.claims["metadata"]["openid_provider"]
    for key, value in superior_overlay.items():
        assert provider[key] == value, f"superior's {key} was lost in the merge"


def test_trust_chain_refuses_an_issuer_the_federation_master_does_not_vouch_for(
    fedmaster_client: FederationMasterClient, http_client: httpx.Client
) -> None:
    """A syntactically fine https issuer that is simply not in this federation must fail
    closed. Uses the Federation Master's own URL as the subject: it is definitely reachable
    and definitely serves an entity statement, so a pass here cannot be an artefact of the
    host being unreachable."""
    with pytest.raises(TrustChainError):
        resolve_trust_chain(subject_issuer=FEDMASTER_URL, fedmaster_client=fedmaster_client, http_client=http_client)


def test_trust_chain_still_refuses_a_non_https_issuer(
    fedmaster_client: FederationMasterClient, http_client: httpx.Client
) -> None:
    """The reason this whole setup runs behind a TLS terminator.

    gematik's services are plain HTTP, and the temptation was to relax this check for local
    testing. This asserts the check is still there, against the very federation that would
    have benefited from the exception -- `http://localhost:8085` is genuinely reachable and
    genuinely serves the same entity statement, and must still be refused.
    """
    with pytest.raises(TrustChainError, match="https"):
        resolve_trust_chain(
            subject_issuer="http://localhost:8085", fedmaster_client=fedmaster_client, http_client=http_client
        )
