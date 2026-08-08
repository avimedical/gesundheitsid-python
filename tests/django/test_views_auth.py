"""`GET /auth`: the downstream authorization endpoint.

The `idp_iss` rejection test is the important one here -- `resolve_trust_chain` only
shape-checks `idp_iss` (see its module docstring), so validating it against
`list_idps()` in this view IS the SSRF control. Asserting the PAR route's call count
stays at zero is what actually proves the rejection happens before any server-side
fetch of an attacker-supplied `idp_iss`, not just that the response looks like an error.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from django.urls import reverse

from tests.django.conftest import FederationRoutes
from tests.django.conftest import build_auth_url as _auth_url


def test_auth_rejects_an_idp_iss_that_is_not_in_list_idps(client, federation_routes: FederationRoutes) -> None:
    federation_routes.fm_entity_configuration()
    federation_routes.idps_list()
    par_route = federation_routes.par()

    response = client.get(_auth_url(idp_iss="https://not-a-real-sectoral-idp.invalid"))

    assert response.status_code == 400
    assert par_route.call_count == 0


def test_auth_happy_path_redirects_to_the_idp_with_client_id_and_request_uri(
    client, federation_routes: FederationRoutes, gesundheitsid_settings: dict
) -> None:
    federation_routes.happy_path()

    response = client.get(_auth_url())

    assert response.status_code == 302
    location = response["Location"]
    parsed = urlsplit(location)
    query = parse_qs(parsed.query)

    assert query["client_id"] == [gesundheitsid_settings["ISSUER"]]
    assert query["request_uri"] == ["urn:request_uri:test123"]


def test_auth_rejects_an_unregistered_redirect_uri(client, federation_routes: FederationRoutes) -> None:
    par_route = federation_routes.par()

    response = client.get(_auth_url(redirect_uri="https://not-registered.invalid/callback"))

    assert response.status_code == 400
    assert par_route.call_count == 0


def test_auth_rejects_an_unknown_client_id(client) -> None:
    response = client.get(_auth_url(client_id="not-a-registered-client"))
    assert response.status_code == 401


def test_auth_requires_pkce(client) -> None:
    response = client.get(_auth_url(code_challenge_method="plain"))
    assert response.status_code == 400


def test_auth_rejects_non_get(client) -> None:
    response = client.post(reverse("django_gesundheitsid:auth"))
    assert response.status_code == 405
