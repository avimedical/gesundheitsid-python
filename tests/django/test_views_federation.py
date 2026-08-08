"""`GET /.well-known/openid-federation` and `GET /api/v1/idps`."""

from __future__ import annotations

from django.urls import reverse

from gesundheitsid.crypto import load_jwks
from gesundheitsid.federation import verify_entity_statement
from tests.django.conftest import IDP_ISSUER, FederationRoutes


def test_entity_statement_returns_a_verifiable_jwt_with_the_right_content_type(
    client, gesundheitsid_settings: dict
) -> None:
    response = client.get(reverse("django_gesundheitsid:entity-statement"))

    assert response.status_code == 200
    assert response["Content-Type"] == "application/entity-statement+jwt"

    signing_keys = load_jwks(gesundheitsid_settings["KEYS"]["ENTITY_STATEMENT_SIG"])
    statement = verify_entity_statement(response.content.decode("utf-8"), signing_keys)
    assert statement.iss == gesundheitsid_settings["ISSUER"]
    assert statement.sub == gesundheitsid_settings["ISSUER"]
    assert statement.relying_party_metadata["redirect_uris"] == [gesundheitsid_settings["REDIRECT_URI"]]


def test_entity_statement_is_unauthenticated(client) -> None:
    # No login, no session, no auth header -- just a bare GET, same as the non-interactive
    # fetches gematik's Federation Master and testsuites actually issue.
    response = client.get(reverse("django_gesundheitsid:entity-statement"))
    assert response.status_code == 200


def test_entity_statement_rejects_non_get(client) -> None:
    response = client.post(reverse("django_gesundheitsid:entity-statement"))
    assert response.status_code == 405


def test_idps_returns_the_federations_sectoral_idp_list(client, federation_routes: FederationRoutes) -> None:
    federation_routes.fm_entity_configuration()
    federation_routes.idps_list()

    response = client.get(reverse("django_gesundheitsid:idps"))

    assert response.status_code == 200
    assert response.json() == [{"issuer": IDP_ISSUER, "organization_name": "Test Insurer", "logo_uri": None}]


def test_idps_surfaces_a_federation_master_failure_as_502(client, federation_routes: FederationRoutes) -> None:
    federation_routes.fm_entity_configuration(status_code=500)

    response = client.get(reverse("django_gesundheitsid:idps"))

    assert response.status_code == 502
