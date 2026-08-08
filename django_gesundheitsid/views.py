"""HTTP views: the federation-facing entity statement / sectoral-IdP list, the downstream
authorization<->callback pair that talks to a sectoral IdP, and this relying party's own
downstream OIDC provider face (discovery, token, jwks) for ITS OWN clients.

AUTHLIB DECISION: `authlib.integrations.django_oauth2.AuthorizationServer` (Authlib's
Django server integration) is model-centric -- it wants a `client_model`/`token_model`
pair of Django models implementing its `OAuth2ClientMixin`/`OAuth2TokenMixin` contracts,
and its OIDC grant mixins (`authlib.oidc.core.grants.OpenIDCode`) expect to own
authorization-code persistence too. That would be a second storage layer parallel to the
`Store` protocol this whole project is built on, just to reach a single grant type
(authorization_code with mandatory PKCE) issuing an id_token that is essentially a
re-signed pass-through of the already-verified `GesundheitsIdIdentity.claims`. So the
downstream authorize/token/discovery/jwks endpoints below are implemented directly on
`gesundheitsid.crypto` (ES256 signing with the `DOWNSTREAM_SIG` key) and
`stores.get_store()` (single-use downstream codes), not through `AuthorizationServer`.

What DOES come from Authlib: `authlib.oauth2.rfc7523.JWTBearerClientAssertion`, used
directly for its `process_assertion_claims`/`resolve_client_public_key`/`validate_jti`
hooks (not its `__call__`/`query_client`/`AuthorizationServer.register_client_auth_method`
orchestration, which assumes the same client/token persistence model above) to verify a
`private_key_jwt` client assertion at `/auth/token`. That is exactly the narrow,
security-sensitive RFC 7523 logic (iss/sub/aud/exp/jti validation) worth reusing rather
than hand-rolling, and it does not require adopting Authlib's client persistence model --
`resolve_client_public_key` below reads straight from `GESUNDHEITSID["DOWNSTREAM_CLIENTS"]`
via `conf.DownstreamClient`.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from authlib.oauth2.rfc6749 import InvalidClientError as AuthlibInvalidClientError
from authlib.oauth2.rfc7523 import JWTBearerClientAssertion
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from django_gesundheitsid.conf import DownstreamClient, GesundheitsIdSettings, get_settings
from django_gesundheitsid.stores import get_store
from gesundheitsid.crypto import load_jwks, mtls_client, public_jwks, sign_compact
from gesundheitsid.errors import FederationMasterError, ProtocolError, TrustChainError
from gesundheitsid.federation import FederationMasterClient, TrustChain, build_entity_statement, resolve_trust_chain
from gesundheitsid.oidc import (
    REQUEST_URI_EXPIRY_SECONDS,
    PkceMaterial,
    build_authorization_url,
    exchange_code,
    generate_nonce,
    generate_pkce,
    generate_state,
    parse_id_token,
    push_authorization_request,
)
from gesundheitsid.storage import Store

__all__ = [
    "auth",
    "auth_callback",
    "entity_statement",
    "idps",
    "jwks",
    "openid_configuration",
    "token",
]

#: how long a downstream authorization code lives before it must be exchanged. Short --
#: this is a redirect-to-redirect handoff within one browser navigation, not something a
#: client should ever need to hold onto.
_DOWNSTREAM_CODE_TTL_SECONDS = 60
#: how long a minted downstream id_token is valid for.
_DOWNSTREAM_ID_TOKEN_TTL_SECONDS = 300
#: how long a `private_key_jwt` client assertion's `jti` is remembered, to reject replay.
_CLIENT_ASSERTION_JTI_TTL_SECONDS = 300


def _error_response(error: str, description: str, *, status: int = 400) -> JsonResponse:
    return JsonResponse({"error": error, "error_description": description}, status=status)


def _session_key(upstream_state: str) -> str:
    return f"gesundheitsid:auth-session:{upstream_state}"


def _downstream_code_key(code: str) -> str:
    return f"gesundheitsid:downstream-code:{code}"


def _federation_master_client(settings_: GesundheitsIdSettings, store: Store) -> FederationMasterClient:
    return FederationMasterClient(settings_.environment, trust_anchor_jwks=settings_.trust_anchor_jwks, store=store)


def _find_downstream_client(settings_: GesundheitsIdSettings, client_id: str) -> DownstreamClient | None:
    for client in settings_.downstream_clients:
        if client.client_id == client_id:
            return client
    return None


def _verify_pkce(code_verifier: str, code_challenge: str) -> bool:
    """RFC 7636 S256 verification: BASE64URL(SHA256(code_verifier)) == code_challenge."""
    computed = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    )
    return hmac.compare_digest(computed, code_challenge)


def _pairwise_subject(kvnr: str, pepper: str) -> str:
    """The downstream id_token's `sub`: BASE64URL(HMAC-SHA256(key=pepper, msg=kvnr)).

    Deliberately NOT the raw KVNR, and NOT the sectoral IdP's own `sub` claim -- the KVNR
    is patient-identifying and must never become a primary key, log line, or
    federated-identity-table entry in a downstream consumer. What downstream consumers
    (`patient`'s `account_external_identity.pairwise_sub`, the Keycloak grant that binds a
    token to an account by comparing `sub` against it) actually need is a subject that is
    STABLE across logins for the same person -- a random per-session value would break
    that binding entirely. The KVNR's 10-character core is stable for life (it survives an
    insurer change), so an HMAC of it is exactly that: stable, but never reversible back to
    the KVNR without `pepper`. See `GesundheitsIdSettings.pairwise_pepper`'s docstring for
    why that pepper is effectively a permanent secret once real accounts depend on it.
    """
    digest = hmac.new(pepper.encode("utf-8"), kvnr.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _append_query(url: str, **params: str | None) -> str:
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query))
    query.update({key: value for key, value in params.items() if value is not None})
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


# --------------------------------------------------------------------------------------
# Federation-facing endpoints
# --------------------------------------------------------------------------------------


@require_GET
def entity_statement(request: HttpRequest) -> HttpResponse:
    """The relying party's own signed entity configuration. Unauthenticated by design --
    gematik's Federation Master, sectoral IdPs, and federation testsuites all fetch this
    non-interactively, without a bot challenge.
    """
    settings_ = get_settings()
    token = build_entity_statement(
        issuer=settings_.issuer,
        signing_key=settings_.entity_statement_sig_key,
        federation_master=settings_.environment.base_url,
        redirect_uris=[settings_.redirect_uri],
        scopes=settings_.scopes,
        client_name=settings_.client_name,
        contacts=settings_.contacts,
        organization_name=settings_.organization_name,
        mtls_client_key=settings_.mtls_client_key,
        idtoken_enc_key=settings_.idtoken_enc_key,
    )
    return HttpResponse(token, content_type="application/entity-statement+jwt")


@require_GET
def idps(request: HttpRequest) -> HttpResponse:
    """The insurer picker list: gematik's signed `federation/listidps`, verified and
    parsed by `FederationMasterClient.list_idps()`.
    """
    settings_ = get_settings()
    fedmaster_client = _federation_master_client(settings_, get_store())
    try:
        sectoral_idps = fedmaster_client.list_idps()
    except FederationMasterError as exc:
        return _error_response("server_error", f"could not fetch the sectoral IdP list: {exc}", status=502)

    return JsonResponse(
        [
            {"issuer": idp.issuer, "organization_name": idp.organization_name, "logo_uri": idp.logo_uri}
            for idp in sectoral_idps
        ],
        safe=False,
    )


# --------------------------------------------------------------------------------------
# Downstream authorization <-> sectoral IdP callback
# --------------------------------------------------------------------------------------


@require_GET
def auth(request: HttpRequest) -> HttpResponse:
    """The downstream authorization endpoint: a client of THIS relying party starts a
    GesundheitsID login here, naming which sectoral IdP (`idp_iss`) the user picked.

    `idp_iss` is attacker-controlled and is what `resolve_trust_chain` will make a
    server-side GET to -- validating it against `list_idps()` here, BEFORE resolving
    anything, is the actual SSRF control; `resolve_trust_chain` itself only shape-checks
    it (see that module's docstring).
    """
    settings_ = get_settings()
    store = get_store()

    client_id = request.GET.get("client_id")
    redirect_uri = request.GET.get("redirect_uri")
    response_type = request.GET.get("response_type")
    code_challenge = request.GET.get("code_challenge")
    code_challenge_method = request.GET.get("code_challenge_method")
    idp_iss = request.GET.get("idp_iss")
    downstream_state = request.GET.get("state")
    downstream_nonce = request.GET.get("nonce")

    if response_type != "code":
        return _error_response("unsupported_response_type", "response_type must be 'code'")
    if not client_id:
        return _error_response("invalid_request", "client_id is required")
    if not redirect_uri:
        return _error_response("invalid_request", "redirect_uri is required")
    if code_challenge_method != "S256" or not code_challenge:
        return _error_response("invalid_request", "PKCE is required: code_challenge and code_challenge_method=S256")
    if not idp_iss:
        return _error_response("invalid_request", "idp_iss is required")

    client = _find_downstream_client(settings_, client_id)
    if client is None:
        return _error_response("unauthorized_client", "unknown client_id", status=401)
    if redirect_uri not in client.redirect_uris:
        return _error_response("invalid_request", "redirect_uri is not registered for this client")

    fedmaster_client = _federation_master_client(settings_, store)

    # THE SSRF control -- see this view's docstring.
    try:
        allowed_issuers = {idp.issuer for idp in fedmaster_client.list_idps()}
    except FederationMasterError as exc:
        return _error_response("server_error", f"could not fetch the sectoral IdP list: {exc}", status=502)
    if idp_iss not in allowed_issuers:
        return _error_response("invalid_request", "idp_iss is not a known sectoral IdP")

    try:
        trust_chain = resolve_trust_chain(subject_issuer=idp_iss, fedmaster_client=fedmaster_client)
    except TrustChainError as exc:
        return _error_response("server_error", f"could not resolve trust chain for idp_iss: {exc}", status=502)

    pkce = generate_pkce()
    upstream_state = generate_state()
    nonce = generate_nonce()

    with mtls_client(*settings_.mtls_paths) as http_client:
        try:
            par_response = push_authorization_request(
                trust_chain=trust_chain,
                client_id=settings_.issuer,
                redirect_uri=settings_.redirect_uri,
                scopes=settings_.scopes,
                pkce=pkce,
                state=upstream_state,
                nonce=nonce,
                http_client=http_client,
            )
        except ProtocolError as exc:
            return _error_response("server_error", f"PAR request to the sectoral IdP failed: {exc}", status=502)

    session = {
        "downstream_client_id": client_id,
        "downstream_redirect_uri": redirect_uri,
        "downstream_state": downstream_state,
        "downstream_code_challenge": code_challenge,
        "downstream_nonce": downstream_nonce,
        "pkce_verifier": pkce.verifier,
        "pkce_challenge": pkce.challenge,
        "nonce": nonce,
        "trust_chain": {
            "subject": trust_chain.subject,
            "trust_anchor": trust_chain.trust_anchor,
            "signing_keys": trust_chain.signing_keys,
            "metadata": trust_chain.metadata,
            "expires_at": trust_chain.expires_at,
        },
    }
    store.set(_session_key(upstream_state), json.dumps(session).encode("utf-8"), ttl_seconds=REQUEST_URI_EXPIRY_SECONDS)

    authorization_url = build_authorization_url(
        trust_chain, client_id=settings_.issuer, request_uri=par_response.request_uri
    )
    return HttpResponseRedirect(authorization_url)


@require_GET
def auth_callback(request: HttpRequest) -> HttpResponse:
    """The redirect URI registered with gematik: the sectoral IdP sends the browser back
    here with `code`/`state` (or `error`) after the user authenticates.

    `state` is popped, not merely read: the PAR/PKCE session it names must only ever be
    consumable once, exactly like the downstream code minted at the end of this view.
    """
    settings_ = get_settings()
    store = get_store()

    state = request.GET.get("state")
    if not state:
        return _error_response("invalid_request", "state is required")

    raw_session = store.pop(_session_key(state))
    if raw_session is None:
        return _error_response("invalid_request", "unknown or expired state")
    session = json.loads(raw_session)

    idp_error = request.GET.get("error")
    if idp_error:
        return _error_response("access_denied", f"the sectoral IdP returned an error: {idp_error}")

    code = request.GET.get("code")
    if not code:
        return _error_response("invalid_request", "code is required")

    trust_chain = TrustChain(**session["trust_chain"])
    pkce = PkceMaterial(verifier=session["pkce_verifier"], challenge=session["pkce_challenge"])

    with mtls_client(*settings_.mtls_paths) as http_client:
        try:
            token_response = exchange_code(
                trust_chain=trust_chain,
                client_id=settings_.issuer,
                redirect_uri=settings_.redirect_uri,
                code=code,
                pkce=pkce,
                http_client=http_client,
            )
        except ProtocolError as exc:
            return _error_response("server_error", f"token exchange with the sectoral IdP failed: {exc}", status=502)

    try:
        identity = parse_id_token(
            token=token_response.id_token,
            trust_chain=trust_chain,
            encryption_key=settings_.idtoken_enc_key,
            client_id=settings_.issuer,
            nonce=session["nonce"],
        )
    except ProtocolError as exc:
        return _error_response("server_error", f"id_token from the sectoral IdP failed validation: {exc}", status=502)

    if not identity.kvnr:
        # No kvnr claim -> no stable pairwise sub can be derived -> refuse to mint a
        # downstream identity at all, rather than falling back to something unstable
        # (a random or session-scoped sub would silently break account binding
        # downstream). See `_pairwise_subject`'s docstring.
        return _error_response(
            "server_error",
            "id_token from the sectoral IdP has no kvnr claim; cannot mint a stable identity",
            status=502,
        )

    downstream_claims = dict(identity.claims)
    downstream_claims["sub"] = _pairwise_subject(identity.kvnr, settings_.pairwise_pepper)

    downstream_code = generate_state()
    downstream_payload = {
        "client_id": session["downstream_client_id"],
        "redirect_uri": session["downstream_redirect_uri"],
        "code_challenge": session["downstream_code_challenge"],
        "nonce": session["downstream_nonce"],
        "claims": downstream_claims,
    }
    store.set(
        _downstream_code_key(downstream_code),
        json.dumps(downstream_payload).encode("utf-8"),
        ttl_seconds=_DOWNSTREAM_CODE_TTL_SECONDS,
    )

    redirect_url = _append_query(
        session["downstream_redirect_uri"], code=downstream_code, state=session["downstream_state"]
    )
    return HttpResponseRedirect(redirect_url)


# --------------------------------------------------------------------------------------
# Downstream OIDC provider face (Authlib's JWTBearerClientAssertion for private_key_jwt
# only -- see this module's docstring)
# --------------------------------------------------------------------------------------


class _PrivateKeyJwtVerifier(JWTBearerClientAssertion):
    """`GESUNDHEITSID["DOWNSTREAM_CLIENTS"]`-backed `private_key_jwt` verification. See
    this module's docstring for why only this narrow piece of Authlib is used, called
    directly rather than through `AuthorizationServer.register_client_auth_method`.
    """

    def __init__(self, *, token_endpoint: str, store: Store) -> None:
        super().__init__()
        self._token_endpoint = token_endpoint
        self._store = store

    def get_audiences(self) -> list[str]:
        return [self._token_endpoint]

    def resolve_client_public_key(self, client: DownstreamClient):
        return load_jwks(client.jwks)

    def validate_jti(self, claims: dict, jti: str) -> bool:
        # Single-use: a client_assertion whose jti was already seen is a replay.
        key = f"gesundheitsid:downstream-client-jti:{claims.get('iss')}:{jti}"
        if self._store.get(key) is not None:
            return False
        self._store.set(key, b"1", ttl_seconds=_CLIENT_ASSERTION_JTI_TTL_SECONDS)
        return True


class _TokenEndpointError(Exception):
    def __init__(self, error: str, description: str, *, status: int = 400) -> None:
        super().__init__(f"{error}: {description}")
        self.error = error
        self.description = description
        self.status = status

    def response(self) -> JsonResponse:
        return _error_response(self.error, self.description, status=self.status)


def _authenticate_private_key_jwt(
    request: HttpRequest, client: DownstreamClient, token_endpoint: str, store: Store
) -> None:
    assertion_type = request.POST.get("client_assertion_type")
    assertion = request.POST.get("client_assertion")
    if assertion_type != JWTBearerClientAssertion.CLIENT_ASSERTION_TYPE or not assertion:
        raise _TokenEndpointError(
            "invalid_client",
            "private_key_jwt authentication requires client_assertion_type and client_assertion",
            status=401,
        )

    verifier = _PrivateKeyJwtVerifier(token_endpoint=token_endpoint, store=store)
    try:
        client_key = verifier.resolve_client_public_key(client)
        claims = verifier.process_assertion_claims(assertion, client_key)
    except AuthlibInvalidClientError as exc:
        raise _TokenEndpointError(
            "invalid_client", exc.description or "client_assertion is invalid", status=401
        ) from exc

    if claims.get("sub") != client.client_id:
        raise _TokenEndpointError("invalid_client", "client_assertion sub does not match client_id", status=401)


@require_GET
def openid_configuration(request: HttpRequest) -> HttpResponse:
    """This relying party's OWN downstream OIDC discovery document -- distinct from
    `entity_statement`, which is the federation-facing document."""
    settings_ = get_settings()
    base = request.build_absolute_uri("/").rstrip("/")
    return JsonResponse(
        {
            "issuer": settings_.issuer,
            "authorization_endpoint": base + reverse("django_gesundheitsid:auth"),
            "token_endpoint": base + reverse("django_gesundheitsid:token"),
            "jwks_uri": base + reverse("django_gesundheitsid:jwks"),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["ES256"],
            "scopes_supported": list(settings_.scopes),
            "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
            "code_challenge_methods_supported": ["S256"],
            "grant_types_supported": ["authorization_code"],
        }
    )


@require_GET
def jwks(request: HttpRequest) -> HttpResponse:
    """This relying party's downstream-facing JWKS -- the public half of the
    `DOWNSTREAM_SIG` key, for verifying the id_tokens `token()` issues. Distinct from the
    federation-facing JWKS embedded in `entity_statement`.
    """
    settings_ = get_settings()
    return JsonResponse(public_jwks([settings_.downstream_sig_key]))


@csrf_exempt
@require_POST
def token(request: HttpRequest) -> HttpResponse:
    """This relying party's own downstream token endpoint: exchanges a single-use
    downstream code (minted by `auth_callback`) for an ES256 id_token carrying the
    `urn:telematik:claims:*` claims through from GesundheitsID, unmodified -- except
    `sub`, which `auth_callback` already replaced with a pairwise, KVNR-derived subject
    before the code was ever stored (see `_pairwise_subject`). This view only re-signs
    what `auth_callback` prepared; it does not touch `sub` itself.
    """
    settings_ = get_settings()
    store = get_store()

    if request.POST.get("grant_type") != "authorization_code":
        return _error_response("unsupported_grant_type", "grant_type must be 'authorization_code'")

    client_id = request.POST.get("client_id")
    code = request.POST.get("code")
    redirect_uri = request.POST.get("redirect_uri")
    code_verifier = request.POST.get("code_verifier")
    if not client_id or not code or not redirect_uri or not code_verifier:
        return _error_response("invalid_request", "client_id, code, redirect_uri and code_verifier are required")

    client = _find_downstream_client(settings_, client_id)
    if client is None:
        return _error_response("invalid_client", "unknown client_id", status=401)

    if client.token_endpoint_auth_method == "private_key_jwt":
        token_endpoint = request.build_absolute_uri(reverse("django_gesundheitsid:token"))
        try:
            _authenticate_private_key_jwt(request, client, token_endpoint, store)
        except _TokenEndpointError as exc:
            return exc.response()

    raw_payload = store.pop(_downstream_code_key(code))
    if raw_payload is None:
        return _error_response("invalid_grant", "code is invalid, expired, or already used")
    payload = json.loads(raw_payload)

    if payload["client_id"] != client_id:
        return _error_response("invalid_grant", "code was not issued to this client")
    if payload["redirect_uri"] != redirect_uri:
        return _error_response("invalid_grant", "redirect_uri does not match the one used to obtain this code")
    if not _verify_pkce(code_verifier, payload["code_challenge"]):
        return _error_response("invalid_grant", "code_verifier does not match code_challenge")

    now = int(time.time())
    id_token_claims = dict(payload["claims"])
    id_token_claims.pop("nonce", None)
    id_token_claims.update(
        {
            "iss": settings_.issuer,
            "aud": client_id,
            "iat": now,
            "exp": now + _DOWNSTREAM_ID_TOKEN_TTL_SECONDS,
        }
    )
    if payload.get("nonce"):
        id_token_claims["nonce"] = payload["nonce"]

    id_token = sign_compact(id_token_claims, settings_.downstream_sig_key, typ="JWT")

    return JsonResponse(
        {
            # Opaque and unverifiable beyond this response -- no resource protector /
            # userinfo endpoint is in scope here. Present only because RFC 6749 requires
            # an access_token in a successful token response; the id_token is the actual
            # payload downstream clients of this relying party care about.
            "access_token": generate_state(),
            "token_type": "Bearer",
            "expires_in": _DOWNSTREAM_ID_TOKEN_TTL_SECONDS,
            "id_token": id_token,
        }
    )
