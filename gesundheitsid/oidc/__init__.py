"""OAuth2/OIDC protocol layer for talking to a sectoral IdP once a trust chain is resolved:
PKCE/state/nonce generation, PAR, authorization-code exchange, and ID token parsing.

Re-exports only the deliberate public surface -- internal helpers stay import-only from
their defining module (`gesundheitsid.oidc.pkce`, `.par`, `.token`, `.idtoken`).
"""

from gesundheitsid.oidc.idtoken import REQUIRED_ACR, GesundheitsIdIdentity, parse_id_token
from gesundheitsid.oidc.par import (
    REQUEST_URI_EXPIRY_SECONDS,
    ParResponse,
    build_authorization_url,
    push_authorization_request,
)
from gesundheitsid.oidc.pkce import PkceMaterial, generate_nonce, generate_pkce, generate_state
from gesundheitsid.oidc.token import TokenResponse, exchange_code

__all__ = [
    "REQUEST_URI_EXPIRY_SECONDS",
    "REQUIRED_ACR",
    "GesundheitsIdIdentity",
    "ParResponse",
    "PkceMaterial",
    "TokenResponse",
    "build_authorization_url",
    "exchange_code",
    "generate_nonce",
    "generate_pkce",
    "generate_state",
    "parse_id_token",
    "push_authorization_request",
]
