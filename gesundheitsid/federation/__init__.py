"""OpenID Federation 1.0 relying party support for the gematik TI-Föderation: entity
statements, the Federation Master client, and trust-chain resolution.
"""

from gesundheitsid.federation.entity_statement import (
    EntityStatement,
    build_entity_statement,
    parse_entity_statement,
    verify_entity_statement,
    verify_self_signed,
)
from gesundheitsid.federation.fedmaster import (
    FederationMasterClient,
    FederationMasterEnvironment,
    SectoralIdp,
)
from gesundheitsid.federation.trust_chain import TrustChain, resolve_trust_chain

__all__ = [
    "EntityStatement",
    "FederationMasterClient",
    "FederationMasterEnvironment",
    "SectoralIdp",
    "TrustChain",
    "build_entity_statement",
    "parse_entity_statement",
    "resolve_trust_chain",
    "verify_entity_statement",
    "verify_self_signed",
]
