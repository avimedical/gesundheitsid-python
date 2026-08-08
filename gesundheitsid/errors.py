"""Exception hierarchy for gesundheitsid.

Deliberately flat and payload-free: every raise site embeds a specific, human-readable
message rather than asking callers to introspect structured error data.
"""


class GesundheitsIdError(Exception):
    """Base class for every exception raised by this library."""


class CryptoError(GesundheitsIdError):
    """Key generation, JOSE (JWS/JWE), or mTLS material is invalid or was misused."""


class EntityStatementError(GesundheitsIdError):
    """An entity statement is malformed, unparsable, or fails its own internal checks."""


class TrustChainError(GesundheitsIdError):
    """The chain from a leaf entity statement up to the Federation Master does not validate."""


class FederationMasterError(GesundheitsIdError):
    """gematik's Federation Master returned an unexpected, missing, or unusable response."""


class ProtocolError(GesundheitsIdError):
    """An OAuth2/OpenID Connect exchange (PAR, token, etc.) did not follow the expected protocol."""
