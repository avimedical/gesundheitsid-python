"""PKCE verifier/challenge derivation, and that state/nonce/verifier are all freshly random
per call -- a repeated value would defeat the CSRF/replay protection they exist for."""

from __future__ import annotations

import base64
import hashlib
import re

from gesundheitsid.oidc.pkce import generate_nonce, generate_pkce, generate_state

#: RFC 4648 Section 5 base64url alphabet, no padding -- what every value here must look like.
_B64URL_NO_PAD = re.compile(r"^[A-Za-z0-9_-]+$")


def test_challenge_is_the_base64url_sha256_of_the_verifier() -> None:
    material = generate_pkce()

    # Computed independently with hashlib rather than by re-calling generate_pkce, so this
    # actually checks the RFC 7636 derivation instead of just checking generate_pkce agrees
    # with itself.
    expected_digest = hashlib.sha256(material.verifier.encode("ascii")).digest()
    expected_challenge = base64.urlsafe_b64encode(expected_digest).rstrip(b"=").decode("ascii")

    assert material.challenge == expected_challenge
    assert material.method == "S256"


def test_verifier_and_challenge_have_no_base64_padding() -> None:
    material = generate_pkce()

    assert "=" not in material.verifier
    assert "=" not in material.challenge
    assert _B64URL_NO_PAD.match(material.verifier)
    assert _B64URL_NO_PAD.match(material.challenge)


def test_successive_pkce_calls_produce_different_verifiers_and_challenges() -> None:
    first = generate_pkce()
    second = generate_pkce()

    assert first.verifier != second.verifier
    assert first.challenge != second.challenge


def test_state_has_no_padding_and_differs_across_calls() -> None:
    first = generate_state()
    second = generate_state()

    assert first != second
    assert "=" not in first
    assert _B64URL_NO_PAD.match(first)


def test_nonce_has_no_padding_and_differs_across_calls() -> None:
    first = generate_nonce()
    second = generate_nonce()

    assert first != second
    assert "=" not in first
    assert _B64URL_NO_PAD.match(first)


def test_state_and_nonce_are_not_interchangeable_values() -> None:
    # not a security property, just a sanity check that they are independently drawn
    assert generate_state() != generate_nonce()
