"""The cross-language known-answer vector for the pairwise subject.

This is a CONTRACT test, not a unit test. `_pairwise_subject` is one half of a value that
three independently-built services must agree on byte for byte:

    gesundheitsid-service   id_token `sub`                  <- computed here
      -> patient            account_external_identity.pairwise_sub, mirrored onto the
                            Keycloak user attribute `gesundheitsid_sub`
      -> Keycloak grant     constant-time compares the token's `sub` to that attribute

Every property you would naturally test about an HMAC -- deterministic, differs per KVNR,
differs per pepper, does not leak the input -- holds just as well for a hex encoding, a
padded base64, or a different digest. Those properties are all true of a value the other
two services will nonetheless reject. That is not hypothetical: `patient`'s
`PairwiseSubjectUtils` shipped hex against this module's base64url, passed a full suite of
exactly those property tests on both sides, and broke every login at the point where
Keycloak compares the two.

So this test pins the one thing property tests cannot: the literal output for a fixed
input. `tests/.../PairwiseSubjectUtilsTest#hash_matchesTheCrossLanguageKnownAnswerVector`
in the `patient` repo asserts the SAME constants. If you change either, both fail -- which
is the point. Changing them at all invalidates every stored account link (see
`GesundheitsIdSettings.pairwise_pepper`), so a failure here is a design decision, never a
line to update until it goes green.
"""

from __future__ import annotations

import base64

from django_gesundheitsid.views import _pairwise_subject

#: Fixed inputs. `CONTRACT_KVNR` is a syntactically valid but unassigned KVNR, and
#: `CONTRACT_PEPPER` is a literal test string -- neither is a real value from any
#: environment, and this pepper must never be configured anywhere.
CONTRACT_KVNR = "X110411319"
CONTRACT_PEPPER = "gesundheitsid-pairwise-contract-vector"

#: base64url(HMAC-SHA256(key=CONTRACT_PEPPER, msg=CONTRACT_KVNR)), unpadded.
CONTRACT_PAIRWISE_SUB = "0qWvNL5fd36ZS8IL3CIJValwvuF1MMzhvWr7OQmOtM0"


def test_pairwise_subject_matches_the_cross_language_known_answer_vector() -> None:
    assert _pairwise_subject(CONTRACT_KVNR, CONTRACT_PEPPER) == CONTRACT_PAIRWISE_SUB


def test_pairwise_subject_is_unpadded_base64url_of_a_sha256_digest() -> None:
    """Pins the ENCODING itself, independently of the vector above.

    A digest is 32 bytes, so a correct unpadded base64 encoding is always 43 characters and
    can only contain the URL-safe alphabet. Hex (64 chars, `[0-9a-f]`) and standard base64
    (`+`/`/`, or a trailing `=`) both fail here -- the two ways this has actually been got
    wrong.
    """
    subject = _pairwise_subject(CONTRACT_KVNR, CONTRACT_PEPPER)

    assert len(subject) == 43
    assert "=" not in subject
    assert "+" not in subject and "/" not in subject
    # Round-trips back to exactly 32 bytes: it really is a whole SHA-256 digest, not a
    # truncation or a re-encoding of some other representation.
    assert len(base64.urlsafe_b64decode(subject + "=")) == 32
