# Contributing

Thanks for considering a contribution to `gesundheitsid-python`. This is authentication
code for health data, so a couple of things here are stricter than usual -- please read
the [Provenance](#provenance) and [Security-relevant changes](#security-relevant-changes)
sections before opening a PR that touches trust-chain, JOSE, or mTLS code.

## Dev setup

```shell
uv sync --extra django
```

This installs all three import packages (`gesundheitsid`, `gesundheitsid_cli`,
`django_gesundheitsid`) in editable mode plus the dev dependency group (pytest, ruff,
respx, pip-licenses). The `django` extra pulls in Django/Authlib/django-redis; without
it, `pytest.ini`'s `DJANGO_SETTINGS_MODULE` still points at `tests/django/settings.py`,
so every `tests/django/*` test collection-errors on a missing `django` module. The core
`gesundheitsid` package itself stays usable without the extra either way -- see
`pyproject.toml`'s `[project.optional-dependencies]` comment.

### Quality gate

Run all four before opening a PR -- this is exactly what CI runs on every push and pull
request:

```shell
uv run ruff check .
uv run ruff format --check .
uv run pip-licenses --fail-on="GPL.*;AGPL.*"
uv run pytest -q
```

### Running the offline gematik federation

Some tests are marked `integration` and need a running federation: gematik's own
reference sectoral IdP and a minimal Federation Master, both from gematik's
`app-gemSekIdp` (Apache-2.0), running locally so nothing depends on gematik's IP
allowlist. Setup, image build, ports and what has and hasn't been verified about them
are all in [`docs/local-federation.md`](docs/local-federation.md) -- read that before
running:

```shell
docker compose up -d
uv run pytest -m integration
```

Everything else (unit tests, the default `uv run pytest`) needs no database, no
services, and no network access.

## Code style

- **Module docstrings are one to three lines and state the non-obvious invariant** --
  not what the module contains (that's what the file listing is for), but the thing a
  reader would get wrong without being told. Look at any existing module
  (`gesundheitsid/federation/trust_chain.py` is a good example) for the tone to match.
- **Comments explain *why*, not *what*.** If a comment restates the line below it in
  English, delete the comment. If a line does something surprising for a reason that
  lives outside the code (a spec requirement, a prior incident, a constraint imposed by
  gematik's infrastructure), that reason belongs in a comment.
- **Full type hints** on every function signature, including private helpers. `ruff` is
  configured to catch a lot of this, but not all of it -- annotate return types too, even
  `-> None`.
- **No emoji.** Not in code, comments, docstrings, commit messages, or PR descriptions.

## Provenance

The project is Apache-2.0. So are the two prior implementations this project is aware
of and was consulted against for behavioural questions:

- [`oviva-ag/ehealthid-relying-party`](https://github.com/oviva-ag/ehealthid-relying-party) (Java)
- [`BAYOOMED/TI-RelyingParty`](https://github.com/BAYOOMED/TI-RelyingParty) (C#/.NET)

Same licence means code *may* be ported from either of those projects. But if a
contribution becomes a direct port of a file (or a substantial, recognisable part of
one) from either project, that file **must** carry the original project's copyright
notice, and the port **must** be named explicitly in [`NOTICE`](NOTICE). Read `NOTICE`
before contributing -- it already documents the exact standard this repository holds
itself to, and any porting PR is expected to update it in the same commit.

Absent an actual port, write contributions from the primary specifications instead of
translating another implementation's code:

- gemSpec_IDP_Sek, gemSpec_IDP_FD, gemSpec_IDP_FedMaster (<https://gemspec.gematik.de/>)
- [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html)
- RFC 9126 (OAuth 2.0 Pushed Authorization Requests)
- RFC 7636 (PKCE)
- RFC 7515 / 7516 / 7517 / 7518 (JWS / JWE / JWK / JWA)

If you consulted one of the two prior implementations to understand expected behaviour
but wrote your own code independently, that is exactly what `NOTICE`'s "prior art and
references" section already covers -- no per-PR action needed beyond the code itself
being your own.

## Security-relevant changes

A change to trust-chain resolution (`gesundheitsid/federation/trust_chain.py`,
`entity_statement.py`, `fedmaster.py`), JOSE handling (`gesundheitsid/crypto/jose.py`),
or mTLS (`gesundheitsid/crypto/mtls.py`) needs a test that demonstrates the *failure*
it prevents, not just a test that the happy path still works. Concretely: if you're
fixing or hardening a check, add a test where the bad input reaches that check and
confirm it is rejected -- an expired statement, a signature that doesn't verify, a
subordinate statement that disagrees with the self-signed one, a non-P-256 key, a
certificate presented to the wrong endpoint. A green "it still logs in" test does not
tell a reviewer that the vulnerability is actually closed; a red-then-green test
against the specific bad input does.

See [`SECURITY.md`](SECURITY.md) for how the project defines vulnerabilities and scope
in this codebase, including a documented limitation in `resolve_trust_chain` worth
reading before you assume you've found a new one.
