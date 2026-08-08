# Security Policy

This library handles authentication for health data: it is the code that decides
whether a GesundheitsID login is trustworthy. Security reports are taken seriously and
triaged ahead of ordinary bug reports.

## Supported versions

The project is pre-1.0 and has not yet shipped a release (see [CHANGELOG.md](CHANGELOG.md)
-- everything so far is `[Unreleased]`). Until a 1.0 is tagged, only the `main` branch is
supported: fixes land there, not on a matrix of maintained release lines. Once versioned
releases exist, this section will be updated to state which lines still receive security
fixes.

## Reporting a vulnerability

**Do not open a public GitHub issue for a suspected vulnerability.**

Report it privately through GitHub Security Advisories:

<https://github.com/avimedical/gesundheitsid-python/security/advisories/new>

Include, as far as you can:

- the affected file(s)/function(s) and, if possible, a minimal reproduction;
- the impact you believe it has (what a successful exploit would let an attacker do);
- whether you believe it affects the *library's* trust decisions specifically, or a
  downstream integration's use of it (see [Scope](#scope) below -- the distinction
  matters here).

### What to expect

- **Acknowledgement:** within 5 business days of the report being filed.
- **Disclosure:** coordinated. We will work with you on a fix and a release before any
  public disclosure, and will credit you in the advisory unless you ask not to be named.
  We do not currently commit to a fixed patch-by date, because that depends heavily on
  severity and on whether a fix requires a coordinated change with gematik's Federation
  Master or a sectoral IdP -- but we will keep you updated as the timeline firms up.

## Scope

### In scope

- Trust-chain resolution and validation (`gesundheitsid.federation.trust_chain`,
  `.entity_statement`, `.fedmaster`) accepting or trusting something it should reject:
  an unsigned or badly-signed entity statement, a subordinate statement that disagrees
  with the Federation Master and is trusted anyway, an expired statement treated as
  valid, or similar.
- JOSE handling (`gesundheitsid.crypto.jose`) that verifies a signature it shouldn't, or
  that treats a JWE's successful decryption as proof of who signed the payload inside it
  (it is not -- decryption only proves confidentiality; the inner JWS is verified
  separately, on purpose).
- Key handling (`gesundheitsid.crypto.keys`, `.mtls`) that accepts a non-P-256 key where
  the spec requires P-256, or that lets an mTLS client certificate meant for a sectoral
  IdP's PAR/token endpoints be presented anywhere else.
- `gesundheitsid_cli` writing key material somewhere unsafe, or with unsafe permissions.
- Anything in this repository's CI/CD (`.github/workflows/`) that could let an attacker
  publish a malicious release under this project's name.

### Known, documented limitation -- not a vulnerability

`resolve_trust_chain` in `gesundheitsid.federation.trust_chain` performs only a *shape*
check on `subject_issuer` (`_validate_subject_issuer`): it rejects the obviously unsafe
forms (non-https, a URL with userinfo, a query string, a fragment), but that is not, and
is not intended to be, an SSRF defence on its own. `subject_issuer` is normally taken
from the `idp_iss` authorization-request parameter, which is attacker-controlled, and
resolving a chain makes a server-side GET to whatever URL is passed in. **A report that
this function will fetch an attacker-supplied `https://` URL, including one pointing at
an internal host, is a known and already-documented limitation, not a new finding.**

The actual control is the caller's responsibility, not this function's: callers must
constrain `idp_iss` to `FederationMasterClient.list_idps()` -- gematik's own signed
allowlist of sectoral IdPs -- *before* calling `resolve_trust_chain` with it. That list
is what actually limits which hosts this library will ever connect to; the shape check
inside `resolve_trust_chain` is a second line of defence, not the primary one. If you
believe you have found a way for `list_idps()` itself to be bypassed or poisoned, or a
way to make its allowlist-checked value still resolve to something unintended, that
*is* in scope and should be reported per the process above.

### Out of scope

- Vulnerabilities in a downstream integration's own handling of this library, e.g. an
  application that fails to check `idp_iss` against `list_idps()` before calling
  `resolve_trust_chain`, or that stores tokens insecurely. Report those to the
  integration, not here -- though we are glad to hear about common misuse patterns so we
  can make the API harder to misuse.
- Vulnerabilities in gematik's Federation Master, a sectoral IdP, or any other party in
  the TI-Föderation. Report those to gematik (`diga@gematik.de`) or the operator
  concerned.
- Denial of service against the public `app-test`/`app-ref`/`app.federationmaster.de`
  endpoints themselves -- those are gematik's infrastructure, not this project's.
- Findings that require the reporter to already control this repository's CI/CD secrets,
  a maintainer's GitHub account, or a private key that per the next section should never
  have existed in the first place.

## Key material

This project never generates, stores, or reads key material into or from the
repository. `gesundheitsid-cli keygen` writes private keys to a directory the caller
chooses (`--out-dir`), outside version control; `.gitignore` additionally excludes
`*.pem`, `*.p12`, `*_jwks.json` and `secrets/` as a second line of defence, not the
primary one -- the primary one is that no code path in this repository ever writes key
material to a path under the repository itself. If you find a code path that does, that
is a vulnerability under [Scope](#scope) above: report it.
