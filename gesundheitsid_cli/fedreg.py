"""`gesundheitsid-cli fedreg` -- generate the XML form for registering a Fachdienst with
gematik's Federation Master, emailed to idp-registrierung@gematik.de.

UNVERIFIED-STRUCTURE CAVEAT: the element names and nesting produced here come from
gematik's Fachdienst-registration wiki page
(https://wiki.gematik.de/spaces/IDPKB/pages/544316583/) and its published
RP_register.xml / RP_register_unkommentiert.xml / RP_register.xsd attachments, which were
fetched and cross-checked against each other while writing this module. gematik can
change those documents at any time and this tool does not re-fetch or validate against
them at submission time -- always diff the generated XML against the *current*
RP_register.xsd before sending it.
"""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import ParseResult, urlparse

from joserfc.errors import JoseError
from joserfc.jwk import ECKey

from gesundheitsid.crypto import assert_p256, load_jwks
from gesundheitsid.errors import GesundheitsIdError
from gesundheitsid_cli.keygen import public_key_pem

__all__ = ["add_subparser", "build_registration_xml", "run"]

_ENVIRONMENTS = ("TU", "RU", "PU")
# urn:telematik:email is deliberate: the scope list is registered with gematik, so adding one
# later means re-submitting, not deploying. Every IdP sampled in TU and RU advertises it, and a
# scope an insurer declines is harmless - the claim simply does not arrive.
_DEFAULT_SCOPES = (
    "openid",
    "urn:telematik:display_name",
    "urn:telematik:versicherter",
    "urn:telematik:email",
)
# No trailing slash: with one, gematik's wiki returns 404. This URL is baked into the
# disclaimer comment of every generated registration, so a reader hits the 404, not us.
_WIKI_URL = "https://wiki.gematik.de/spaces/IDPKB/pages/544316583"

# Element order matches RP_register.xsd's <xs:sequence> exactly, fetched while writing this
# module -- getting this order wrong is exactly the kind of thing that would produce a
# schema-invalid document without any visible clue.
_DISCLAIMER = f"""<!--
  This registration form's element names and nesting were derived from gematik's
  Fachdienst-registration wiki page and its RP_register.xml / RP_register.xsd
  attachments ({_WIKI_URL}), fetched while building this generator. gematik can change
  those documents at any time; this tool does not re-fetch or validate against them at
  submission time. VALIDATE THIS FILE AGAINST THE CURRENT RP_register.xsd BEFORE SENDING
  IT to idp-registrierung@gematik.de.
-->
"""


def _validate_https(uri: str, *, arg_name: str) -> ParseResult:
    parsed = urlparse(uri)
    if parsed.scheme != "https":
        raise GesundheitsIdError(f"{arg_name} must be https, got {uri!r}")
    if not parsed.hostname:
        raise GesundheitsIdError(f"{arg_name} must include a host, got {uri!r}")
    return parsed


def _validate_fachdienst_uri(uri: str) -> ParseResult:
    parsed = _validate_https(uri, arg_name="--issuer-uri")
    if parsed.query:
        raise GesundheitsIdError(f"--issuer-uri must not contain a query string, got {uri!r}")
    if parsed.fragment:
        raise GesundheitsIdError(f"--issuer-uri must not contain a fragment, got {uri!r}")
    return parsed


def _origin(parsed: ParseResult) -> tuple[str, int]:
    # Both sides are already forced to https by the caller, so (host, port) -- with the
    # default port filled in -- is enough to decide "same origin".
    return (parsed.hostname or "", parsed.port or 443)


def _resolve_scopes(raw: list[str] | None) -> list[str]:
    """`--scopes` accepts repeated flags and/or comma-separated values; normalize both to a
    flat list, falling back to gematik's documented default set when nothing was given."""
    if not raw:
        return list(_DEFAULT_SCOPES)
    scopes: list[str] = []
    for item in raw:
        scopes.extend(part.strip() for part in item.split(",") if part.strip())
    return scopes


def _load_entity_statement_key(jwks_path: Path) -> ECKey:
    """Load the single entity-statement signing key from a JWKS file written by `keygen`.

    KID and public key must come from real key material, never free text, so this is the
    only path by which `fedreg` learns them.
    """
    try:
        text = jwks_path.read_text()
    except OSError as exc:
        raise GesundheitsIdError(f"could not read --jwks file {jwks_path}: {exc}") from exc
    try:
        key_set = load_jwks(text)
    except (ValueError, JoseError) as exc:
        raise GesundheitsIdError(f"--jwks file {jwks_path} is not a valid JWKS: {exc}") from exc
    if len(key_set.keys) != 1:
        raise GesundheitsIdError(
            f"--jwks file {jwks_path} must contain exactly one key (the ENTITY_STATEMENT_SIG "
            f"JWKS produced by 'keygen'); found {len(key_set.keys)}"
        )
    key = key_set.keys[0]
    assert_p256(key)
    if key.kid is None:
        raise GesundheitsIdError(f"--jwks file {jwks_path} key has no 'kid'")
    return key


def _sub(parent: ET.Element, tag: str, text: str) -> ET.Element:
    element = ET.SubElement(parent, tag)
    element.text = text
    return element


def build_registration_xml(
    *,
    environment: str,
    issuer_uri: str,
    member_id: str,
    contact_email: str,
    organization_name: str,
    fachdienst_name: str,
    scopes: list[str],
    redirect_uris: list[str],
    signing_key: ECKey,
    vfs_bestaetigung: str,
    zuweisungsgruppe: str,
) -> tuple[str, list[str]]:
    """Build the registration XML and return `(xml_text, warnings)`.

    `xml_text` is the bare `<registrierungtifoederation>` document, indented but without an
    XML declaration or the disclaimer comment -- `run()` adds those. `warnings` are
    non-fatal issues the caller should surface, e.g. a `vfsbestaetigung` given outside PU.
    """
    if environment not in _ENVIRONMENTS:
        raise GesundheitsIdError(f"--environment must be one of {_ENVIRONMENTS}, got {environment!r}")

    fachdienst_parsed = _validate_fachdienst_uri(issuer_uri)

    warnings: list[str] = []
    if environment == "PU" and not vfs_bestaetigung:
        raise GesundheitsIdError("--vfs-bestaetigung is required when --environment=PU")
    if environment != "PU" and vfs_bestaetigung:
        warnings.append(
            f"--vfs-bestaetigung is only meaningful for PU registrations; gematik ignores it for {environment}"
        )

    if "openid" not in scopes:
        raise GesundheitsIdError("scopes must include 'openid'")

    fachdienst_origin = _origin(fachdienst_parsed)
    for uri in redirect_uris:
        redirect_parsed = _validate_https(uri, arg_name="--redirect-uri")
        if _origin(redirect_parsed) != fachdienst_origin:
            raise GesundheitsIdError(
                f"--redirect-uri {uri!r} must share the Fachdienst-URI's origin "
                f"({fachdienst_parsed.scheme}://{fachdienst_parsed.netloc})"
            )

    assert_p256(signing_key)
    kid = signing_key.kid
    if kid is None:
        raise GesundheitsIdError("signing key has no 'kid'")
    key_pem = public_key_pem(signing_key)

    root = ET.Element("registrierungtifoederation")
    _sub(root, "teilnehmertyp", "Fachdienst")
    _sub(root, "betriebsumgebung", environment)
    _sub(root, "kontaktemail", contact_email)
    _sub(root, "vfsbestaetigung", vfs_bestaetigung)
    _sub(root, "zuweisungsgruppe", zuweisungsgruppe)
    _sub(root, "memberid", member_id)
    _sub(root, "organisationsname", organization_name)
    _sub(root, "fachdienstname", fachdienst_name)
    _sub(root, "fachdiensturi", issuer_uri)

    scopes_element = ET.SubElement(root, "scopes")
    for scope in scopes:
        _sub(scopes_element, "scope", scope)

    # gematik's current recommendation (per the commented wiki template) is to submit an
    # empty <claims/> container unless the Fachdienst genuinely needs claims beyond what
    # its scopes already imply -- this CLI has no --claims flag, so it is always empty.
    ET.SubElement(root, "claims")

    redirect_uris_element = ET.SubElement(root, "redirect_uris")
    for uri in redirect_uris:
        _sub(redirect_uris_element, "redirect_uri", uri)

    publickeysjwt_element = ET.SubElement(root, "publickeysjwt")
    publickey_element = ET.SubElement(publickeysjwt_element, "publickey")
    _sub(publickey_element, "kid", kid)
    _sub(publickey_element, "key", key_pem)

    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode"), warnings


def add_subparser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "fedreg",
        help="generate the gematik Fachdienst registration XML for idp-registrierung@gematik.de",
    )
    parser.add_argument("--environment", required=True, choices=_ENVIRONMENTS)
    parser.add_argument("--issuer-uri", required=True, help="the Fachdienst-URI (entity statement issuer)")
    # gematik ASSIGNS the Member-ID and tells you to submit the tag present but empty, so this
    # cannot be required. Defaults to "" to produce exactly the <memberid /> they ask for.
    parser.add_argument("--member-id", default="", help="leave unset: gematik assigns it on registration")
    parser.add_argument("--contact-email", required=True)
    parser.add_argument("--organization-name", default="")
    parser.add_argument("--fachdienst-name", default="")
    parser.add_argument(
        "--scopes",
        action="append",
        help=f"repeatable and/or comma-separated (default: {' '.join(_DEFAULT_SCOPES)})",
    )
    parser.add_argument("--redirect-uri", action="append", help="repeatable")
    parser.add_argument(
        "--jwks",
        required=True,
        help="path to the ENTITY_STATEMENT_SIG JWKS file produced by 'keygen' (KID + public key come from here)",
    )
    parser.add_argument("--vfs-bestaetigung", default="", help="required for --environment=PU only")
    parser.add_argument("--zuweisungsgruppe", default="")
    parser.add_argument("--out", help="write the XML here instead of stdout")
    parser.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    signing_key = _load_entity_statement_key(Path(args.jwks))
    scopes = _resolve_scopes(args.scopes)

    body, warnings = build_registration_xml(
        environment=args.environment,
        issuer_uri=args.issuer_uri,
        member_id=args.member_id,
        contact_email=args.contact_email,
        organization_name=args.organization_name,
        fachdienst_name=args.fachdienst_name,
        scopes=scopes,
        redirect_uris=list(args.redirect_uri or []),
        signing_key=signing_key,
        vfs_bestaetigung=args.vfs_bestaetigung,
        zuweisungsgruppe=args.zuweisungsgruppe,
    )
    document = f'<?xml version="1.0" encoding="UTF-8"?>\n{_DISCLAIMER}{body}\n'

    print(
        f"WARNING: this XML's structure is derived from gematik's wiki field documentation "
        f"({_WIKI_URL}) and must be validated against gematik's current RP_register.xsd "
        f"before submission.",
        file=sys.stderr,
    )
    for warning in warnings:
        print(f"WARNING: {warning}", file=sys.stderr)

    if args.out:
        out_path = Path(args.out)
        out_path.write_text(document)
        print(f"Wrote {out_path}")
    else:
        print(document)

    return 0
