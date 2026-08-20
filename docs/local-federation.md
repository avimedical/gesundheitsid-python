# Local reference federation (gematik `app-gemSekIdp`)

gematik publishes [`app-gemSekIdp`](https://github.com/gematik/app-gemSekIdp) (Apache-2.0),
containing `gsi-server` (a reference sectoral IdP) and `gsi-fedmaster` (a minimal Federation
Master). Running both locally gives a complete offline federation, removing gematik's IP
allowlist from the development loop.

This document says plainly what was actually verified against gematik's real repository and
config files, and what was not.

## What was verified by reading the source (2026-08-08)

- **No prebuilt image exists anywhere.** Checked GitHub Container Registry
  (`github.com/gematik/app-gemSekIdp/pkgs/container/gsi-server` -> 404;
  `github.com/orgs/gematik/packages?repo_name=app-gemSekIdp` -> "0 packages") and the
  `gematik1` Docker Hub organization (93 repositories listed via its public API; none named
  `gsi-server`, `gsi-fedmaster`, or anything "sektoraler idp"/"gemSekIdp"-shaped). The
  README does not mention a registry either. `docker-compose.yml` therefore references
  images that must be built locally, not pulled.
- **The project builds a local Docker image by default settings, but the build is
  opt-in.** Both `gsi-server/pom.xml` and `gsi-fedmaster/pom.xml` bind the `fabric8`
  `docker-maven-plugin` to the Maven `package` phase, but each module also sets
  `<skip.dockerbuild>true</skip.dockerbuild>` in its own `<properties>` (confirmed by
  reading both POMs; also called out as "skip docker build as default" in
  `ReleaseNotes.md`). You must pass `-Dskip.dockerbuild=false` explicitly to get an image.
- **Resulting image name/tag.** The root `pom.xml` sets
  `docker.registry.gematik` to `local` by default (only overridden in gematik's own
  Jenkins CI) and derives the image names from it:
  `${docker.registry.gematik}/idm/gsi-server` and `${docker.registry.gematik}/idm/gsi-fedmaster`,
  tagged `${project.version}`. At the time of writing, the parent POM's
  `<version>` is `8.4.2`, so a local build produces `local/idm/gsi-server:8.4.2` and
  `local/idm/gsi-fedmaster:8.4.2` -- **verify this against the checkout you actually build**
  (see the version-check command below); this project does not track gematik's releases.
- **Ports and health checks**, read from each module's
  `src/main/resources/application.yml`:

  | Service | HTTP port (`server.port`) | Actuator/health port (`management.server.port`) |
  |---|---|---|
  | `gsi-server` | `8085` (`SERVER_PORT`) | `8185` (`MANAGEMENT_PORT`) |
  | `gsi-fedmaster` | `8083` (`SERVER_PORT`) | `8183` (`MANAGEMENT_PORT`) |

  The README's own worked example confirms `gsi-server` on 8085:
  `curl http://localhost:8085/.well-known/openid-federation` returns a signed entity
  statement JWT. Each module's `Dockerfile` (`src/main/docker/Dockerfile`) bakes in a
  `HEALTHCHECK` against port `8180`, which does not match the `application.yml` default of
  `8185` -- this discrepancy is real and unexplained in the source; it is presumably closed
  by a `MANAGEMENT_PORT=8180` override in gematik's own deployment, not by anything in this
  repo. Not independently resolved here.
- **Environment variables that matter for a multi-container setup**, also read from
  `application.yml`: `gsi-server` takes `GSI_SERVER_URL` (its own `iss`, default
  `http://127.0.0.1:8085`) and `FEDMASTER_SERVER_URL` (default `http://127.0.0.1:8083`);
  `gsi-fedmaster` takes `ISSUER_IDP_01` (the sectoral IdP it trusts, default
  `http://127.0.0.1:8085`) and `ISSUER_RP_01` (an example relying party it trusts, default
  `http://127.0.0.1:8084`, pre-configured for an organization named "GRAS" in the upstream
  repo -- not this project). `docker-compose.yml` overrides `ISSUER_IDP_01` and
  `FEDMASTER_SERVER_URL` to the compose service names so the two containers can reach each
  other; `GSI_SERVER_URL` is left at its `127.0.0.1` default because that is what a host
  developer's browser/HTTP client actually needs (it reaches `gsi-server` via the
  `8085:8085` port mapping, i.e. `localhost`, not the container network).
- **Java 21**, per `<java.version>21</java.version>` in the root POM and each Dockerfile's
  `FROM gematik1/osadl-alpine-openjdk21-jre:...` base image.

## What was verified by actually running it (2026-08-19)

The whole stack was built and run on this machine, and the integration suite
(`tests/integration/`) now drives the real thing on every `uv run pytest -m integration`.
Findings, in the order they bit:

- **The docker build is broken as checked out, and the fix is one `cp`.** `gsi-server/pom.xml`
  copies `certs_trusted/**` from `${basedir}/src/main/resources`, but that directory only exists
  under `src/test/resources`. The build fails at
  `COPY ... certs_trusted /app/certs_trusted` with `no such file or directory`. Copy it across
  before building (see below). `gsi-fedmaster` is unaffected -- its Dockerfile does not use
  `certs_trusted` at all. This is almost certainly why `skip.dockerbuild` defaults to true.
- **`gsi-fedmaster` does serve `/.well-known/openid-federation`**, as assumed above. Confirmed 200.
- **The `iss` mismatch worry was real, and is avoided by configuration.** Both services now take
  their public https URL (`FEDMASTER_SERVER_URL`, `GSI_SERVER_URL`) so `iss`, `sub` and
  `authority_hints` all agree with the URL a host-side validator fetches. Nothing in the trust
  plane needs container-to-container traffic -- the fedmaster issues subordinate statements from
  static config and never calls the IdP -- so publishing both on `localhost` is sufficient.
- **The Federation Master's endpoint paths are not what this project assumed**, and are not
  guessable. It serves `/federation_fetch_endpoint`, `/federation_list` and
  `/.well-known/idp_list`, and advertises all three in `metadata.federation_entity` of its own
  entity statement. `FederationMasterClient` now discovers them there.
- **The signed idp_list keys its array `idp_entity`**, not `idps`.
- **A subordinate statement carries only a metadata overlay.** gematik's returns
  `{"openid_provider": {"client_registration_types_supported": ["automatic"]}}`; the
  authorization, token and PAR endpoints live in the IdP's own entity configuration. Resolution
  now merges leaf metadata with the superior's winning per key, while keys still come from the
  subordinate statement alone.
- **`resolve_trust_chain` requires https, and gematik's services are plain HTTP.** Rather than
  adding a "permit http in tests" switch -- the kind that later gets set in production -- the
  compose stack fronts both services with nginx and a throwaway CA
  (`scripts/local_federation_certs.py`, `docker/local-federation/nginx.conf`). An integration
  test asserts the https requirement still rejects `http://localhost:8085`, which is genuinely
  reachable and serves the same statement.
- **Python 3.14 verifies certificates more strictly than curl.** A self-signed CA needs
  `SubjectKeyIdentifier` and an explicit `keyCertSign` `KeyUsage`, or handshakes fail with
  "Missing Authority Key Identifier" / "Path length given without key usage keyCertSign" while
  `curl --cacert` accepts the same chain.

### Still not verified

- The full authorization flow (PAR -> token -> encrypted ID token) against `gsi-server`. That
  needs this relying party registered with the local fedmaster (a public-key PEM mounted into
  the container plus `ISSUER_RP_01`) and its entity statement served somewhere `gsi-server` can
  fetch. Note also that `gsi-server` advertises `authorization_endpoint` under its configured
  `GSI_SERVER_URL` but leaves `token_endpoint` and `pushed_authorization_request_endpoint` on
  `http://127.0.0.1:8085`, so a PAR call from the host would leave TLS behind.
  **RESOLVED 2026-08-20**: confirmed by reading `EntityStatementBuilder.buildMetadata()` --
  `token_endpoint`/`pushed_authorization_request_endpoint` come from `gsi.serverUrlMtls`
  (`GSI_SERVER_URL_MTLS`), a property genuinely separate from `gsi.serverUrl`
  (`GSI_SERVER_URL`, which only fixes `authorization_endpoint`). `docker-compose.yml` now
  sets both to the same `https://idp.gsi.test:8445` nginx vhost; see the "OIDC data plane"
  section below for the verified resulting entity statement.
- `mvn` is not installed on this machine; the build was run with a Maven unpacked into a
  scratch directory. Any Maven 3.9.x works.

## What was NOT verified (as of the source-reading pass above)

- **The full three-container handshake was not run.** No Docker/Podman build of this
  project was executed as part of writing this document -- only the POM/YAML/Dockerfile
  *source* was read. In particular, OpenID Federation conventionally expects a fetched
  entity statement's `iss` to equal the URL it was fetched from; `gsi-server`'s `iss`
  defaults to `http://127.0.0.1:8085` while `gsi-fedmaster` (per the compose override above)
  fetches it from `http://gsi-server:8085`. Whether `gsi-fedmaster`'s validation actually
  tolerates that mismatch is unconfirmed. If it does not, override `GSI_SERVER_URL` to
  `http://gsi-server:8085` too and accept that `localhost:8085` callers then see an `iss`
  that does not match the URL they used.
- **`gsi-fedmaster`'s own `/.well-known/openid-federation` endpoint** was not independently
  confirmed in its source (no controller was read); it is assumed present by analogy with
  `gsi-server` and the OpenID Federation spec's universal convention, and should be checked
  with `curl http://localhost:8083/.well-known/openid-federation` once the container is up.
- Whether `docker-maven-plugin` needs a `DOCKER_HOST` pointing at a running daemon (Docker
  or, as on this machine, Podman) was not tested end-to-end here, only inferred from the
  plugin's documented behavior (it always needs a Docker-API-speaking socket at build time).

## Building the images

```shell
git clone https://github.com/gematik/app-gemSekIdp.git
cd app-gemSekIdp

# Confirm the version you're about to build -- pin docker-compose.yml's tags to match if it differs from 8.4.2
mvn -q help:evaluate -Dexpression=project.version -DforceStdout

# Required: the docker build copies certs_trusted from src/main/resources, where it does not
# exist. Without this the gsi-server image build fails on its COPY step.
cp -R gsi-server/src/test/resources/certs_trusted gsi-server/src/main/resources/certs_trusted

# skip.dockerbuild defaults to true in both gsi-server and gsi-fedmaster; -Dskip.unittests
# just avoids waiting on the test suite, it does not affect the docker build itself
mvn clean package -pl gsi-server,gsi-fedmaster -am -Dskip.unittests -Dskip.dockerbuild=false
```

This requires a Docker-API-speaking daemon reachable at build time (the `fabric8`
`docker-maven-plugin` talks to whatever `DOCKER_HOST` points at, or the default Unix socket
if unset). On a Podman-only machine, export `DOCKER_HOST` at the podman socket before
running `mvn`.

On success, `docker images` (or `podman images`) should list
`local/idm/gsi-server:<version>` and `local/idm/gsi-fedmaster:<version>`.

## Running it

First, add the three federation members' names to `/etc/hosts` (once; requires sudo, and is
deliberately NOT automated by any script here -- see "Hostnames" below for why):

```shell
echo '127.0.0.1 fedmaster.gsi.test idp.gsi.test rp.gsi.test' | sudo tee -a /etc/hosts
```

Then, from this repository's root:

```shell
uv run python scripts/local_federation_certs.py   # once; throwaway CA for the TLS terminator
docker compose up -d
```

Then, from the host:

```shell
CA=.local-federation/ca.pem
curl --cacert $CA https://idp.gsi.test:8445/.well-known/openid-federation       # gsi-server
curl --cacert $CA https://fedmaster.gsi.test:8443/.well-known/openid-federation # gsi-fedmaster
```

Plain HTTP on 8083/8085 still works and is what the containers use internally; the https ports
exist because `resolve_trust_chain` refuses non-https issuers, and that refusal is worth keeping
exactly as production runs it.

### Hostnames

All three federation members (`gsi-fedmaster`, `gsi-server`, and -- once registered -- this
relying party) are published as `fedmaster.gsi.test`, `idp.gsi.test`, `rp.gsi.test`, not
`localhost`. `localhost` inside a container is that container's own loopback, not the host's --
publishing on `localhost:<port>` only ever worked for the trust plane, because the fedmaster
never calls the IdP and the integration test process itself runs on the host. The OIDC data
plane does need container-to-container traffic (`gsi-server` fetches the fedmaster's
`federation_fetch_endpoint`, and our RP's own entity statement), so all three names are wired to
resolve identically in both places: to `127.0.0.1` on the host via `/etc/hosts`, and to the
`tls-proxy` container via `networks.default.aliases` on that service in `docker-compose.yml`.

`.test`, not `.local`: `.local` is mDNS/Bonjour territory on macOS, and `mDNSResponder`
intercepts those lookups -- tried first, it produced intermittent resolution failures that
looked exactly like federation bugs. `.test` is IANA-reserved for exactly this purpose
(RFC 6761) and every general-purpose resolver leaves it alone.

**If you recreate `gsi-fedmaster` or `gsi-server` (e.g. after an env var or image change),
restart `tls-proxy` too:** nginx resolves `proxy_pass` upstream hostnames once, at startup, and
does not notice a recreated container's new IP on its own -- the symptom is a `502 Bad Gateway`
from a service that is actually up and healthy underneath.

```shell
docker compose up -d --force-recreate gsi-server   # or gsi-fedmaster
docker compose restart tls-proxy
```

## Running the integration suite against it

```shell
uv run pytest -m integration
```

These are excluded from a normal `uv run pytest` (see `pytest.ini`) and skip -- never fail --
when the federation is not running.

## Registering our relying party

Verified end to end 2026-08-20. gematik's reference repo ships exactly one pre-registered
relying party ("GRAS"), and only its PUBLIC key (`ref-gras-pubkey.pem`) -- there is no
private half anywhere in the checkout, so it cannot be reused. Registering our own means
generating our own keypairs and telling `gsi-fedmaster` to trust the public half instead.

### 1. Generate keys

```shell
uv run gesundheitsid-cli keygen --issuer-uri=https://rp.gsi.test:8447 --out-dir=.local-federation/rp
```

Prints the ES-signing key's `kid` and public PEM -- keep both; the next step needs them.
`.local-federation/` is gitignored (verify with `git check-ignore -v .local-federation/rp/anything`
before generating anything) -- nothing under it is ever committed.

### 2. Rebuild `gsi-fedmaster` with our public key baked in

`gsi-fedmaster` loads a registered relying party's key via
`Thread.currentThread().getContextClassLoader().getResourceAsStream(keyConfig.fileName)`
(`KeyConfiguration`/gematik's `ResourceReader`) -- i.e. **only** from inside the running
jar's own classpath. The Dockerfile launches it with `java -jar`, and Spring Boot's
`JarLauncher` (confirmed by decompiling the built jar's manifest and loader classes) fixes
the classpath to the jar's own nested archives; `loader.path`/`PropertiesLauncher`-style
extra locations are not consulted. **A bind-mounted key file is invisible to it, no matter
where you mount it** -- there is no shortcut around a rebuild here, only two real options:
switch the container's entrypoint to `PropertiesLauncher` with `LOADER_PATH` (more moving
parts, unverified), or rebuild the image with the key inside it (what we did, since this
project already has a documented Maven recipe for exactly that from the `gsi-server`
`certs_trusted` fix above).

```shell
CA_PEM=.local-federation/rp/es_sig_pubkey.pem   # derive from the *_jwks.json keygen wrote,
                                                 # or copy the PEM keygen printed to stdout

cp "$CA_PEM" /path/to/app-gemSekIdp/gsi-fedmaster/src/main/resources/keys/ref-rp-local-es-sig-pubkey.pem

cd /path/to/app-gemSekIdp
JAVA_HOME=$(/usr/libexec/java_home -v21) PATH="$JAVA_HOME/bin:$PATH"   DOCKER_HOST=unix:///path/to/podman-machine-default-api.sock   mvn -pl gsi-fedmaster -am -Dskip.unittests -Dskip.dockerbuild=false clean package

podman tag local/idm/gsi-fedmaster:8.4.2 docker.io/local/idm/gsi-fedmaster:8.4.2-rp
```

**`JAVA_HOME` must point at a JDK 21, not whatever `java` resolves to by default.** Building
with JDK 25 (this machine's default `/usr/bin/java`) fails with dozens of `cannot find
symbol` errors for Lombok-generated methods (`builder()`, `getX()`, the `@Slf4j` `log`
field) -- Lombok 1.18.46 (pinned by this checkout) does not fully support JDK 25's
annotation-processing internals yet. The existing `gsi-server`/`gsi-fedmaster` build
succeeded previously on this same machine only because JDK 21 was selected at the time; it
is not recorded in the Maven command itself, so it is easy to silently regress.

Only the PUBLIC key enters the image; retagging as `8.4.2-rp` (not overwriting `8.4.2`)
keeps it obvious this image is customized and distinct from what gematik's own build
produces.

### 3. Point `gsi-fedmaster` at it

See `docker-compose.yml`'s `gsi-fedmaster.environment` for the full, commented set of
`FEDMASTER_RELYINGPARTYCONFIGS_0_*` variables and **the defect they work around**: Spring
Boot's `@ConfigurationProperties` binder does not merge a `List<T>`-typed property across
multiple property sources per-element. Setting only
`FEDMASTER_RELYINGPARTYCONFIGS_0_KEYCONFIG_FILENAME`/`_KEYID` (relying on the shipped
YAML's own `${ISSUER_RP_01:...}` placeholder for `issuer`, the way `ISSUER_IDP_01` works
for `identityProviderConfigs`) silently produced
`RelyingPartyConfig(issuer=null, organizationName=null, keyConfig=KeyConfig(..., use=null,
...))` -- confirmed via `gsi-fedmaster`'s own `fedMasterConfiguration: ...` startup log
line -- which then threw a `NullPointerException` inside
`EntityStatementFederationMemberBuilder.getKey` (`issuer=null`). All five fields
(`issuer`, `organizationName`, `keyConfig.fileName`, `keyConfig.keyId`, `keyConfig.use`)
must be set together once any one of them is.

### 4. Run this relying party for real, on the host

```shell
uv run gesundheitsid-cli keygen --issuer-uri=https://rp.gsi.test:8447 --out-dir=.local-federation/rp
DJANGO_SETTINGS_MODULE=tests.integration.local_federation_settings uv run python -m django runserver 0.0.0.0:8000
```

See `tests/integration/local_federation_settings.py`'s module docstring for why this
exists and is not a production settings module: `gsi-server` fetches our RP's own
`.well-known/openid-federation` to get our real `jwks` (the fedmaster's subordinate
statement about us, fetched above, carries only the hardcoded metadata overlay you can see
in it -- redirect_uris/scope, never keys). `docker-compose.yml`'s `tls-proxy` forwards
`https://rp.gsi.test:8447` to `host.docker.internal:8000`, which podman's gvproxy resolves
from inside a container automatically (verified: no `extra_hosts` entry was needed).

### The hardcoded RP metadata limitation

`EntityStatementFederationMemberBuilder.buildMetadataForRelyingParty` hardcodes
`redirect_uris` and `scope` into the subordinate statement it issues about **any**
relying party it is configured to vouch for -- our real `GESUNDHEITSID["REDIRECT_URI"]`/
`SCOPES` are never consulted, and `gsi-server` validates PAR against this hardcoded
overlay (`RequestValidator.validateParParams` -> `EntityStatementRpVerifier`). So exercising
PAR against the local federation is only possible with:

- `REDIRECT_URI = "https://redirect.testsuite.gsi"` (one of exactly four hardcoded URIs,
  the only one meant for exactly this kind of exercise)
- `SCOPES = ["openid", "urn:telematik:display_name", "urn:telematik:versicherter"]` (the
  hardcoded scope string, order does not matter)

This means the harness cannot exercise a real browser redirect landing at our own
`redirect.testsuite.gsi` (it doesn't exist), and cannot exercise the `email` scope (not in
the hardcoded set) -- see `tests/integration/`'s own docstrings for how the test suite
works around the first limitation.
