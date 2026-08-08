# Local reference federation (gematik `app-gemSekIdp`)

gematik publishes [`app-gemSekIdp`](https://github.com/gematik/app-gemSekIdp) (Apache-2.0),
containing `gsi-server` (a reference sectoral IdP) and `gsi-fedmaster` (a minimal Federation
Master). Running both locally gives a complete offline federation, removing gematik's IP
allowlist from the development loop.

This document says plainly what was actually verified against gematik's real repository and
config files, and what was not.

## What was verified (2026-08-08)

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

## What was NOT verified

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

# skip.dockerbuild defaults to true in both gsi-server and gsi-fedmaster; -Dskip.unittests
# just avoids waiting on the test suite, it does not affect the docker build itself
mvn clean package -Dskip.unittests -Dskip.dockerbuild=false
```

This requires a Docker-API-speaking daemon reachable at build time (the `fabric8`
`docker-maven-plugin` talks to whatever `DOCKER_HOST` points at, or the default Unix socket
if unset). On a Podman-only machine, export `DOCKER_HOST` at the podman socket before
running `mvn`.

On success, `docker images` (or `podman images`) should list
`local/idm/gsi-server:<version>` and `local/idm/gsi-fedmaster:<version>`.

## Running it

From this repository's root:

```shell
docker compose up -d
```

Then, from the host:

```shell
curl http://localhost:8085/.well-known/openid-federation   # gsi-server's entity statement (confirmed by gematik's own README)
curl http://localhost:8083/.well-known/openid-federation   # gsi-fedmaster's own entity statement (expected by convention, not independently confirmed above)
```

## Running the CLI against it

Once `gsi-server` answers on 8085, generate your own relying-party keys and point them at
the local federation:

```shell
uv run gesundheitsid-cli keygen --issuer-uri=https://your-rp.local.test --out-dir=./secrets
```

Registering your RP with the local `gsi-fedmaster` (as opposed to gematik's real Federation
Master) is a matter of adding an `ISSUER_RP_01`-style entry pointing at your RP's own
locally-served entity statement -- see `gsi-fedmaster/src/main/resources/application.yml`
in the cloned repo for the exact `relyingPartyConfigs` shape. `gesundheitsid-cli fedreg`
itself always targets gematik's real Federation Master process (the email workflow); it has
no local-federation mode.
