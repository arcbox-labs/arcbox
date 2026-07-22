# docker build E2E matrix — derived from a real-world Dockerfile corpus

Companion to `network-workload-e2e.md`. W14 there proved the *network
datapath* survives one `docker build`; this plan derives the **build
compatibility and performance matrix** from what flagship open-source
projects actually put in their Dockerfiles, so the future `docker_build`
e2e suite tests the build surface developers really hit — not features we
imagine they use.

Method: 25 Dockerfiles fetched 2026-07-22 from each repo's default branch
(`raw.githubusercontent.com/<repo>/HEAD/<path>`), feature vectors extracted
programmatically (stage counts, `--mount` types, platform ARGs, heredocs,
syntax directives, network calls). Re-fetch with the same repo/path table
below to refresh the census.

## Corpus

| Source (repo — path) | Ecosystem | Shape highlights |
|---|---|---|
| moby/moby — `Dockerfile` | Go | 56 stages, 51 cache mounts, 35 `COPY --link`, heredocs, `FROM scratch` exports |
| moby/buildkit — `Dockerfile` | Go | 44 stages, 19 bind mounts, 51 `COPY --link`, 8 `FROM scratch`, cross-platform (`--platform=$BUILDPLATFORM`) |
| docker/buildx — `Dockerfile` | Go | 29 stages, same family as buildkit |
| grafana/grafana — `Dockerfile` | Go+Node hybrid | 14 stages, `syntax=docker/dockerfile:1.7-labs`, `COPY --parents` |
| apache/airflow — `Dockerfile` | Python | 1.9k lines, 94 ARGs, ARG-parameterized `FROM ${BASE_IMAGE}`, `FROM scratch as scripts` heredoc script-carrier stage, 15 heredocs |
| mastodon/mastodon — `Dockerfile` | Ruby+Node | 9 stages, 11 cache mounts with `sharing=locked` + per-`TARGETPLATFORM` cache IDs |
| goauthentik/authentik — `lifecycle/container/Dockerfile` | Go+Python+Node | 34 bind mounts, **2 `--mount=type=secret`** (only secret user in corpus), `ADD` from URL |
| immich-app/immich — `server/Dockerfile` | Node native-deps | 16 bind mounts for pnpm lockfiles, 6 cache mounts |
| vercel/next.js — `examples/with-docker/Dockerfile` | Node | canonical 3-stage standalone build; npm/yarn/pnpm autodetect via corepack; cache mounts |
| vercel/turborepo — `examples/with-docker/apps/web/Dockerfile` | Node monorepo | `turbo prune --docker` context-slimming pattern |
| n8n-io/n8n — `docker/images/n8n/Dockerfile` | Node | modest 2-FROM prod image |
| go-gitea/gitea — `Dockerfile` | Go | 2-stage + cross-platform FROM |
| traefik/traefik — `Dockerfile` | Go | minimal `syntax=1.2` + TARGETPLATFORM COPY |
| caddyserver/caddy-docker — `2.11/builder/Dockerfile` | Go | xcaddy builder: toolchain download at build time |
| prometheus/prometheus — `Dockerfile` | Go | pure COPY-binary, zero network |
| dani-garcia/vaultwarden — `docker/Dockerfile.debian` | Rust | 4 FROMs, TARGETPLATFORM cross-compile |
| meilisearch/meilisearch — `Dockerfile` | Rust | alpine cargo build |
| home-assistant/core — `Dockerfile` | Python | `syntax=` **pinned by sha256 digest**, uv installs |
| paperless-ngx/paperless-ngx — `Dockerfile` | Python+Node | 2-stage, TARGETPLATFORM, HEALTHCHECK |
| keycloak/keycloak — `quarkus/container/Dockerfile` | JVM | 1-stage + chown COPY |
| mastodon-class official images: docker-library/postgres `17/bookworm`, docker-library/redis `7.4/debian`, nginxinc/docker-nginx `mainline/debian`, docker-library/ghost `6/bookworm` | C/misc | classic single-stage: apt + `wget` release binaries + **gpg keyserver verify**, tiny build context |
| traefik/traefik — `webui/buildx.Dockerfile` | Node | trivial single-stage yarn |

## Feature census (what production Dockerfiles actually use)

Ranked by prevalence in the corpus (n=25):

| Feature | Prevalence | Exemplars |
|---|---|---|
| Multi-stage + `COPY --from` | 17/25; extremes 56/44/29 stages | moby, buildkit, buildx, grafana |
| Build-time network (apt/apk/npm/pip/cargo/bundle) | 24/25 | everything except prometheus |
| External `# syntax=` frontend (adds a frontend **image pull** to every build) | 12/25 — incl. version-pinned (`1.18`, `1.2`), digest-pinned (home-assistant), labs channel (grafana), master (buildkit) | see syntax list |
| `RUN --mount=type=cache` | 10/25 | moby(51), mastodon(11, `sharing=locked`, per-platform IDs), authentik, immich, next.js |
| `TARGETPLATFORM`/`TARGETARCH` + `--platform=$BUILDPLATFORM` cross-compile | 9/25 | moby, buildkit, mastodon, vaultwarden, gitea, paperless |
| `RUN --mount=type=bind` (lockfile mounts, no COPY layer) | 5/25, heavy | authentik(34), immich(16), buildkit(19) |
| `COPY --link` | 4/25 | buildkit(51), moby(35), buildx, grafana |
| Heredocs (`RUN <<EOT`) | 4/25 | airflow(15), buildkit, moby, buildx |
| `FROM scratch` export stages | 3/25 | buildkit(8), buildx, moby |
| gpg keyserver fetch during build | 4/25 | postgres, redis, nginx, ghost |
| `ADD` from URL | 4/25 | authentik, immich, paperless, vaultwarden |
| `RUN --mount=type=secret` | 1/25 | authentik (GeoIP credentials) |
| `RUN --mount=type=ssh` | 0/25 (private-repo installs; absent from OSS by nature, still API surface) | — |
| labs frontend features (`COPY --parents`) | 1/25 | grafana |
| ARG-parameterized `FROM ${BASE_IMAGE}` | 2/25 | airflow, keycloak |
| HEALTHCHECK in Dockerfile | 4/25 | authentik, immich, paperless, vaultwarden |

## What each feature stresses in ArcBox

The build request is forwarded verbatim to guest dockerd's BuildKit
(`app/arcbox-docker/src/handlers/build.rs`), so our exposure is the proxy
and the guest environment, not the builder logic:

| Corpus feature | ArcBox surface at risk |
|---|---|
| Build context upload | vsock upload proxy backpressure (`proxy_upload_to_system_vm`) — designed for GB contexts, e2e-tested only at 8 MiB (W14) |
| `# syntax=` frontend, `FROM` pulls | registry pull path through guest dockerd + datapath + DNS + TLS (⇒ guest clock, ABX-416) |
| RUN-step network (apt/npm/gpg keyservers) | egress datapath, UDP DNS, keyserver ports — the network_workload/fault suites' surface, now composed inside a build |
| `--secret` / `--ssh` | `/session` HTTP upgrade proxy (`proxy/upgrade.rs`) — unit-tested only |
| `--platform linux/amd64` | FEX path; `require_amd64_runtime` fail-closed — no e2e either direction |
| Cache mounts, 50-stage graphs, parallel layer commits | guest disk (`docker.img`) I/O + CPU/memory pressure; balloon interaction |
| `docker build -o` (local/tar exporter) | reverse-direction session traffic (build artifacts stream host-ward) |
| Chatty builds (`--progress=plain`, MB-scale RUN stdout) | build-output streaming through the proxy |

## Derived test matrix

Tier D is the default suite: locally runnable, no external network (base
images pre-pulled via the existing `ensure_image` fixture; RUN-step
downloads served by the in-process blob server), one booted daemon shared
by all scenarios, failures aggregated — the `network_workload` pattern.
Fixture preamble records the guest dockerd + BuildKit versions so failures
are attributable. All wall times go to `RunMetrics` as trend lines;
assertions are deadlines and behavior, never absolute throughput.

| ID | Pattern (modeled on) | Mechanism | Assertions |
|---|---|---|---|
| D1 | large context upload (immich/next.js node_modules shape) | 512 MiB incompressible + 100k small files; `.dockerignore` excluding a marker dir | build ok ≤ deadline; in-build payload sha + whole-tree sha byte-exact; ignored dir absent in-guest; `large_context_transfer` trend *(implemented)* |
| D2 | deep multi-stage graph (grafana/buildkit) | 12-stage diamond: `FROM scratch AS scripts` carrier, 4 parallel-schedulable branches, `COPY --from` joins, `FROM scratch AS export` tail, `COPY --link`, heredoc RUN, `# syntax=docker/dockerfile:1` (frontend pre-loaded) | export-stage artifact byte-exact via `docker cp`; full `docker export` listing free of builder residue; build ok ≤ deadline *(implemented)* |
| D3 | cache semantics (mastodon/next.js) | `RUN --mount=type=cache,sharing=locked`; then 3 rebuilds: unchanged, one-file leaf change, base-layer change | unchanged rebuild reuses the image (identical ID) with wall ≤ max(cold/10, 3 s floor); per-execution stamps baked into the image prove leaf change re-runs only downstream steps and base change re-runs both; cache-mount token survives across builds *(implemented)* |
| D4 | BuildKit session (authentik secrets; ssh has no OSS exemplar but same channel) | `--secret id=x,src=file` consumed by `RUN --mount=type=secret`; `--ssh default=<sock>` against a throwaway host `ssh-agent` (one loaded key) | secret readable in RUN, gone next layer, **absent from every byte of `docker save`** (gzip-aware sweep); forwarded ssh sock present in RUN; quiet-log covers the `/session` upgrades *(implemented)* |
| D5 | bind-mount lockfiles (authentik/immich) | `RUN --mount=type=bind,source=...` consuming context files without COPY layers | in-build read + derived hash lands in image; mount leaves no trace in the final fs *(implemented)* |
| D6 | cross-platform args + FEX (vaultwarden/moby; ABX-375) | (a) `--platform=$BUILDPLATFORM` FROM + `TARGETARCH` expansion, native; (b) `--platform linux/amd64` with a `RUN uname -m` step | (a) correct arch strings baked; (b) FEX provisioned ⇒ `x86_64` output, else **fail-closed** with the actionable error (both directions asserted) |
| D7 | concurrent builds (CI shape) | 4 parallel distinct builds + 2 same-context duplicates | all complete ≤ deadline; no cross-talk (unique markers per image); zombie sweep clean |
| D8 | cancellation (production reality) | kill client mid-context-upload and mid-RUN; rebuild after | daemon log free of proxy ERROR; follow-up build succeeds; no leaked build processes guest-side |
| D9 | output streaming | `--progress=plain` with a RUN emitting 50k ordered lines PACED under BuildKit's 200 KiB/s step-log rate clip (bulk output is clipped by design and proves nothing); `docker build -q` | tail lines present, no clip marker, deadline catches a wedge; quiet mode prints exactly one image ID *(implemented)* |
| D10 | exporters | `docker build -o type=local,dest=…` and `-o type=tar` | exported artifact byte-exact vs in-image content — exercises reverse session streaming *(implemented)* |

External syntax frontends (`# syntax=docker/dockerfile:1`) are exercised in
D2 by pre-pulling the frontend image in the fixture; if the guest BuildKit
still dials out for it, the scenario moves to Tier X rather than weakening
the no-network rule.

Tier X (`ARCBOX_E2E_EXTERNAL=1`, manual, real internet — the
network-workload plan's external-phase convention), pinned to specific
upstream commits:

| ID | Build | Why this one |
|---|---|---|
| X1 | docker-library/postgres `17/bookworm`, redis `7.4/debian`, nginx `mainline/debian` | tiny contexts, real apt + wget + **gpg keyserver** traffic — the classic official-image shape, near-zero context cost |
| X2 | vercel/next.js `examples/with-docker` | real `npm ci` through the datapath; the single most common user Dockerfile shape |
| X3 | caddyserver/caddy-docker builder | Go toolchain + module downloads inside the build |
| X4 | mastodon or immich at a pinned tag | hour-scale polyglot heavyweight; manual smoke when touching the proxy or datapath, never CI |

## Bench methodology

No criterion micro-bench: build performance is dominated by the guest and
the datapath, so the signal is the Tier-D wall-time trend lines
(`docker_build_wall`, `context_upload_wall`, cold-vs-warm ratios in D3)
recorded per run by `RunMetrics` — same trend-not-gate policy as the
workload suite. Cross-runtime comparison (OrbStack / Docker Desktop) is a
manual `xtask` run of the same fixtures against another engine's
`DOCKER_HOST`, not an automated gate.

## Status

D1–D3 are implemented (`tests/e2e/tests/docker_build.rs`) and currently
**red for a real product reason**: every buildx-driven build hangs because
guest FEX spins forever on BuildKit's amd64 arch-probe ELF, permanently
wedging the BuildKit Control API (ABX-494 — first caught by this suite's
first run; `network_workload` W14 reproduces it too). Do not weaken the
suite; it goes green when ABX-494 is fixed.

## Phasing

1. D1–D3 (context, stages, cache) — pure fixture work, no new capability
   questions, covers the three highest-prevalence census rows.
2. D4–D5 + D9–D10 (session, streaming, exporters) — the proxy-layer
   surfaces with today’s thinnest coverage.
3. D6 (FEX) once an e2e knob to assert the unprovisioned path exists;
   D7–D8 alongside, sharing the concurrency fixtures.
4. Tier X wiring (pinned clones, env gate) — manual-run documentation.
