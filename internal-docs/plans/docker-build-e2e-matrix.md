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
| D3 | cache semantics (mastodon/next.js) | `RUN --mount=type=cache,sharing=locked`; then 3 rebuilds: unchanged, one-file leaf change, base-layer change | per-execution stamps baked into the image prove the unchanged rebuild re-runs nothing (image IDs are NOT comparable — BuildKit re-stamps `created` per build), leaf change re-runs only downstream steps, base change re-runs both; warm wall ≤ max(cold/10, 3 s floor); cache-mount token survives across builds *(implemented)* |
| D4 | BuildKit session (authentik secrets; ssh has no OSS exemplar but same channel) | `--secret id=x,src=file` consumed by `RUN --mount=type=secret`; `--ssh default=<sock>` against a throwaway host `ssh-agent` (one loaded key) | secret readable in RUN, gone next layer, **absent from every byte of `docker save`** (gzip-aware sweep); forwarded ssh sock present in RUN; quiet-log covers the `/session` upgrades *(implemented)* |
| D5 | bind-mount lockfiles (authentik/immich) | `RUN --mount=type=bind,source=...` consuming context files without COPY layers | in-build read + derived hash lands in image; mount leaves no trace in the final fs *(implemented)* |
| D6 | cross-platform args + FEX (vaultwarden/moby; ABX-375) | (a) `--platform=$BUILDPLATFORM` FROM + `TARGETARCH` expansion, native; (b) `--platform linux/amd64` with a `RUN uname -m` step | (a) `linux/arm64:arm64` baked; (b) `x86_64` asserted in-build + image records `amd64` — the surface ABX-494 wedged. Fail-closed unprovisioned direction still awaits an e2e knob (FEX ships in every bundle ≥ 0.6.6) *(implemented, positive paths)* |
| D7 | concurrent builds (CI shape) | 4 parallel distinct builds + 2 same-context duplicates, all in flight at once | all complete ≤ deadline; no cross-talk (unique markers per image); suite quiet-log covers the daemon side *(implemented)* |
| D8 | cancellation (production reality) | SIGKILL the client mid-RUN and mid-context-upload (256 MiB); rebuild after | guest reaps the cancelled RUN's process (polled via `--pid=host`); follow-up build succeeds promptly; suite quiet-log asserts the daemon rode both kills without proxy ERRORs *(implemented)* |
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
| X1 | docker-library/postgres `17/bookworm` | tiny context, real apt + wget + **gpg keyserver** traffic — the classic official-image shape; smoke: `postgres --version` *(implemented; redis/nginx are the same shape and stay out to keep the run bounded)* |
| X2 | vercel/next.js `examples/with-docker` | real `pnpm install --frozen-lockfile` + `next build` through the datapath; the single most common user Dockerfile shape *(implemented)* |
| X3 | caddyserver/caddy-docker `2.11/builder` | apk + checksum-verified xcaddy release fetch (the builder image installs the toolchain; the full compile happens when it is used) *(implemented)* |
| X4 | mastodon or immich at a pinned tag | hour-scale polyglot heavyweight; manual smoke when touching the proxy or datapath, never CI |

## Baseline (2026-07-22, M-series host, VZ guest, boot 0.6.10, dockerd 29.6.1 / BuildKit v0.31.1)

Measured with an engine-agnostic harness (plain `docker build` timed
host-side via `DOCKER_HOST`; cold-ness via a per-build nonce file in the
context so no engine-global cache prune is needed; base images pre-pulled
outside the timed region; real-project contexts fetched at the Tier X
pins, with X2's pnpm accommodation). Single-shot numbers — trend anchors,
not gates.

Comparison engine: Colima 0.10.3 on the same host, matched shape (18
vCPU / 16 GiB, VZ, virtiofs, `--vz-rosetta`; its dockerd 29.5.2 — one
minor behind ArcBox's 29.6.1, same BuildKit generation).

| shape | ArcBox | Colima | ratio |
|---|---|---|---|
| simple 3-RUN alpine build, cold | 8.1 s | 0.60 s | **13.5×** |
| same build, full cache hit | 1.8 s | 0.16 s | **11×** |
| 512 MiB + 100k-file context, cold | 26.4 s | 20.3 s | 1.3× |
| 12-stage diamond, cold | 12.7 s | 1.5 s | **8.4×** |
| `--platform linux/amd64` (FEX vs Rosetta): probe + 300k-iter shell loop | 6.4 s | 0.87 s | 7.3× |
| postgres `17/bookworm` (real apt + gpg + wget) | 75.6 s | 40.7 s | 1.9× |
| next.js `with-docker` (pnpm frozen install + `next build`) | 37.8 s | 27.1 s | 1.4× |
| caddy `2.11/builder` (apk + xcaddy fetch) | 25.2 s | 16.0 s | 1.6× |

Reading: throughput-bound shapes (large context, real network builds)
sit at 1.3–1.9× — the datapath holds up. The 8–13× rows are all
**per-build / per-step overhead**: ~1 s per stage on ArcBox vs ~0.1 s on
Colima (multistage), and a 1.8 s floor for a fully-cached build vs
0.16 s. The bottleneck is round-trip/latency-shaped, not
bandwidth-shaped — suspects are the per-request vsock connect in the
docker proxy, session/gRPC round trips through the two-hop relay, and
per-layer snapshot-commit cost on the guest disk; profiling needed
(tracked in Linear). The amd64 row is dominated by the same overhead,
so it does NOT cleanly measure FEX-vs-Rosetta CPU speed. Pre-ABX-494
every ArcBox row below the cache-hit line was ∞ (all buildx builds
hung).

### 2026-07-23 re-run — after the ABX-496 fixes

Same script, same fixtures, same host, both engines cold and measured in
the same session. ArcBox = master `e4aca033` (rcu_expedited + ext4
metadata volume + VZ `.fsync`, boot bundle 0.6.11). Absolute numbers for
the network rows are not comparable across days (registry weather);
ratios within a session are.

| shape | ArcBox | Colima | ratio (was) |
|---|---|---|---|
| simple 3-RUN alpine build, cold | 3.0 s | 0.95 s | 3.2× (13.5×) |
| same build, full cache hit | 0.52 s | 0.30 s | 1.7× (11×) |
| 512 MiB + 100k-file context, cold | 23.8–31.6 s | 32.9 s | **≤1× (1.3×)** |
| 12-stage diamond, cold | 5.0 s | 1.6 s | 3.0× (8.4×) |
| `--platform linux/amd64` (FEX vs Rosetta) | 2.13 s | 2.14 s | **1.0× (7.3×)** |
| postgres `17/bookworm` | 83.7 s | 67.5 s | 1.24× (1.9×) |
| next.js `with-docker` | 54.3 s | 50.3 s | 1.08× (1.4×) |
| caddy `2.11/builder` | 23.7 s | 23.8 s | **1.0× (1.6×)** |

Reading: real-project builds, the amd64 row, and large-context are at
parity (1.0–1.24×). The residual gap is confined to the pure-overhead
shapes (3.0–3.2×, ~2 s absolute) and matches the still-open `docker
start` network-endpoint/iptables segment (~330 ms per container-backed
step, measured 416 ms vs Colima 82 ms) — the next lever, tracked
separately from ABX-496. Bench-hygiene note: Colima retains BuildKit
cache across sessions and the real-project contexts carry no nonce, so
re-runs must `docker builder prune -af` on Colima first or its
real-project rows are cache hits.

## Bench methodology

No criterion micro-bench: build performance is dominated by the guest and
the datapath, so the signal is the Tier-D wall-time trend lines
(`docker_build_wall`, `context_upload_wall`, cold-vs-warm ratios in D3)
recorded per run by `RunMetrics` — same trend-not-gate policy as the
workload suite. Cross-runtime comparison (OrbStack / Docker Desktop) is a
manual `xtask` run of the same fixtures against another engine's
`DOCKER_HOST`, not an automated gate.

## Status

The full Tier-D matrix D1–D10 is implemented
(`tests/e2e/tests/docker_build.rs`), plus Tier X X1–X3
(`tests/e2e/tests/docker_build_external.rs`, gated on
`ARCBOX_E2E_EXTERNAL=1`, pinned upstream commits), and Tier D is
**fully green** against boot bundle ≥ 0.6.10. The one deliberate gap:
D6's fail-closed unprovisioned-FEX direction awaits an e2e knob. The suite's first-ever run
caught ABX-494 (guest FEX spun forever on BuildKit's amd64 arch-probe,
wedging the whole BuildKit Control API; fixed by boot-assets#44), and its
first green-guest run caught a latent harness bug (`run_with_timeout`
didn't drain pipes, turning any >64 KiB-output command into a bogus
timeout). On bundles < 0.6.10 the suite is red by design — do not weaken
it. Two BuildKit realities encoded in the assertions: image IDs are not
comparable across builds (`created` is re-stamped even on full cache
hits), and step logs are rate-clipped at 200 KiB/s (chatty RUNs must be
paced).

## Phasing

1. D1–D3 (context, stages, cache) — pure fixture work, no new capability
   questions, covers the three highest-prevalence census rows.
2. D4–D5 + D9–D10 (session, streaming, exporters) — the proxy-layer
   surfaces with today’s thinnest coverage.
3. D6 (FEX) once an e2e knob to assert the unprovisioned path exists;
   D7–D8 alongside, sharing the concurrency fixtures.
4. Tier X wiring (pinned clones, env gate) — manual-run documentation.
