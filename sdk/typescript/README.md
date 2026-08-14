# @arcbox/sandbox

TypeScript SDK for ArcBox sandboxes: isolated microVMs on your Mac,
driven over the local daemon's Unix socket with the Connect protocol.
Requires Node ≥ 22.

```sh
npm install @arcbox/sandbox
```

## Hello world

With the daemon running (`abctl daemon start`):

```ts
import { Sandbox } from '@arcbox/sandbox';

// Local daemon over ~/.arcbox/run/arcbox.sock — zero config.
await using sandbox = await Sandbox.create('', { ttlMs: 300_000 });

await sandbox.files.writeText('/tmp/hello.txt', 'hello from arcbox\n');

const check = await sandbox.commands.run(['/bin/cat', '/tmp/hello.txt']);
console.log(check.expect().stdout, '→ exit', check.exitCode);

const job = await sandbox.commands.run('for i in 1 2 3; do echo line$i; done', {
  background: true,
});
for await (const chunk of job.output) {
  process.stdout.write(chunk.data);
}
const done = await job.waitForExit();
console.log('background job exited', done.exitCode);
// scope exit: await using → sandbox killed, nothing leaked
```

Non-zero exit is data (`result.exitCode`), never an exception —
`result.expect()` is the opt-in throw. Every daemon error maps to a
typed class (`SandboxNotFoundError`, `CapabilityError`,
`ConnectionFailedError`, ...) carrying a machine-readable `code`, an
actionable `suggestion`, and the failed `operation`.

## Connection

Resolution order: explicit option > environment > default.

| Environment      | Meaning                                                                                       |
| ---------------- | --------------------------------------------------------------------------------------------- |
| `ARCBOX_SOCKET`  | daemon Unix socket (default `$ARCBOX_DATA_DIR/run/arcbox.sock`; data dir default `~/.arcbox`, or `~/.arcbox-dev` under `ARCBOX_PROFILE=development`) |
| `ARCBOX_API_URL` | remote daemon / cloud front door; setting it selects the remote tier (reserved, CORE-63)      |
| `ARCBOX_API_KEY` | bearer credential, attached as `Authorization` when set; unused by the local daemon           |

Every entry point takes a `connection` options slot
(`socketPath` / `apiUrl` / `apiKey` / `requestTimeoutMs` / injected
`transport` for mocking).

## E2B-compatible surface

`@arcbox/sandbox/e2b` serves the [`e2b`](https://e2b.dev) SDK's shape, so
existing E2B code runs against the local daemon with one import change:

```ts
import { Sandbox } from '@arcbox/sandbox/e2b'; // was: from 'e2b'

const sandbox = await Sandbox.create({ timeoutMs: 300_000 });
await sandbox.files.write('/tmp/hello.txt', 'hello\n');
console.log((await sandbox.commands.run('cat /tmp/hello.txt')).stdout);
await sandbox.kill();
```

No API key and no network: E2B's connection options (`apiKey`, `domain`,
`accessToken`, ...) are accepted and ignored, so an app that reads
`E2B_API_KEY` from its environment keeps working.

Most of the surface is a rename the type checker already checks for you.
These behaviours genuinely differ:

- **`getHost(port)` needs the port exposed first.** E2B fronts every
  sandbox port with an edge proxy at `{port}-{id}.e2b.app` and so can
  answer for a port nobody declared; ArcBox forwards on request, so
  `await sandbox.exposePort(3000)` comes first and `getHost(3000)` is
  synchronous from there on. An un-exposed port throws rather than
  returning an address nothing is listening on.
- **`setTimeout` replaces rather than extends.** E2B only pushes the
  deadline out; ArcBox re-arms it from now.
- **`'base'` and an omitted template** both resolve to the built-in
  minimal template. Other names come from the local catalog, not E2B's
  registry.
- **`files.getInfo().owner`/`.group` are numeric** — the daemon reports
  uids and gids, and inventing a name would not be honest.
- **`commands.list()` reports ids only** — the daemon does not report
  argv, so `cmd`/`args`/`envs` are empty rather than invented.
- **The error classes are aliases of this package's**, not new
  subclasses, so `instanceof SandboxError` matches what the SDK throws.
  `CommandExitError` is real and is thrown by `commands.run()` on a
  non-zero exit, as in E2B.

Anything with no local counterpart throws `UnsupportedError` on the
first call rather than failing quietly: `fork`, volumes, signed
upload/download URLs, `getMetrics`, the MCP gateway, the `Template`
build DSL, `git.dangerouslyAuthenticate`, and
`files.read({ format: 'blob' | 'stream' })`. `NotEnoughSpaceError`,
`RateLimitError`, `GitAuthError`, `GitUpstreamError`, `BuildError`,
`FileUploadError` and `VolumeError` are exported so existing imports
resolve, but a local daemon has no quota, no registry build and no
volumes, so nothing raises them.

> Aliasing a dependency that imports `e2b` itself (`e2b-code-interpreter`
> and friends) needs a package whose *entry point* is the E2B surface;
> a subpath export cannot be aliased that way. Direct imports are what
> this covers.

## Development

Inside the arcbox repo (`sdk/typescript`):

```sh
npm install
npm run generate      # regenerate src/gen from ../../rpc/arcbox-protocol/proto (buf + protoc-gen-es)
npm run lint          # eslint (eslint-config-sukka)
npm run format:check  # biome formatter check (biome format --write . fixes)
npm test              # vitest unit tests (no daemon needed)
npm run typecheck     # tsc --noEmit
npm run build         # bunchee → dist/
```

Generated code under `src/gen/` is committed and is **never** exported
from the package entry point — public shapes are hand-written and mapped
at the transport boundary.

The end-to-end hello-world loop runs only against a live daemon and is
opt-in:

```sh
ARCBOX_SDK_E2E=1 npm test -- test/e2e.test.ts
```

The gates above (lint, format check, tests, typecheck, build) run on
every PR as the `sdk-typescript` job in `.github/workflows/ci.yml`, on
Node 22 from a clean `npm ci`.

## Releasing

The SDK is a release-please component (`sdk-typescript` in
`release-please-config.json`), released on its own cadence, independent
of the main arcbox release train:

1. Conventional commits touching `sdk/typescript` accumulate on
   `master`.
2. release-please maintains a dedicated release PR for the component
   (separate from the root and fleet-agent PRs) that bumps
   `package.json` and updates `CHANGELOG.md`.
3. Merging that PR creates the GitHub release and the tag
   `sdk-typescript-vX.Y.Z` (same convention as `fleet-agent-vX.Y.Z`).
4. The tag is what an npm publish workflow
   (`.github/workflows/release-sdk-typescript.yml`) triggers on: it
   re-runs the full gate suite (`lint`, `format:check`, `test`,
   `typecheck`), builds with `npm run build:publish`, and publishes to
   npm via [trusted publishing](https://docs.npmjs.com/trusted-publishers)
   (OIDC) — tokenless, with provenance attestations generated
   automatically. The job skips cleanly if the version is already on the
   registry, so a re-dispatch never fails on an already-published
   release.

> A tag minted while the publish workflow was absent (or a tag whose
> run failed) is **not replayed** by a later push — re-dispatch the
> workflow against the existing tag instead: it takes the tag as a
> `workflow_dispatch` input for exactly this.

One-time bootstrap (trusted publishing can only be configured for a
package that already exists on the registry):

1. First publish is manual, from `sdk/typescript`, logged in to an npm
   account with publish rights on the `@arcbox` scope:
   `npm run build:publish && npm publish --access public`.
2. On npmjs.com → package settings → Trusted Publisher: select GitHub
   Actions, repository `arcboxlabs/arcbox`, workflow filename
   `release-sdk-typescript.yml`. From then on the tag-triggered
   workflow publishes without any token.

## Status

Phases 2a and 2b of CORE-58. Shipped:

| Surface | Notes |
| --- | --- |
| `Sandbox` create/connect/list, `kill`/`pause`/`info` | pause/resume are live daemon-side (CORE-21); data-plane calls auto-resume a paused sandbox |
| `commands.run` | foreground result + background handle; `stdin: string\|bytes` (write-then-close) or `stdin: true` (keep open); `pty: {cols, rows}` |
| `CommandHandle` | streamed `output` with transparent offset-resume across stream death (bounded retries → `ConnectionLostError`), `waitForExit`, `kill`, `writeStdin`/`closeStdin`/`stdinStatus` (offset-idempotent), `resize` |
| `handle.waitForLog(pattern)` | first log line matching a substring/regex, SDK-side over the replayed offset-addressed output (resumes across drops); deadline → `TimeoutError` naming the knob |
| `commands.get(id)` / `commands.list()` | re-attach a handle by execution id (stdin cursor seeded from the daemon); list running and exited executions as `CommandInfo` summaries |
| `sandbox.events()` | typed lifecycle events, keepalives filtered; a mid-stream drop is `ConnectionLostError` |
| `sandbox.setLifecycle()` | tri-state: omitted = unchanged, `null` = restore default, value = replace |
| `arcbox.capabilities()` | daemon handshake (version/protocol/features/nested virt), cached per client |
| `files` | whole-file read/write; path verbs `stat`/`list`/`mkdir`/`remove`/`move` (typed `FileStat`, `mkdir -p` semantics, `FileNotFoundError` with the path in context) |
| `files.watch(path)` | typed `FsEvent` stream (renames paired, keepalives filtered); ends cleanly on sandbox stop; a mid-stream drop is `ConnectionLostError` — never auto-reconnected (events cannot be replayed) |
| `ports.waitForPort(port)` | guest-side listen-table wait (no client polling); expiry → `TimeoutError` naming the `timeoutMs` knob (daemon default 30 s, cap 600 s) |
| `ports.expose(port)` / `unexpose` / `list` | publish a guest port on host loopback (daemon-allocated or specific host port, tcp/udp); `list` reads the daemon's authoritative live listener table |
| `sandbox.checkpoint()` | pause + snapshot + resume under the same id; returns the `Snapshot` catalog row |
| `ArcBox.restore(snapshotId)` | new READY sandbox from a snapshot (fresh client-minted id; `freshNetwork` for concurrent restores); plus `listSnapshots` (auto-paginating) and `deleteSnapshot` |

Template statics shipped: `Template.build/get/list/delete` + instance `publish()/delete()`; `Sandbox.create` accepts a `Template` instance; `noDefaultCmd`/`noDefaultEnv` create options carry explicit-empty overrides.
