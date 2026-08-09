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

Phase 2a of CORE-58. Shipped:

| Surface | Notes |
| --- | --- |
| `Sandbox` create/connect/list, `kill`/`pause`/`info` | pause/resume are live daemon-side (CORE-21); data-plane calls auto-resume a paused sandbox |
| `commands.run` | foreground result + background handle; `stdin: string\|bytes` (write-then-close) or `stdin: true` (keep open); `pty: {cols, rows}` |
| `CommandHandle` | streamed `output` with transparent offset-resume across stream death (bounded retries → `ConnectionLostError`), `waitForExit`, `kill`, `writeStdin`/`closeStdin`/`stdinStatus` (offset-idempotent), `resize` |
| `commands.get(id)` | re-attach a handle by execution id (stdin cursor seeded from the daemon) |
| `sandbox.events()` | typed lifecycle events, keepalives filtered; a mid-stream drop is `ConnectionLostError` |
| `sandbox.setLifecycle()` | tri-state: omitted = unchanged, `null` = restore default, value = replace |
| `arcbox.capabilities()` | daemon handshake (version/protocol/features/nested virt), cached per client |
| `files` | whole-file read/write |

Deferred to phase 2b (the daemon answers Unimplemented today):
`commands.list()` (ListExecutions), `ports` + `waitForPort`, filesystem
path verbs (stat/list/mkdir/…), `Template` statics.
