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
| `ARCBOX_SOCKET`  | daemon Unix socket (default `$ARCBOX_DATA_DIR/run/arcbox.sock`, data dir default `~/.arcbox`) |
| `ARCBOX_API_URL` | remote daemon / cloud front door; setting it selects the remote tier (reserved, CORE-63)      |
| `ARCBOX_API_KEY` | bearer credential, attached as `Authorization` when set; unused by the local daemon           |

Every entry point takes a `connection` options slot
(`socketPath` / `apiUrl` / `apiKey` / `requestTimeoutMs` / injected
`transport` for mocking).

## Development

Inside the arcbox repo (`sdk/typescript`):

```sh
npm install
npm run generate   # regenerate src/gen from ../../rpc/arcbox-protocol/proto (buf + protoc-gen-es)
npm run lint       # eslint + prettier --check
npm test           # vitest unit tests (no daemon needed)
npm run typecheck  # tsc --noEmit
npm run build      # emit dist/
```

Generated code under `src/gen/` is committed and is **never** exported
from the package entry point — public shapes are hand-written and mapped
at the transport boundary.

The end-to-end hello-world loop runs only against a live daemon and is
opt-in:

```sh
ARCBOX_SDK_E2E=1 npm test -- test/e2e.test.ts
```

TODO(CI): wire `npm run lint`, `npm test`, and `npm run typecheck` into
`.github/workflows` as an `sdk-typescript` job (follow-up; workflow
changes are intentionally not part of this branch).

## Status

Phase 1 of CORE-58 — the hello-world closed loop: `Sandbox`
create/connect/list, `kill`/`pause`/`info`, `commands.run` (foreground
result + background handle with streamed output, `waitForExit`, `kill`),
and whole-file `files` read/write. Deferred: PTY, `ports`,
`waitForPort`/`waitForLog`, filesystem path verbs (stat/list/mkdir/…),
`Template` statics, `events()`, `setLifecycle`, capabilities handshake.
