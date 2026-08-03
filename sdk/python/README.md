# arcbox

Python SDK for ArcBox sandboxes: isolated microVMs on your Mac, driven
over the local daemon's Unix socket with the Connect protocol. Requires
Python ≥ 3.10.

```sh
uv add arcbox        # or: pip install arcbox
```

## Hello world

With the daemon running (`abctl daemon start`):

```python
from arcbox import Sandbox

# Local daemon over ~/.arcbox/run/arcbox.sock — zero config.
with Sandbox.create("", ttl=300) as sandbox:
    sandbox.files.write_text("/tmp/hello.txt", "hello from arcbox\n")

    check = sandbox.commands.run(["/bin/cat", "/tmp/hello.txt"])
    print(check.expect().stdout, "→ exit", check.exit_code)

    job = sandbox.commands.run("for i in 1 2 3; do echo line$i; done", background=True)
    for chunk in job.output:
        print(chunk.data.decode(), end="")
    print("background job exited", job.wait_for_exit().exit_code)
# context exit: sandbox killed, nothing leaked
```

Async is a first-class mirror (`AsyncSandbox`, `async with`, `async for`):

```python
from arcbox import AsyncSandbox


async def main() -> None:
    sandbox = await AsyncSandbox.create("", ttl=300)
    async with sandbox:
        await sandbox.files.write_text("/tmp/hello.txt", "hello from arcbox\n")
        result = await sandbox.commands.run(["/bin/cat", "/tmp/hello.txt"])
        print(result.expect().stdout)
```

Non-zero exit is data (`result.exit_code`), never an exception —
`result.expect()` (or `run(..., check=True)`, `subprocess.run`-style) is
the opt-in raise. Every daemon error maps to a typed class in
`arcbox.errors` (`SandboxNotFoundError`, `CapabilityError`,
`ConnectionFailedError`, ...) carrying a machine-readable `code`, an
actionable `suggestion`, and the failed `operation`. Time arguments are
seconds (floats) everywhere.

## Connection

Resolution order: explicit option > environment > default.

| Environment      | Meaning                                                                                       |
| ---------------- | --------------------------------------------------------------------------------------------- |
| `ARCBOX_SOCKET`  | daemon Unix socket (default `$ARCBOX_DATA_DIR/run/arcbox.sock`; data dir default `~/.arcbox`, or `~/.arcbox-dev` under `ARCBOX_PROFILE=development`) |
| `ARCBOX_API_URL` | remote daemon / cloud front door; setting it selects the remote tier (reserved, CORE-63)      |
| `ARCBOX_API_KEY` | bearer credential, attached as `Authorization` when set; unused by the local daemon           |

Every entry point takes a `connection=Connection(...)` slot
(`socket_path` / `api_url` / `api_key` / `request_timeout` / injected
`http_client` for mocking — pass an `httpx.Client` to the sync surface,
an `httpx.AsyncClient` to the async one).

The `Sandbox` / `AsyncSandbox` classmethods resolve a hidden connection
per call, and the returned handle closes its HTTP client on context
exit. Long-lived programs should hold an `ArcBox` / `AsyncArcBox`
instead: it is a context manager (or call `.close()` / `.aclose()`),
and every handle it creates shares its client. An injected
`http_client` always belongs to the caller and is never closed by the
SDK.

## Development

Inside the arcbox repo (`sdk/python`):

```sh
uv sync                                  # create .venv from uv.lock
uv run python scripts/gen_proto.py       # regenerate src/arcbox/_gen from ../../rpc/arcbox-protocol/proto
uv run python scripts/gen_sync.py        # regenerate src/arcbox/_sync from src/arcbox/_async
uv run ruff check . && uv run ruff format --check .
uv run pyright
uv run pytest                            # includes the sync-tree lockstep + parity checks
```

Generated code under `src/arcbox/_gen/` is committed and is **never**
exported from the package — public shapes are hand-written and mapped
at the transport boundary.

The async tree (`src/arcbox/_async/`) is the source of truth; the sync
tree (`src/arcbox/_sync/`) is generated from it by an unasync token
transform and committed. Edit only the async tree, then rerun
`scripts/gen_sync.py`. Lockstep is CI-enforced twice: the transform is
rerun and diffed (`scripts/gen_sync.py --check`, also wired into
pytest), and a parity test asserts identical public surfaces modulo
async markers.

Optional pre-commit hooks (scoped to `sdk/python`), via
[prek](https://github.com/j178/prek) or classic pre-commit:

```sh
prek install -c sdk/python/prek.yaml
```

The end-to-end hello-world loop runs only against a live daemon and is
opt-in:

```sh
ARCBOX_SDK_E2E=1 uv run pytest tests/test_e2e.py
```

## Toolchain notes

- **uv** is the package/project manager (`uv_build` backend, `uv.lock`
  committed). Publishing is CI-only: `uv build && uv publish` under
  PyPI trusted publishing (OIDC) — see [Releasing](#releasing); no
  `UV_PUBLISH_TOKEN` anywhere.
- **ruff** is both linter and formatter (`E,F,W,I,UP,B,SIM,RUF`).
- **pyright** (strict) is the authoritative type checker. Evaluated
  alternatives (2026-08): **ty** 0.0.65 reports 16 false positives here
  (all `unresolved-attribute` on protobuf generated-module members) —
  kept in dev-deps for `uv run ty check`, may replace pyright when it
  stabilizes; **pyrefly** 1.2.0 passes cleanly (it imports the pyright
  config) and serves as an informational second opinion — one
  authoritative checker avoids double-suppression drift.
- **msgspec** parses the SDK's one JSON seam — Connect error bodies and
  `EndStreamResponse` frames — as typed, validated Structs at the
  untrusted-input boundary (chosen for the typed decoding, not speed).
- Message types are upstream **protobuf** runtime code generated by the
  protoc bundled with grpcio-tools (dev-dep); the bundled protoc version
  matches the pinned runtime.
- A future native-acceleration path (if profiling ever demands one) is a
  **maturin**/PyO3 extension crate in this repo's workspace; nothing in
  the current SDK needs it.

TODO(CI): wire the gates above into `.github/workflows` as an
`sdk-python` job (follow-up; workflow changes are intentionally not part
of this branch).

## Releasing

The SDK is a release-please component (`sdk-python` in
`release-please-config.json`), released on its own cadence, independent
of the main arcbox release train:

1. Conventional commits touching `sdk/python` accumulate on `master`.
2. release-please maintains a dedicated release PR for the component
   (separate from the root, fleet-agent, and sdk-typescript PRs) that
   bumps the `pyproject.toml` version and updates `CHANGELOG.md`.
3. Merging that PR creates the GitHub release and the tag
   `sdk-python-vX.Y.Z` (same convention as `sdk-typescript-vX.Y.Z`).
4. The tag triggers the PyPI publish workflow
   (`release-sdk-python.yml`), which checks out the tag's tree, re-runs
   the full gate suite (`ruff check`, `ruff format --check`, `pyright`,
   `pytest`, `gen_sync.py --check`), builds with `uv build`, and
   publishes with `uv publish` via [trusted
   publishing](https://docs.pypi.org/trusted-publishers/) (OIDC) —
   tokenless: the job's `id-token: write` permission is exchanged for a
   short-lived PyPI credential. The job skips cleanly if the version is
   already on PyPI, so a re-dispatch never fails on an
   already-published release.

One-time bootstrap — unlike npm, PyPI supports [pending
publishers](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/):
the trusted publisher is registered *before* the first upload and CI
does the first publish, so there is no local bootstrap publish and no
API token at any point:

1. On pypi.org → account → Publishing → "Add a new pending publisher"
   (GitHub): PyPI project name `arcbox`, owner `arcboxlabs`, repository
   `arcbox`, workflow filename `release-sdk-python.yml`, environment
   left empty.
2. The first tag-triggered run then creates the `arcbox` project on
   PyPI as it publishes, and the pending publisher becomes the
   project's regular trusted publisher. Nothing else to configure.

## Status

Phase 1 of CORE-58 — the hello-world closed loop: `Sandbox` /
`AsyncSandbox` create/connect/list, `kill`/`pause`/`info` (`pause` and
the paused-sandbox reconnect path are wire-complete but reject with an
unimplemented error until the daemon's CORE-21 lands), `commands.run`
(foreground result + background handle with streamed output,
`wait_for_exit`, `kill`), and whole-file `files` read/write. Deferred:
PTY, `ports`, `wait_for_port`/`wait_for_log`, stdin, filesystem path
verbs (stat/list/mkdir/...), `Template` statics, `events()`,
`set_lifecycle`, the capabilities handshake, and the SDK-side default
idle-reaping policy (design decision 4 — applied once the daemon
enforces the lifecycle knobs).
