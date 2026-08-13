# arcbox

Rust SDK for ArcBox sandboxes: isolated microVMs on your Mac, driven
over the local daemon's Unix socket with the Connect protocol.

```rust,no_run
use arcbox::{ArcBox, CreateOptions};

#[tokio::main]
async fn main() -> arcbox::Result<()> {
    // Local daemon over ~/.arcbox/run/arcbox.sock — zero config.
    let client = ArcBox::new()?;
    let sandbox = client.create("", CreateOptions::default()).await?;
    println!("sandbox {} is ready", sandbox.id());
    sandbox.kill().await?;
    Ok(())
}
```

Every daemon error maps to one [`Error`] carrying a machine-usable
`ErrorKind` derived from the daemon's error registry, the registry code
(`SANDBOX_NOT_FOUND`, ...), an actionable `suggestion`, and the failed
`operation`. Time arguments are `std::time::Duration`; the wire is
whole seconds and always rounds up.

## Connection

Resolution order: explicit option > environment > default.

| Environment      | Meaning                                                                 |
| ---------------- | ----------------------------------------------------------------------- |
| `ARCBOX_SOCKET`  | daemon Unix socket (default `$ARCBOX_DATA_DIR/run/arcbox.sock`; data dir default `~/.arcbox`, or `~/.arcbox-dev` under `ARCBOX_PROFILE=development`) |
| `ARCBOX_API_URL` | remote tier (reserved, CORE-63) — **not supported by this SDK yet**; setting it without `ARCBOX_SOCKET` is an error rather than a silent fallback |

`Connection::new().socket_path(...)` overrides everything. Nothing is
dialled at construction — the socket opens on the first call, so a
connection failure surfaces at the call that needed it.

## Development

Inside the arcbox repo (`sdk/rust`):

```sh
cargo test -p arcbox            # unit + mock-daemon tests (no daemon needed)
cargo clippy -p arcbox --all-targets -- -D warnings
cargo fmt -p arcbox
```

The crate is a workspace member, so the repo's `Build, Lint, and Test`
CI job gates it with everything else. The mock tests serve the real
generated Connect services on a temp Unix socket — the same wire the
daemon speaks.

## Publishing

Published as `arcbox` by the release tag's coordinated
`cargo publish --workspace`, on the workspace version — not on a
cadence of its own like the TypeScript and Python SDKs, which live in
other registries. Two reasons it rides the workspace: crates.io already
carries `arcbox` 0.6.3 from the runtime facade this SDK replaced, so a
0.1.x line would publish and then never be selected by
`cargo add arcbox`; and the same run publishes `arcbox-connect`, the
path dependency this crate resolves against.

Versions **0.6.3 and below on crates.io are not this crate**: they are
the `arcbox` runtime facade — a re-export shell over `arcbox-core` and
the VM crates — which this SDK replaced by taking the name. The API
changes completely at the first release that carries this SDK, inside
a version line semver says it shouldn't. The facade had no dependents on the registry and its
re-exports were commented out, so nothing can be broken by it, but a
`arcbox = "0.6"` requirement written against the old crate does need
rewriting rather than merely re-resolving.

## Status

Shipped: connection resolution, the registry-derived error type, the
sandbox lifecycle core — `capabilities`, `create` (readiness watch
armed before Create; failed creates remove their client-minted id),
`connect` (PAUSING settle poll, PAUSED resume, STARTING readiness wait,
one overall deadline), `list` (auto-paginating), `info`, `kill`,
`pause`, tri-state `set_lifecycle` — and the commands surface:
`run` (foreground, output collected, non-zero exit is data) / `spawn`
(background handle), an output stream that re-attaches at the retained
byte offsets across transport drops, offset-idempotent `write_stdin`
(serialized; a failed write re-reads the daemon's accepted count),
`close_stdin`, `stdin_status`, `resize`, `kill(signal)`, `get`
(stdin cursor seeded from the daemon), and `list`.

Also shipped, completing the data plane:

- **files**: streamed `read`/`write` (bytes end to end; `write` takes
  `impl AsRef<[u8]>`), `stat`/`list`/`mkdir`/`remove`/`rename` (typed
  `FileStat`, `mkdir -p` semantics, symlinks reported not followed),
  and `watch` — a typed `FsEvent` stream, keepalives filtered, clean
  end on sandbox stop.
- **ports**: `wait_for_port` (guest-side listen-table wait; expiry is a
  `Timeout` naming this knob), `expose`/`unexpose`/`list` (host
  loopback publishing; `list` reads the daemon's authoritative live
  listener table).
- **snapshots**: `checkpoint` (pause + snapshot + resume under the same
  id), `restore` (fresh client-minted id; failed restores force-remove
  it), auto-paginating `list_snapshots`, `delete_snapshot`.
- **events**: `Sandbox::events()` — typed lifecycle events, keepalives
  filtered.

Deferred: `wait_for_log` (filter `output()` directly), the remote tier
(CORE-63), and Template statics.
