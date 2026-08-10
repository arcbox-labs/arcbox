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

Not on crates.io yet: the SDK speaks Connect through the `connectrpc`
crate, which the workspace pins to a git revision until its 0.9 release
reaches the registry. `cargo publish` fails loudly on the git
dependency, so an accidental publish cannot ship a broken manifest.
When `connectrpc` (and `arcbox-connect`) are on the registry, this
crate publishes as `arcbox` on its own release-please cadence like the
TypeScript and Python SDKs.

## Status

Phase 1 of the Rust SDK: connection resolution, the registry-derived
error type, and the sandbox lifecycle core — `capabilities`, `create`
(readiness watch armed before Create; failed creates remove their
client-minted id), `connect` (PAUSING settle poll, PAUSED resume,
STARTING readiness wait, one overall deadline), `list`
(auto-paginating), `info`, `kill`, `pause`, and tri-state
`set_lifecycle`.

Next: the commands surface (`run`/`spawn`, offset-idempotent stdin,
output streams with attach-resume), then files, ports, snapshots, and
events.
