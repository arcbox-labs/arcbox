# arcbox-helper

Privileged root helper for host mutations that the user-space daemon cannot
perform: `/usr/local/bin` CLI symlinks, `/var/run/docker.sock`, `/etc/resolver`,
`/etc/hosts` alias, and utun/route setup.

## Independent version

`arcbox-helper` owns its **own** Cargo package version
(`app/arcbox-helper/Cargo.toml`), currently `1.0.0`. It is **not** tied to
`workspace.package.version` (`0.4.x`).

| Pin | Location |
|-----|----------|
| Helper package version | `app/arcbox-helper/Cargo.toml` → `version = "1.0.0"` |
| Workspace path-dep | root `Cargo.toml` → `arcbox-helper = { version = "1.0.0", path = ... }` (**no** `x-release-please-version`) |
| Daemon/CLI floor | `arcbox_constants::helper::MIN_HELPER_VERSION` |

`arcbox-helper --version` and the tarpc `version` RPC both print:

```text
arcbox-helper 1.0.0
```

Desktop and daemon parse that line with
`arcbox_constants::helper::parse_helper_version` and compare by semver triple
**within the same major** (a higher major is a wire break, not “newer is fine”).

### When to bump

Bump the helper version (and the three pins above **together**) only when the
**on-disk root binary** must be replaced:

- tarpc wire break / required new RPC method
- security fix in the privileged helper
- behavior the current daemon hard-requires

Ordinary daemon / CLI / guest / networking work must **not** bump the helper.
Otherwise every Desktop user gets an admin-password reinstall prompt.

release-please does **not** bump `app/arcbox-helper/Cargo.toml` (no
`x-release-please-version` on that pin). Helper bumps are manual.

A regression test (`helper_version_pins_are_aligned` in
`app/arcbox-helper/tests/connection_test.rs`) fails if the three pins drift.

### Admin password impact

Installing or upgrading the helper requires admin authorization (AppleScript /
`osascript` admin prompt, or `sudo abctl _install`). Once the on-disk helper
semver is **≥** the bundled helper, subsequent ArcBox app updates that only
bump the runtime (`0.4.x`) must **not** re-prompt.

## Threat model

### Socket mode `0666` / `SockPathMode` 438

`/var/run/arcbox-helper.sock` is world-connectable so the non-root daemon and
CLI can reach a root launchd service without setuid tricks.

**Authorization is not the filesystem mode.** Release builds run peer code-
signature verification on every accept (`peer_auth::verify`):

1. Prefer `LOCAL_PEERTOKEN` (audit token) — binds to the live connecting process.
2. Fall back to `LOCAL_PEERPID`.
3. `SecCodeCopyGuestWithAttributes` → `SecCodeCheckValidity` with
   `identifier "…" and anchor apple generic and certificate leaf[subject.OU] = "TEAM"`.
4. Allow-list: `com.arcboxlabs.desktop{,.dev}{,.daemon,.cli}`.

Debug builds skip signature checks so ad-hoc local binaries can talk to a
manually started helper. **Never** ship a release helper with auth disabled.

Rejected peers are dropped before any tarpc dispatch; logs include
`source` (`audit_token` / `pid` / `none`) and `stage`.

### Mutation ownership rules

| Mutation | Create / replace | Delete |
|----------|------------------|--------|
| `cli_link` / `cli_unlink` | Target must be a **regular file** under `.app/Contents/MacOS/xbin/` (`/Applications` or `/Users`); existing `/usr/local/bin` entry replaced only if ArcBox-owned symlink | Only ArcBox-owned symlink |
| `socket_link` / `socket_unlink` | Target must parse as `SocketTarget` (`~/.arcbox` / `~/.arcbox-dev`); replace only ArcBox-owned symlink | Only ArcBox-owned symlink; never real sockets |
| `dns_install` / `dns_uninstall` | Writes marker `# managed by arcbox-helper`; refuses to overwrite foreign resolvers | Only files carrying the marker |
| `hosts_alias_*` | Fixed `127.0.0.1 ArcBox # managed by arcbox-helper` line only | Lines carrying the marker only |

`is_arcbox_owned` (shared with `CliTarget`) rejects relative paths, `..`, and
anything outside `/Applications/` or `/Users/` without a
`.app/Contents/MacOS/xbin/` segment.

### Daemon compatibility gate

If the helper is unreachable, unparseable, or older than
`MIN_HELPER_VERSION`, daemon `self_setup` **skips all privileged tasks** so it
never drives new tarpc ordinals into a legacy binary.

## Local E2E (no root)

Debug builds honour `ARCBOX_HELPER_TEST_ROOT`. When set, privileged paths are
rewritten under that directory so the real helper binary can be exercised
without touching the live system:

```bash
cargo test -p arcbox-helper --test e2e_fs_test
```

Release builds **ignore** the env var (production must never be redirected).

Also covered by unit tests in the helper binary (`--bins`) and mock tarpc
integration tests (`--tests` excluding `e2e_fs_test`).

## Wire errors

RPC failures use structured [`HelperError`](../app/arcbox-helper/src/error.rs)
(`Result<(), HelperError>` over bincode). Variants are **append-only** (index
encoded). Clients match on `HelperError::code()` / enum arms; `Display` remains
human-readable for logs.

## Peer auth implementation

Release builds use the `security-framework` crate
(`GuestAttributes` + `SecCode` + `SecRequirement`) rather than hand-rolled
Security.framework FFI. Debug builds skip signature checks.

## Non-goals (not 1.0.0 blockers)

- Batch `cli_link` RPC — call sites link a fixed small set of tools.
- Helper `health` RPC — `version` + connect success is enough for doctor.
- Doctor codesign detail dump — useful later; not required for correctness.

## Related paths

See also [data-directories.md](data-directories.md) and
[code-signing-troubleshooting.md](code-signing-troubleshooting.md).

| Path | Role |
|------|------|
| `/usr/local/libexec/arcbox-helper` | Installed root binary |
| `/Library/LaunchDaemons/com.arcboxlabs.desktop.helper.plist` | launchd job |
| `/var/run/arcbox-helper.sock` | RPC socket |
| `/var/log/arcbox/helper.log` | Helper log |
| `/usr/local/bin/docker*` | CLI convenience symlinks into app xbin |
| `/var/run/docker.sock` | Optional symlink to `~/.arcbox/run/docker.sock` |
