# arcbox-route — Agent Guidelines

## Build & Test
- Check: `cargo check -p arcbox-route`
- Test all: `cargo test -p arcbox-route`
- Single test: `cargo test -p arcbox-route -- test_name`
- Lint: `cargo clippy -p arcbox-route -- -D warnings`
- Format: `cargo fmt -p arcbox-route`

## Architecture
- `lib.rs` — Public API (`add`, `remove`, `get`) + `Ipv4Net` validated type (source of truth for "valid subnet")
- `msg.rs` — `rt_msghdr` message construction, `route_write()` (mutations) / `route_query()` (RTM_GET reply matching) I/O via `PF_ROUTE` socket
- `sockaddr.rs` — `sockaddr_in`/`sockaddr_dl` builders (crate-internal, not re-exported)
- Only dependency beyond `libc`: `tracing` for structured logging
- Consumer: `arcbox-helper` (privileged root daemon) calls this via `app/arcbox-helper/src/server/mutations/route.rs`

## Code Style
- `Ipv4Net` is `Copy` (5 bytes) — always pass by value, never `&Ipv4Net`
- `unsafe` blocks require `// Safety:` comments explaining the invariant
- `sockaddr` module is `pub(crate)` — public API uses `Ipv4Net`, not raw libc types
- EEXIST replacement must delete then add; XNU's `RTM_CHANGE` cannot clear a conflicting route's `RTF_GATEWAY` flag
- Error type: `Result<(), String>` to match helper's tarpc interface; `Ipv4NetError` for construction
- Follow root `CLAUDE.md` for all general conventions (clippy, fmt, English comments, no section dividers)
