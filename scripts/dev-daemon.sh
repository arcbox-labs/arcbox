#!/usr/bin/env bash
#
# Reliable local daemon dev/test harness for the custom-HV backend.
#
# WHY THIS EXISTS
#   `ArcBox Dev.app` ships and RESTORES its own bundled daemon binary on launch.
#   Swapping a freshly-built daemon into the bundle is therefore unreliable — the
#   app may revert it and you end up testing the wrong binary without noticing.
#   This harness runs YOUR build directly and verifies the running process logs
#   the expected `ARCBOX_BUILD_SHA` (embedded by app/arcbox-daemon/build.rs), so
#   "which daemon is actually running?" is always answerable.
#
#   Rule of thumb: use the packaged app to test the PRODUCT; use this harness to
#   test DAEMON CODE.
#
# USAGE
#   scripts/dev-daemon.sh build         # build (symboled) + sign daemon, stage agent
#   scripts/dev-daemon.sh run           # run the daemon directly, then verify the build SHA
#   scripts/dev-daemon.sh verify        # confirm the running daemon == this checkout
#   scripts/dev-daemon.sh boot-test [N] # N cold-boot reliability loop + crash symbolication
#   scripts/dev-daemon.sh stop
#
# ENV
#   ARCBOX_DATA_DIR          data dir (default ~/.arcbox)
#   ARCBOX_NO_DEBUG_CONSOLE  set to 1 to disable the always-on hvc0 debug console
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
DAEMON="$REPO/target/release/arcbox-daemon"
AGENT="$REPO/target/aarch64-unknown-linux-musl/release/arcbox-agent"
DATADIR="${ARCBOX_DATA_DIR:-$HOME/.arcbox}"
LOG="$DATADIR/log/daemon.log"
SIGN_ID="Developer ID Application: ArcBox, Inc. (422ACSY6Y5)"
ENTITLEMENTS="$REPO/bundle/arcbox.dev.entitlements"

expected_sha() {
    local sha dirty=""
    sha="$(git -C "$REPO" rev-parse --short=12 HEAD)"
    [ -n "$(git -C "$REPO" status --porcelain)" ] && dirty="-dirty"
    printf '%s%s' "$sha" "$dirty"
}

running_pid() { pgrep -f "release/arcbox-daemon" | head -1; }

cmd_build() {
    echo "==> building symboled daemon + agent"
    cargo build --release -p arcbox-daemon \
        --config 'profile.release.strip=false' --config 'profile.release.debug=1'
    cargo build -p arcbox-agent --target aarch64-unknown-linux-musl --release
    echo "==> signing daemon (HV entitlements)"
    codesign --force --options runtime --entitlements "$ENTITLEMENTS" -s "$SIGN_ID" "$DAEMON"
    mkdir -p "$DATADIR/bin"
    install -m0755 "$AGENT" "$DATADIR/bin/arcbox-agent"
    echo "built $(expected_sha)  daemon=$(shasum -a256 "$DAEMON" | cut -c1-12)  agent=$(shasum -a256 "$DATADIR/bin/arcbox-agent" | cut -c1-12)"
}

cmd_stop() {
    osascript -e 'tell application "ArcBox Dev" to quit' >/dev/null 2>&1 || true
    pkill -f "release/arcbox-daemon" 2>/dev/null || true
    pkill -f "desktop.dev.daemon" 2>/dev/null || true
    sleep 2
    rm -f "$DATADIR/run/daemon.lock" "$DATADIR"/run/*.sock 2>/dev/null || true
}

# Confirm the running daemon's logged build SHA matches this checkout.
cmd_verify() {
    local want got
    want="$(expected_sha)"
    got="$(grep -ao '"build":"[^"]*"' "$LOG" 2>/dev/null | tail -1 | sed 's/.*:"//; s/"//')"
    if [ -z "$(running_pid)" ]; then echo "VERIFY: no daemon running"; return 1; fi
    if [ "$got" = "$want" ]; then
        echo "VERIFY OK: running daemon == this checkout ($got)"
    else
        echo "VERIFY FAIL: running daemon build=$got, expected $want — you are testing the WRONG binary"
        return 1
    fi
}

cmd_run() {
    cmd_stop
    echo "==> running $DAEMON directly (ARCBOX_NO_DEBUG_CONSOLE=${ARCBOX_NO_DEBUG_CONSOLE:-unset})"
    ARCBOX_NO_DEBUG_CONSOLE="${ARCBOX_NO_DEBUG_CONSOLE:-}" \
        nohup "$DAEMON" --docker-integration >> "$DATADIR/log/dev-daemon.out" 2>&1 &
    sleep 4
    cmd_verify
}

# Symbolicate the most recent arcbox-daemon crash against the symboled binary.
symbolicate_latest_crash() {
    local cr base
    cr="$(ls -t "$HOME"/Library/Logs/DiagnosticReports/arcbox-daemon*.ips 2>/dev/null | head -1)"
    [ -z "$cr" ] && { echo "(no crash report)"; return; }
    echo "==> crash: $cr"
    python3 - "$cr" "$DAEMON" <<'PY'
import json, subprocess, sys
cr, binp = sys.argv[1], sys.argv[2]
j = json.loads(open(cr).read().split('\n', 1)[1])
exc = j.get('exception', {})
print("signal:", exc.get('signal'), exc.get('type'), "at", exc.get('subtype', ''))
base = next(i['base'] for i in j['usedImages'] if i.get('name') == 'arcbox-daemon')
for t in j.get('threads', []):
    if t.get('triggered'):
        print("faulting thread:", t.get('name', '') or t.get('queue', ''))
        addrs = [str(base + f['imageOffset']) for f in t.get('frames', [])
                 if j['usedImages'][f['imageIndex']].get('name') == 'arcbox-daemon'][:16]
        out = subprocess.run(['atos', '-o', binp, '-arch', 'arm64', '-l', str(base), *addrs],
                             capture_output=True, text=True)
        print(out.stdout or out.stderr)
        break
PY
}

cmd_boot_test() {
    local n="${1:-8}" ok=0 fail=0 seg=0 results=""
    echo "==> boot-test: $n cold boots (debug console=${ARCBOX_NO_DEBUG_CONSOLE:-on})"
    for i in $(seq 1 "$n"); do
        if [ -z "$(running_pid)" ]; then
            rm -f "$DATADIR/run/daemon.lock" "$DATADIR"/run/*.sock 2>/dev/null || true
            ARCBOX_NO_DEBUG_CONSOLE="${ARCBOX_NO_DEBUG_CONSOLE:-}" \
                nohup "$DAEMON" --docker-integration >> "$DATADIR/log/dev-daemon.out" 2>&1 &
            sleep 1
        fi
        local outcome="" t
        for t in $(seq 1 48); do
            [ "$(curl -s -m3 --unix-socket "$DATADIR/run/docker.sock" http://./_ping -o /dev/null -w '%{http_code}' 2>/dev/null)" = "200" ] && { outcome=OK; break; }
            [ -z "$(running_pid)" ] && { outcome=FAIL; break; }
            sleep 2
        done
        if [ "$outcome" = OK ]; then ok=$((ok + 1)); results="$results OK"
        else fail=$((fail + 1)); results="$results F"
             grep -q "Segmentation fault" "$DATADIR/log/dev-daemon.out" 2>/dev/null && seg=$((seg + 1))
        fi
        pkill -f "release/arcbox-daemon" 2>/dev/null || true; sleep 2
    done
    echo "RESULT: OK=$ok FAIL=$fail (segfaults seen=$seg)  seq:$results"
    [ "$seg" -gt 0 ] && symbolicate_latest_crash
}

case "${1:-}" in
    build) cmd_build ;;
    run) cmd_run ;;
    verify) cmd_verify ;;
    boot-test) cmd_boot_test "${2:-8}" ;;
    stop) cmd_stop ;;
    *) sed -n '2,30p' "$0"; exit 1 ;;
esac
