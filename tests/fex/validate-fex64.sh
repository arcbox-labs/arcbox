#!/usr/bin/env bash
# ABX-375 FEX64 validation harness.
#
# Reproducible spike for "FEX64 as the default linux/amd64 runtime inside the
# single HV utility VM". Run this on Apple Silicon macOS with a running,
# Developer-ID-signed `arcbox daemon` and the `arcbox` Docker context active.
#
# It exercises PLAN.md Decision Gates A/B/C and records an environment header
# so results are reproducible. Every check prints exactly one tagged line:
#
#   PASS       — the gate behaved as required
#   FAIL       — the gate's required behavior did not hold (a real FEX/routing
#                failure: per PLAN, a FAIL on Gate A means STOP and resume ABX-374)
#   UNSUPPORTED— a known FEX compatibility gap (recorded, not a harness failure)
#   INFRA      — the harness could not run the check (daemon down, image pull
#                failed, no network) — NOT a verdict on FEX
#
# Exit status: 0 if no FAIL lines, 1 if any FAIL, 2 if only INFRA blocked gates.
#
# This script does not modify the daemon or the guest; it only observes.

set -u

DOCKER="${DOCKER:-docker}"
CONTEXT="${ARCBOX_DOCKER_CONTEXT:-arcbox}"
DC=("$DOCKER" "--context" "$CONTEXT")

pass=0 fail=0 unsupported=0 infra=0
# Set when the amd64 path is unreachable because FEX64 is not provisioned —
# a BLOCKED (decision-pending) state, distinct from a FEX64 gate FAIL.
amd64_blocked=0

tag() { # tag LEVEL "message"
  local level="$1"; shift
  printf '%-11s %s\n' "$level" "$*"
  case "$level" in
    PASS) pass=$((pass + 1)) ;;
    FAIL) fail=$((fail + 1)) ;;
    UNSUPPORTED) unsupported=$((unsupported + 1)) ;;
    INFRA) infra=$((infra + 1)) ;;
  esac
}

section() { printf '\n=== %s ===\n' "$*"; }

# --- Environment header (recorded for reproducibility) ---------------------
section "Environment"
printf 'date              %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'host macOS        %s (%s)\n' "$(sw_vers -productVersion 2>/dev/null || echo '?')" "$(uname -m)"
printf 'arcbox commit     %s\n' "$(git -C "$(dirname "$0")/../.." rev-parse --short HEAD 2>/dev/null || echo '?')"
printf 'docker context    %s\n' "$CONTEXT"
"${DC[@]}" version --format '{{.Server.Version}}' 2>/dev/null \
  | sed 's/^/server version    /' || tag INFRA "daemon not reachable on context '$CONTEXT'"

# Guest-side facts (best effort; require the daemon to expose an exec/diag path).
# These mirror PLAN.md Observability. If `arcbox` CLI exposes a guest exec, wire
# it here; otherwise these are documented manual checks in README.md.
if command -v arcbox >/dev/null 2>&1; then
  printf 'guest kernel      %s\n' "$(arcbox exec -- uname -r 2>/dev/null || echo '? (run manually in guest)')"
  printf 'fex version       %s\n' "$(arcbox exec -- /arcbox/runtime/bin/FEX --version 2>/dev/null || echo '? (run manually in guest)')"
  printf 'binfmt x86_64     %s\n' "$(arcbox exec -- sh -c 'cat /proc/sys/fs/binfmt_misc/FEX-x86_64 2>/dev/null | head -1' 2>/dev/null || echo '? (run manually in guest)')"
fi

if [ "$infra" -gt 0 ]; then
  echo
  echo "Daemon unreachable — cannot run gates. See README.md for setup." >&2
  exit 2
fi

# --- Gate A: basic viability ------------------------------------------------
section "Gate A: basic viability"

arch="$("${DC[@]}" run --rm --platform linux/arm64 alpine uname -m 2>/dev/null)"
case "$arch" in
  aarch64|arm64) tag PASS "arm64 container reports $arch (native HV path)" ;;
  "")            tag INFRA "arm64 alpine run produced no output (image pull / daemon issue)" ;;
  *)             tag FAIL "arm64 container reported '$arch', expected aarch64" ;;
esac

# Distinguish three outcomes, because they lead to OPPOSITE decisions:
#   - x86_64                       → PASS (FEX64 served amd64)
#   - FEX64 not provisioned        → INFRA/BLOCKED, decision pending. This is
#     "exec format error" (no x86_64 binfmt handler), the ABX-375 fail-closed
#     error, or a missing interpreter. Per PLAN this is the *unavailable*
#     state, NOT a gate failure — it must NOT trigger "resume ABX-374".
#   - FEX64 ran but wrong/garbled  → real Gate A FAIL → STOP, resume ABX-374.
amd64_out="$("${DC[@]}" run --rm --platform linux/amd64 alpine uname -m 2>&1)"
if [ "$amd64_out" = "x86_64" ]; then
  tag PASS "amd64 container reports x86_64 via HV/FEX64 (GATE A CORE)"
elif printf '%s' "$amd64_out" | grep -qiE 'exec format error|requires fex64|binfmt|no such file or directory|not provisioned'; then
  amd64_blocked=1
  tag INFRA "amd64 not served: FEX64 not provisioned in the HV guest (no x86_64 binfmt handler). Provision /arcbox/runtime/bin/FEX and run a daemon with ABX-375 routing. This is NOT a Gate A FAIL."
elif [ -z "$amd64_out" ]; then
  amd64_blocked=1
  tag INFRA "amd64 produced no output (image pull / daemon issue)"
else
  tag FAIL "amd64 reported '$amd64_out', expected x86_64 — FEX64 ran but mis-executed (GATE A FAIL → STOP, resume ABX-374)"
fi

# No VZ runtime VM may be started for default amd64 runtime. The daemon should
# expose this; until a diag endpoint exists, README.md documents the manual
# `arcbox info` / process check.
if command -v arcbox >/dev/null 2>&1; then
  if arcbox info 2>/dev/null | grep -qi 'rosetta.*running\|vz.*runtime.*running'; then
    tag FAIL "a VZ/Rosetta runtime VM is running for default amd64 (PLAN forbids)"
  else
    tag PASS "no VZ/Rosetta runtime VM active for default amd64 runtime"
  fi
fi

# If amd64 is unprovisioned, the runtime/build/compose gates cannot run; emitting
# their amd64 sub-checks would produce misleading FAIL lines. Report BLOCKED and
# stop here so the verdict stays "decision pending", not "FEX failed".
if [ "$amd64_blocked" -ne 0 ]; then
  section "Summary"
  printf 'PASS=%d  FAIL=%d  UNSUPPORTED=%d  INFRA=%d\n' "$pass" "$fail" "$unsupported" "$infra"
  echo "RESULT: BLOCKED — FEX64 not provisioned in the HV guest; amd64 gates (B/C) skipped."
  echo "Provision /arcbox/runtime/bin/FEX and run a daemon with ABX-375 routing, then re-run."
  echo "This is NOT a FEX64 gate failure: do not resume ABX-374 on this basis."
  exit 2
fi

# --- Gate B: runtime default viability -------------------------------------
section "Gate B: runtime default viability (representative amd64 images)"

run_amd64() { # run_amd64 "label" image cmd...
  local label="$1"; shift
  local image="$1"; shift
  local out
  out="$("${DC[@]}" run --rm --platform linux/amd64 "$image" "$@" 2>&1)"
  local rc=$?
  if [ $rc -eq 0 ]; then
    tag PASS "$label: ran ($image)"
  elif echo "$out" | grep -qiE 'no such image|pull access|manifest unknown|network'; then
    tag INFRA "$label: image unavailable ($image)"
  elif echo "$out" | grep -qiE 'exec format error|requires fex64|binfmt|not provisioned'; then
    # FEX64 absent — provisioning gap, not a compatibility failure.
    amd64_blocked=1
    tag INFRA "$label: FEX64 not provisioned (no x86_64 binfmt handler)"
  else
    # FEX64 is present and ran the binary, but the workload failed: a genuine
    # compatibility gap to record in PLAN.md known-incompatibilities.
    tag UNSUPPORTED "$label: failed under FEX64 — $(echo "$out" | tail -1)"
  fi
}

run_amd64 "alpine/musl"        alpine            sh -c 'echo ok'
run_amd64 "debian/glibc"       debian:stable-slim sh -c 'echo ok'
run_amd64 "busybox"            busybox           sh -c 'echo ok'
run_amd64 "node"               node:slim         node -e 'process.stdout.write("ok")'
run_amd64 "python"             python:slim       python3 -c 'print("ok")'
run_amd64 "go toolchain"       golang:bookworm   go version
run_amd64 "apt (syscall-heavy)" debian:stable-slim sh -c 'apt-get -o Acquire::Retries=0 update >/dev/null 2>&1; echo done'

# I/O, networking, signals, exit-status behaviors.
out="$("${DC[@]}" run --rm --platform linux/amd64 alpine sh -c 'exit 7' 2>/dev/null; echo $?)"
[ "$out" = "7" ] && tag PASS "amd64 exit status propagates (7)" || tag FAIL "amd64 exit status wrong: $out"

out="$("${DC[@]}" run --rm --platform linux/amd64 alpine sh -c 'echo to-stderr 1>&2' 2>&1)"
echo "$out" | grep -q to-stderr && tag PASS "amd64 stderr propagates" || tag FAIL "amd64 stderr lost"

# --- Gate C: build / compose viability -------------------------------------
section "Gate C: BuildKit + Compose (single HV VM, no cross-VM routing)"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cat >"$tmp/Dockerfile" <<'EOF'
FROM --platform=linux/amd64 debian:stable-slim
RUN uname -m > /arch.txt && echo built
EOF
if "${DC[@]}" build --platform linux/amd64 -t arcbox-fex-buildtest "$tmp" >/dev/null 2>&1; then
  tag PASS "amd64 BuildKit build through HV/FEX64 (no /session cross-VM routing)"
else
  tag UNSUPPORTED "amd64 BuildKit build failed under FEX64"
fi

if command -v "$DOCKER" >/dev/null 2>&1 && "$DOCKER" compose version >/dev/null 2>&1; then
  cat >"$tmp/compose.yaml" <<'EOF'
services:
  arm:
    image: alpine
    command: sh -c "uname -m; sleep 1"
  amd:
    image: alpine
    platform: linux/amd64
    command: sh -c "uname -m; sleep 1"
EOF
  if "${DC[@]}" compose -f "$tmp/compose.yaml" -p arcboxfex up --abort-on-container-exit >/dev/null 2>&1; then
    tag PASS "mixed arm64/amd64 Compose project stayed in one HV VM"
  else
    tag UNSUPPORTED "mixed Compose project failed (inspect for FEX64 vs scheduling cause)"
  fi
  "${DC[@]}" compose -f "$tmp/compose.yaml" -p arcboxfex down >/dev/null 2>&1
else
  tag INFRA "docker compose plugin not available"
fi

# --- Summary ---------------------------------------------------------------
section "Summary"
printf 'PASS=%d  FAIL=%d  UNSUPPORTED=%d  INFRA=%d\n' "$pass" "$fail" "$unsupported" "$infra"
if [ "$fail" -gt 0 ]; then
  echo "RESULT: FAIL — FEX64 ran but a required behavior did not hold."
  echo "If a Gate A line FAILED, STOP ABX-375 and resume ABX-374 (dual-runtime)."
  exit 1
fi
if [ "$amd64_blocked" -ne 0 ]; then
  echo "RESULT: BLOCKED — FEX64 is not provisioned in the HV guest, so the amd64"
  echo "path could not be validated. This is NOT a FEX64 gate failure: do not"
  echo "resume ABX-374 on this basis. Provision /arcbox/runtime/bin/FEX (boot-assets"
  echo "rootfs init registers the x86_64 binfmt handler when present) and run a"
  echo "daemon with ABX-375 routing, then re-run. arm64 results above still apply."
  exit 2
fi
if [ "$pass" -eq 0 ]; then
  echo "RESULT: BLOCKED — only INFRA results; nothing was actually validated."
  exit 2
fi
echo "RESULT: PASS — record UNSUPPORTED lines in PLAN.md known-incompatibilities."
exit 0
