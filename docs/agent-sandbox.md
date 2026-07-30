# Coding agents in a sandbox

`abctl claude` opens Claude Code inside a dedicated ArcBox sandbox (a
Firecracker microVM). The agent runs with its permission prompts switched off,
because the microVM — not the prompt — is the isolation boundary.

```console
$ export ANTHROPIC_API_KEY=sk-...
$ abctl claude
```

The first run builds the agent image (a couple of minutes); later runs reuse it
and start in about a second.

## Requirements

Sandboxes need nested virtualization: the VZ backend on Apple Silicon M3 or
newer with macOS 15+. Elsewhere every sandbox RPC fails with
`FAILED_PRECONDITION`. See [sandbox-api.md](sandbox-api.md).

## Getting code in and out

`/workspace` starts **empty**. Nothing on the host is mounted into the sandbox,
so the agent brings code in itself:

```
> clone https://github.com/some/repo into /workspace and fix the failing test
```

Results come back out through the sandbox file API. It transfers one file at a
time (256 MiB limit), so archive a tree first:

```console
$ abctl sandbox run agent-claude -- tar -czf /tmp/out.tgz -C /workspace .
$ abctl sandbox cp agent-claude:/tmp/out.tgz .
```

**Everything in `/workspace` is destroyed when the sandbox is stopped or
removed** — stopping tears down the sandbox's copy-on-write layer. Copy out what
you want to keep before running `abctl sandbox rm`.

## Sessions

One sandbox is reused per agent (`agent-claude`), so exiting the TUI leaves it
running and reopening continues where you left off — including `claude
--continue`, since the agent's own state lives in the sandbox.

```console
$ abctl claude                      # reuse or create
$ abctl claude --id review          # a second, independent session
$ abctl claude -- --model opus      # everything after -- goes to the agent
$ abctl claude --no-bypass          # keep the agent's permission prompts
$ abctl sandbox ls                  # see agent sandboxes
$ abctl sandbox rm agent-claude     # discard one (destroys /workspace)
```

Resources default to 2 vCPUs and 2048 MiB; override with `--cpus` / `--memory`.

## Credentials

`ANTHROPIC_API_KEY` (or `ANTHROPIC_AUTH_TOKEN`) must be set in your shell, and
is forwarded for that session only — never written into the image or the
sandbox record. `ANTHROPIC_*` and `CLAUDE_*` variables are forwarded too; other
host environment variables are not, so unrelated credentials stay out of the
sandbox. OAuth credentials from `~/.claude` are deliberately not copied in.

## Customizing the image

The image comes from a built-in template. Inspect it, edit it, and build your
version:

```console
$ abctl sandbox templates
claude     Claude Code on Node.js 22 with git, running as a non-root user

$ abctl sandbox templates --show claude > Dockerfile
$ # edit Dockerfile, then:
$ abctl sandbox create --id mine --from-dockerfile ./Dockerfile --memory 2048
$ abctl sandbox exec -t mine -- claude
```

A template can also be used directly, without the `claude` wrapper:

```console
$ abctl sandbox create --id t1 --from-template claude --memory 2048
```

Keep in mind Claude Code refuses to skip permission prompts as root, which is
why the template creates a non-root `agent` user that owns `/workspace`.
