# xtask — Agent Guidance

- xtask is the repository automation hub: new developer workflows
  (test runners, samplers, asset staging, release tooling) belong here,
  not in ad-hoc shell scripts.
- `xtask e2e`: the prebuild recipes in `commands/e2e.rs` must stay in
  sync with what each `arcbox-e2e` test target builds for itself.
  `SKIP_BUILD=1` is passed to a run only when a prebuild recipe matched;
  unknown targets must build on their own.
- `xtask idle` computes CPU% from `ps` cputime deltas over the window,
  not `%cpu` (a decaying average that lies on short windows). Keep it
  that way, and keep the printed verdicts tied to the idle targets in
  the root CLAUDE.md performance table.
