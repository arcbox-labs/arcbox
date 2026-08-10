/**
 * The `sandbox.git` namespace.
 *
 * `e2b` implements this as sugar over its command runner — its `Git`
 * takes nothing but a `Commands` — so this shim does the same, shelling
 * out to the `git` already in the sandbox image. A sandbox without `git`
 * surfaces the usual non-zero exit.
 */

import type { CommandResult, Commands } from "./commands";
import { unsupported } from "./errors";

/** Options accepted by every git verb. */
export interface GitRequestOpts {
  user?: string;
  timeoutMs?: number;
}

/** Options for {@link Git.clone}. */
export interface GitCloneOpts extends GitRequestOpts {
  branch?: string;
  depth?: number;
}

/** Options for {@link Git.commit}. */
export interface GitCommitOpts extends GitRequestOpts {
  author?: { name: string; email: string };
}

/** Branch listing, as `e2b` reports it. */
export interface GitBranches {
  current?: string;
  branches: string[];
}

/** Shell-quote one argument so a path with spaces survives `sh -lc`. */
function quote(value: string): string {
  return `'${value.replaceAll("'", String.raw`'\''`)}'`;
}

/** `git -C <path> …`, the form every verb below uses. */
function git(path: string, args: string[]): string {
  return `git -C ${quote(path)} ${args.map(quote).join(" ")}`;
}

/** Run git operations inside one sandbox. */
export class Git {
  readonly #commands: Commands;

  constructor(commands: Commands) {
    this.#commands = commands;
  }

  #run(cmd: string, opts: GitRequestOpts = {}): Promise<CommandResult> {
    return this.#commands.run(cmd, {
      ...(opts.user !== undefined && { user: opts.user }),
      ...(opts.timeoutMs !== undefined && { timeoutMs: opts.timeoutMs }),
    });
  }

  /** Clone a repository. */
  async clone(
    url: string,
    path: string,
    opts: GitCloneOpts = {},
  ): Promise<CommandResult> {
    const args = ["clone"];
    if (opts.branch !== undefined) {
      args.push("--branch", opts.branch);
    }
    if (opts.depth !== undefined) {
      args.push("--depth", String(opts.depth));
    }
    args.push(url, path);
    return this.#run(`git ${args.map(quote).join(" ")}`, opts);
  }

  /** Initialize a repository. */
  async init(path: string, opts: GitRequestOpts = {}): Promise<CommandResult> {
    return this.#run(`git init ${quote(path)}`, opts);
  }

  /** Add a remote. */
  async remoteAdd(
    path: string,
    name: string,
    url: string,
    opts: GitRequestOpts = {},
  ): Promise<CommandResult> {
    return this.#run(git(path, ["remote", "add", name, url]), opts);
  }

  /** Read a remote's URL. */
  async remoteGet(
    path: string,
    name: string,
    opts: GitRequestOpts = {},
  ): Promise<CommandResult> {
    return this.#run(git(path, ["remote", "get-url", name]), opts);
  }

  /** Porcelain status of the working tree. */
  async status(
    path: string,
    opts: GitRequestOpts = {},
  ): Promise<CommandResult> {
    return this.#run(git(path, ["status", "--porcelain=v1"]), opts);
  }

  /** List branches, with the current one called out. */
  async branches(
    path: string,
    opts: GitRequestOpts = {},
  ): Promise<GitBranches> {
    const result = await this.#run(
      git(path, ["branch", "--format=%(refname:short)"]),
      opts,
    );
    const branches: string[] = [];
    for (const line of result.stdout.split("\n")) {
      const name = line.trim();
      if (name !== "") {
        branches.push(name);
      }
    }
    const current = await this.#run(
      git(path, ["rev-parse", "--abbrev-ref", "HEAD"]),
      opts,
    );
    const head = current.stdout.trim();
    return head === "" ? { branches } : { current: head, branches };
  }

  /** Create a branch. */
  async createBranch(
    path: string,
    name: string,
    opts: GitRequestOpts = {},
  ): Promise<CommandResult> {
    return this.#run(git(path, ["branch", name]), opts);
  }

  /** Check out a branch. */
  async checkoutBranch(
    path: string,
    name: string,
    opts: GitRequestOpts = {},
  ): Promise<CommandResult> {
    return this.#run(git(path, ["checkout", name]), opts);
  }

  /** Delete a branch. */
  async deleteBranch(
    path: string,
    name: string,
    opts: GitRequestOpts = {},
  ): Promise<CommandResult> {
    return this.#run(git(path, ["branch", "-D", name]), opts);
  }

  /** Stage paths (all of them when `paths` is empty). */
  async add(
    path: string,
    paths: string[] = [],
    opts: GitRequestOpts = {},
  ): Promise<CommandResult> {
    const targets = paths.length === 0 ? ["."] : paths;
    return this.#run(git(path, ["add", ...targets]), opts);
  }

  /** Commit the staged tree. */
  async commit(
    path: string,
    message: string,
    opts: GitCommitOpts = {},
  ): Promise<CommandResult> {
    const args = ["commit", "-m", message];
    if (opts.author !== undefined) {
      args.push("--author", `${opts.author.name} <${opts.author.email}>`);
    }
    return this.#run(git(path, args), opts);
  }

  /** Push to a remote. */
  async push(
    path: string,
    remote = "origin",
    branch?: string,
    opts: GitRequestOpts = {},
  ): Promise<CommandResult> {
    const args = ["push", remote];
    if (branch !== undefined) {
      args.push(branch);
    }
    return this.#run(git(path, args), opts);
  }

  /** Pull from a remote. */
  async pull(
    path: string,
    remote = "origin",
    branch?: string,
    opts: GitRequestOpts = {},
  ): Promise<CommandResult> {
    const args = ["pull", remote];
    if (branch !== undefined) {
      args.push(branch);
    }
    return this.#run(git(path, args), opts);
  }

  /** Set a config value in the given scope (default `local`). */
  async setConfig(
    path: string,
    key: string,
    value: string,
    opts: GitRequestOpts & { scope?: "local" | "global" } = {},
  ): Promise<CommandResult> {
    const scope = opts.scope === "global" ? "--global" : "--local";
    return this.#run(git(path, ["config", scope, key, value]), opts);
  }

  /** Read a config value. */
  async getConfig(
    path: string,
    key: string,
    opts: GitRequestOpts = {},
  ): Promise<CommandResult> {
    return this.#run(git(path, ["config", "--get", key]), opts);
  }

  /** Set `user.name` and `user.email` for the repository. */
  async configureUser(
    path: string,
    name: string,
    email: string,
    opts: GitRequestOpts = {},
  ): Promise<CommandResult> {
    await this.setConfig(path, "user.name", name, opts);
    return this.setConfig(path, "user.email", email, opts);
  }

  /**
   * Unsupported: `e2b` stores the credential in its cloud credential
   * helper, which has no local counterpart.
   *
   * Configure a credential helper or an SSH key inside the sandbox
   * instead — `git` there is an ordinary program.
   */
  dangerouslyAuthenticate(): never {
    unsupported(
      "git.dangerouslyAuthenticate",
      "there is no cloud credential store; configure git credentials inside the sandbox",
    );
  }
}
