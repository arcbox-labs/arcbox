/** The `sandbox.files` namespace in `e2b`'s shape. */

import type { FileStat, Files, FsEvent } from "../index";
import { FileNotFoundError } from "../index";

import { missingBit } from "foxts/bitwise";
import { extractErrorMessage } from "foxts/extract-error-message";
import { noop } from "foxts/noop";

import { unsupported } from "./errors";
/** Kind of a filesystem entry, as `e2b` names them. */
export enum FileType {
  FILE = "file",
  DIR = "dir",
}

/** What `e2b` reports for a written file. */
export interface WriteInfo {
  name: string;
  type?: FileType;
  path: string;
}

/** One entry of a directory listing. */
export interface EntryInfo extends WriteInfo {
  /** Size in bytes. */
  size: number;
  /** Unix permission bits. */
  mode: number;
  /** Permissions rendered the way `ls -l` does, e.g. `-rw-r--r--`. */
  permissions: string;
  owner: string;
  group: string;
  /** Last modification time. */
  modifiedTime?: Date;
  /** Target of a symlink; unset for every other kind. */
  symlinkTarget?: string;
}

/** Options accepted by the write verbs. `user` is ignored — see the README. */
export interface FilesystemWriteOpts {
  user?: string;
  requestTimeoutMs?: number;
}

/** Options accepted by the read verbs. */
export interface FilesystemReadOpts {
  user?: string;
  requestTimeoutMs?: number;
  format?: "text" | "bytes" | "blob" | "stream";
}

/** One `writeFiles` entry. */
export interface WriteEntry {
  path: string;
  data: string | Uint8Array | ArrayBuffer;
}

/** Kind of a filesystem event, as `e2b` names them. */
export type FilesystemEventType = "create" | "write" | "remove" | "rename";

/** One filesystem event delivered by {@link Filesystem.watchDir}. */
export interface FilesystemEvent {
  /** Path of the affected entry, relative to the watched directory. */
  name: string;
  type: FilesystemEventType;
}

/** Options for {@link Filesystem.watchDir}. */
export interface WatchOpts {
  /** Watch subdirectories too. */
  recursive?: boolean;
  /**
   * Called once when the watch ends **on its own** — with the error
   * that killed it, or with nothing on a clean end (sandbox stop).
   * Not called for {@link WatchHandle.stop}.
   */
  onExit?: (error?: Error) => void | Promise<void>;
}

/**
 * A running directory watch. {@link stop} cancels delivery; the sandbox
 * stopping ends the watch cleanly on its own.
 */
export class WatchHandle {
  readonly #stop: () => Promise<void>;

  constructor(stop: () => Promise<void>) {
    this.#stop = stop;
  }

  /**
   * Stop delivering events. Idempotent, resolves immediately — the
   * underlying subscription closes on the next event or when the
   * sandbox stops (a pending read cannot be interrupted client-side).
   */
  async stop(): Promise<void> {
    await this.#stop();
  }
}

const EVENT_TYPES: Partial<Record<FsEvent["kind"], FilesystemEventType>> = {
  created: "create",
  modified: "write",
  removed: "remove",
  renamed: "rename",
};

/**
 * Render permission bits the way `ls -l` does.
 *
 * `e2b` exposes this string and some callers match on it, so it is
 * computed rather than left blank.
 */
export function permissionString(mode: number, isDirectory: boolean): string {
  return `${isDirectory ? "d" : "-"}${rwx((mode >> 6) & 0b111)}${rwx(
    (mode >> 3) & 0b111,
  )}${rwx(mode & 0b111)}`;
}

/** One `rwx` triple of a permission string. */
function rwx(bits: number): string {
  return `${missingBit(bits, 0b100) ? "-" : "r"}${
    missingBit(bits, 0b010) ? "-" : "w"
  }${missingBit(bits, 0b001) ? "-" : "x"}`;
}

/** Join a directory path and an entry name without doubling the slash. */
function joinPath(dir: string, name: string): string {
  return dir.endsWith("/") ? `${dir}${name}` : `${dir}/${name}`;
}

/** Map an ArcBox {@link FileStat} onto `e2b`'s entry shape. */
export function toEntryInfo(info: FileStat, dir: string): EntryInfo {
  const isDirectory = info.kind === "directory";
  const out: EntryInfo = {
    name: info.name,
    type: isDirectory ? FileType.DIR : FileType.FILE,
    path: joinPath(dir, info.name),
    size: info.size,
    mode: info.mode,
    permissions: permissionString(info.mode, isDirectory),
    // The daemon reports numeric ids only; `e2b` reports names. Showing
    // the number is honest — inventing a name would not be.
    owner: String(info.uid),
    group: String(info.gid),
  };
  if (info.modifiedAt !== undefined) {
    out.modifiedTime = info.modifiedAt;
  }
  if (info.symlinkTarget !== undefined) {
    out.symlinkTarget = info.symlinkTarget;
  }
  return out;
}

/**
 * `e2b`'s `Filesystem`, backed by `@arcbox/sandbox`'s `files`.
 *
 * The `user` option is accepted and ignored: the daemon's file channel
 * acts as the sandbox's own root, and silently succeeding under the
 * wrong identity is better than failing on an argument most callers
 * pass out of habit.
 */
export class Filesystem {
  readonly #files: Files;

  constructor(files: Files) {
    this.#files = files;
  }

  /** Read a file. `format: 'bytes'` yields a `Uint8Array`, otherwise UTF-8 text. */
  async read(
    path: string,
    opts?: FilesystemReadOpts,
  ): Promise<string | Uint8Array> {
    if (opts?.format === "blob" || opts?.format === "stream") {
      unsupported(
        `files.read(format: '${opts.format}')`,
        "only 'text' and 'bytes' are available; the daemon returns a whole file, not a stream",
      );
    }
    return opts?.format === "bytes"
      ? this.#files.readBytes(path)
      : this.#files.readText(path);
  }

  /** Write one file, or several when given a {@link WriteEntry} list. */
  async write(
    path: string,
    data: string | Uint8Array | ArrayBuffer,
    opts?: FilesystemWriteOpts,
  ): Promise<WriteInfo>;
  async write(entries: WriteEntry[]): Promise<WriteInfo[]>;
  async write(
    pathOrEntries: string | WriteEntry[],
    data?: string | Uint8Array | ArrayBuffer,
    _opts?: FilesystemWriteOpts,
  ): Promise<WriteInfo | WriteInfo[]> {
    if (Array.isArray(pathOrEntries)) {
      return this.writeFiles(pathOrEntries);
    }
    if (data === undefined) {
      unsupported(
        "files.write(path)",
        "writing a file needs its content; pass data as the second argument",
      );
    }
    await this.#write(pathOrEntries, data);
    return writeInfo(pathOrEntries);
  }

  /** Write several files. Sequential — the wire has no batch write. */
  async writeFiles(entries: WriteEntry[]): Promise<WriteInfo[]> {
    const written: WriteInfo[] = [];
    for (const entry of entries) {
      // eslint-disable-next-line no-await-in-loop -- sequential by design: one WriteFile stream at a time keeps a partial failure's boundary obvious
      await this.#write(entry.path, entry.data);
      written.push(writeInfo(entry.path));
    }
    return written;
  }

  async #write(
    path: string,
    data: string | Uint8Array | ArrayBuffer,
  ): Promise<void> {
    if (typeof data === "string") {
      await this.#files.writeText(path, data);
      return;
    }
    await this.#files.writeBytes(
      path,
      data instanceof Uint8Array ? data : new Uint8Array(data),
    );
  }

  /** List a directory's entries, non-recursively. */
  async list(path: string): Promise<EntryInfo[]> {
    const entries = await this.#files.list(path);
    return entries.map((entry) => toEntryInfo(entry, path));
  }

  /** Metadata of one path. */
  async getInfo(path: string): Promise<EntryInfo> {
    const info = await this.#files.stat(path);
    return toEntryInfo(info, parentOf(path));
  }

  /** Whether the path exists. */
  async exists(path: string): Promise<boolean> {
    try {
      await this.#files.stat(path);
      return true;
    } catch (error) {
      if (error instanceof FileNotFoundError) {
        return false;
      }
      throw error;
    }
  }

  /**
   * Create a directory and any missing parents.
   *
   * @returns `false` when it already existed, matching `e2b`.
   */
  async makeDir(path: string): Promise<boolean> {
    const existed = await this.exists(path);
    await this.#files.mkdir(path);
    return !existed;
  }

  /** Rename or move an entry. */
  async rename(oldPath: string, newPath: string): Promise<EntryInfo> {
    await this.#files.move(oldPath, newPath);
    return this.getInfo(newPath);
  }

  /** Remove a file, symlink, or directory (recursively). */
  async remove(path: string): Promise<void> {
    // e2b's remove takes no recursive flag and deletes directories, so
    // the shim always asks for the recursive form.
    await this.#files.remove(path, { recursive: true });
  }

  /**
   * Watch a directory and push each change into `onEvent`, `e2b`'s
   * callback shape over ArcBox's event iterable. Event paths are made
   * relative to `path`, matching `e2b`'s `name` field.
   */
  watchDir(
    path: string,
    onEvent: (event: FilesystemEvent) => void | Promise<void>,
    opts: WatchOpts = {},
  ): Promise<WatchHandle> {
    const stream = this.#files.watch(path, {
      recursive: opts.recursive ?? false,
    });
    const iterator = stream[Symbol.asyncIterator]();
    const prefix = path.endsWith("/") ? path : `${path}/`;
    // Shared with the pump: an event or error that lands after stop()
    // is the teardown that was asked for, not something to deliver.
    const state = { stopped: false };
    void (async () => {
      try {
        while (true) {
          // eslint-disable-next-line no-await-in-loop -- sequential by design: events are delivered one at a time, in order
          const next = await iterator.next();
          if (next.done === true || state.stopped) {
            break;
          }
          const type = EVENT_TYPES[next.value.kind];
          if (type === undefined) {
            continue;
          }
          const name = next.value.path.startsWith(prefix)
            ? next.value.path.slice(prefix.length)
            : next.value.path;
          // eslint-disable-next-line no-await-in-loop -- sequential by design: the next event waits for the sink
          await onEvent({ name, type });
        }
        if (!state.stopped) {
          await opts.onExit?.();
        }
      } catch (error) {
        if (state.stopped) {
          return;
        }
        // Always a fresh Error with the original as `cause`: the SDK's
        // typed class (and anything else) survives there, and the
        // callback's declared parameter type holds without a cast.
        await opts.onExit?.(
          new Error(extractErrorMessage(error) ?? "the watch stream failed", {
            cause: error,
          }),
        );
      }
    })();
    return Promise.resolve(
      new WatchHandle(() => {
        state.stopped = true;
        // A pending read cannot be interrupted without transport-level
        // cancellation, and the generator queues return() behind it —
        // so stop() must not await either. The subscription itself
        // closes when the queued return() drains: on the next event, or
        // when the sandbox stops.
        void iterator.return?.().catch(noop);
        return Promise.resolve();
      }),
    );
  }
}

function writeInfo(path: string): WriteInfo {
  return { name: basenameOf(path), type: FileType.FILE, path };
}

function basenameOf(path: string): string {
  return path.slice(path.lastIndexOf("/") + 1);
}

function parentOf(path: string): string {
  const cut = path.lastIndexOf("/");
  return cut <= 0 ? "/" : path.slice(0, cut);
}
