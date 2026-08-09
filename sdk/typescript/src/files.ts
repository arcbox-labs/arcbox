import { Buffer } from "node:buffer";

import type { Client } from "@connectrpc/connect";
import { createClient } from "@connectrpc/connect";
import type { MessageInitShape } from "@bufbuild/protobuf";
import { timestampDate } from "@bufbuild/protobuf/wkt";

import { FileTooLargeError, toArcBoxError } from "./errors";
import type {
  FileStat as FileStatProto,
  WriteFileRequestSchema,
} from "./gen/arcbox/sandbox/v1/filesystem_pb";
import {
  FileKind as FileKindProto,
  SandboxFilesystemService,
} from "./gen/arcbox/sandbox/v1/filesystem_pb";
import type { ClientContext } from "./transport";
import { unaryOptions } from "./transport";

/** Per-file transfer cap enforced by the daemon (`filesystem.proto`). */
export const MAX_FILE_BYTES = 256 * 1024 * 1024;

/** Chunk size for streamed writes. */
const WRITE_CHUNK_BYTES = 256 * 1024;

/** Default permission bits for created files (mirrors the daemon's default). */
const DEFAULT_WRITE_MODE = 0o644;

/** Options for file writes. */
export interface WriteOptions {
  /**
   * Unix permission bits for the created file (default 0o644). The wire
   * protocol reserves 0 as "use the default" (`filesystem.proto`), so a
   * literal mode of 0 is not expressible — it also yields 0o644.
   */
  mode?: number;
}

/**
 * What kind of filesystem object a path is. `"other"` covers device
 * nodes, FIFOs, and sockets; `"unknown"` covers kinds this SDK predates.
 */
export type FileKind = "file" | "directory" | "symlink" | "other" | "unknown";

/** Metadata of one filesystem entry, as reported by {@link Files.stat} / {@link Files.list}. */
export interface FileStat {
  /** Base name of the entry (the final path component). */
  name: string;
  /** Kind of entry (symlinks are reported as `"symlink"`, not followed). */
  kind: FileKind;
  /** Size in bytes (regular files; 0 otherwise). */
  size: number;
  /** Unix permission bits (the low 12 bits of `st_mode`). */
  mode: number;
  /** Last modification time. */
  modifiedAt?: Date;
  /** Owning user ID. */
  uid: number;
  /** Owning group ID. */
  gid: number;
  /** Symlink target (set only when kind is `"symlink"`). */
  symlinkTarget?: string;
}

/** Options for {@link Files.mkdir}. */
export interface MkdirOptions {
  /**
   * Unix permission bits for created directories (default 0o755). The
   * wire protocol reserves 0 as "use the default" (`filesystem.proto`),
   * so a literal mode of 0 is not expressible — it also yields 0o755.
   */
  mode?: number;
}

/** Options for {@link Files.remove}. */
export interface RemoveOptions {
  /**
   * Remove directories and their contents recursively. Without it a
   * non-empty directory fails with a precondition error.
   */
  recursive?: boolean;
}

const FILE_KIND_NAMES: Partial<Record<FileKindProto, FileKind>> = {
  [FileKindProto.FILE]: "file",
  [FileKindProto.DIRECTORY]: "directory",
  [FileKindProto.SYMLINK]: "symlink",
  [FileKindProto.OTHER]: "other",
};

/** Map one wire FileStat to the public DTO ("unknown" for kinds this SDK predates). */
export function fileStatFromProto(stat: FileStatProto): FileStat {
  const out: FileStat = {
    name: stat.name,
    kind: FILE_KIND_NAMES[stat.kind] ?? "unknown",
    size: Number(stat.size),
    mode: stat.mode,
    uid: stat.uid,
    gid: stat.gid,
  };
  if (stat.modifiedAt !== undefined) {
    out.modifiedAt = timestampDate(stat.modifiedAt);
  }
  if (stat.symlinkTarget !== "") {
    out.symlinkTarget = stat.symlinkTarget;
  }
  return out;
}

type FilesystemClient = Client<typeof SandboxFilesystemService>;

/**
 * The `sandbox.files` namespace: move bytes in and out of one sandbox.
 * Bytes-first — text variants are explicit UTF-8 conveniences, never a
 * silent default.
 */
export class Files {
  readonly #client: FilesystemClient;
  readonly #ctx: ClientContext;
  readonly #sandboxId: string;

  constructor(ctx: ClientContext, sandboxId: string) {
    this.#client = createClient(SandboxFilesystemService, ctx.transport);
    this.#ctx = ctx;
    this.#sandboxId = sandboxId;
  }

  /** Read a file as raw bytes. */
  async readBytes(path: string): Promise<Uint8Array> {
    try {
      const chunks: Uint8Array[] = [];
      let total = 0;
      for await (const chunk of this.#client.readFile({
        id: this.#sandboxId,
        path,
      })) {
        if (chunk.data.byteLength > 0) {
          chunks.push(chunk.data);
          total += chunk.data.byteLength;
        }
        if (chunk.done) {
          break;
        }
      }
      // Buffer IS a Uint8Array; concat is the native single-copy assembly.
      return Buffer.concat(chunks, total);
    } catch (error) {
      throw toArcBoxError(error, "files.readBytes");
    }
  }

  /** Read a file and decode it as UTF-8. */
  async readText(path: string): Promise<string> {
    return new TextDecoder().decode(await this.readBytes(path));
  }

  /** Write raw bytes to a file, creating or truncating it. */
  async writeBytes(
    path: string,
    data: Uint8Array,
    opts: WriteOptions = {},
  ): Promise<void> {
    if (data.byteLength > MAX_FILE_BYTES) {
      throw new FileTooLargeError(
        `file of ${String(data.byteLength)} bytes exceeds the ${String(MAX_FILE_BYTES)}-byte per-file cap`,
        {
          operation: "files.writeBytes",
          context: {
            path,
            limit: String(MAX_FILE_BYTES),
            size: String(data.byteLength),
          },
        },
      );
    }
    const id = this.#sandboxId;
    // eslint-disable-next-line @typescript-eslint/require-await -- connect-es client streaming takes an AsyncIterable
    async function* requests(): AsyncGenerator<
      MessageInitShape<typeof WriteFileRequestSchema>
    > {
      yield {
        payload: {
          case: "open",
          value: { id, path, mode: opts.mode ?? DEFAULT_WRITE_MODE },
        },
      };
      // Always send at least one chunk so `done` is observed, even for
      // an empty file.
      for (let offset = 0; ; offset += WRITE_CHUNK_BYTES) {
        const end = Math.min(offset + WRITE_CHUNK_BYTES, data.byteLength);
        const done = end === data.byteLength;
        yield {
          payload: {
            case: "chunk",
            value: { data: data.subarray(offset, end), done },
          },
        };
        if (done) {
          return;
        }
      }
    }
    try {
      await this.#client.writeFile(requests());
    } catch (error) {
      throw toArcBoxError(error, "files.writeBytes");
    }
  }

  /** Write text to a file as UTF-8. */
  async writeText(
    path: string,
    text: string,
    opts: WriteOptions = {},
  ): Promise<void> {
    await this.writeBytes(path, new TextEncoder().encode(text), opts);
  }

  /**
   * Metadata for one path. Symlinks are reported (`kind: "symlink"` with
   * `symlinkTarget`), not followed. A missing path is a
   * `FileNotFoundError` carrying the path in its context.
   */
  async stat(path: string): Promise<FileStat> {
    try {
      return fileStatFromProto(
        await this.#client.stat(
          { id: this.#sandboxId, path },
          unaryOptions(this.#ctx),
        ),
      );
    } catch (error) {
      throw toArcBoxError(error, "files.stat");
    }
  }

  /**
   * A directory's entries, non-recursively. Every entry carries full
   * {@link FileStat} metadata — no per-entry stat round-trips needed.
   */
  async list(path: string): Promise<FileStat[]> {
    try {
      const listing = await this.#client.listDir(
        { id: this.#sandboxId, path },
        unaryOptions(this.#ctx),
      );
      return listing.entries.map(fileStatFromProto);
    } catch (error) {
      throw toArcBoxError(error, "files.list");
    }
  }

  /**
   * Create a directory. Always `mkdir -p`: missing parents are created
   * and an existing directory succeeds — the daemon exposes no
   * non-recursive variant (`filesystem.proto`).
   */
  async mkdir(path: string, opts: MkdirOptions = {}): Promise<void> {
    try {
      await this.#client.makeDir(
        { id: this.#sandboxId, path, mode: opts.mode ?? 0 },
        unaryOptions(this.#ctx),
      );
    } catch (error) {
      throw toArcBoxError(error, "files.mkdir");
    }
  }

  /**
   * Remove a file, symlink, or directory. A non-empty directory
   * requires `recursive: true` — without it the daemon refuses with a
   * precondition error.
   */
  async remove(path: string, opts: RemoveOptions = {}): Promise<void> {
    try {
      await this.#client.remove(
        { id: this.#sandboxId, path, recursive: opts.recursive ?? false },
        unaryOptions(this.#ctx),
      );
    } catch (error) {
      throw toArcBoxError(error, "files.remove");
    }
  }

  /** Rename / move a file or directory within the sandbox. */
  async move(from: string, to: string): Promise<void> {
    try {
      await this.#client.move(
        { id: this.#sandboxId, fromPath: from, toPath: to },
        unaryOptions(this.#ctx),
      );
    } catch (error) {
      throw toArcBoxError(error, "files.move");
    }
  }
}
