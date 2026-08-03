import type { Client } from '@connectrpc/connect';
import { createClient } from '@connectrpc/connect';
import type { MessageInitShape } from '@bufbuild/protobuf';

import { FileTooLargeError, toArcBoxError } from './errors.js';
import type { WriteFileRequestSchema } from './gen/arcbox/sandbox/v1/filesystem_pb.js';
import { SandboxFilesystemService } from './gen/arcbox/sandbox/v1/filesystem_pb.js';
import type { ClientContext } from './transport.js';

/** Per-file transfer cap enforced by the daemon (`filesystem.proto`). */
export const MAX_FILE_BYTES = 256 * 1024 * 1024;

/** Chunk size for streamed writes. */
const WRITE_CHUNK_BYTES = 256 * 1024;

/** Options for file writes. */
export interface WriteOptions {
  /** Unix permission bits for the created file (default 0o644). */
  mode?: number;
}

type FilesystemClient = Client<typeof SandboxFilesystemService>;

/**
 * The `sandbox.files` namespace: move bytes in and out of one sandbox.
 * Bytes-first — text variants are explicit UTF-8 conveniences, never a
 * silent default.
 */
export class Files {
  readonly #client: FilesystemClient;
  readonly #sandboxId: string;

  constructor(ctx: ClientContext, sandboxId: string) {
    this.#client = createClient(SandboxFilesystemService, ctx.transport);
    this.#sandboxId = sandboxId;
  }

  /** Read a file as raw bytes. */
  async readBytes(path: string): Promise<Uint8Array> {
    try {
      const chunks: Uint8Array[] = [];
      let total = 0;
      for await (const chunk of this.#client.readFile({ id: this.#sandboxId, path })) {
        if (chunk.data.byteLength > 0) {
          chunks.push(chunk.data);
          total += chunk.data.byteLength;
        }
        if (chunk.done) {
          break;
        }
      }
      const out = new Uint8Array(total);
      let offset = 0;
      for (const chunk of chunks) {
        out.set(chunk, offset);
        offset += chunk.byteLength;
      }
      return out;
    } catch (reason) {
      throw toArcBoxError(reason, 'files.readBytes');
    }
  }

  /** Read a file and decode it as UTF-8. */
  async readText(path: string): Promise<string> {
    return new TextDecoder().decode(await this.readBytes(path));
  }

  /** Write raw bytes to a file, creating or truncating it. */
  async writeBytes(path: string, data: Uint8Array, opts: WriteOptions = {}): Promise<void> {
    if (data.byteLength > MAX_FILE_BYTES) {
      throw new FileTooLargeError(
        `file of ${String(data.byteLength)} bytes exceeds the ${String(MAX_FILE_BYTES)}-byte per-file cap`,
        {
          operation: 'files.writeBytes',
          context: { path, limit: String(MAX_FILE_BYTES), size: String(data.byteLength) },
        },
      );
    }
    const id = this.#sandboxId;
    // eslint-disable-next-line @typescript-eslint/require-await -- connect-es client streaming takes an AsyncIterable
    async function* requests(): AsyncGenerator<MessageInitShape<typeof WriteFileRequestSchema>> {
      yield { payload: { case: 'open', value: { id, path, mode: opts.mode ?? 0 } } };
      // Always send at least one chunk so `done` is observed, even for
      // an empty file.
      for (let offset = 0; ; offset += WRITE_CHUNK_BYTES) {
        const end = Math.min(offset + WRITE_CHUNK_BYTES, data.byteLength);
        const done = end === data.byteLength;
        yield { payload: { case: 'chunk', value: { data: data.subarray(offset, end), done } } };
        if (done) {
          return;
        }
      }
    }
    try {
      await this.#client.writeFile(requests());
    } catch (reason) {
      throw toArcBoxError(reason, 'files.writeBytes');
    }
  }

  /** Write text to a file as UTF-8. */
  async writeText(path: string, text: string, opts: WriteOptions = {}): Promise<void> {
    await this.writeBytes(path, new TextEncoder().encode(text), opts);
  }
}
