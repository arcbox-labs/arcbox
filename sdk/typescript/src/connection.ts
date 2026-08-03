import { homedir } from 'node:os';
import { join } from 'node:path';

import type { Transport } from '@connectrpc/connect';

import { InvalidArgumentError } from './errors.js';

/**
 * Connection configuration for reaching an ArcBox daemon.
 *
 * Resolution order for every field: explicit option > environment > default.
 * The default tier is the local daemon's Unix socket; setting an API URL
 * (option or `ARCBOX_API_URL`) selects the remote tier instead (CORE-63,
 * reserved — no cloud front door exists yet).
 */
export interface ConnectionOptions {
  /** Unix socket path of the local daemon (env: `ARCBOX_SOCKET`). */
  socketPath?: string;
  /** Base URL of a remote daemon / cloud front door (env: `ARCBOX_API_URL`). */
  apiUrl?: string;
  /**
   * Bearer credential attached as an `Authorization` header when set
   * (env: `ARCBOX_API_KEY`). Unused by the local daemon, which trusts
   * socket file permissions instead.
   */
  apiKey?: string;
  /** Per-RPC deadline in milliseconds for unary calls. Streams are exempt. */
  requestTimeoutMs?: number;
  /**
   * Injected connect-es Transport, replacing socket/URL resolution
   * entirely — the mock/testing seam.
   */
  transport?: Transport;
}

/** A fully resolved connection target. */
export interface ResolvedConnection {
  /**
   * Base URL handed to the transport. On the Unix-socket tier this is a
   * placeholder (`http://arcbox`) that only supplies the Host header and
   * request paths — the connection itself goes to `socketPath`.
   */
  baseUrl: string;
  /** Unix socket to dial; unset on the remote (TCP) tier. */
  socketPath?: string;
  /** Bearer credential to attach, when set. */
  apiKey?: string;
  /** Per-unary-RPC deadline in milliseconds, when set. */
  requestTimeoutMs?: number;
}

/**
 * Placeholder authority for Unix-socket requests. Node's `http.request`
 * takes the connection target from `socketPath` and uses the URL only for
 * the Host header and path, so any stable name works here.
 */
export const UDS_BASE_URL = 'http://arcbox';

/** Default socket location relative to the daemon data dir: `run/arcbox.sock`. */
function defaultSocketPath(env: NodeJS.ProcessEnv): string {
  // Mirrors arcbox-constants paths.rs: `<data_dir>/run/arcbox.sock`, data
  // dir from ARCBOX_DATA_DIR, default `~/.arcbox`.
  const dataDir = env.ARCBOX_DATA_DIR ?? join(homedir(), '.arcbox');
  return join(dataDir, 'run', 'arcbox.sock');
}

/**
 * Resolve connection options against the environment.
 *
 * Tier selection: an explicit `socketPath` and an explicit `apiUrl` are
 * contradictory and rejected. At the environment level `ARCBOX_API_URL`
 * wins over `ARCBOX_SOCKET` — setting it selects the remote tier.
 */
export function resolveConnection(
  options: ConnectionOptions = {},
  env: NodeJS.ProcessEnv = process.env,
): ResolvedConnection {
  if (options.socketPath !== undefined && options.apiUrl !== undefined) {
    throw new InvalidArgumentError(
      'connection.socketPath and connection.apiUrl are mutually exclusive: ' +
        'a connection dials either the local Unix socket or a remote URL',
    );
  }

  const apiKey = options.apiKey ?? env.ARCBOX_API_KEY;
  const requestTimeoutMs = options.requestTimeoutMs;
  const common = { apiKey, requestTimeoutMs };

  if (options.socketPath !== undefined) {
    return { baseUrl: UDS_BASE_URL, socketPath: options.socketPath, ...common };
  }
  if (options.apiUrl !== undefined) {
    return { baseUrl: options.apiUrl, ...common };
  }
  if (env.ARCBOX_API_URL !== undefined && env.ARCBOX_API_URL !== '') {
    return { baseUrl: env.ARCBOX_API_URL, ...common };
  }
  const socketPath =
    env.ARCBOX_SOCKET !== undefined && env.ARCBOX_SOCKET !== ''
      ? env.ARCBOX_SOCKET
      : defaultSocketPath(env);
  return { baseUrl: UDS_BASE_URL, socketPath, ...common };
}
