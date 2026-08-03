import type { Interceptor, Transport } from '@connectrpc/connect';
import { createConnectTransport } from '@connectrpc/connect-node';

import type { ConnectionOptions, ResolvedConnection } from './connection.js';
import { resolveConnection } from './connection.js';

/**
 * A resolved transport plus the per-unary deadline call sites apply.
 *
 * `requestTimeoutMs` is deliberately NOT wired as the transport's
 * `defaultTimeoutMs`: that default applies to every call including
 * long-lived server streams (Events, AttachExecution), which must stay
 * open indefinitely. Unary call sites pass it as `timeoutMs` instead.
 */
export interface ClientContext {
  readonly transport: Transport;
  readonly requestTimeoutMs?: number;
}

/**
 * Build the connect-es transport for a connection.
 *
 * Unix-socket mechanism (the local tier): `@connectrpc/connect-node`'s
 * HTTP/1.1 transport forwards `nodeOptions` verbatim into Node's
 * `http.request(url, options)` — see connect-node `node-transport-options.d.ts`
 * (`NodeHttp1TransportOptions.nodeOptions: Omit<http.RequestOptions, "signal">`,
 * "Options passed to the request() call of the Node.js built-in http or
 * https module") and `node-universal-client.js` (`createNodeHttp1Client`
 * → `h1Request`: `http.request(url, { ...nodeOptions, headers, method })`).
 * Node core's `http.RequestOptions.socketPath` then dials the Unix domain
 * socket, while the URL contributes only the request path and Host header
 * — hence the placeholder `baseUrl` (`UDS_BASE_URL`). No undici Agent is
 * needed: the hook is first-class and typed.
 *
 * HTTP/1.1 covers every RPC shape the sandbox surface uses: unary,
 * server-streaming (Events, AttachExecution, ReadFile, WatchDir), and
 * client-streaming (WriteFile, StreamStdin — Node's http client streams
 * request bodies, unlike fetch over h1). Only bidi streaming would
 * require HTTP/2, and the surface has none.
 */
export function createClientContext(options: ConnectionOptions = {}): ClientContext {
  if (options.transport !== undefined) {
    return { transport: options.transport, requestTimeoutMs: options.requestTimeoutMs };
  }
  const conn = resolveConnection(options);
  return { transport: createUdsOrTcpTransport(conn), requestTimeoutMs: conn.requestTimeoutMs };
}

function createUdsOrTcpTransport(conn: ResolvedConnection): Transport {
  const interceptors: Interceptor[] = [];
  if (conn.apiKey !== undefined && conn.apiKey !== '') {
    interceptors.push(bearerAuth(conn.apiKey));
  }
  return createConnectTransport({
    httpVersion: '1.1',
    baseUrl: conn.baseUrl,
    interceptors,
    ...(conn.socketPath === undefined ? {} : { nodeOptions: { socketPath: conn.socketPath } }),
  });
}

/** Attach the API key as a bearer credential (remote tier; ignored by the local daemon). */
function bearerAuth(apiKey: string): Interceptor {
  return (next) => (req) => {
    req.header.set('Authorization', `Bearer ${apiKey}`);
    return next(req);
  };
}
