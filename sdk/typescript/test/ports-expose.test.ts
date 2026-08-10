// ports.expose()/unexpose()/list() against a mock daemon.
//
// The contracts under test: the request shapes (0 = allocate a host
// port, explicit protocol — never UNSPECIFIED on the wire), the
// returned mapping echoing the daemon's allocation, the ListExposedPorts
// row mapping (UNSPECIFIED decodes as tcp), and error wrapping naming
// the ports.* operation.

import { create } from "@bufbuild/protobuf";
import type { Transport } from "@connectrpc/connect";
import { Code, ConnectError, createRouterTransport } from "@connectrpc/connect";
import { describe, expect, it } from "vitest";

import { NotFoundError } from "../src/errors";
import type {
  ExposePortRequest,
  UnexposePortRequest,
} from "../src/gen/arcbox/sandbox/v1/sandbox_pb";
import {
  ExposePortResponseSchema,
  ListExposedPortsResponseSchema,
  PortProtocol,
  SandboxService,
} from "../src/gen/arcbox/sandbox/v1/sandbox_pb";
import { Ports } from "../src/ports";

function portsOn(transport: Transport): Ports {
  return new Ports({ transport }, "sb-1");
}

describe("ports.expose", () => {
  it("asks for an allocated host port by default and echoes the allocation", async () => {
    let seen: ExposePortRequest | undefined;
    const mock = createRouterTransport(({ service }) => {
      service(SandboxService, {
        exposePort(req) {
          seen = req;
          return create(ExposePortResponseSchema, {
            hostPort: 49152,
            guestPort: 61000,
          });
        },
      });
    });
    const mapping = await portsOn(mock).expose(8080);
    expect(seen?.id).toBe("sb-1");
    expect(seen?.sandboxPort).toBe(8080);
    expect(seen?.hostPort).toBe(0);
    expect(seen?.protocol).toBe(PortProtocol.TCP);
    expect(mapping).toEqual({
      sandboxPort: 8080,
      hostPort: 49152,
      protocol: "tcp",
    });
  });

  it("passes a specific host port and udp through", async () => {
    let seen: ExposePortRequest | undefined;
    const mock = createRouterTransport(({ service }) => {
      service(SandboxService, {
        exposePort(req) {
          seen = req;
          return create(ExposePortResponseSchema, { hostPort: 5353 });
        },
      });
    });
    const mapping = await portsOn(mock).expose(53, {
      hostPort: 5353,
      protocol: "udp",
    });
    expect(seen?.hostPort).toBe(5353);
    expect(seen?.protocol).toBe(PortProtocol.UDP);
    expect(mapping.protocol).toBe("udp");
  });

  it("wraps daemon errors naming the operation", async () => {
    const mock = createRouterTransport(({ service }) => {
      service(SandboxService, {
        exposePort() {
          throw new ConnectError("sandbox sb-1 not found", Code.NotFound);
        },
      });
    });
    const exposing = portsOn(mock).expose(8080);
    await expect(exposing).rejects.toBeInstanceOf(NotFoundError);
    await expect(exposing).rejects.toMatchObject({
      operation: "ports.expose",
    });
  });
});

describe("ports.unexpose", () => {
  it("names the mapping by sandbox port and protocol", async () => {
    let seen: UnexposePortRequest | undefined;
    const mock = createRouterTransport(({ service }) => {
      service(SandboxService, {
        unexposePort(req) {
          seen = req;
          return {};
        },
      });
    });
    await portsOn(mock).unexpose(8080);
    expect(seen?.id).toBe("sb-1");
    expect(seen?.sandboxPort).toBe(8080);
    expect(seen?.protocol).toBe(PortProtocol.TCP);
  });
});

describe("ports.list", () => {
  it("maps the daemon's rows, decoding UNSPECIFIED as tcp", async () => {
    const mock = createRouterTransport(({ service }) => {
      service(SandboxService, {
        listExposedPorts(req) {
          expect(req.id).toBe("sb-1");
          return create(ListExposedPortsResponseSchema, {
            ports: [
              {
                sandboxPort: 8080,
                hostPort: 49152,
                protocol: PortProtocol.TCP,
              },
              { sandboxPort: 53, hostPort: 5353, protocol: PortProtocol.UDP },
              {
                sandboxPort: 9000,
                hostPort: 49153,
                protocol: PortProtocol.UNSPECIFIED,
              },
            ],
          });
        },
      });
    });
    expect(await portsOn(mock).list()).toEqual([
      { sandboxPort: 8080, hostPort: 49152, protocol: "tcp" },
      { sandboxPort: 53, hostPort: 5353, protocol: "udp" },
      { sandboxPort: 9000, hostPort: 49153, protocol: "tcp" },
    ]);
  });

  it("wraps a vanished sandbox as NotFoundError naming the operation", async () => {
    const mock = createRouterTransport(({ service }) => {
      service(SandboxService, {
        listExposedPorts() {
          throw new ConnectError("sandbox sb-1 not found", Code.NotFound);
        },
      });
    });
    const listing = portsOn(mock).list();
    await expect(listing).rejects.toBeInstanceOf(NotFoundError);
    await expect(listing).rejects.toMatchObject({ operation: "ports.list" });
  });
});
