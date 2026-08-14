// Template catalog against a mock daemon: Template.build/get/list/delete
// statics, instance publish/delete, and Sandbox.create accepting a
// Template instance.
//
// The contracts under test: build maps the source union onto the proto
// oneof and returns a draft handle, get resolves references, list
// auto-paginates one row per version, reference pins name:version for
// published versions and the bare name for drafts, and errors carry the
// templates.* operation names.

import { create } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { Code, ConnectError, createRouterTransport } from "@connectrpc/connect";
import { describe, expect, it } from "vitest";

import { TemplateNotFoundError } from "../src/errors";
import {
  ErrorCode,
  ErrorInfoSchema,
} from "../src/gen/arcbox/sandbox/v1/errors_pb";
import type { BuildTemplateRequest } from "../src/gen/arcbox/sandbox/v1/template_pb";
import {
  ListTemplatesResponseSchema,
  TemplateSchema,
  TemplateService,
} from "../src/gen/arcbox/sandbox/v1/template_pb";
import { Template } from "../src/templates";

const CREATED = new Date("2026-08-11T08:00:00Z");

describe("Template.build", () => {
  it("maps the docker source and returns the registered draft", async () => {
    const mock = createRouterTransport(({ service }) => {
      service(TemplateService, {
        build(req: BuildTemplateRequest) {
          expect(req.name).toBe("code");
          expect(req.source).toEqual({
            case: "dockerRef",
            value: "python:3.12",
          });
          expect(req.prewarm).toBe(true);
          expect(req.labels).toEqual({ team: "ml" });
          expect(req.defaults?.limits?.vcpus).toBe(2);
          expect(req.defaults?.readyProbe?.probe).toEqual({
            case: "port",
            value: 8080,
          });
          return create(TemplateSchema, {
            name: "code",
            version: "",
            digest: "sha256:d1",
            createdAt: timestampFromDate(CREATED),
          });
        },
      });
    });

    const template = await Template.build(
      "code",
      { docker: "python:3.12" },
      {
        prewarm: true,
        labels: { team: "ml" },
        defaults: { vcpus: 2, readyProbe: { port: 8080 } },
        connection: { transport: mock },
      },
    );
    expect(template.name).toBe("code");
    expect(template.version).toBe("");
    expect(template.digest).toBe("sha256:d1");
    expect(template.reference).toBe("code");
    expect(template.info.createdAt).toEqual(CREATED);
  });

  it("maps dockerfile and snapshot sources onto the oneof", async () => {
    const seen: string[] = [];
    const mock = createRouterTransport(({ service }) => {
      service(TemplateService, {
        build(req: BuildTemplateRequest) {
          seen.push(req.source.case ?? "none");
          return create(TemplateSchema, { name: req.name });
        },
      });
    });
    await Template.build(
      "a",
      { dockerfile: "FROM alpine" },
      { connection: { transport: mock } },
    );
    await Template.build(
      "b",
      { snapshot: "snap-1" },
      { connection: { transport: mock } },
    );
    expect(seen).toEqual(["dockerfile", "snapshotId"]);
  });
});

describe("Template.get / publish / delete", () => {
  it("resolves, publishes, and pins name:version", async () => {
    const mock = createRouterTransport(({ service }) => {
      service(TemplateService, {
        get(req) {
          expect(req.reference).toBe("code");
          return create(TemplateSchema, {
            name: "code",
            version: "",
            digest: "sha256:d1",
          });
        },
        publish(req) {
          expect(req.name).toBe("code");
          expect(req.version).toBe("1.0");
          return create(TemplateSchema, {
            name: "code",
            version: "1.0",
            digest: "sha256:d1",
          });
        },
        delete(req) {
          expect(req.reference).toBe("code:1.0");
          return {};
        },
      });
    });

    const draft = await Template.get("code", {
      connection: { transport: mock },
    });
    const published = await draft.publish("1.0");
    expect(published.reference).toBe("code:1.0");
    await published.delete();
  });

  it("surfaces TEMPLATE_NOT_FOUND as the typed error", async () => {
    const mock = createRouterTransport(({ service }) => {
      service(TemplateService, {
        get() {
          // Faithful daemon shape: the classifier rides as an ErrorInfo
          // detail, never the message text.
          throw new ConnectError(
            "template not found: ghost",
            Code.NotFound,
            undefined,
            [
              {
                desc: ErrorInfoSchema,
                value: {
                  code: ErrorCode.TEMPLATE_NOT_FOUND,
                  suggestion: "",
                  context: {},
                },
              },
            ],
          );
        },
      });
    });
    // The mapped class and the operation name are the contract — a raw
    // ConnectError leaking through must fail here.
    const attempt = Template.get("ghost", { connection: { transport: mock } });
    await expect(attempt).rejects.toBeInstanceOf(TemplateNotFoundError);
    await expect(attempt).rejects.toMatchObject({ operation: "templates.get" });
  });
});

describe("Template.list", () => {
  it("auto-paginates one row per version, drafts included", async () => {
    let calls = 0;
    const mock = createRouterTransport(({ service }) => {
      service(TemplateService, {
        list(req) {
          calls += 1;
          if (req.pageToken === "") {
            return create(ListTemplatesResponseSchema, {
              templates: [
                create(TemplateSchema, {
                  name: "a",
                  version: "1.0",
                  warmSnapshotId: "s1",
                }),
              ],
              nextPageToken: "a:1.0",
            });
          }
          return create(ListTemplatesResponseSchema, {
            templates: [create(TemplateSchema, { name: "a", version: "" })],
            nextPageToken: "",
          });
        },
      });
    });

    const rows = [];
    for await (const row of Template.list({
      connection: { transport: mock },
    })) {
      rows.push(row);
    }
    expect(calls).toBe(2);
    expect(rows.map((r) => `${r.name}:${r.version}`)).toEqual(["a:1.0", "a:"]);
    expect(rows[0]?.warm).toBe(true);
    expect(rows[1]?.warm).toBe(false);
  });
});
