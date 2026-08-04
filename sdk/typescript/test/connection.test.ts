import { homedir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { resolveConnection, UDS_BASE_URL } from "../src/connection.js";
import { InvalidArgumentError } from "../src/errors.js";

describe("resolveConnection", () => {
  it("defaults to <home>/.arcbox/run/arcbox.sock", () => {
    const conn = resolveConnection({}, {});
    expect(conn.baseUrl).toBe(UDS_BASE_URL);
    expect(conn.socketPath).toBe(
      join(homedir(), ".arcbox", "run", "arcbox.sock"),
    );
    expect(conn.apiKey).toBeUndefined();
  });

  it("ARCBOX_DATA_DIR relocates the default socket", () => {
    const conn = resolveConnection({}, { ARCBOX_DATA_DIR: "/tmp/abx" });
    expect(conn.socketPath).toBe(join("/tmp/abx", "run", "arcbox.sock"));
  });

  it.each(["development", "dev", " Development "])(
    "ARCBOX_PROFILE=%j selects ~/.arcbox-dev, like the daemon",
    (profile) => {
      const conn = resolveConnection({}, { ARCBOX_PROFILE: profile });
      expect(conn.socketPath).toBe(
        join(homedir(), ".arcbox-dev", "run", "arcbox.sock"),
      );
    },
  );

  it("unknown profiles fall back to production, like from_env_or_default", () => {
    const conn = resolveConnection({}, { ARCBOX_PROFILE: "staging" });
    expect(conn.socketPath).toBe(
      join(homedir(), ".arcbox", "run", "arcbox.sock"),
    );
  });

  it("a non-empty ARCBOX_DATA_DIR beats the profile; an empty one is unset", () => {
    expect(
      resolveConnection(
        {},
        { ARCBOX_DATA_DIR: "/tmp/abx", ARCBOX_PROFILE: "dev" },
      ).socketPath,
    ).toBe(join("/tmp/abx", "run", "arcbox.sock"));
    expect(
      resolveConnection({}, { ARCBOX_DATA_DIR: "", ARCBOX_PROFILE: "dev" })
        .socketPath,
    ).toBe(join(homedir(), ".arcbox-dev", "run", "arcbox.sock"));
  });

  it("ARCBOX_SOCKET overrides the data-dir default", () => {
    const conn = resolveConnection(
      {},
      { ARCBOX_DATA_DIR: "/tmp/abx", ARCBOX_SOCKET: "/tmp/x.sock" },
    );
    expect(conn.socketPath).toBe("/tmp/x.sock");
  });

  it("an explicit socketPath beats every environment variable", () => {
    const conn = resolveConnection(
      { socketPath: "/opt/d.sock" },
      { ARCBOX_SOCKET: "/tmp/x.sock", ARCBOX_API_URL: "https://cloud.example" },
    );
    expect(conn.socketPath).toBe("/opt/d.sock");
    expect(conn.baseUrl).toBe(UDS_BASE_URL);
  });

  it("ARCBOX_API_URL selects the remote tier over ARCBOX_SOCKET", () => {
    const conn = resolveConnection(
      {},
      { ARCBOX_API_URL: "https://cloud.example", ARCBOX_SOCKET: "/tmp/x.sock" },
    );
    expect(conn.baseUrl).toBe("https://cloud.example");
    expect(conn.socketPath).toBeUndefined();
  });

  it("an explicit apiUrl selects the remote tier", () => {
    const conn = resolveConnection({ apiUrl: "https://cloud.example" }, {});
    expect(conn.baseUrl).toBe("https://cloud.example");
    expect(conn.socketPath).toBeUndefined();
  });

  it("rejects socketPath together with apiUrl", () => {
    expect(() =>
      resolveConnection(
        { socketPath: "/tmp/x.sock", apiUrl: "https://cloud.example" },
        {},
      ),
    ).toThrow(InvalidArgumentError);
  });

  it("resolves the api key from option over environment", () => {
    expect(
      resolveConnection({ apiKey: "opt" }, { ARCBOX_API_KEY: "env" }).apiKey,
    ).toBe("opt");
    expect(resolveConnection({}, { ARCBOX_API_KEY: "env" }).apiKey).toBe("env");
  });

  it("treats empty environment strings as unset", () => {
    const conn = resolveConnection(
      {},
      { ARCBOX_API_URL: "", ARCBOX_SOCKET: "" },
    );
    expect(conn.baseUrl).toBe(UDS_BASE_URL);
    expect(conn.socketPath).toBe(
      join(homedir(), ".arcbox", "run", "arcbox.sock"),
    );
  });

  it("carries requestTimeoutMs through", () => {
    expect(
      resolveConnection({ requestTimeoutMs: 5000 }, {}).requestTimeoutMs,
    ).toBe(5000);
  });
});
