process.env.REDASH_URL = "https://redash.example.com";
process.env.REDASH_OIDC_ISSUER = "https://idp.example.com";
process.env.REDASH_OIDC_CLIENT_ID = "redash-api";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { jest } from "@jest/globals";
import { request as httpRequest } from "node:http";
import {
  resolveHttpServerOptions,
  startHttpServer,
  type RunningHttpServer,
} from "../http.js";

jest.setTimeout(15_000);

describe("Streamable HTTP transport", () => {
  let running: RunningHttpServer;

  beforeAll(async () => {
    running = await startHttpServer({
      host: "127.0.0.1",
      port: 0,
      allowedOrigins: [],
    });
  });

  afterAll(async () => {
    await running.close();
    await running.close();
  });

  async function listTools(clientName: string): Promise<string[]> {
    const client = new Client({ name: clientName, version: "1.0.0" });
    const transport = new StreamableHTTPClientTransport(new URL(running.url));

    try {
      await client.connect(transport);
      const result = await client.listTools();
      return result.tools.map((tool) => tool.name);
    } finally {
      await client.close();
    }
  }

  it("serves health without exposing cached configuration", async () => {
    const response = await fetch(new URL("/health", running.url));

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.json()).toEqual({ status: "ok" });
  });

  it("completes MCP initialization and lists tools", async () => {
    const tools = await listTools("http-integration-test");

    expect(tools).toContain("list_queries");
    expect(tools).toContain("get_dashboard");
  });

  it("isolates concurrent stateless clients", async () => {
    const [first, second] = await Promise.all([
      listTools("http-client-one"),
      listTools("http-client-two"),
    ]);

    expect(first).toEqual(second);
    expect(first.length).toBeGreaterThan(10);
  });

  it("returns 405 for unsupported MCP methods", async () => {
    const response = await fetch(running.url);
    const body = await response.json() as { error: { message: string } };

    expect(response.status).toBe(405);
    expect(body.error.message).toBe("Method not allowed");
  });

  it("rejects browser origins unless explicitly allowed", async () => {
    const response = await fetch(new URL("/health", running.url), {
      headers: { Origin: "https://evil.example.com" },
    });

    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({
      jsonrpc: "2.0",
      error: { code: -32000, message: "Origin not allowed" },
      id: null,
    });
  });

  it("accepts an explicitly allowed browser origin", async () => {
    const originServer = await startHttpServer({
      host: "127.0.0.1",
      port: 0,
      allowedOrigins: ["https://client.example.com"],
    });

    try {
      const response = await fetch(new URL("/health", originServer.url), {
        headers: { Origin: "https://client.example.com" },
      });

      expect(response.status).toBe(200);
    } finally {
      await originServer.close();
    }
  });

  it("returns JSON-RPC errors for invalid or oversized JSON bodies", async () => {
    const invalidResponse = await fetch(running.url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{",
    });
    const invalidBody = await invalidResponse.json() as { error: { code: number; message: string } };

    expect(invalidResponse.status).toBe(400);
    expect(invalidBody.error.code).toBe(-32700);
    expect(invalidBody.error.message).toBe("Invalid JSON body");

    const unsupportedResponse = await fetch(running.url, {
      method: "POST",
      headers: { "Content-Type": "application/json; charset=iso-8859-1" },
      body: "{}",
    });
    const unsupportedBody = await unsupportedResponse.json() as { error: { code: number; message: string } };

    expect(unsupportedResponse.status).toBe(415);
    expect(unsupportedBody.error.code).toBe(-32600);
    expect(unsupportedBody.error.message).toBe("Unsupported request body");

    const limitedServer = await startHttpServer({
      host: "127.0.0.1",
      port: 0,
      bodyLimit: "1kb",
    });

    try {
      const oversizedResponse = await fetch(limitedServer.url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/list",
          params: { padding: "x".repeat(2048) },
        }),
      });
      const oversizedBody = await oversizedResponse.json() as { error: { code: number; message: string } };

      expect(oversizedResponse.status).toBe(413);
      expect(oversizedBody.error.code).toBe(-32000);
      expect(oversizedBody.error.message).toBe("Request body too large");
    } finally {
      await limitedServer.close();
    }
  });

  it("rejects unexpected Host headers", async () => {
    const status = await new Promise<number>((resolve, reject) => {
      const request = httpRequest({
        host: running.host,
        port: running.port,
        path: "/health",
        headers: { Host: "evil.example.com" },
      }, (response) => {
        response.resume();
        resolve(response.statusCode ?? 0);
      });
      request.on("error", reject);
      request.end();
    });

    expect(status).toBe(403);
  });
});

describe("HTTP configuration", () => {
  const emptyEnv: NodeJS.ProcessEnv = {};

  it("uses loopback-safe defaults", () => {
    expect(resolveHttpServerOptions({}, emptyEnv)).toMatchObject({
      host: "127.0.0.1",
      port: 3000,
      path: "/mcp",
      bodyLimit: "1mb",
      allowedOrigins: [],
    });
    expect(resolveHttpServerOptions({}, {
      MCP_HTTP_ALLOWED_HOSTS: "",
      MCP_HTTP_ALLOWED_ORIGINS: "",
    })).toMatchObject({
      allowedHosts: undefined,
      allowedOrigins: [],
    });
  });

  it("requires a Host allowlist for non-loopback bindings", () => {
    expect(() => resolveHttpServerOptions({ host: "0.0.0.0" }, emptyEnv))
      .toThrow("MCP_HTTP_ALLOWED_HOSTS");

    expect(resolveHttpServerOptions({
      host: "0.0.0.0",
      allowedHosts: ["mcp.example.com"],
    }, emptyEnv).allowedHosts).toEqual(["mcp.example.com"]);
  });

  it("rejects invalid ports and reserved paths", () => {
    expect(() => resolveHttpServerOptions({}, { MCP_HTTP_PORT: "not-a-port" }))
      .toThrow("MCP_HTTP_PORT");
    expect(() => resolveHttpServerOptions({ path: "/health" }, emptyEnv))
      .toThrow("/health");
    expect(() => resolveHttpServerOptions({ bodyLimit: "unlimited" }, emptyEnv))
      .toThrow("MCP_HTTP_BODY_LIMIT");
    expect(() => resolveHttpServerOptions({ bodyLimit: 0 }, emptyEnv))
      .toThrow("positive integer");
    expect(() => resolveHttpServerOptions({ bodyLimit: "0kb" }, emptyEnv))
      .toThrow("MCP_HTTP_BODY_LIMIT");
  });
});
