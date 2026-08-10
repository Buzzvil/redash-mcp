import type { Server as NodeHttpServer } from "node:http";
import { hostHeaderValidation } from "@modelcontextprotocol/sdk/server/middleware/hostHeaderValidation.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import express, { type NextFunction, type Request, type Response } from "express";
import { initializeAuth, shutdownAuth } from "./auth.js";
import { createRedashMcpServer } from "./server.js";
import { logger } from "./logger.js";

const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_PORT = 3000;
const DEFAULT_PATH = "/mcp";
const DEFAULT_BODY_LIMIT = "1mb";
const SHUTDOWN_GRACE_MS = 10_000;

export interface HttpServerOptions {
  host?: string;
  port?: number;
  path?: string;
  bodyLimit?: string | number;
  allowedHosts?: string[];
  allowedOrigins?: string[];
}

export interface ResolvedHttpServerOptions {
  host: string;
  port: number;
  path: string;
  bodyLimit: string | number;
  allowedHosts?: string[];
  allowedOrigins: string[];
}

export interface RunningHttpServer {
  server: NodeHttpServer;
  host: string;
  port: number;
  path: string;
  url: string;
  close: () => Promise<void>;
}

function parseList(value: string | undefined): string[] | undefined {
  if (value === undefined) {
    return undefined;
  }

  const entries = value
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);

  return entries.length > 0 ? entries : undefined;
}

function parsePort(value: string | undefined): number {
  if (value === undefined || value.trim() === "") {
    return DEFAULT_PORT;
  }

  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`MCP_HTTP_PORT must be an integer between 1 and 65535, got: ${value}`);
  }

  return port;
}

function parseBodyLimit(value: string | number | undefined): string | number {
  if (value === undefined) {
    return DEFAULT_BODY_LIMIT;
  }
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 1) {
      throw new Error(`HTTP body limit must be a positive integer, got: ${value}`);
    }
    return value;
  }

  const bodyLimit = value.trim().toLowerCase();
  const match = /^(\d+)(?:b|kb|mb|gb)?$/.exec(bodyLimit);
  if (!match || Number(match[1]) < 1) {
    throw new Error(`MCP_HTTP_BODY_LIMIT must be a byte size such as 1mb, got: ${value}`);
  }
  return bodyLimit;
}

export function resolveHttpServerOptions(
  options: HttpServerOptions = {},
  env: NodeJS.ProcessEnv = process.env
): ResolvedHttpServerOptions {
  const host = (options.host ?? env.MCP_HTTP_HOST ?? DEFAULT_HOST).trim();
  if (!host) {
    throw new Error("MCP_HTTP_HOST must not be empty");
  }

  const port = options.port ?? parsePort(env.MCP_HTTP_PORT);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error(`HTTP port must be an integer between 0 and 65535, got: ${port}`);
  }

  const path = (options.path ?? env.MCP_HTTP_PATH ?? DEFAULT_PATH).trim();
  if (!/^\/[A-Za-z0-9._~\/%-]*$/.test(path)) {
    throw new Error(`MCP_HTTP_PATH must be an absolute URL path, got: ${path}`);
  }
  if (path === "/health") {
    throw new Error("MCP_HTTP_PATH must not conflict with the /health endpoint");
  }

  const bodyLimit = parseBodyLimit(options.bodyLimit ?? env.MCP_HTTP_BODY_LIMIT);
  const allowedHosts = options.allowedHosts ?? parseList(env.MCP_HTTP_ALLOWED_HOSTS);
  const allowedOrigins = options.allowedOrigins ?? parseList(env.MCP_HTTP_ALLOWED_ORIGINS) ?? [];

  const loopbackHosts = new Set(["127.0.0.1", "localhost", "::1"]);
  if (!loopbackHosts.has(host) && (!allowedHosts || allowedHosts.length === 0)) {
    throw new Error("MCP_HTTP_ALLOWED_HOSTS is required when binding outside loopback");
  }

  return { host, port, path, bodyLimit, allowedHosts, allowedOrigins };
}

function jsonRpcError(res: Response, status: number, code: number, message: string): void {
  res.status(status).json({
    jsonrpc: "2.0",
    error: {
      code,
      message,
    },
    id: null,
  });
}

function formatHost(host: string): string {
  return host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
}

export async function startHttpServer(options: HttpServerOptions = {}): Promise<RunningHttpServer> {
  const resolved = resolveHttpServerOptions(options);
  initializeAuth();
  const app = express();
  const allowedHosts = resolved.allowedHosts ?? ["localhost", "127.0.0.1", "[::1]"];

  app.use(hostHeaderValidation(allowedHosts));

  app.use((req: Request, res: Response, next) => {
    const origin = req.get("origin");
    if (!origin || resolved.allowedOrigins.includes(origin)) {
      next();
      return;
    }

    jsonRpcError(res, 403, -32000, "Origin not allowed");
  });

  app.use(express.json({ limit: resolved.bodyLimit }));

  app.get("/health", (_req: Request, res: Response) => {
    res.set("Cache-Control", "no-store");
    res.status(200).json({ status: "ok" });
  });

  type ActiveRequest = {
    server: ReturnType<typeof createRedashMcpServer>;
    transport: StreamableHTTPServerTransport;
    closePromise?: Promise<void>;
  };

  const activeRequests = new Set<ActiveRequest>();

  const closeRequest = (active: ActiveRequest): Promise<void> => {
    if (!active.closePromise) {
      active.closePromise = Promise.allSettled([
        active.transport.close(),
        active.server.close(),
      ]).then(() => {
        activeRequests.delete(active);
      });
    }

    return active.closePromise;
  };

  app.post(resolved.path, async (req: Request, res: Response) => {
    const mcpServer = createRedashMcpServer();
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
    });
    const active: ActiveRequest = { server: mcpServer, transport };
    activeRequests.add(active);

    res.once("close", () => {
      void closeRequest(active);
    });

    try {
      await mcpServer.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      logger.error(`Failed to handle Streamable HTTP request: ${error}`);
      if (!res.headersSent) {
        jsonRpcError(res, 500, -32603, "Internal server error");
      }
      await closeRequest(active);
    }
  });

  app.get(resolved.path, (_req: Request, res: Response) => {
    res.set("Allow", "POST");
    jsonRpcError(res, 405, -32000, "Method not allowed");
  });

  app.delete(resolved.path, (_req: Request, res: Response) => {
    res.set("Allow", "POST");
    jsonRpcError(res, 405, -32000, "Method not allowed");
  });

  app.use((error: unknown, _req: Request, res: Response, next: NextFunction) => {
    const bodyError = error as { status?: unknown; type?: unknown };
    if (bodyError.status === 413) {
      jsonRpcError(res, 413, -32000, "Request body too large");
      return;
    }
    if (bodyError.status === 400 && bodyError.type === "entity.parse.failed") {
      jsonRpcError(res, 400, -32700, "Invalid JSON body");
      return;
    }
    if (typeof bodyError.status === "number" && bodyError.status >= 400 && bodyError.status < 500) {
      const message = bodyError.status === 415 ? "Unsupported request body" : "Invalid request body";
      jsonRpcError(res, bodyError.status, -32600, message);
      return;
    }

    logger.error(`Unhandled HTTP middleware error: ${error}`);
    if (res.headersSent) {
      next(error);
      return;
    }
    jsonRpcError(res, 500, -32603, "Internal server error");
  });

  const nodeServer = app.listen(resolved.port, resolved.host);
  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error) => {
      nodeServer.off("listening", onListening);
      reject(error);
    };
    const onListening = () => {
      nodeServer.off("error", onError);
      resolve();
    };

    nodeServer.once("error", onError);
    nodeServer.once("listening", onListening);
  });

  const address = nodeServer.address();
  if (!address || typeof address === "string") {
    nodeServer.close();
    throw new Error("Unable to determine HTTP server address");
  }

  const port = address.port;
  const url = `http://${formatHost(resolved.host)}:${port}${resolved.path}`;
  let closePromise: Promise<void> | undefined;

  const close = (): Promise<void> => {
    if (!closePromise) {
      closePromise = (async () => {
        const authClosed = shutdownAuth();
        const listenerClosed = new Promise<void>((resolve, reject) => {
          if (!nodeServer.listening) {
            resolve();
            return;
          }

          nodeServer.close((error) => {
            if (error) {
              reject(error);
            } else {
              resolve();
            }
          });
          nodeServer.closeIdleConnections?.();
        });

        const requestsClosed = Promise.allSettled(Array.from(activeRequests, closeRequest));
        const forceCloseTimer = setTimeout(() => {
          nodeServer.closeAllConnections?.();
        }, SHUTDOWN_GRACE_MS);
        forceCloseTimer.unref();

        try {
          await Promise.all([listenerClosed, requestsClosed, authClosed]);
        } finally {
          clearTimeout(forceCloseTimer);
        }
      })();
    }

    return closePromise;
  };

  logger.info(`Redash MCP Streamable HTTP server listening at ${url}`);

  return {
    server: nodeServer,
    host: resolved.host,
    port,
    path: resolved.path,
    url,
    close,
  };
}
