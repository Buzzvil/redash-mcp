#!/usr/bin/env node

import * as dotenv from 'dotenv';
import { existsSync } from 'fs';
import * as path from 'path';

const HTTP_SHUTDOWN_TIMEOUT_MS = 12_000;

// Load .env from cwd before anything else so subcommands see the same config.
const envPath = path.join(process.cwd(), '.env');
if (existsSync(envPath)) {
  dotenv.config({ path: envPath });
}

function printAuthEnvUsage(stream: NodeJS.WriteStream = process.stderr): void {
  stream.write(`Required environment variables:
  REDASH_URL              e.g. https://redash.example.com
  REDASH_OIDC_ISSUER      e.g. https://authentik.example.com/application/o/redash-api/
  REDASH_OIDC_CLIENT_ID   e.g. redash-api

Optional:
  REDASH_OIDC_AUDIENCE    defaults to REDASH_OIDC_CLIENT_ID
  REDASH_OIDC_SCOPES      default: "openid email offline_access"
  REDASH_OIDC_TOKEN_CACHE_PATH  override token cache file path
`);
}

function printHttpEnvUsage(stream: NodeJS.WriteStream = process.stderr): void {
  stream.write(`HTTP transport options:
  MCP_TRANSPORT          stdio (default) or http
  MCP_HTTP_HOST          bind address (default: 127.0.0.1)
  MCP_HTTP_PORT          listen port (default: 3000)
  MCP_HTTP_PATH          MCP endpoint path (default: /mcp)
  MCP_HTTP_BODY_LIMIT    maximum JSON request size (default: 1mb)
  MCP_HTTP_ALLOWED_HOSTS comma-separated hostnames without ports
  MCP_HTTP_ALLOWED_ORIGINS comma-separated browser Origin allowlist
`);
}

function requireServerEnv(): void {
  const required = ['REDASH_URL', 'REDASH_OIDC_ISSUER', 'REDASH_OIDC_CLIENT_ID'];
  const missing = required.filter((v) => !process.env[v]);
  if (missing.length > 0) {
    process.stderr.write(`Error: Missing required environment variables: ${missing.join(', ')}\n\n`);
    printAuthEnvUsage();
    process.exit(1);
  }
}

async function runLogin(): Promise<void> {
  requireServerEnv();
  const { performLogin, tokenCachePath } = await import('./auth.js');
  try {
    process.stderr.write('Opening browser for OIDC login...\n');
    const tokens = await performLogin();
    const expires = new Date(tokens.expiresAt).toISOString();
    const cache = tokenCachePath();
    process.stderr.write(`\nLogin successful. Tokens cached at ${cache} (expires ${expires}).\n`);
  } catch (err: any) {
    process.stderr.write(`Login failed: ${err?.message || err}\n`);
    process.exit(1);
  }
}

async function runLogout(): Promise<void> {
  const { performLogout, tokenCachePath } = await import('./auth.js');
  const cache = tokenCachePath();
  await performLogout();
  process.stderr.write(`Cleared token cache at ${cache}.\n`);
}

async function runStatus(): Promise<void> {
  const { readStatus, tokenCachePath } = await import('./auth.js');
  const cache = tokenCachePath();
  const status = await readStatus();
  if (!status.hasTokens) {
    process.stderr.write(`No cached tokens at ${cache}. Run \`redash-mcp login\` to authenticate.\n`);
    process.exit(1);
  }
  const expires = status.expiresAt ? new Date(status.expiresAt).toISOString() : 'unknown';
  const remainingMs = (status.expiresAt ?? 0) - Date.now();
  const remaining = remainingMs > 0 ? `${Math.floor(remainingMs / 1000)}s` : 'expired';
  process.stdout.write(`Cache:     ${cache}\n`);
  process.stdout.write(`Issuer:    ${status.issuer ?? '-'}\n`);
  process.stdout.write(`Client ID: ${status.clientId ?? '-'}\n`);
  process.stdout.write(`Email:     ${status.email ?? '-'}\n`);
  process.stdout.write(`Subject:   ${status.subject ?? '-'}\n`);
  process.stdout.write(`Expires:   ${expires} (${remaining})\n`);
}

type ServerTransport = 'stdio' | 'http';

function parseServerTransport(args: string[]): ServerTransport {
  let value = process.env.MCP_TRANSPORT;

  if (args.length > 0) {
    if (args.length === 2 && args[0] === '--transport') {
      value = args[1];
    } else if (args.length === 1 && args[0].startsWith('--transport=')) {
      value = args[0].slice('--transport='.length);
    } else {
      throw new Error(`Unknown serve option: ${args.join(' ')}`);
    }
  }

  switch ((value ?? 'stdio').trim().toLowerCase()) {
    case 'stdio':
      return 'stdio';
    case 'http':
    case 'streamable-http':
      return 'http';
    default:
      throw new Error(`Unsupported MCP transport: ${value}`);
  }
}

async function runHttpServer(): Promise<void> {
  const { startHttpServer } = await import('./http.js');
  const running = await startHttpServer();
  let shuttingDown = false;

  const shutdown = async (signal: string): Promise<void> => {
    if (shuttingDown) {
      return;
    }

    shuttingDown = true;
    process.stderr.write(`Received ${signal}, shutting down HTTP server...\n`);
    const forceExitTimer = setTimeout(() => {
      process.stderr.write(`HTTP shutdown exceeded ${HTTP_SHUTDOWN_TIMEOUT_MS}ms; forcing exit.\n`);
      process.exit(1);
    }, HTTP_SHUTDOWN_TIMEOUT_MS);
    forceExitTimer.unref();

    try {
      await running.close();
      clearTimeout(forceExitTimer);
      process.exit(0);
    } catch (error) {
      clearTimeout(forceExitTimer);
      throw error;
    }
  };

  process.once('SIGINT', () => {
    void shutdown('SIGINT').catch((error) => {
      process.stderr.write(`HTTP shutdown failed: ${error instanceof Error ? error.message : String(error)}\n`);
      process.exitCode = 1;
    });
  });
  process.once('SIGTERM', () => {
    void shutdown('SIGTERM').catch((error) => {
      process.stderr.write(`HTTP shutdown failed: ${error instanceof Error ? error.message : String(error)}\n`);
      process.exitCode = 1;
    });
  });
}

async function runServer(args: string[] = []): Promise<void> {
  requireServerEnv();
  const transport = parseServerTransport(args);

  if (transport === 'http') {
    await runHttpServer();
    return;
  }

  // Auth is deferred to the request interceptor in redashClient.ts. If no
  // usable token is cached, the first tool call starts device authorization
  // and returns the verification instructions to the MCP client.
  const { startStdioServer } = await import('./server.js');
  await startStdioServer();
}

function printHelp(): void {
  process.stdout.write(`redash-mcp — Model Context Protocol server for Redash

Usage:
  redash-mcp [serve]    Start the MCP server over stdio (default).
  redash-mcp serve --transport http
                        Start a stateless Streamable HTTP server.
  redash-mcp serve-http Alias for \`serve --transport http\`.
  redash-mcp login      Run the OIDC device authorization flow and cache tokens.
  redash-mcp logout     Clear the cached tokens.
  redash-mcp status     Show cached token info (email, expiry).
  redash-mcp help       Show this help.

`);
  printAuthEnvUsage(process.stdout);
  printHttpEnvUsage(process.stdout);
}

async function main(): Promise<void> {
  const arg = process.argv[2];
  switch (arg) {
    case undefined:
      await runServer();
      break;
    case 'serve':
      await runServer(process.argv.slice(3));
      break;
    case 'serve-http':
      await runServer(['--transport', 'http']);
      break;
    case 'login':
      await runLogin();
      break;
    case 'logout':
      await runLogout();
      break;
    case 'status':
      await runStatus();
      break;
    case 'help':
    case '--help':
    case '-h':
      printHelp();
      break;
    default:
      process.stderr.write(`Unknown subcommand: ${arg}\n\n`);
      printHelp();
      process.exit(1);
  }
}

main().catch((err) => {
  process.stderr.write(`Fatal: ${err?.stack || err}\n`);
  process.exit(1);
});
