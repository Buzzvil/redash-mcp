#!/usr/bin/env node

import * as dotenv from 'dotenv';
import { existsSync } from 'fs';
import * as path from 'path';

// Load .env from cwd before anything else so subcommands see the same config.
const envPath = path.join(process.cwd(), '.env');
if (existsSync(envPath)) {
  dotenv.config({ path: envPath });
}

function printAuthEnvUsage(stream: NodeJS.WriteStream = process.stderr): void {
  stream.write(`Required environment variables:
  REDASH_URL              e.g. https://redash.example.com
  REDASH_OIDC_ISSUER      e.g. https://authentik.example.com/application/o/redash-cli/
  REDASH_OIDC_CLIENT_ID   e.g. redash-cli

Optional:
  REDASH_OIDC_AUDIENCE    defaults to REDASH_OIDC_CLIENT_ID
  REDASH_OIDC_SCOPES      default: "openid email offline_access"
  REDASH_OIDC_TOKEN_CACHE_PATH  override token cache file path
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

async function runServer(): Promise<void> {
  requireServerEnv();
  // Do NOT check auth here. The MCP server runs as a stdio subprocess of the
  // host (Claude Desktop / IDE), and any browser popup launched during boot
  // is invisible to the user — they have no way to know what's happening.
  // Auth is deferred to the request interceptor in redashClient.ts: the first
  // tool call triggers the PKCE flow if no usable token is cached, so the
  // browser opens in response to an explicit user action.
  await import('./index.js');
}

function printHelp(): void {
  process.stdout.write(`redash-mcp — Model Context Protocol server for Redash

Usage:
  redash-mcp [serve]    Start the MCP server (default). Requires a prior \`login\`.
  redash-mcp login      Run the OIDC PKCE browser flow and cache tokens.
  redash-mcp logout     Clear the cached tokens.
  redash-mcp status     Show cached token info (email, expiry).
  redash-mcp help       Show this help.

`);
  printAuthEnvUsage(process.stdout);
}

async function main(): Promise<void> {
  const arg = process.argv[2];
  switch (arg) {
    case undefined:
    case 'serve':
      await runServer();
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
