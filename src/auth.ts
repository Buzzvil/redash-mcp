/**
 * OIDC + PKCE browser login for the Redash MCP server.
 *
 * Why a separate `login` subcommand instead of starting the flow inside the
 * MCP server itself: the MCP server runs as a stdio subprocess of Claude
 * Desktop (or similar), so it has no way to interactively open a browser and
 * receive the user's attention. The user runs `redash-mcp login` once in
 * their terminal; the MCP server consumes the cached tokens silently and
 * refreshes them when needed.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as fsp from 'fs/promises';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { spawn } from 'child_process';
import { AddressInfo } from 'net';
import axios from 'axios';

import { logger } from './logger.js';

export interface OidcConfig {
  issuer: string;
  clientId: string;
  audience: string;
  scopes: string;
}

export interface CachedTokens {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  // ms epoch when accessToken expires
  expiresAt: number;
  // Bound to the OIDC config used to obtain the tokens so a config change
  // invalidates the cache rather than silently using the wrong audience.
  issuer: string;
  clientId: string;
}

interface DiscoveryDocument {
  authorization_endpoint: string;
  token_endpoint: string;
}

const REFRESH_LEEWAY_MS = 60_000; // refresh 60s before expiry

export class AuthError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = 'AuthError';
  }
}

export function loadOidcConfig(env: NodeJS.ProcessEnv = process.env): OidcConfig {
  const issuer = (env.REDASH_OIDC_ISSUER || '').replace(/\/+$/, '');
  const clientId = env.REDASH_OIDC_CLIENT_ID || '';
  if (!issuer) throw new AuthError('REDASH_OIDC_ISSUER is required');
  if (!clientId) throw new AuthError('REDASH_OIDC_CLIENT_ID is required');

  const audience = env.REDASH_OIDC_AUDIENCE || clientId;
  // offline_access is requested by default so the cache can renew without
  // re-opening the browser. Override with REDASH_OIDC_SCOPES if the IdP
  // doesn't support it.
  const scopes = env.REDASH_OIDC_SCOPES || 'openid email offline_access';

  return { issuer, clientId, audience, scopes };
}

export function tokenCachePath(env: NodeJS.ProcessEnv = process.env): string {
  if (env.REDASH_OIDC_TOKEN_CACHE_PATH) return env.REDASH_OIDC_TOKEN_CACHE_PATH;
  const base = env.XDG_STATE_HOME || path.join(os.homedir(), '.local', 'state');
  return path.join(base, 'redash-mcp', 'tokens.json');
}

async function readTokenCache(file: string): Promise<CachedTokens | null> {
  try {
    const raw = await fsp.readFile(file, 'utf8');
    const parsed = JSON.parse(raw) as CachedTokens;
    if (!parsed.accessToken || !parsed.expiresAt) return null;
    return parsed;
  } catch (err: any) {
    if (err?.code === 'ENOENT') return null;
    logger.warning(`Failed to read token cache at ${file}: ${err?.message || err}`);
    return null;
  }
}

async function writeTokenCache(file: string, tokens: CachedTokens): Promise<void> {
  await fsp.mkdir(path.dirname(file), { recursive: true });
  // Write atomically and restrict perms — refresh tokens are sensitive.
  const tmp = `${file}.${process.pid}.tmp`;
  await fsp.writeFile(tmp, JSON.stringify(tokens, null, 2), { mode: 0o600 });
  await fsp.rename(tmp, file);
  // rename preserves the mode on POSIX but be defensive.
  try { await fsp.chmod(file, 0o600); } catch { /* best effort */ }
}

async function clearTokenCache(file: string): Promise<void> {
  try { await fsp.unlink(file); } catch (err: any) { if (err?.code !== 'ENOENT') throw err; }
}

async function discover(issuer: string): Promise<DiscoveryDocument> {
  const url = `${issuer}/.well-known/openid-configuration`;
  try {
    const { data } = await axios.get<DiscoveryDocument>(url, { timeout: 10_000 });
    if (!data.authorization_endpoint || !data.token_endpoint) {
      throw new AuthError(`Discovery document at ${url} is missing endpoints`);
    }
    return data;
  } catch (err: any) {
    throw new AuthError(`OIDC discovery failed for ${url}: ${err?.message || err}`, err);
  }
}

function base64UrlEncode(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function generatePkcePair(): { verifier: string; challenge: string } {
  const verifier = base64UrlEncode(crypto.randomBytes(64));
  const challenge = base64UrlEncode(crypto.createHash('sha256').update(verifier).digest());
  return { verifier, challenge };
}

function openBrowser(url: string): void {
  // No third-party `open` dep — small platform shim is enough.
  const platform = process.platform;
  let cmd: string;
  let args: string[];
  if (platform === 'darwin') { cmd = 'open'; args = [url]; }
  else if (platform === 'win32') { cmd = 'cmd'; args = ['/c', 'start', '""', url]; }
  else { cmd = 'xdg-open'; args = [url]; }

  try {
    const child = spawn(cmd, args, { stdio: 'ignore', detached: true });
    child.on('error', () => { /* surfaced via the manual-URL message below */ });
    child.unref();
  } catch {
    // Caller already prints the URL so the user can paste it manually.
  }
}

interface CallbackResult {
  code: string;
  state: string;
}

function awaitCallback(expectedState: string, timeoutMs: number): Promise<{ result: CallbackResult; port: number; redirectUri: string; close: () => void }> {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      const url = new URL(req.url || '/', `http://127.0.0.1`);
      if (url.pathname !== '/callback') {
        res.writeHead(404).end();
        return;
      }
      const error = url.searchParams.get('error');
      if (error) {
        const description = url.searchParams.get('error_description') || '';
        res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(`<h1>Login failed</h1><p>${error}: ${description}</p>`);
        reject(new AuthError(`IdP returned error: ${error} ${description}`));
        return;
      }
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');
      if (!code || !state) {
        res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end('<h1>Missing code or state</h1>');
        reject(new AuthError('Callback missing code or state'));
        return;
      }
      if (state !== expectedState) {
        res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end('<h1>State mismatch</h1>');
        reject(new AuthError('CSRF state mismatch on OIDC callback'));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end('<h1>Logged in</h1><p>You can close this tab and return to the terminal.</p>');
      resolve({ result: { code, state }, port: (server.address() as AddressInfo).port, redirectUri: '', close: () => server.close() });
    });

    server.on('error', (err) => reject(new AuthError(`Loopback server error: ${err.message}`, err)));
    server.listen(0, '127.0.0.1', () => {
      const port = (server.address() as AddressInfo).port;
      const redirectUri = `http://127.0.0.1:${port}/callback`;
      // Expose port + redirectUri to the caller before any redirect arrives by
      // resolving the timeout-controlled promise from the outer login() below.
      (server as any)._redashCliRedirectUri = redirectUri;
      (server as any)._redashCliPort = port;
    });

    const timer = setTimeout(() => {
      try { server.close(); } catch { /* ignore */ }
      reject(new AuthError(`Timed out waiting for OIDC callback after ${timeoutMs}ms`));
    }, timeoutMs);
    server.on('close', () => clearTimeout(timer));
  });
}

interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
}

async function exchangeCodeForTokens(
  tokenEndpoint: string,
  params: { code: string; clientId: string; redirectUri: string; codeVerifier: string },
): Promise<TokenResponse> {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: params.code,
    redirect_uri: params.redirectUri,
    client_id: params.clientId,
    code_verifier: params.codeVerifier,
  });
  try {
    const { data } = await axios.post<TokenResponse>(tokenEndpoint, body.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
      timeout: 15_000,
    });
    return data;
  } catch (err: any) {
    const detail = err?.response?.data ? JSON.stringify(err.response.data) : err?.message;
    throw new AuthError(`Token exchange failed: ${detail}`, err);
  }
}

async function refreshTokens(
  tokenEndpoint: string,
  params: { refreshToken: string; clientId: string; scopes: string },
): Promise<TokenResponse> {
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: params.refreshToken,
    client_id: params.clientId,
    scope: params.scopes,
  });
  try {
    const { data } = await axios.post<TokenResponse>(tokenEndpoint, body.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
      timeout: 15_000,
    });
    return data;
  } catch (err: any) {
    const detail = err?.response?.data ? JSON.stringify(err.response.data) : err?.message;
    throw new AuthError(`Token refresh failed: ${detail}`, err);
  }
}

function tokenResponseToCached(resp: TokenResponse, cfg: OidcConfig, fallbackRefresh?: string): CachedTokens {
  return {
    accessToken: resp.access_token,
    refreshToken: resp.refresh_token || fallbackRefresh,
    idToken: resp.id_token,
    expiresAt: Date.now() + (resp.expires_in ?? 0) * 1000,
    issuer: cfg.issuer,
    clientId: cfg.clientId,
  };
}

/**
 * Run the full PKCE login flow: open browser, wait for callback, exchange
 * code, persist tokens. Intended to be invoked from `redash-mcp login`.
 */
interface LoginFlowHandle {
  url: string;
  completion: Promise<CachedTokens>;
}

/**
 * Start a PKCE login flow: spin up the loopback callback server, build the
 * auth URL, and return both immediately. The caller decides how to surface
 * the URL (auto-launch browser in a terminal, return it via tool response in
 * an MCP context, etc.) and may await `completion` to receive the cached
 * tokens once the callback arrives.
 */
async function beginLoginFlow(opts: { cfg?: OidcConfig; cachePath?: string; timeoutMs?: number } = {}): Promise<LoginFlowHandle> {
  const cfg = opts.cfg ?? loadOidcConfig();
  const cache = opts.cachePath ?? tokenCachePath();
  const timeoutMs = opts.timeoutMs ?? 5 * 60_000;

  const discovery = await discover(cfg.issuer);
  const { verifier, challenge } = generatePkcePair();
  const state = base64UrlEncode(crypto.randomBytes(16));

  const server = http.createServer();
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const port = (server.address() as AddressInfo).port;
  const redirectUri = `http://127.0.0.1:${port}/callback`;

  const callbackPromise = new Promise<CallbackResult>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new AuthError(`Timed out waiting for OIDC callback after ${timeoutMs}ms`));
      try { server.close(); } catch { /* ignore */ }
    }, timeoutMs);

    server.on('request', (req, res) => {
      const url = new URL(req.url || '/', `http://127.0.0.1:${port}`);
      if (url.pathname !== '/callback') { res.writeHead(404).end(); return; }
      const errorParam = url.searchParams.get('error');
      if (errorParam) {
        const description = url.searchParams.get('error_description') || '';
        res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(`<h1>Login failed</h1><p>${errorParam}: ${description}</p>`);
        clearTimeout(timer);
        reject(new AuthError(`IdP returned error: ${errorParam} ${description}`));
        return;
      }
      const code = url.searchParams.get('code');
      const stateParam = url.searchParams.get('state');
      if (!code || !stateParam) {
        res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end('<h1>Missing code or state</h1>');
        clearTimeout(timer);
        reject(new AuthError('Callback missing code or state'));
        return;
      }
      if (stateParam !== state) {
        res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end('<h1>State mismatch</h1>');
        clearTimeout(timer);
        reject(new AuthError('CSRF state mismatch on OIDC callback'));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end('<h1>Logged in</h1><p>You can close this tab and return to the terminal.</p>');
      clearTimeout(timer);
      resolve({ code, state: stateParam });
    });
  });

  const authUrl = new URL(discovery.authorization_endpoint);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', cfg.clientId);
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('scope', cfg.scopes);
  authUrl.searchParams.set('audience', cfg.audience);
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('code_challenge', challenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');

  const completion = (async () => {
    try {
      const callback = await callbackPromise;
      const tokens = await exchangeCodeForTokens(discovery.token_endpoint, {
        code: callback.code,
        clientId: cfg.clientId,
        redirectUri,
        codeVerifier: verifier,
      });
      const cached = tokenResponseToCached(tokens, cfg);
      await writeTokenCache(cache, cached);
      return cached;
    } finally {
      try { server.close(); } catch { /* ignore */ }
    }
  })();

  return { url: authUrl.toString(), completion };
}

/**
 * Run the full PKCE login flow: open browser, wait for callback, exchange
 * code, persist tokens. Intended to be invoked from `redash-mcp login`
 * (interactive terminal). For the MCP server path see `startPendingLogin`.
 */
export async function performLogin(opts: { cfg?: OidcConfig; cachePath?: string; timeoutMs?: number } = {}): Promise<CachedTokens> {
  const { url, completion } = await beginLoginFlow(opts);
  process.stderr.write(`\nOpen this URL in your browser if it doesn't open automatically:\n  ${url}\n\n`);
  openBrowser(url);
  return completion;
}

interface PendingLogin {
  url: string;
  completion: Promise<CachedTokens>;
  startedAt: number;
}

let pendingLogin: PendingLogin | null = null;
const PENDING_LOGIN_TTL_MS = 5 * 60_000;

/**
 * Start (or attach to) a non-interactive PKCE login. The loopback callback
 * server is started but the browser is NOT auto-launched — the caller surfaces
 * the returned URL to a user-facing channel (MCP tool response) and the user
 * clicks/pastes it themselves. Returns immediately with the URL.
 *
 * Concurrent callers share one in-flight login. Once the callback arrives the
 * tokens are cached and `pendingLogin` is cleared so subsequent failures start
 * a fresh flow.
 */
export async function startPendingLogin(opts: { cfg?: OidcConfig; cachePath?: string; timeoutMs?: number } = {}): Promise<{ url: string }> {
  if (pendingLogin && Date.now() - pendingLogin.startedAt < PENDING_LOGIN_TTL_MS) {
    return { url: pendingLogin.url };
  }

  const { url, completion } = await beginLoginFlow(opts);
  const handle: PendingLogin = {
    url,
    completion,
    startedAt: Date.now(),
  };
  pendingLogin = handle;
  // Clear pendingLogin once the flow resolves either way so a fresh attempt
  // can start on the next failure.
  completion.finally(() => {
    if (pendingLogin === handle) pendingLogin = null;
  }).catch(() => { /* errors surface via the next ensureValidTokens call */ });

  return { url };
}

/**
 * Read the cached tokens and refresh if near expiry. Throws AuthError if no
 * usable cache exists — callers should surface a "run `redash-mcp login`"
 * message instead of falling back to a different auth method.
 */
export async function getValidTokens(opts: { cfg?: OidcConfig; cachePath?: string; now?: () => number } = {}): Promise<CachedTokens> {
  const cfg = opts.cfg ?? loadOidcConfig();
  const cache = opts.cachePath ?? tokenCachePath();
  const now = opts.now ?? Date.now;

  const cached = await readTokenCache(cache);
  if (!cached) {
    throw new AuthError(
      `No cached OIDC tokens at ${cache}. Run \`redash-mcp login\` once in your terminal.`,
    );
  }
  if (cached.issuer !== cfg.issuer || cached.clientId !== cfg.clientId) {
    throw new AuthError(
      `Cached tokens belong to a different OIDC client (issuer=${cached.issuer}, client_id=${cached.clientId}). Run \`redash-mcp login\` again.`,
    );
  }
  if (cached.expiresAt - REFRESH_LEEWAY_MS > now()) {
    return cached;
  }
  if (!cached.refreshToken) {
    throw new AuthError(
      'Cached access token is expired and no refresh_token is available. Run `redash-mcp login` again.',
    );
  }

  const discovery = await discover(cfg.issuer);
  const refreshed = await refreshTokens(discovery.token_endpoint, {
    refreshToken: cached.refreshToken,
    clientId: cfg.clientId,
    scopes: cfg.scopes,
  });
  const updated = tokenResponseToCached(refreshed, cfg, cached.refreshToken);
  await writeTokenCache(cache, updated);
  return updated;
}

/**
 * Force a refresh and persist new tokens. Used by the API client when a
 * request fails with 401 — the cached token may have been revoked or rotated
 * by the IdP earlier than its stated expiry.
 */
export async function forceRefresh(opts: { cfg?: OidcConfig; cachePath?: string } = {}): Promise<CachedTokens> {
  const cfg = opts.cfg ?? loadOidcConfig();
  const cache = opts.cachePath ?? tokenCachePath();

  const cached = await readTokenCache(cache);
  if (!cached?.refreshToken) {
    throw new AuthError('No refresh_token available; run `redash-mcp login` again.');
  }
  const discovery = await discover(cfg.issuer);
  const refreshed = await refreshTokens(discovery.token_endpoint, {
    refreshToken: cached.refreshToken,
    clientId: cfg.clientId,
    scopes: cfg.scopes,
  });
  const updated = tokenResponseToCached(refreshed, cfg, cached.refreshToken);
  await writeTokenCache(cache, updated);
  return updated;
}

/**
 * Like getValidTokens, but on cache miss / unrecoverable AuthError starts a
 * non-interactive login flow (loopback server only — no browser spawn) and
 * throws an AuthError whose message contains the auth URL. The caller is
 * expected to surface that URL to the user via a tool response; once the
 * user completes PKCE in their browser, the loopback server receives the
 * callback and the next call to this function succeeds.
 *
 * Why not auto-launch the browser: the MCP server typically runs as a stdio
 * subprocess (Claude Desktop / IDE) or in a container without `xdg-open`. A
 * silent browser spawn is invisible to the user; an explicit URL surfaced
 * through the tool response is universally actionable.
 */
export async function ensureValidTokens(opts: { cfg?: OidcConfig; cachePath?: string; now?: () => number } = {}): Promise<CachedTokens> {
  try {
    return await getValidTokens(opts);
  } catch (err) {
    if (!(err instanceof AuthError)) throw err;
    const { url } = await startPendingLogin(opts);
    throw new AuthError(
      `OIDC login required. Open this URL in your browser to authenticate:\n\n  ${url}\n\nAfter completing the browser flow, retry the tool call.`,
    );
  }
}

export async function performLogout(opts: { cachePath?: string } = {}): Promise<void> {
  await clearTokenCache(opts.cachePath ?? tokenCachePath());
}

export interface AuthStatus {
  hasTokens: boolean;
  email?: string;
  subject?: string;
  expiresAt?: number;
  issuer?: string;
  clientId?: string;
}

/** Decode a JWT payload without verifying — only used for showing user info in status. */
function decodeJwtPayloadUnsafe(token: string): Record<string, unknown> | null {
  const parts = token.split('.');
  if (parts.length < 2) return null;
  try {
    const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = payload + '='.repeat((4 - (payload.length % 4)) % 4);
    return JSON.parse(Buffer.from(padded, 'base64').toString('utf8'));
  } catch {
    return null;
  }
}

export async function readStatus(opts: { cachePath?: string } = {}): Promise<AuthStatus> {
  const cache = opts.cachePath ?? tokenCachePath();
  const cached = await readTokenCache(cache);
  if (!cached) return { hasTokens: false };
  // Prefer id_token for user claims when present; access tokens may not be JWT.
  const payload = (cached.idToken && decodeJwtPayloadUnsafe(cached.idToken))
    || decodeJwtPayloadUnsafe(cached.accessToken)
    || {};
  return {
    hasTokens: true,
    email: typeof payload.email === 'string' ? payload.email : undefined,
    subject: typeof payload.sub === 'string' ? payload.sub : undefined,
    expiresAt: cached.expiresAt,
    issuer: cached.issuer,
    clientId: cached.clientId,
  };
}
