/**
 * OIDC Device Authorization Grant (RFC 8628) login for the Redash MCP server.
 *
 * Why device flow only: the MCP server typically runs as a stdio subprocess of
 * Claude Desktop / Claude Code (often in a container, often without a
 * reachable browser). PKCE + loopback redirect needs (a) a browser the user
 * can see, (b) the user's browser to be able to reach our 127.0.0.1:<port>
 * redirect — both fail in containers and headless setups. Device flow needs
 * only outbound HTTPS to the IdP and surfaces a short URL + user_code that
 * the user opens on any device with a browser.
 *
 * CLI subcommand `redash-mcp login` still attempts to spawn the user's
 * browser (`open` / `start` / `xdg-open`) as a convenience for interactive
 * terminal use, but silently degrades when no browser is reachable.
 */

import * as fs from 'fs';
import * as fsp from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import { spawn } from 'child_process';
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
  token_endpoint: string;
  device_authorization_endpoint?: string;
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
  // offline_access requested by default so cached tokens can renew without a
  // fresh browser dance. Override with REDASH_OIDC_SCOPES if the IdP doesn't
  // support it.
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
  try { await fsp.chmod(file, 0o600); } catch { /* best effort */ }
}

async function clearTokenCache(file: string): Promise<void> {
  try { await fsp.unlink(file); } catch (err: any) { if (err?.code !== 'ENOENT') throw err; }
}

async function discover(issuer: string): Promise<DiscoveryDocument> {
  const url = `${issuer}/.well-known/openid-configuration`;
  try {
    const { data } = await axios.get<DiscoveryDocument>(url, { timeout: 10_000 });
    if (!data.token_endpoint) {
      throw new AuthError(`Discovery document at ${url} is missing token_endpoint`);
    }
    return data;
  } catch (err: any) {
    if (err instanceof AuthError) throw err;
    throw new AuthError(`OIDC discovery failed for ${url}: ${err?.message || err}`, err);
  }
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
    child.on('error', () => { /* user has the URL printed regardless */ });
    child.unref();
  } catch {
    // Caller already prints the URL so the user can paste it manually.
  }
}

interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
}

interface DeviceCodeResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete?: string;
  expires_in: number;
  interval: number;
}

async function requestDeviceCode(
  deviceAuthEndpoint: string,
  params: { clientId: string; scopes: string; audience?: string },
): Promise<DeviceCodeResponse> {
  const body = new URLSearchParams({
    client_id: params.clientId,
    scope: params.scopes,
  });
  if (params.audience) body.set('audience', params.audience);
  try {
    const { data } = await axios.post<DeviceCodeResponse>(deviceAuthEndpoint, body.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
      timeout: 15_000,
    });
    if (!data.device_code || !data.user_code || !data.verification_uri) {
      throw new AuthError('Device authorization response missing required fields');
    }
    return data;
  } catch (err: any) {
    if (err instanceof AuthError) throw err;
    const detail = err?.response?.data ? JSON.stringify(err.response.data) : err?.message;
    throw new AuthError(`Device authorization request failed: ${detail}`, err);
  }
}

async function pollForDeviceToken(
  tokenEndpoint: string,
  params: { clientId: string; deviceCode: string; initialIntervalSec: number; expiresInSec: number },
): Promise<TokenResponse> {
  const deadline = Date.now() + params.expiresInSec * 1000;
  let intervalMs = Math.max(params.initialIntervalSec, 1) * 1000;
  const body = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
    device_code: params.deviceCode,
    client_id: params.clientId,
  });

  while (Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
    try {
      const { data } = await axios.post<TokenResponse>(tokenEndpoint, body.toString(), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
        timeout: 15_000,
        validateStatus: () => true, // RFC 8628 signals pending/slow_down via 400
      });
      if (data && (data as any).error === undefined && data.access_token) {
        return data;
      }
      const errCode = (data as any)?.error;
      if (errCode === 'authorization_pending') continue;
      if (errCode === 'slow_down') { intervalMs += 5000; continue; }
      if (errCode === 'expired_token') {
        throw new AuthError('Device code expired before user completed authorization');
      }
      if (errCode === 'access_denied') {
        throw new AuthError('User denied the device authorization request');
      }
      throw new AuthError(`Device token poll failed: ${JSON.stringify(data)}`);
    } catch (err: any) {
      if (err instanceof AuthError) throw err;
      const detail = err?.response?.data ? JSON.stringify(err.response.data) : err?.message;
      throw new AuthError(`Device token poll failed: ${detail}`, err);
    }
  }
  throw new AuthError(`Device code expired after ${params.expiresInSec}s`);
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

interface LoginFlowHandle {
  /** Pre-filled verification URL the user opens (`verification_uri_complete` if present, else bare `verification_uri`). */
  url: string;
  /** Short user-typeable code as a fallback for clients that can't load the pre-filled URL. */
  userCode: string;
  /** Resolves with cached tokens once the user completes browser-side authorization. */
  completion: Promise<CachedTokens>;
  /** Seconds the user has to complete authorization before `completion` rejects. */
  expiresInSec: number;
}

/**
 * Start an RFC 8628 Device Authorization Grant flow. Requests a device code
 * and starts polling the token endpoint in the background. Returns the
 * user-facing URL + code immediately; await `completion` to receive cached
 * tokens once the user finishes browser-side authorization.
 */
async function beginDeviceFlow(opts: { cfg?: OidcConfig; cachePath?: string } = {}): Promise<LoginFlowHandle> {
  const cfg = opts.cfg ?? loadOidcConfig();
  const cache = opts.cachePath ?? tokenCachePath();

  const discovery = await discover(cfg.issuer);
  if (!discovery.device_authorization_endpoint) {
    throw new AuthError(
      `IdP discovery document at ${cfg.issuer} does not advertise device_authorization_endpoint. ` +
      `Enable RFC 8628 device flow on the OIDC provider before using this MCP server.`,
    );
  }

  const dc = await requestDeviceCode(discovery.device_authorization_endpoint, {
    clientId: cfg.clientId,
    scopes: cfg.scopes,
    audience: cfg.audience,
  });

  const completion = (async () => {
    const tokens = await pollForDeviceToken(discovery.token_endpoint, {
      clientId: cfg.clientId,
      deviceCode: dc.device_code,
      initialIntervalSec: dc.interval || 5,
      expiresInSec: dc.expires_in,
    });
    const cached = tokenResponseToCached(tokens, cfg);
    await writeTokenCache(cache, cached);
    return cached;
  })();

  return {
    url: dc.verification_uri_complete || dc.verification_uri,
    userCode: dc.user_code,
    completion,
    expiresInSec: dc.expires_in,
  };
}

/**
 * Run a full device-flow login from a terminal: print the URL + user code,
 * try to open the browser (best-effort — silently no-ops if unavailable),
 * then poll for the token. Intended for `redash-mcp login`.
 */
export async function performLogin(opts: { cfg?: OidcConfig; cachePath?: string } = {}): Promise<CachedTokens> {
  const handle = await beginDeviceFlow(opts);
  process.stderr.write(
    `\nDevice authorization required. Open this URL in your browser:\n  ${handle.url}\n\n` +
    `If the page asks for a code, enter: ${handle.userCode}\n` +
    `(code expires in ${handle.expiresInSec}s)\n\n`,
  );
  openBrowser(handle.url);
  return handle.completion;
}

interface PendingLogin {
  url: string;
  userCode: string;
  completion: Promise<CachedTokens>;
  expiresAt: number;
}

let pendingLogin: PendingLogin | null = null;

/**
 * Start (or attach to) a non-interactive device login. The IdP issues a
 * device code and pre-filled verification URL; the caller surfaces both to
 * the user via an MCP tool response and waits for the user to complete the
 * flow on a separate device. Returns immediately.
 *
 * Concurrent callers share one in-flight login until it resolves or its
 * `expiresAt` passes.
 */
export async function startPendingLogin(opts: { cfg?: OidcConfig; cachePath?: string } = {}): Promise<{ url: string; userCode: string; expiresAt: number }> {
  if (pendingLogin && pendingLogin.expiresAt > Date.now()) {
    return { url: pendingLogin.url, userCode: pendingLogin.userCode, expiresAt: pendingLogin.expiresAt };
  }

  const handle = await beginDeviceFlow(opts);
  const entry: PendingLogin = {
    url: handle.url,
    userCode: handle.userCode,
    completion: handle.completion,
    expiresAt: Date.now() + handle.expiresInSec * 1000,
  };
  pendingLogin = entry;
  handle.completion.finally(() => {
    if (pendingLogin === entry) pendingLogin = null;
  }).catch(() => { /* errors surface via the next ensureValidTokens call */ });

  return { url: entry.url, userCode: entry.userCode, expiresAt: entry.expiresAt };
}

/**
 * Block until the currently-pending login (or a freshly-started one) finishes.
 * Used by the `wait_for_oidc_login` MCP tool so the assistant can call it
 * after surfacing the verification URL to the user; once the user completes
 * device authorization in their browser, this resolves with the cached
 * tokens and the assistant can immediately retry the original tool.
 *
 * If tokens are already valid, returns immediately without starting a new
 * flow. If no pending flow exists, starts one.
 */
export async function waitForPendingLogin(opts: { cfg?: OidcConfig; cachePath?: string; timeoutMs?: number } = {}): Promise<CachedTokens> {
  try {
    return await getValidTokens(opts);
  } catch (err) {
    if (!(err instanceof AuthError)) throw err;
  }

  if (!pendingLogin || pendingLogin.expiresAt <= Date.now()) {
    await startPendingLogin(opts);
  }
  const pl = pendingLogin!;
  const hardDeadline = pl.expiresAt - Date.now() + 5_000; // device code expiry + small slack
  const timeoutMs = Math.max(0, Math.min(opts.timeoutMs ?? hardDeadline, hardDeadline));

  return await Promise.race([
    pl.completion,
    new Promise<CachedTokens>((_, reject) =>
      setTimeout(() => reject(new AuthError('Timed out waiting for OIDC login. Have the user re-open the verification URL and try again.')), timeoutMs),
    ),
  ]);
}

/**
 * Snapshot of the currently-pending login flow, or null if none is in
 * progress. Used by the MCP server to advertise the verification URL on
 * follow-up tool calls without restarting the flow.
 */
export function getPendingLogin(): { url: string; userCode: string; expiresAt: number } | null {
  if (!pendingLogin || pendingLogin.expiresAt <= Date.now()) return null;
  return { url: pendingLogin.url, userCode: pendingLogin.userCode, expiresAt: pendingLogin.expiresAt };
}

/**
 * Read the cached tokens and refresh if near expiry. Throws AuthError if no
 * usable cache exists.
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
 * Build an AuthError that contains both the verification URL (for the user)
 * and the next-action instruction (for the assistant — surface URL + call
 * `wait_for_oidc_login`, then retry the original tool). Starts a fresh
 * pending device flow if one is not already in progress.
 *
 * Used by `ensureValidTokens` for cold cache-miss and by the redash API
 * client's 401 retry path when a stale token can't be refreshed.
 */
export async function makeLoginRequiredError(
  reason: string,
  opts: { cfg?: OidcConfig; cachePath?: string } = {},
): Promise<AuthError> {
  const pending = await startPendingLogin(opts);
  return new AuthError(
    `${reason}\n\n` +
    `## For the user\n` +
    `Open this URL in your browser to authorize:\n  ${pending.url}\n` +
    `If the page asks for a code, enter: ${pending.userCode}\n\n` +
    `## For the assistant\n` +
    `In this same response: surface the URL above to the user, then immediately call the \`wait_for_oidc_login\` tool. ` +
    `It will block until the user finishes the browser flow (or the device code expires). ` +
    `Once it returns successfully, retry the original tool call — do not ask the user for confirmation in between.`,
  );
}

/**
 * Like getValidTokens, but on cache miss / unrecoverable AuthError starts a
 * device flow in the background and throws an AuthError whose message
 * contains the verification URL and user code. The caller surfaces this to
 * the user via a tool response. Once the user completes the device flow on
 * their browser, the polling resolves, the cache is hydrated, and the next
 * call to this function succeeds.
 */
export async function ensureValidTokens(opts: { cfg?: OidcConfig; cachePath?: string; now?: () => number } = {}): Promise<CachedTokens> {
  try {
    return await getValidTokens(opts);
  } catch (err) {
    if (!(err instanceof AuthError)) throw err;
    throw await makeLoginRequiredError('Authorization required to access Redash.', opts);
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
