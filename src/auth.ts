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

/**
 * Decide which OIDC flow to use for this environment.
 *
 * The default PKCE+loopback flow assumes (a) we can spawn a browser on the
 * machine running this process, and (b) the user's browser can reach our
 * 127.0.0.1 redirect URI. Both are false in containers and headless Linux,
 * so for those we fall back to RFC 8628 Device Authorization Grant which
 * needs only outbound HTTPS to the IdP.
 *
 * Overridable with `REDASH_OIDC_FLOW=device` / `REDASH_OIDC_FLOW=pkce`.
 */
type AuthFlow = 'pkce' | 'device';
export function selectAuthFlow(env: NodeJS.ProcessEnv = process.env): AuthFlow {
  const override = (env.REDASH_OIDC_FLOW || '').toLowerCase();
  if (override === 'device' || override === 'pkce') return override;
  return detectContainerLike(env) ? 'device' : 'pkce';
}

function detectContainerLike(env: NodeJS.ProcessEnv): boolean {
  // Kubernetes always injects this.
  if (env.KUBERNETES_SERVICE_HOST) return true;
  // systemd-nspawn / podman / some Docker setups expose this.
  if (env.container) return true;
  // Docker.
  try { if (fs.existsSync('/.dockerenv')) return true; } catch { /* ignore */ }
  // Podman.
  try { if (fs.existsSync('/run/.containerenv')) return true; } catch { /* ignore */ }
  // cgroup heuristic — last resort.
  try {
    const cg = fs.readFileSync('/proc/1/cgroup', 'utf8');
    if (/\b(docker|kubepods|containerd|libpod|garden)\b/.test(cg)) return true;
  } catch { /* /proc/1/cgroup may not exist or be readable */ }
  // Headless Linux can't reach a browser either way — treat as container.
  if (process.platform === 'linux' && !env.DISPLAY && !env.WAYLAND_DISPLAY) {
    return true;
  }
  return false;
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
  flow: AuthFlow;
  /** URL the user opens — PKCE auth URL or device verification_uri_complete. */
  url: string;
  /** Device flow only — short code in case verification_uri_complete is not accepted. */
  userCode?: string;
  /** Promise resolves with cached tokens once the user finishes browser-side auth. */
  completion: Promise<CachedTokens>;
  /** Seconds until the flow expires. PKCE: timeoutMs/1000; device: server-provided expires_in. */
  expiresInSec: number;
}

/**
 * Start a PKCE login flow: spin up the loopback callback server, build the
 * auth URL, and return both immediately. The caller decides how to surface
 * the URL (auto-launch browser in a terminal, return it via tool response in
 * an MCP context, etc.) and may await `completion` to receive the cached
 * tokens once the callback arrives.
 */
async function beginPkceFlow(opts: { cfg?: OidcConfig; cachePath?: string; timeoutMs?: number } = {}): Promise<LoginFlowHandle> {
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

  return {
    flow: 'pkce',
    url: authUrl.toString(),
    completion,
    expiresInSec: Math.floor(timeoutMs / 1000),
  };
}

/**
 * Start an OAuth 2.0 Device Authorization Grant (RFC 8628) flow. Requests a
 * device code from the IdP and starts polling the token endpoint in the
 * background. Works in containers / headless / locked-down environments
 * because it needs only outbound HTTPS to the IdP — no loopback redirect.
 */
async function beginDeviceFlow(opts: { cfg?: OidcConfig; cachePath?: string } = {}): Promise<LoginFlowHandle> {
  const cfg = opts.cfg ?? loadOidcConfig();
  const cache = opts.cachePath ?? tokenCachePath();

  const discovery = await discover(cfg.issuer);
  if (!discovery.device_authorization_endpoint) {
    throw new AuthError(
      `IdP discovery document at ${cfg.issuer} does not advertise device_authorization_endpoint. ` +
      `Enable RFC 8628 device flow on the OIDC provider or set REDASH_OIDC_FLOW=pkce.`,
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
    flow: 'device',
    url: dc.verification_uri_complete || dc.verification_uri,
    userCode: dc.user_code,
    completion,
    expiresInSec: dc.expires_in,
  };
}

/**
 * Dispatch to PKCE or device flow based on `selectAuthFlow()`. PKCE for
 * regular desktops (browser available, loopback reachable); device flow for
 * containers / headless. Override with `REDASH_OIDC_FLOW`.
 */
async function beginLoginFlow(opts: { cfg?: OidcConfig; cachePath?: string; timeoutMs?: number } = {}): Promise<LoginFlowHandle> {
  const flow = selectAuthFlow();
  logger.debug(`Selected OIDC auth flow: ${flow}`);
  if (flow === 'device') return beginDeviceFlow(opts);
  return beginPkceFlow(opts);
}

/**
 * Run the full PKCE login flow: open browser, wait for callback, exchange
 * code, persist tokens. Intended to be invoked from `redash-mcp login`
 * (interactive terminal). For the MCP server path see `startPendingLogin`.
 */
export async function performLogin(opts: { cfg?: OidcConfig; cachePath?: string; timeoutMs?: number } = {}): Promise<CachedTokens> {
  const handle = await beginLoginFlow(opts);
  if (handle.flow === 'device') {
    process.stderr.write(
      `\nDevice authorization required. Open this URL in your browser:\n  ${handle.url}\n\n` +
      `If you're prompted for a code, enter: ${handle.userCode}\n` +
      `(code expires in ${handle.expiresInSec}s)\n\n`,
    );
  } else {
    process.stderr.write(`\nOpen this URL in your browser if it doesn't open automatically:\n  ${handle.url}\n\n`);
  }
  openBrowser(handle.url);
  return handle.completion;
}

interface PendingLogin {
  flow: AuthFlow;
  url: string;
  userCode?: string;
  completion: Promise<CachedTokens>;
  expiresAt: number;
  browserLaunched: boolean;
}

let pendingLogin: PendingLogin | null = null;

/**
 * Start (or attach to) a non-interactive login flow (PKCE or device — see
 * `selectAuthFlow`). The flow runs in the background. Caller surfaces `url`
 * (and `userCode` for device flow) to the user via MCP tool response. Once
 * the user finishes browser-side authorization the tokens are written to
 * cache and the next call succeeds.
 *
 * For the PKCE branch (i.e. non-container desktop) we additionally try to
 * spawn the user's default browser here — the user's command sits on the
 * same machine as this MCP process, so `open` / `start` / `xdg-open` will
 * pop up a window they can see and complete. For device flow we don't, both
 * because the server may have no browser at all and because the IdP page is
 * meant to be opened on a separate trusted device. Opt out with
 * `REDASH_OIDC_AUTO_LAUNCH_BROWSER=false`.
 *
 * Concurrent callers share one in-flight login until it resolves or its
 * `expiresAt` passes. Browser is launched only on the first attempt.
 */
export async function startPendingLogin(opts: { cfg?: OidcConfig; cachePath?: string; timeoutMs?: number } = {}): Promise<{ flow: AuthFlow; url: string; userCode?: string; expiresAt: number; browserLaunched: boolean }> {
  if (pendingLogin && pendingLogin.expiresAt > Date.now()) {
    return {
      flow: pendingLogin.flow,
      url: pendingLogin.url,
      userCode: pendingLogin.userCode,
      expiresAt: pendingLogin.expiresAt,
      browserLaunched: pendingLogin.browserLaunched,
    };
  }

  const handle = await beginLoginFlow(opts);
  const autoLaunchOpt = (process.env.REDASH_OIDC_AUTO_LAUNCH_BROWSER || '').toLowerCase();
  const autoLaunchDisabled = autoLaunchOpt === 'false' || autoLaunchOpt === '0' || autoLaunchOpt === 'no';
  const browserLaunched = handle.flow === 'pkce' && !autoLaunchDisabled;
  if (browserLaunched) {
    openBrowser(handle.url);
  }

  const entry: PendingLogin = {
    flow: handle.flow,
    url: handle.url,
    userCode: handle.userCode,
    completion: handle.completion,
    expiresAt: Date.now() + handle.expiresInSec * 1000,
    browserLaunched,
  };
  pendingLogin = entry;
  handle.completion.finally(() => {
    if (pendingLogin === entry) pendingLogin = null;
  }).catch(() => { /* errors surface via the next ensureValidTokens call */ });

  return { flow: entry.flow, url: entry.url, userCode: entry.userCode, expiresAt: entry.expiresAt, browserLaunched };
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
 * pending login flow and throws an AuthError whose message contains the auth
 * URL (and on PKCE non-container desktops, the browser is also auto-launched
 * by `startPendingLogin`). The caller surfaces the URL to the user via a
 * tool response so they have a clickable fallback in case the auto-launch
 * silently failed. Once the user completes the browser flow, the loopback
 * callback (PKCE) or device-flow polling (device) hydrates the cache and the
 * next call to this function succeeds.
 */
export async function ensureValidTokens(opts: { cfg?: OidcConfig; cachePath?: string; now?: () => number } = {}): Promise<CachedTokens> {
  try {
    return await getValidTokens(opts);
  } catch (err) {
    if (!(err instanceof AuthError)) throw err;
    const pending = await startPendingLogin(opts);
    const codeLine = pending.flow === 'device' && pending.userCode
      ? `\nIf the page asks for a code, enter: ${pending.userCode}`
      : '';
    const lead = pending.browserLaunched
      ? `OIDC login required. Your browser should have opened automatically — if not, open this URL manually:`
      : `OIDC login required. Open this URL in your browser to authenticate:`;
    throw new AuthError(
      `${lead}\n\n  ${pending.url}${codeLine}\n\nAfter completing the browser flow, retry the tool call.`,
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
