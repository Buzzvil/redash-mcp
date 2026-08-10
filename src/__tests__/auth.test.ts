import { jest } from '@jest/globals';
import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';

import axios from 'axios';

jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

jest.mock('../logger.js', () => ({
  logger: {
    debug: jest.fn(), info: jest.fn(), warning: jest.fn(), error: jest.fn(), log: jest.fn(),
  },
}));

import {
  AuthError,
  forceRefresh,
  getValidTokens,
  initializeAuth,
  loadOidcConfig,
  performLogout,
  readStatus,
  shutdownAuth,
  startPendingLogin,
  tokenCachePath,
} from '../auth.js';

const ORIGINAL_ENV = { ...process.env };

async function mktmp(): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'redash-mcp-auth-'));
  return path.join(dir, 'tokens.json');
}

function deferred<T>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason?: unknown) => void;
} {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

beforeEach(() => {
  initializeAuth();
  process.env = {
    ...ORIGINAL_ENV,
    REDASH_OIDC_ISSUER: 'https://idp.example.com',
    REDASH_OIDC_CLIENT_ID: 'redash-api',
    REDASH_OIDC_AUDIENCE: 'redash-api',
    REDASH_OIDC_SCOPES: 'openid email offline_access',
  };
  jest.clearAllMocks();
});

afterEach(async () => {
  await shutdownAuth();
  process.env = { ...ORIGINAL_ENV };
});

describe('loadOidcConfig', () => {
  it('requires issuer and client id', () => {
    delete process.env.REDASH_OIDC_ISSUER;
    expect(() => loadOidcConfig()).toThrow('REDASH_OIDC_ISSUER is required');

    process.env.REDASH_OIDC_ISSUER = 'https://idp.example.com';
    delete process.env.REDASH_OIDC_CLIENT_ID;
    expect(() => loadOidcConfig()).toThrow('REDASH_OIDC_CLIENT_ID is required');
  });

  it('strips trailing slash on issuer and falls back audience to client id', () => {
    process.env.REDASH_OIDC_ISSUER = 'https://idp.example.com/';
    delete process.env.REDASH_OIDC_AUDIENCE;
    const cfg = loadOidcConfig();
    expect(cfg.issuer).toBe('https://idp.example.com');
    expect(cfg.audience).toBe('redash-api');
  });
});

describe('tokenCachePath', () => {
  it('honors explicit override', () => {
    expect(tokenCachePath({ REDASH_OIDC_TOKEN_CACHE_PATH: '/tmp/foo.json' } as any)).toBe('/tmp/foo.json');
  });

  it('uses XDG_STATE_HOME when set', () => {
    expect(tokenCachePath({ XDG_STATE_HOME: '/x/state' } as any)).toBe('/x/state/redash-mcp/tokens.json');
  });
});

describe('pending device login', () => {
  it('shares one startup across concurrent callers and aborts it on shutdown', async () => {
    const cache = await mktmp();
    mockedAxios.get.mockResolvedValueOnce({
      data: {
        token_endpoint: 'https://idp.example.com/token',
        device_authorization_endpoint: 'https://idp.example.com/device',
      },
    } as any);
    mockedAxios.post.mockResolvedValueOnce({
      data: {
        device_code: 'device-code',
        user_code: 'ABCD-EFGH',
        verification_uri: 'https://idp.example.com/activate',
        verification_uri_complete: 'https://idp.example.com/activate?code=ABCD-EFGH',
        expires_in: 600,
        interval: 60,
      },
    } as any);

    const [first, second] = await Promise.all([
      startPendingLogin({ cachePath: cache }),
      startPendingLogin({ cachePath: cache }),
    ]);

    expect(first).toEqual(second);
    expect(mockedAxios.get).toHaveBeenCalledTimes(1);
    expect(mockedAxios.post).toHaveBeenCalledTimes(1);
    const requestSignal = (mockedAxios.post.mock.calls[0][2] as { signal: AbortSignal }).signal;
    expect(requestSignal.aborted).toBe(false);

    await shutdownAuth();
    expect(requestSignal.aborted).toBe(true);
  });

  it('does not restart auth work after shutdown until a new lifecycle starts', async () => {
    const cache = await mktmp();
    await shutdownAuth();

    await expect(startPendingLogin({ cachePath: cache }))
      .rejects.toThrow(/cancelled during shutdown/);
    expect(mockedAxios.get).not.toHaveBeenCalled();
    expect(mockedAxios.post).not.toHaveBeenCalled();

    initializeAuth();
    await expect(getValidTokens({ cachePath: cache })).rejects.toThrow(/No cached OIDC tokens/);
  });
});

describe('getValidTokens', () => {
  it('throws AuthError when no cache exists', async () => {
    const cache = await mktmp();
    await expect(getValidTokens({ cachePath: cache })).rejects.toThrow(AuthError);
  });

  it('returns cached tokens when not near expiry', async () => {
    const cache = await mktmp();
    await fs.mkdir(path.dirname(cache), { recursive: true });
    await fs.writeFile(cache, JSON.stringify({
      accessToken: 'fresh', refreshToken: 'r', expiresAt: Date.now() + 600_000,
      issuer: 'https://idp.example.com', clientId: 'redash-api',
    }));
    const tokens = await getValidTokens({ cachePath: cache });
    expect(tokens.accessToken).toBe('fresh');
    expect(mockedAxios.get).not.toHaveBeenCalled();
    expect(mockedAxios.post).not.toHaveBeenCalled();
  });

  it('invalidates cache when issuer or client id mismatch', async () => {
    const cache = await mktmp();
    await fs.mkdir(path.dirname(cache), { recursive: true });
    await fs.writeFile(cache, JSON.stringify({
      accessToken: 'x', expiresAt: Date.now() + 600_000,
      issuer: 'https://other.example.com', clientId: 'redash-api',
    }));
    await expect(getValidTokens({ cachePath: cache })).rejects.toThrow(/different OIDC client/);
  });

  it('refreshes when near expiry and persists the new tokens', async () => {
    const cache = await mktmp();
    await fs.mkdir(path.dirname(cache), { recursive: true });
    await fs.writeFile(cache, JSON.stringify({
      accessToken: 'expired', refreshToken: 'rt', expiresAt: Date.now() - 1_000,
      issuer: 'https://idp.example.com', clientId: 'redash-api',
    }));

    mockedAxios.get.mockResolvedValueOnce({
      data: {
        authorization_endpoint: 'https://idp.example.com/auth',
        token_endpoint: 'https://idp.example.com/token',
      },
    } as any);
    mockedAxios.post.mockResolvedValueOnce({
      data: { access_token: 'new', refresh_token: 'rt2', expires_in: 600 },
    } as any);

    const tokens = await getValidTokens({ cachePath: cache });
    expect(tokens.accessToken).toBe('new');
    expect(tokens.refreshToken).toBe('rt2');

    const persisted = JSON.parse(await fs.readFile(cache, 'utf8'));
    expect(persisted.accessToken).toBe('new');
  });

  it('shares one refresh across concurrent automatic and forced refreshes', async () => {
    const cache = await mktmp();
    await fs.mkdir(path.dirname(cache), { recursive: true });
    await fs.writeFile(cache, JSON.stringify({
      accessToken: 'expired', refreshToken: 'rotating-refresh', expiresAt: Date.now() - 1_000,
      issuer: 'https://idp.example.com', clientId: 'redash-api',
    }));

    mockedAxios.get.mockResolvedValueOnce({
      data: { token_endpoint: 'https://idp.example.com/token' },
    } as any);
    const refreshStarted = deferred<void>();
    const refreshResponse = deferred<any>();
    mockedAxios.post.mockImplementationOnce(() => {
      refreshStarted.resolve();
      return refreshResponse.promise;
    });

    const automatic = getValidTokens({ cachePath: cache });
    const forced = forceRefresh({ cachePath: cache });
    await refreshStarted.promise;

    expect(mockedAxios.get).toHaveBeenCalledTimes(1);
    expect(mockedAxios.post).toHaveBeenCalledTimes(1);
    refreshResponse.resolve({
      data: { access_token: 'shared-new', refresh_token: 'rotated-refresh', expires_in: 600 },
    });

    const [automaticTokens, forcedTokens] = await Promise.all([automatic, forced]);
    expect(automaticTokens.accessToken).toBe('shared-new');
    expect(forcedTokens).toEqual(automaticTokens);
    expect(mockedAxios.get).toHaveBeenCalledTimes(1);
    expect(mockedAxios.post).toHaveBeenCalledTimes(1);
  });

  it('throws when token expired and no refresh token available', async () => {
    const cache = await mktmp();
    await fs.mkdir(path.dirname(cache), { recursive: true });
    await fs.writeFile(cache, JSON.stringify({
      accessToken: 'expired', expiresAt: Date.now() - 1_000,
      issuer: 'https://idp.example.com', clientId: 'redash-api',
    }));
    await expect(getValidTokens({ cachePath: cache })).rejects.toThrow(/refresh_token/);
  });

  it('preserves refresh_token when the IdP omits it on refresh', async () => {
    const cache = await mktmp();
    await fs.mkdir(path.dirname(cache), { recursive: true });
    await fs.writeFile(cache, JSON.stringify({
      accessToken: 'expired', refreshToken: 'rt-original', expiresAt: Date.now() - 1_000,
      issuer: 'https://idp.example.com', clientId: 'redash-api',
    }));

    mockedAxios.get.mockResolvedValueOnce({
      data: {
        authorization_endpoint: 'https://idp.example.com/auth',
        token_endpoint: 'https://idp.example.com/token',
      },
    } as any);
    mockedAxios.post.mockResolvedValueOnce({
      data: { access_token: 'new', expires_in: 600 }, // no refresh_token in response
    } as any);

    const tokens = await getValidTokens({ cachePath: cache });
    expect(tokens.refreshToken).toBe('rt-original');
  });
});

describe('forceRefresh', () => {
  it('throws if no refresh_token cached', async () => {
    const cache = await mktmp();
    await fs.mkdir(path.dirname(cache), { recursive: true });
    await fs.writeFile(cache, JSON.stringify({
      accessToken: 'x', expiresAt: Date.now() + 60_000,
      issuer: 'https://idp.example.com', clientId: 'redash-api',
    }));
    await expect(forceRefresh({ cachePath: cache })).rejects.toThrow(/refresh_token/);
  });
});

describe('performLogout', () => {
  it('removes the cache file and is idempotent when no cache exists', async () => {
    const cache = await mktmp();
    await fs.mkdir(path.dirname(cache), { recursive: true });
    await fs.writeFile(cache, '{}');
    await performLogout({ cachePath: cache });
    await expect(fs.access(cache)).rejects.toThrow();
    // Idempotent
    await expect(performLogout({ cachePath: cache })).resolves.toBeUndefined();
  });
});

describe('readStatus', () => {
  it('reports no tokens when cache is missing', async () => {
    const cache = await mktmp();
    const status = await readStatus({ cachePath: cache });
    expect(status.hasTokens).toBe(false);
  });

  it('extracts email from id_token payload', async () => {
    const cache = await mktmp();
    await fs.mkdir(path.dirname(cache), { recursive: true });
    // Forge a JWT-shaped string: header.payload.signature
    const payload = Buffer.from(JSON.stringify({ email: 'user@example.com', sub: 'abc' })).toString('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    await fs.writeFile(cache, JSON.stringify({
      accessToken: 'opaque', idToken: `h.${payload}.sig`,
      expiresAt: Date.now() + 60_000,
      issuer: 'https://idp.example.com', clientId: 'redash-api',
    }));
    const status = await readStatus({ cachePath: cache });
    expect(status.hasTokens).toBe(true);
    expect(status.email).toBe('user@example.com');
    expect(status.subject).toBe('abc');
  });
});
