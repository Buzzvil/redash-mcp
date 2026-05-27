// Set environment variables before any imports
process.env.REDASH_URL = 'https://redash.example.com';
process.env.REDASH_OIDC_ISSUER = 'https://idp.example.com';
process.env.REDASH_OIDC_CLIENT_ID = 'redash-cli';
process.env.REDASH_TIMEOUT = '30000';

import { jest } from '@jest/globals';
import axios from 'axios';

import { RedashClient } from '../redashClient.js';

// Mock axios
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

// Mock auth module so the client never tries to read a real token cache or
// hit the IdP during tests. The interceptor will pull `accessToken` from
// whatever the mock returns.
jest.mock('../auth.js', () => ({
  AuthError: class AuthError extends Error {},
  getValidTokens: jest.fn<any>().mockResolvedValue({
    accessToken: 'test-access-token',
    expiresAt: Date.now() + 60_000,
    issuer: 'https://idp.example.com',
    clientId: 'redash-cli',
  }),
  forceRefresh: jest.fn<any>().mockResolvedValue({
    accessToken: 'refreshed-access-token',
    expiresAt: Date.now() + 60_000,
    issuer: 'https://idp.example.com',
    clientId: 'redash-cli',
  }),
}));

// Mock logger
jest.mock('../logger.js', () => ({
  logger: {
    debug: jest.fn(),
    info: jest.fn(),
    warning: jest.fn(),
    error: jest.fn(),
    log: jest.fn(),
  },
}));

describe('RedashClient', () => {
  let client: RedashClient;
  let mockAxiosInstance: any;
  let requestInterceptor: ((config: any) => any) | undefined;
  let responseErrorInterceptor: ((err: any) => any) | undefined;

  beforeEach(() => {
    process.env.REDASH_URL = 'https://redash.example.com';
    process.env.REDASH_OIDC_ISSUER = 'https://idp.example.com';
    process.env.REDASH_OIDC_CLIENT_ID = 'redash-cli';
    process.env.REDASH_TIMEOUT = '30000';
    delete process.env.REDASH_EXTRA_HEADERS;

    requestInterceptor = undefined;
    responseErrorInterceptor = undefined;

    mockAxiosInstance = {
      get: jest.fn(),
      post: jest.fn(),
      delete: jest.fn(),
      request: jest.fn(),
      defaults: { headers: {} },
      interceptors: {
        request: {
          use: jest.fn((fn: any) => { requestInterceptor = fn; }),
        },
        response: {
          // axios signature: use(onFulfilled, onRejected)
          use: jest.fn((_fulfilled: any, rejected: any) => { responseErrorInterceptor = rejected; }),
        },
      },
    };

    mockedAxios.create.mockReturnValue(mockAxiosInstance as any);

    client = new RedashClient();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('constructor', () => {
    it('should throw error if REDASH_URL is not set', () => {
      delete process.env.REDASH_URL;
      expect(() => new RedashClient()).toThrow(
        'REDASH_URL must be set in the environment'
      );
    });

    it('should NOT require REDASH_API_KEY', () => {
      // Auth is now OIDC; the API key env var is intentionally not consulted.
      delete process.env.REDASH_API_KEY;
      expect(() => new RedashClient()).not.toThrow();
    });

    it('should create axios instance without an Authorization header in defaults', () => {
      const callArgs = mockedAxios.create.mock.calls[0]?.[0];
      expect(callArgs).toEqual(
        expect.objectContaining({
          baseURL: 'https://redash.example.com',
          timeout: 30000,
        })
      );
      // Authorization is added per-request by the interceptor, not baked in.
      expect((callArgs?.headers as any)?.Authorization).toBeUndefined();
      expect((callArgs?.headers as any)?.['Content-Type']).toBe('application/json');
    });

    it('should attach Bearer token via request interceptor', async () => {
      expect(requestInterceptor).toBeDefined();
      const config: any = { headers: {} };
      const next = await requestInterceptor!(config);
      expect(next.headers.Authorization).toBe('Bearer test-access-token');
    });

    it('should retry once with refreshed token on 401', async () => {
      expect(responseErrorInterceptor).toBeDefined();
      const originalConfig: any = { headers: {}, url: '/api/queries', method: 'get' };
      const err: any = { response: { status: 401 }, config: originalConfig };
      mockAxiosInstance.request.mockResolvedValue({ data: { ok: true } });

      const result = await responseErrorInterceptor!(err);

      expect(originalConfig._retried).toBe(true);
      expect(originalConfig.headers.Authorization).toBe('Bearer refreshed-access-token');
      expect(mockAxiosInstance.request).toHaveBeenCalledWith(originalConfig);
      expect(result).toEqual({ data: { ok: true } });
    });

    it('should not retry on non-401 errors', async () => {
      const cfg: any = { headers: {} };
      const err: any = { response: { status: 500 }, config: cfg };
      await expect(responseErrorInterceptor!(err)).rejects.toBe(err);
      expect(mockAxiosInstance.request).not.toHaveBeenCalled();
    });

    it('should parse JSON extra headers', () => {
      process.env.REDASH_EXTRA_HEADERS = '{"CF-Access-Client-Id":"test-id","CF-Access-Client-Secret":"test-secret"}';

      mockedAxios.create.mockClear();
      new RedashClient();

      expect(mockedAxios.create).toHaveBeenCalledWith(
        expect.objectContaining({
          headers: expect.objectContaining({
            'CF-Access-Client-Id': 'test-id',
            'CF-Access-Client-Secret': 'test-secret',
          }),
        })
      );
    });

    it('should parse key=value extra headers', () => {
      process.env.REDASH_EXTRA_HEADERS = 'X-Custom-Header=value1;X-Another-Header=value2';

      mockedAxios.create.mockClear();
      new RedashClient();

      expect(mockedAxios.create).toHaveBeenCalledWith(
        expect.objectContaining({
          headers: expect.objectContaining({
            'X-Custom-Header': 'value1',
            'X-Another-Header': 'value2',
          }),
        })
      );
    });

    it('should refuse to let extra headers override Authorization', () => {
      process.env.REDASH_EXTRA_HEADERS = '{"Authorization":"malicious-key"}';

      mockedAxios.create.mockClear();
      new RedashClient();

      const callArgs = mockedAxios.create.mock.calls[0]?.[0];
      // No baked-in Authorization at construction time — the interceptor sets it.
      expect((callArgs?.headers as any)?.Authorization).toBeUndefined();
    });
  });

  // The remaining describe blocks below cover HTTP methods on the axios
  // instance — auth wiring is independent of which endpoint is being hit, so
  // these tests are unchanged in spirit (just using the new mock instance).
  describe('getQueries', () => {
    it('should fetch queries with pagination', async () => {
      const mockResponse = {
        data: {
          count: 100,
          page: 1,
          page_size: 25,
          results: [
            { id: 1, name: 'Query 1' },
            { id: 2, name: 'Query 2' },
          ],
        },
      };

      mockAxiosInstance.get.mockResolvedValue(mockResponse);

      const result = await client.getQueries(1, 25);

      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/api/queries', {
        params: { page: 1, page_size: 25, q: undefined },
      });
      expect(result).toEqual({
        count: 100,
        page: 1,
        pageSize: 25,
        results: mockResponse.data.results,
      });
    });

    it('should throw error on failure', async () => {
      mockAxiosInstance.get.mockRejectedValue(new Error('Network error'));

      await expect(client.getQueries()).rejects.toThrow(
        'Failed to fetch queries from Redash'
      );
    });
  });

  describe('getQuery', () => {
    it('should fetch a specific query', async () => {
      const mockQuery = { id: 1, name: 'Test Query', query: 'SELECT 1' };
      mockAxiosInstance.get.mockResolvedValue({ data: mockQuery });
      const result = await client.getQuery(1);
      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/api/queries/1');
      expect(result).toEqual(mockQuery);
    });
  });

  describe('archiveQuery', () => {
    it('should archive a query', async () => {
      mockAxiosInstance.delete.mockResolvedValue({});
      const result = await client.archiveQuery(1);
      expect(mockAxiosInstance.delete).toHaveBeenCalledWith('/api/queries/1');
      expect(result).toEqual({ success: true });
    });
  });

  describe('executeQuery', () => {
    it('should execute a query and return immediate results', async () => {
      const mockResult = {
        id: 1, query_id: 123,
        data: { columns: [{ name: 'id', type: 'integer' }], rows: [{ id: 1 }] },
      };
      mockAxiosInstance.post.mockResolvedValue({ data: mockResult });
      const result = await client.executeQuery(123);
      expect(mockAxiosInstance.post).toHaveBeenCalledWith(
        '/api/queries/123/results',
        { parameters: undefined, max_age: undefined }
      );
      expect(result).toEqual(mockResult);
    });
  });

  describe('getDataSources', () => {
    it('should fetch data sources', async () => {
      const mockDataSources = [{ id: 1, name: 'PostgreSQL' }];
      mockAxiosInstance.get.mockResolvedValue({ data: mockDataSources });
      const result = await client.getDataSources();
      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/api/data_sources');
      expect(result).toEqual(mockDataSources);
    });
  });

  describe('getDashboards', () => {
    it('should fetch dashboards', async () => {
      const mockResponse = {
        data: { count: 10, page: 1, page_size: 25, results: [{ id: 1, name: 'Dashboard 1' }] },
      };
      mockAxiosInstance.get.mockResolvedValue(mockResponse);
      const result = await client.getDashboards(1, 25);
      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/api/dashboards', {
        params: { page: 1, page_size: 25 },
      });
      expect(result.results).toHaveLength(1);
    });
  });

  describe('getSchema', () => {
    it('should fetch data source schema', async () => {
      const mockSchema = { schema: [{ name: 'users', columns: [{ name: 'id', type: 'integer' }] }] };
      mockAxiosInstance.get.mockResolvedValue({ data: mockSchema });
      const result = await client.getSchema(1);
      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/api/data_sources/1/schema');
      expect(result).toEqual(mockSchema);
    });
  });
});
