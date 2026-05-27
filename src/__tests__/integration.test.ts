/**
 * Integration tests for MCP server
 *
 * These tests verify the integration between different components
 * of the Redash MCP server.
 */

// Set environment variables before any imports
process.env.REDASH_URL = 'https://redash.example.com';
process.env.REDASH_OIDC_ISSUER = 'https://idp.example.com';
process.env.REDASH_OIDC_CLIENT_ID = 'redash-cli';
process.env.REDASH_TIMEOUT = '30000';

import { jest } from '@jest/globals';

// Mock auth so the singleton redashClient (imported below) doesn't try to
// hit the IdP or read a real token cache.
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

// Mock axios to avoid real API calls
jest.mock('axios');

import { redashClient } from '../redashClient.js';
import { logger } from '../logger.js';

describe('MCP Server Integration', () => {
  beforeEach(() => {
    process.env.REDASH_URL = 'https://redash.example.com';
    process.env.REDASH_OIDC_ISSUER = 'https://idp.example.com';
    process.env.REDASH_OIDC_CLIENT_ID = 'redash-cli';
  });

  describe('redashClient and logger integration', () => {
    it('should use logger for error reporting', async () => {
      const errorSpy = jest.spyOn(logger, 'error');

      // Mock axios to throw an error
      const axios = await import('axios');
      const mockedAxios = axios as any;

      if (mockedAxios.create) {
        const mockInstance = {
          get: jest.fn<any>().mockRejectedValue(new Error('Network error')),
          defaults: { headers: {} },
          interceptors: {
            request: { use: jest.fn() },
            response: { use: jest.fn() },
          },
        };
        mockedAxios.create.mockReturnValue(mockInstance as any);
      }

      try {
        await redashClient.getQueries();
      } catch (error) {
        // Expected to fail
      }

      expect(errorSpy).toHaveBeenCalled();
      errorSpy.mockRestore();
    });
  });

  describe('Environment configuration', () => {
    it('should require REDASH_URL', () => {
      const originalUrl = process.env.REDASH_URL;
      delete process.env.REDASH_URL;

      expect(() => {
        const { RedashClient } = require('../redashClient.js');
        new RedashClient();
      }).toThrow('REDASH_URL');

      process.env.REDASH_URL = originalUrl;
    });
  });

  describe('Tool schemas validation', () => {
    it('should validate query creation parameters', () => {
      const { z } = require('zod');

      const createQuerySchema = z.object({
        name: z.string(),
        data_source_id: z.number(),
        query: z.string(),
        description: z.string().optional(),
        options: z.any().optional(),
        schedule: z.any().optional(),
        tags: z.array(z.string()).optional()
      });

      const validData = {
        name: 'Test Query',
        data_source_id: 1,
        query: 'SELECT 1',
      };

      expect(() => createQuerySchema.parse(validData)).not.toThrow();

      const invalidData = {
        name: 'Test Query',
        // missing data_source_id
        query: 'SELECT 1',
      };

      expect(() => createQuerySchema.parse(invalidData)).toThrow();
    });

    it('should validate query update parameters', () => {
      const { z } = require('zod');

      const updateQuerySchema = z.object({
        queryId: z.number(),
        name: z.string().optional(),
        data_source_id: z.number().optional(),
        query: z.string().optional(),
        description: z.string().optional(),
        options: z.any().optional(),
        schedule: z.any().optional(),
        tags: z.array(z.string()).optional(),
        is_archived: z.boolean().optional(),
        is_draft: z.boolean().optional()
      });

      const validData = {
        queryId: 123,
        name: 'Updated Query',
      };

      expect(() => updateQuerySchema.parse(validData)).not.toThrow();

      const invalidData = {
        // missing queryId
        name: 'Updated Query',
      };

      expect(() => updateQuerySchema.parse(invalidData)).toThrow();
    });

    it('should validate execute query parameters', () => {
      const { z } = require('zod');

      const executeQuerySchema = z.object({
        queryId: z.number(),
        parameters: z.record(z.any()).optional(),
        maxAge: z.number().optional()
      });

      const validData = {
        queryId: 123,
        parameters: { date: '2024-01-01' },
      };

      expect(() => executeQuerySchema.parse(validData)).not.toThrow();

      const validDataWithoutParams = {
        queryId: 123,
      };

      expect(() => executeQuerySchema.parse(validDataWithoutParams)).not.toThrow();
    });

    it('should validate parameterized query execution parameters', () => {
      const { z } = require('zod');

      const executeParameterizedQuerySchema = z.object({
        queryId: z.number(),
        parameters: z.record(z.any()).optional(),
        useSavedDefaults: z.boolean().optional(),
        maxAge: z.number().optional(),
      });

      expect(() => executeParameterizedQuerySchema.parse({
        queryId: 123,
        parameters: { category: 'example-value', flag: true },
        useSavedDefaults: true,
        maxAge: 0,
      })).not.toThrow();

      expect(() => executeParameterizedQuerySchema.parse({
        parameters: { category: 'example-value' },
      })).toThrow();
    });

    it('should validate visualization creation parameters', () => {
      const { z } = require('zod');

      const createVisualizationSchema = z.object({
        query_id: z.number(),
        type: z.string(),
        name: z.string(),
        description: z.string().optional(),
        options: z.any()
      });

      const validData = {
        query_id: 1,
        type: 'CHART',
        name: 'Test Chart',
        options: { chartType: 'bar' },
      };

      expect(() => createVisualizationSchema.parse(validData)).not.toThrow();

      const invalidData = {
        query_id: 1,
        type: 'CHART',
        // missing name and options
      };

      expect(() => createVisualizationSchema.parse(invalidData)).toThrow();
    });

    it('should validate chart visualization update parameters', () => {
      const { chartVisualizationUpdateSchema } = require('../chartVisualization.js');

      const validData = {
        visualizationId: 184,
        globalSeriesType: 'column',
        columnMapping: { x: 'send_hour', y: 'clicks' },
        chartOptions: { legend: { enabled: true } },
      };

      expect(() => chartVisualizationUpdateSchema.parse(validData)).not.toThrow();

      const invalidData = {
        globalSeriesType: 'column',
      };

      expect(() => chartVisualizationUpdateSchema.parse(invalidData)).toThrow();
    });
  });

  describe('Resource URI parsing', () => {
    it('should parse query resource URIs', () => {
      const uri = 'redash://query/123';
      const match = uri.match(/^redash:\/\/(query|dashboard)\/(\d+)$/);

      expect(match).not.toBeNull();
      expect(match![1]).toBe('query');
      expect(match![2]).toBe('123');
    });

    it('should parse dashboard resource URIs', () => {
      const uri = 'redash://dashboard/456';
      const match = uri.match(/^redash:\/\/(query|dashboard)\/(\d+)$/);

      expect(match).not.toBeNull();
      expect(match![1]).toBe('dashboard');
      expect(match![2]).toBe('456');
    });

    it('should reject invalid resource URIs', () => {
      const invalidUris = [
        'redash://invalid/123',
        'redash://query/abc',
        'invalid://query/123',
        'redash://query',
      ];

      invalidUris.forEach((uri) => {
        const match = uri.match(/^redash:\/\/(query|dashboard)\/(\d+)$/);
        expect(match).toBeNull();
      });
    });
  });
});
