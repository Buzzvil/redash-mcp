import { defineConfig, devices } from '@playwright/test';

// Test environment defaults. The MCP server now uses OIDC; e2e expects a
// pre-existing token cache at REDASH_OIDC_TOKEN_CACHE_PATH (writable by the
// test runner) and the same issuer/client id that was used to mint it.
const TEST_REDASH_URL = process.env.REDASH_URL || 'https://demo.redash.io';
const TEST_OIDC_ISSUER = process.env.REDASH_OIDC_ISSUER || 'https://idp.example.com';
const TEST_OIDC_CLIENT_ID = process.env.REDASH_OIDC_CLIENT_ID || 'redash-api';
const TEST_OIDC_TOKEN_CACHE_PATH = process.env.REDASH_OIDC_TOKEN_CACHE_PATH || '';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  timeout: 60000,
  reporter: [
    ['html'],
    ['list']
  ],
  use: {
    baseURL: 'http://localhost:6274',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    actionTimeout: 15000,
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  webServer: process.env.SKIP_WEBSERVER ? undefined : {
    command: [
      `REDASH_URL=${TEST_REDASH_URL}`,
      `REDASH_OIDC_ISSUER=${TEST_OIDC_ISSUER}`,
      `REDASH_OIDC_CLIENT_ID=${TEST_OIDC_CLIENT_ID}`,
      TEST_OIDC_TOKEN_CACHE_PATH ? `REDASH_OIDC_TOKEN_CACHE_PATH=${TEST_OIDC_TOKEN_CACHE_PATH}` : '',
      'DANGEROUSLY_OMIT_AUTH=true',
      'npm run inspector',
    ].filter(Boolean).join(' '),
    url: 'http://localhost:6274',
    reuseExistingServer: !process.env.CI,
    timeout: 120000,
    stdout: 'pipe',
    stderr: 'pipe',
  },
});
